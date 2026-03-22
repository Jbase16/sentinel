from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import List, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from .base import Mutator
from ..contracts.enums import VulnerabilityClass, WebMethod, ParamLocation, DeltaSeverity
from ..contracts.models import ParamSpec, WebMission
from ..context import WebContext
from ..transport import MutatingTransport, MutationResult


# ---------------------------------------------------------------------------
# Error signature patterns (database-specific error messages)
# ---------------------------------------------------------------------------

_ERROR_SIGNATURES: List[Tuple[re.Pattern, str]] = [
    # MySQL
    (re.compile(r"You have an error in your SQL syntax", re.I), "mysql_syntax"),
    (re.compile(r"mysql_fetch|mysql_num_rows|mysql_query", re.I), "mysql_func"),
    (re.compile(r"Warning:.*mysql_", re.I), "mysql_warning"),
    # PostgreSQL
    (re.compile(r"ERROR:\s+syntax error at or near", re.I), "pgsql_syntax"),
    (re.compile(r"pg_query|pg_exec|pg_prepare", re.I), "pgsql_func"),
    (re.compile(r"unterminated quoted string", re.I), "pgsql_quote"),
    # MSSQL
    (re.compile(r"Unclosed quotation mark", re.I), "mssql_quote"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I), "mssql_oledb"),
    (re.compile(r"\bconvert\b.*\bint\b.*\bvarchar\b", re.I), "mssql_convert"),
    # SQLite
    (re.compile(r"SQLite3?::query|SQLITE_ERROR|near \".*\": syntax error", re.I), "sqlite_syntax"),
    # Oracle
    (re.compile(r"ORA-\d{5}", re.I), "oracle_error"),
    (re.compile(r"quoted string not properly terminated", re.I), "oracle_quote"),
    # Generic
    (re.compile(r"SQL syntax.*?error|syntax error.*?SQL", re.I), "generic_sql_syntax"),
    (re.compile(r"ODBC.*?Driver.*?SQL", re.I), "generic_odbc"),
]

# Error-based payloads: designed to break SQL syntax and trigger error messages.
# These are safe read-only probes — no data modification.
_ERROR_PAYLOADS = [
    "'",              # Unmatched single quote
    "''",             # Double single quote (escape test)
    "' OR '1'='1",    # Classic tautology
    "1' AND '1'='2",  # False tautology (should change behavior)
    "1 AND 1=1",      # Numeric tautology
    "1 AND 1=2",      # Numeric false (compare with above)
    "' UNION SELECT NULL--",  # Union probe
]

# Time-based payloads: inject a delay and measure timing delta.
# Delay is kept short (3s) to avoid DoS-like behavior.
_TIME_DELAY_SECONDS = 3
_TIME_PAYLOADS = [
    f"' OR SLEEP({_TIME_DELAY_SECONDS})--",                          # MySQL
    f"' OR pg_sleep({_TIME_DELAY_SECONDS})--",                       # PostgreSQL
    f"'; WAITFOR DELAY '0:0:{_TIME_DELAY_SECONDS}'--",               # MSSQL
    f"' OR 1=1 AND SLEEP({_TIME_DELAY_SECONDS})--",                  # MySQL variant
]

# Timing threshold: response must exceed baseline by this much (ms) to count
_TIMING_THRESHOLD_MS = 2000


def _decode_body(b64: str | None) -> str:
    if not b64:
        return ""
    try:
        return base64.b64decode(b64).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _check_error_signatures(body: str) -> List[str]:
    """Return list of matched error signature names."""
    hits = []
    for pattern, name in _ERROR_SIGNATURES:
        if pattern.search(body):
            hits.append(name)
    return hits


@dataclass
class SqlInjectionMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.SQLI

    def run(
        self,
        mission: WebMission,
        ctx: WebContext,
        transport: MutatingTransport,
        url: str,
        method: WebMethod,
        budget_index: int,
    ) -> List[MutationResult]:
        results: List[MutationResult] = []

        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        # V1: Only GET query params. POST body injection comes in V2.
        if not params or method != WebMethod.GET:
            return results

        # Establish baseline once
        handle = transport.establish_baseline(mission, ctx, method, url)
        baseline_body = _decode_body(handle.exchange.response_body_b64)

        mutation_count = 0

        for param_idx, (param_name, original_value) in enumerate(params):
            # --- Phase 1: Error-based detection ---
            error_confirmed = False
            for payload in _ERROR_PAYLOADS:
                if budget_index + mutation_count >= mission.exploit_ceiling:
                    return results

                mutated_url = self._inject_param(
                    parsed, params, param_idx, payload
                )

                param_spec = ParamSpec(
                    name=param_name,
                    location=ParamLocation.QUERY,
                    example_value=original_value,
                    type_guess="string",
                    reflection_hint=False,
                )

                mutation_res = transport.mutate(
                    mission=mission,
                    ctx=ctx,
                    handle=handle,
                    vuln_class=self.vuln_class,
                    mutation_label=f"sqli_error_{param_name}_{mutation_count}",
                    budget_index=budget_index + mutation_count,
                    mutated_url=mutated_url,
                    mutated_method=method,
                    param_spec=param_spec,
                )
                mutation_count += 1

                resp_body = _decode_body(
                    mutation_res.exchange.response_body_b64
                )
                error_hits = _check_error_signatures(resp_body)

                # Only flag if error signatures appear in mutated response
                # but NOT in baseline (avoids false positives on error pages)
                baseline_hits = _check_error_signatures(baseline_body)
                new_hits = [h for h in error_hits if h not in baseline_hits]

                if new_hits:
                    mutation_res.delta.severity = DeltaSeverity.HIGH
                    mutation_res.delta.notes.append(
                        f"SQLi error-based: {', '.join(new_hits)} triggered by param '{param_name}'"
                    )
                    results.append(mutation_res)
                    error_confirmed = True
                    break  # One confirmed payload per param is enough

            # --- Phase 2: Time-based blind detection ---
            # Only run if error-based didn't confirm (avoids redundant probes)
            if not error_confirmed:
                for payload in _TIME_PAYLOADS:
                    if budget_index + mutation_count >= mission.exploit_ceiling:
                        return results

                    mutated_url = self._inject_param(
                        parsed, params, param_idx, payload
                    )

                    param_spec = ParamSpec(
                        name=param_name,
                        location=ParamLocation.QUERY,
                        example_value=original_value,
                        type_guess="string",
                        reflection_hint=False,
                    )

                    mutation_res = transport.mutate(
                        mission=mission,
                        ctx=ctx,
                        handle=handle,
                        vuln_class=self.vuln_class,
                        mutation_label=f"sqli_time_{param_name}_{mutation_count}",
                        budget_index=budget_index + mutation_count,
                        mutated_url=mutated_url,
                        mutated_method=method,
                        param_spec=param_spec,
                    )
                    mutation_count += 1

                    # Check timing delta
                    timing_delta = mutation_res.delta.timing_delta_ms
                    if (
                        timing_delta is not None
                        and timing_delta >= _TIMING_THRESHOLD_MS
                    ):
                        # Statistical confirmation: repeat the probe once more
                        if budget_index + mutation_count >= mission.exploit_ceiling:
                            return results

                        confirm_res = transport.mutate(
                            mission=mission,
                            ctx=ctx,
                            handle=handle,
                            vuln_class=self.vuln_class,
                            mutation_label=f"sqli_time_confirm_{param_name}_{mutation_count}",
                            budget_index=budget_index + mutation_count,
                            mutated_url=mutated_url,
                            mutated_method=method,
                            param_spec=param_spec,
                        )
                        mutation_count += 1

                        confirm_delta = confirm_res.delta.timing_delta_ms
                        if (
                            confirm_delta is not None
                            and confirm_delta >= _TIMING_THRESHOLD_MS
                        ):
                            confirm_res.delta.severity = DeltaSeverity.HIGH
                            confirm_res.delta.notes.append(
                                f"SQLi time-based blind: param '{param_name}' "
                                f"delayed {confirm_delta}ms (confirmed, threshold={_TIMING_THRESHOLD_MS}ms)"
                            )
                            results.append(confirm_res)
                            break  # One confirmed time-based per param

        return results

    @staticmethod
    def _inject_param(
        parsed,
        params: list,
        param_idx: int,
        payload: str,
    ) -> str:
        """Build URL with payload injected into the specified parameter."""
        mutated_params = list(params)
        mutated_params[param_idx] = (mutated_params[param_idx][0], payload)
        mutated_query = urlencode(mutated_params)
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path,
             parsed.params, mutated_query, parsed.fragment)
        )
