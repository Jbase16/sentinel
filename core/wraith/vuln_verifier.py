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
    r"unterminated string literal", r"sqlstate\["
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

    def _get_resp_body(self, outcome: ActionOutcome) -> str:
        r = getattr(outcome, "response", None)
        return str(getattr(r, "body", None) or getattr(r, "text", None) or "") if r else ""

    async def _confirm_sqli(self, engine: MutationEngine, url: str, headers: Dict[str, str], cookies: Dict[str, str], budget: int) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results, probes = [], 0
        params = [k for k, _ in parse_qsl(urlparse(url).query or "", keep_blank_values=True)]
        if not params: return results, probes

        # Error-based
        for param in params[:min(budget, 2)]:
            probe_url = self._inject_query_param(url, param, "'")
            payload = MutationPayload(value="'", encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.SQLI, description="SQLi error probe")
            outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())})
            probes += 1
            body = self._get_resp_body(outcome)
            if _SQLI_ERROR_RE.search(body):
                return [(0.92, f"SQLi error response: {body[:100]}", f"' in {param}", "SQLi")], probes

        # Time-based
        if probes < budget and params:
            param = params[0]
            sleep_payload = "' OR SLEEP(5)-- -"
            probe_url = self._inject_query_param(url, param, sleep_payload)
            payload = MutationPayload(value=sleep_payload, encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.SQLI, description="SQLi time-based probe")
            outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())})
            probes += 1
            elapsed = float(getattr(getattr(outcome, "response", None), "elapsed_s", 0) or 0)
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
            r = getattr(outcome, "response", None)
            loc = str((getattr(r, "headers", {}) or {}).get("location", ""))
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
                resp = getattr(outcome, "response", None)
                status = getattr(resp, "status_code", 0)

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
        results, probes = [], 0
        r = self._inject_path_segment(url, "999999")
        if not r: return results, probes
        
        _, original_id = r
        try: target_id = int(original_id)
        except ValueError: return results, probes

        for delta in [1, -1][:budget]:
            probe_id = target_id + delta
            if probe_id <= 0: continue
            probe_url, _ = self._inject_path_segment(url, str(probe_id))
            payload = MutationPayload(value=str(probe_id), encoding=PayloadEncoding.NONE, vuln_class=VulnerabilityClass.IDOR, description="IDOR probe")
            outcome, _, _ = await waf_aware_send(engine, probe_url, payload, method=HttpMethod.GET, headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())})
            probes += 1
            
            resp = getattr(outcome, "response", None)
            if getattr(resp, "status_code", 0) == 200 and len(self._get_resp_body(outcome)) > 50:
                results.append((0.75, "IDOR probable: returning HTTP 200", f"id: {target_id}→{probe_id}", "IDOR"))
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
            if getattr(getattr(outcome, "response", None), "status_code", 0) in (500, 503):
                results.append((0.55, "Generic error triggered. Possible injection.", f"{probe_val} in {params[0]}", "Generic Error"))
                break
        return results, probes
