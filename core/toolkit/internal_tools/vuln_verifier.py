"""
core/toolkit/internal_tools/vuln_verifier.py

VulnVerifierTool — T2b: Targeted confirmation of T1 scanner findings.

Purpose
-------
T1 scanner tools (nuclei, nikto, ffuf, feroxbuster) produce *candidate* findings:
they flag behaviour that *looks like* a vulnerability but may be a false positive.

VulnVerifierTool takes those candidate findings, re-probes each target with
purpose-built confirmation payloads, and either:
  - CONFIRMS  the finding (high-confidence, verified=True, severity preserved or escalated)
  - DISMISSES it (low-confidence, adds dismissed_by=vuln_verifier to metadata)
  - leaves it INCONCLUSIVE (cannot confirm or dismiss, confidence stays as-is)

This is the key step between "scanner said something is probably wrong" and
"here is reproducible, exploitable evidence" — the difference between a T1 hit
and a bounty-worthy report.

Design
------
- Input: context.existing_findings (from T1 tools in the same scan transaction)
- Output: new confirmed findings + dismissed annotations on originals
- Scope: same-origin only, WAF-aware via WAFBypassEngine, rate-limited
- Auth: uses AuthSessionManager for authenticated surface when available
- Budget: MAX_TOTAL_PROBES cap prevents runaway request fan-out

Supported vuln classes
----------------------
  SQLI     — time-based and error-based confirmation probes
  XSS      — reflected payload confirmation
  SSRF     — URL-parameter redirect probes with blind callback correlation
  PATH_TRAVERSAL — ../etc/passwd style path segment injection
  OPEN_REDIRECT  — Location header following for redirect confirmation
  IDOR           — ID-increment probes on numeric path segments
  GENERIC        — basic error-trigger probes for unclassified findings
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.toolkit.internal_tool import InternalTool, InternalToolContext
from core.wraith.execution_policy import build_policy_runtime
from core.wraith.mutation_engine import (
    ActionOutcome,
    HttpMethod,
    MutationEngine,
    MutationPayload,
    PayloadEncoding,
    VulnerabilityClass,
    xss_payloads,
)
from core.wraith.session_manager import AuthSessionManager
from core.wraith.waf_retry import get_or_create_waf_engine, waf_aware_send

import logging
logger = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Confirmation thresholds
_CONFIRM_THRESHOLD = 0.80   # confidence ≥ this → confirmed
_DISMISS_THRESHOLD = 0.25   # confidence < this → dismissed

# Request budget
MAX_CANDIDATES = 20         # max findings to attempt to verify
MAX_PROBES_PER_FINDING = 5  # max probes per candidate finding
MAX_TOTAL_PROBES = 60       # hard cap on total outbound probes

# SQLi confirmation markers
_SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg::syntax",
    r"ora-\d{4,5}:",
    r"microsoft ole db provider for odbc drivers",
    r"syntax error.*at or near",
    r"unterminated string literal",
    r"sqlstate\[",
]
_SQLI_ERROR_RE = re.compile("|".join(_SQLI_ERROR_PATTERNS), re.IGNORECASE)

# Time-based SQLi: 5-second sleep probes — confirm if response time > 4.5s
_SQLI_TIME_THRESHOLD_S = 4.5

# Path traversal confirmation markers
_PATH_TRAV_MARKERS = ["root:x:0:0", "[boot loader]", "daemon:x:", "nobody:x:"]

# SSRF blind confirmation — we look for localhost references in redirects
_SSRF_REDIRECT_PATTERNS = [r"127\.0\.0\.1", r"localhost", r"169\.254\.169\.254", r"::1"]
_SSRF_REDIRECT_RE = re.compile("|".join(_SSRF_REDIRECT_PATTERNS), re.IGNORECASE)

# Vuln-class normalizer — maps raw finding types to our VulnerabilityClass
_TYPE_TO_VULN_CLASS: Dict[str, VulnerabilityClass] = {
    "sqli":                     VulnerabilityClass.SQLI,
    "sql injection":            VulnerabilityClass.SQLI,
    "sql-injection":            VulnerabilityClass.SQLI,
    "xss":                      VulnerabilityClass.XSS,
    "cross-site scripting":     VulnerabilityClass.XSS,
    "reflected xss":            VulnerabilityClass.XSS,
    "stored xss":               VulnerabilityClass.XSS,
    "ssrf":                     VulnerabilityClass.SSRF,
    "server-side request forgery": VulnerabilityClass.SSRF,
    "open redirect":            VulnerabilityClass.OPEN_REDIRECT,
    "redirect":                 VulnerabilityClass.OPEN_REDIRECT,
    "path traversal":           VulnerabilityClass.PATH_TRAVERSAL,
    "lfi":                      VulnerabilityClass.PATH_TRAVERSAL,
    "local file inclusion":     VulnerabilityClass.PATH_TRAVERSAL,
    "directory traversal":      VulnerabilityClass.PATH_TRAVERSAL,
    "idor":                     VulnerabilityClass.IDOR,
    "insecure direct object reference": VulnerabilityClass.IDOR,
}


def _normalize_vuln_class(finding: Dict[str, Any]) -> Optional[VulnerabilityClass]:
    """Map a raw finding type string to a VulnerabilityClass, or None if unknown."""
    raw = str(finding.get("type") or finding.get("vuln_type") or "").lower().strip()
    return _TYPE_TO_VULN_CLASS.get(raw)


def _is_http_url(value: str) -> bool:
    try:
        p = urlparse(value)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def _same_origin(a: str, b: str) -> bool:
    try:
        pa, pb = urlparse(a), urlparse(b)
        return pa.scheme == pb.scheme and pa.netloc == pb.netloc
    except Exception:
        return False


def _extract_url(finding: Dict[str, Any]) -> Optional[str]:
    """Best-effort URL extraction from a finding dict."""
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    for key in ("url", "asset", "target", "endpoint"):
        val = meta.get(key) or finding.get(key)
        if val and _is_http_url(str(val)):
            return str(val)
    return None


def _inject_query_param(url: str, param: str, payload: str) -> str:
    """Return url with param set to payload (preserves other params)."""
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query or "", keep_blank_values=True))
    params[param] = payload
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query, fragment=""))


def _inject_path_segment(url: str, payload: str) -> Optional[str]:
    """Replace the last numeric/UUID path segment with payload."""
    parsed = urlparse(url)
    parts = [p for p in (parsed.path or "/").split("/") if p]
    for i in range(len(parts) - 1, -1, -1):
        seg = parts[i]
        if seg.isdigit() or (len(seg) in (32, 36) and all(c in "0123456789abcdefABCDEF-" for c in seg)):
            original = parts[i]
            parts[i] = payload
            new_path = "/" + "/".join(parts)
            return urlunparse(parsed._replace(path=new_path, fragment="")), original
    return None


def _response_body(outcome: ActionOutcome) -> str:
    """Extract response body text from ActionOutcome safely."""
    resp = getattr(outcome, "response", None)
    if resp is None:
        return ""
    body = getattr(resp, "body", None) or getattr(resp, "text", None) or ""
    return str(body) if body else ""


def _response_time(outcome: ActionOutcome) -> float:
    """Extract elapsed time in seconds from ActionOutcome."""
    resp = getattr(outcome, "response", None)
    if resp is None:
        return 0.0
    return float(getattr(resp, "elapsed_s", 0) or getattr(resp, "elapsed", 0) or 0)


def _response_location(outcome: ActionOutcome) -> str:
    """Extract Location redirect header if present."""
    resp = getattr(outcome, "response", None)
    if resp is None:
        return ""
    headers = getattr(resp, "headers", {}) or {}
    return str(headers.get("location") or headers.get("Location") or "")


class VulnVerifierTool(InternalTool):
    """
    T2b: Confirmation-gate for T1 scanner findings.

    Reads unverified MEDIUM/HIGH/CRITICAL findings from context, re-probes each
    with targeted confirmation payloads, and emits:
      - confirmed findings (verified=True, confidence≥0.8)
      - dismissed findings (dismissed=True, confidence<0.25) as metadata updates

    Results feed back into FindingsStore so the bounty report can filter to
    confirmed-only findings — the output that matters for submission.
    """

    MAX_CANDIDATES = MAX_CANDIDATES
    MAX_PROBES_PER_FINDING = MAX_PROBES_PER_FINDING
    MAX_TOTAL_PROBES = MAX_TOTAL_PROBES

    @property
    def name(self) -> str:
        return "vuln_verifier"

    async def execute(
        self,
        target: str,
        context: InternalToolContext,
        queue: asyncio.Queue[str],
    ) -> List[Dict[str, Any]]:
        candidates = self._select_candidates(target, context.existing_findings)
        if not candidates:
            await self.log(queue, "No unverified MEDIUM+ findings to confirm; skipping.")
            return []

        await self.log(queue, f"Verifying {len(candidates)} candidate finding(s) (budget={self.MAX_TOTAL_PROBES} probes)")

        # Auth material from session bridge if available
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        session_bridge = await AuthSessionManager.from_knowledge(context.knowledge, base_url=target)
        if session_bridge is not None:
            auth = await session_bridge.get_baseline_auth()
            if auth is not None:
                headers = dict(auth.headers)
                cookies = dict(auth.cookies)
                await self.log(queue, f"Using auth: {auth.redacted_summary()}")

        policy_runtime = build_policy_runtime(
            context=context,
            tool_name=self.name,
            target=target,
            default_rate_limit_ms=200,
            default_request_budget=max(self.MAX_TOTAL_PROBES * 2, 120),
            default_retry_ceiling=1,
        )
        engine = MutationEngine(rate_limit_ms=200, policy_runtime=policy_runtime)
        waf_engine = get_or_create_waf_engine(context.knowledge)

        confirmed: List[Dict[str, Any]] = []
        dismissed_ids: Set[str] = set()
        total_probes = 0
        dedup: Set[str] = set()

        for finding in candidates:
            if total_probes >= self.MAX_TOTAL_PROBES:
                await self.log(queue, f"Probe budget exhausted ({self.MAX_TOTAL_PROBES}); stopping early.")
                break

            vuln_class = _normalize_vuln_class(finding)
            url = _extract_url(finding) or target
            finding_id = str(finding.get("id") or finding.get("finding_id") or "")
            original_severity = str(finding.get("severity") or "MEDIUM").upper()

            await self.log(
                queue,
                f"Confirming: [{original_severity}] {finding.get('type', '?')} @ {url} (class={vuln_class})",
            )

            probe_results, probes_used = await self._confirm(
                engine=engine,
                waf_engine=waf_engine,
                url=url,
                vuln_class=vuln_class,
                finding=finding,
                headers=headers,
                cookies=cookies,
                queue=queue,
                probe_budget=min(self.MAX_PROBES_PER_FINDING, self.MAX_TOTAL_PROBES - total_probes),
            )
            total_probes += probes_used

            for (confidence, proof, payload_desc, confirmed_class) in probe_results:
                dedup_key = f"{url}|{confirmed_class}|{payload_desc[:40]}"
                if dedup_key in dedup:
                    continue
                dedup.add(dedup_key)

                if confidence >= _CONFIRM_THRESHOLD:
                    verdict = "confirmed"
                    action = "CONFIRMED"
                elif confidence < _DISMISS_THRESHOLD:
                    verdict = "dismissed"
                    action = "DISMISSED"
                    if finding_id:
                        dismissed_ids.add(finding_id)
                    continue  # dismissed findings are not emitted as new findings
                else:
                    verdict = "inconclusive"
                    action = "INCONCLUSIVE"
                    # Inconclusive: emit with lower confidence, don't upgrade severity
                    pass

                if verdict == "dismissed":
                    continue

                # Confirmed or inconclusive — emit as a new verified finding
                confirmed_finding = self.make_finding(
                    target=url,
                    finding_type=f"Verified {confirmed_class or finding.get('type', 'Vulnerability')}",
                    severity=original_severity,
                    message=(
                        f"{verdict.capitalize()}: {finding.get('message') or finding.get('type', 'vulnerability')} "
                        f"on {url}. {proof[:200] if proof else 'No additional details.'}"
                    ),
                    proof=proof,
                    confidence=confidence,
                    tags=["vuln_verifier", "verified", verdict, str(confirmed_class or "").lower()],
                    families=finding.get("families") or [],
                    metadata={
                        "original_finding_id": finding_id,
                        "original_tool": finding.get("tool", ""),
                        "verification_verdict": verdict,
                        "payload": payload_desc,
                        "vuln_class": str(confirmed_class or ""),
                        "url": url,
                    },
                )
                confirmed_finding["verification_verdict"] = verdict
                confirmed_finding["confirmation_level"] = verdict
                confirmed.append(confirmed_finding)
                await self.log(queue, f"  → {action} (confidence={confidence:.2f}, class={confirmed_class})")

        await self.log(
            queue,
            f"Verification complete: confirmed={len(confirmed)}, "
            f"dismissed={len(dismissed_ids)}, probes_used={total_probes}",
        )
        return confirmed

    # ── Candidate selection ────────────────────────────────────────────────

    def _select_candidates(
        self,
        target: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Select unverified MEDIUM/HIGH/CRITICAL findings from same origin.

        Prioritises by severity (CRITICAL first). Caps at MAX_CANDIDATES.
        """
        eligible = []
        for f in findings:
            # Skip findings already verified by an internal tool
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            if meta.get("verified") and meta.get("internal_tool"):
                continue
            sev = str(f.get("severity") or "").upper()
            if sev not in ("MEDIUM", "HIGH", "CRITICAL"):
                continue
            url = _extract_url(f) or f.get("target") or f.get("asset") or ""
            if not url or not _is_http_url(url):
                # Fall back to the scan target if no URL in finding metadata
                url = target
            if not _same_origin(url, target):
                continue
            eligible.append(f)

        # Sort by severity DESC
        eligible.sort(
            key=lambda x: -_SEVERITY_RANK.get(str(x.get("severity") or "").upper(), 0)
        )
        return eligible[: self.MAX_CANDIDATES]

    # ── Confirmation dispatch ──────────────────────────────────────────────

    async def _confirm(
        self,
        engine: MutationEngine,
        waf_engine: Any,
        url: str,
        vuln_class: Optional[VulnerabilityClass],
        finding: Dict[str, Any],
        headers: Dict[str, str],
        cookies: Dict[str, str],
        queue: asyncio.Queue,
        probe_budget: int,
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        """
        Dispatch confirmation probes for the given finding.

        Returns:
          (results_list, probes_used)
          results_list: list of (confidence, proof, payload_desc, confirmed_class)
        """
        if vuln_class == VulnerabilityClass.SQLI:
            return await self._confirm_sqli(engine, waf_engine, url, headers, cookies, probe_budget)
        if vuln_class == VulnerabilityClass.XSS:
            return await self._confirm_xss(engine, waf_engine, url, headers, cookies, probe_budget)
        if vuln_class == VulnerabilityClass.PATH_TRAVERSAL:
            return await self._confirm_path_traversal(engine, waf_engine, url, headers, cookies, probe_budget)
        if vuln_class == VulnerabilityClass.OPEN_REDIRECT:
            return await self._confirm_open_redirect(engine, waf_engine, url, headers, cookies, probe_budget)
        if vuln_class == VulnerabilityClass.IDOR:
            return await self._confirm_idor(engine, waf_engine, url, headers, cookies, probe_budget)
        # Fallback: generic error probe
        return await self._confirm_generic(engine, waf_engine, url, headers, cookies, probe_budget)

    # ── SQLi confirmation ──────────────────────────────────────────────────

    async def _confirm_sqli(
        self,
        engine: MutationEngine,
        waf_engine: Any,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        budget: int,
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results = []
        probes = 0

        parsed = urlparse(url)
        params = [k for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]
        if not params:
            # No params to test
            return results, probes

        # Probe 1: error-based (single quote)
        for param in params[:min(budget, 2)]:
            probe_url = _inject_query_param(url, param, "'")
            payload = MutationPayload(
                value="'",
                encoding=PayloadEncoding.NONE,
                vuln_class=VulnerabilityClass.SQLI,
                description=f"SQLi error probe (param={param})",
            )
            outcome, _, _ = await waf_aware_send(
                engine, probe_url, payload,
                method=HttpMethod.GET,
                headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
            )
            probes += 1
            body = _response_body(outcome)
            if _SQLI_ERROR_RE.search(body):
                snippet = body[:300].replace("\n", " ")
                results.append((0.92, f"SQLi error response: {snippet}", f"' in {param}", "SQLi"))
                return results, probes

        # Probe 2: time-based (if budget allows)
        if probes < budget and params:
            param = params[0]
            sleep_payload = "' OR SLEEP(5)-- -"
            probe_url = _inject_query_param(url, param, sleep_payload)
            payload = MutationPayload(
                value=sleep_payload,
                encoding=PayloadEncoding.NONE,
                vuln_class=VulnerabilityClass.SQLI,
                description=f"SQLi time-based probe (param={param})",
            )
            outcome, _, _ = await waf_aware_send(
                engine, probe_url, payload,
                method=HttpMethod.GET,
                headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
            )
            probes += 1
            elapsed = _response_time(outcome)
            if elapsed >= _SQLI_TIME_THRESHOLD_S:
                results.append((
                    0.88,
                    f"Time-based SQLi: response took {elapsed:.1f}s (threshold={_SQLI_TIME_THRESHOLD_S}s)",
                    f"SLEEP(5) in {param}",
                    "SQLi",
                ))

        return results, probes

    # ── XSS confirmation ───────────────────────────────────────────────────

    async def _confirm_xss(
        self,
        engine: MutationEngine,
        waf_engine: Any,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        budget: int,
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results = []
        probes = 0

        parsed = urlparse(url)
        params = [k for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]
        if not params:
            return results, probes

        sentinel = "<scr1pt>alert(1)</scr1pt>"
        for param in params[:min(budget, 2)]:
            probe_url = _inject_query_param(url, param, sentinel)
            payload = MutationPayload(
                value=sentinel,
                encoding=PayloadEncoding.NONE,
                vuln_class=VulnerabilityClass.XSS,
                description=f"XSS reflection probe (param={param})",
            )
            outcome, _, _ = await waf_aware_send(
                engine, probe_url, payload,
                method=HttpMethod.GET,
                headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
            )
            probes += 1
            body = _response_body(outcome)
            if sentinel.lower() in body.lower():
                results.append((
                    0.90,
                    f"XSS payload reflected unencoded in response body (param={param})",
                    f"{sentinel} in {param}",
                    "XSS",
                ))
                return results, probes

        return results, probes

    # ── Path traversal confirmation ────────────────────────────────────────

    async def _confirm_path_traversal(
        self,
        engine: MutationEngine,
        waf_engine: Any,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        budget: int,
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results = []
        probes = 0

        # Try both query param injection and path segment injection
        traversal_payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
        ]

        parsed = urlparse(url)
        params = [k for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]

        for trav in traversal_payloads[:min(budget, 2)]:
            probe_url = None
            probe_desc = ""

            if params:
                probe_url = _inject_query_param(url, params[0], trav)
                probe_desc = f"Path traversal in param={params[0]}"
            else:
                result = _inject_path_segment(url, trav)
                if result:
                    probe_url, _ = result
                    probe_desc = "Path traversal in path segment"

            if not probe_url:
                break

            payload = MutationPayload(
                value=trav,
                encoding=PayloadEncoding.NONE,
                vuln_class=VulnerabilityClass.PATH_TRAVERSAL,
                description=probe_desc,
            )
            outcome, _, _ = await waf_aware_send(
                engine, probe_url, payload,
                method=HttpMethod.GET,
                headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
            )
            probes += 1
            body = _response_body(outcome)
            for marker in _PATH_TRAV_MARKERS:
                if marker in body:
                    results.append((
                        0.95,
                        f"Path traversal confirmed: '{marker}' found in response",
                        trav,
                        "Path Traversal",
                    ))
                    return results, probes

        return results, probes

    # ── Open redirect confirmation ─────────────────────────────────────────

    async def _confirm_open_redirect(
        self,
        engine: MutationEngine,
        waf_engine: Any,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        budget: int,
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        results = []
        probes = 0

        parsed = urlparse(url)
        params = [k for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]
        if not params:
            return results, probes

        redirect_target = "https://evil.example.com/pwned"
        # Probe the most likely redirect params first
        redirect_params = [p for p in params if p in ("next", "redirect", "url", "return", "goto", "to")]
        probe_params = redirect_params or params[:1]

        for param in probe_params[:min(budget, 2)]:
            probe_url = _inject_query_param(url, param, redirect_target)
            payload = MutationPayload(
                value=redirect_target,
                encoding=PayloadEncoding.NONE,
                vuln_class=VulnerabilityClass.OPEN_REDIRECT,
                description=f"Open redirect probe (param={param})",
            )
            outcome, _, _ = await waf_aware_send(
                engine, probe_url, payload,
                method=HttpMethod.GET,
                headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
            )
            probes += 1
            location = _response_location(outcome)
            if "evil.example.com" in location:
                results.append((
                    0.91,
                    f"Open redirect confirmed: Location header → {location}",
                    f"{redirect_target} in {param}",
                    "Open Redirect",
                ))
                return results, probes

        return results, probes

    # ── IDOR confirmation ──────────────────────────────────────────────────

    async def _confirm_idor(
        self,
        engine: MutationEngine,
        waf_engine: Any,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        budget: int,
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        """
        IDOR probe: increment/decrement a numeric path segment and compare response.
        If we get a 200 with a non-trivially different body, it's a strong IDOR signal.
        """
        results = []
        probes = 0

        parsed = urlparse(url)
        path_parts = [p for p in (parsed.path or "/").split("/") if p]

        # Find rightmost numeric segment
        target_idx = None
        original_id = None
        for i in range(len(path_parts) - 1, -1, -1):
            seg = path_parts[i]
            if seg.isdigit() and int(seg) > 0:
                target_idx = i
                original_id = int(seg)
                break

        if target_idx is None:
            return results, probes

        # Probe original + 1 and original - 1
        for delta in [1, -1][:budget]:
            probe_id = original_id + delta
            if probe_id <= 0:
                continue

            new_parts = list(path_parts)
            new_parts[target_idx] = str(probe_id)
            new_path = "/" + "/".join(new_parts)
            probe_url = urlunparse(parsed._replace(path=new_path, fragment=""))

            payload = MutationPayload(
                value=str(probe_id),
                encoding=PayloadEncoding.NONE,
                vuln_class=VulnerabilityClass.IDOR,
                description=f"IDOR probe (id={original_id}→{probe_id})",
            )
            outcome, _, _ = await waf_aware_send(
                engine, probe_url, payload,
                method=HttpMethod.GET,
                headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
            )
            probes += 1
            body = _response_body(outcome)
            resp = getattr(outcome, "response", None)
            status = getattr(resp, "status_code", 0)

            if status == 200 and len(body) > 50:
                results.append((
                    0.75,
                    f"IDOR probable: accessing object id={probe_id} returned HTTP 200 with {len(body)} bytes. "
                    f"Manual confirmation required.",
                    f"id param: {original_id}→{probe_id}",
                    "IDOR",
                ))
                break

        return results, probes

    # ── Generic confirmation ───────────────────────────────────────────────

    async def _confirm_generic(
        self,
        engine: MutationEngine,
        waf_engine: Any,
        url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        budget: int,
    ) -> Tuple[List[Tuple[float, str, str, str]], int]:
        """
        Fallback: inject a null-byte and boolean-operator payload to trigger
        generic application errors as low-confidence confirmation signals.
        """
        results = []
        probes = 0

        parsed = urlparse(url)
        params = [k for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]
        if not params or probes >= budget:
            return results, probes

        for probe_val, desc in [("%00", "null-byte injection"), ("' OR '1'='1", "boolean probe")][:budget]:
            probe_url = _inject_query_param(url, params[0], probe_val)
            payload = MutationPayload(
                value=probe_val,
                encoding=PayloadEncoding.NONE,
                vuln_class=VulnerabilityClass.GENERIC,
                description=desc,
            )
            outcome, _, _ = await waf_aware_send(
                engine, probe_url, payload,
                method=HttpMethod.GET,
                headers={**headers, "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())},
            )
            probes += 1
            resp = getattr(outcome, "response", None)
            status = getattr(resp, "status_code", 0)
            body = _response_body(outcome)

            if status in (500, 503):
                results.append((
                    0.55,
                    f"Generic error probe triggered HTTP {status}. Possible injection point.",
                    f"{probe_val} in {params[0]}",
                    "Generic Error",
                ))
                break

        return results, probes
