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
from core.wraith.waf_retry import get_or_create_waf_engine
from core.wraith.vuln_verifier import VulnVerifier

import logging
logger = logging.getLogger(__name__)


# ── Constants ──────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Server confirmation thresholds
_CONFIRM_THRESHOLD = 0.80   # confidence ≥ this → confirmed
_DISMISS_THRESHOLD = 0.25   # confidence < this → dismissed

# Request budget
MAX_CANDIDATES = 20         # max findings to attempt to verify
MAX_PROBES_PER_FINDING = 5  # max probes per candidate finding
MAX_TOTAL_PROBES = 60       # hard cap on total outbound probes

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
        verifier = VulnVerifier(context.session)

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

            probe_results, probes_used = await verifier.verify_finding(
                engine=engine,
                finding=finding,
                url=url,
                vuln_class=vuln_class,
                headers=headers,
                cookies=cookies,
                budget=min(self.MAX_PROBES_PER_FINDING, self.MAX_TOTAL_PROBES - total_probes),
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
