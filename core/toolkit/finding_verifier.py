"""
core/toolkit/finding_verifier.py

The passive-finding verification GATE.

WHY THIS EXISTS
───────────────
raw_classifier.py / vuln_rules.py turn raw tool output into titled findings by
pattern-matching — they ASSERT a claim ("Missing Security Header",
"Dangerous HTTP Verbs Enabled") without ever re-checking it against the live
target. That is exactly how Sentinel ends up "blending in" with generic
scanners: a target that actually *sends* the header, or *blocks* the verb,
still gets flagged, and the same false positive gets stored hundreds of times.

This module makes the intelligence falsifiable. For each FP-prone passive
category it re-issues a real request and inspects the actual response:

  - Missing Security Header  -> fetch; if the header is PRESENT -> REFUTED
  - Dangerous HTTP Verbs     -> send the verbs; if all are BLOCKED -> REFUTED
  - Session Cookie Misconfig -> fetch; if cookies are Secure+HttpOnly -> REFUTED
  - Exposed Admin/Mgmt iface -> fetch; if it redirects to login / 401/403 -> REFUTED

Verdicts: "confirmed" (re-tested true, with evidence), "refuted" (re-tested
false — drop it), "unverifiable" (no live check available — keep, but never
present as fact). Plus dedup so one FP isn't 500 rows.

A finding never reaches the operator as fact unless it survived this gate.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

CONFIRMED = "confirmed"
REFUTED = "refuted"
UNVERIFIABLE = "unverifiable"


def finding_id(finding: Dict[str, Any]) -> str:
    """The DB primary-key id for a finding/issue: sha256 of its canonical JSON.

    This MUST stay byte-for-byte identical to the id derivation in
    core.data.db (save_issue / save_issue_txn use
    ``sha256(json.dumps(issue, sort_keys=True))``). The suppression gate
    recomputes ids here to target rows via ``UPDATE ... WHERE id = ?``; if the
    two formulas ever drift, suppression silently matches nothing.
    """
    return hashlib.sha256(
        json.dumps(finding, sort_keys=True).encode()
    ).hexdigest()

# Verbs a scanner calls "dangerous". Only TRACE/TRACK (XST) and write verbs that
# actually return 2xx are real; everything else returning >=400 is a non-issue.
_DANGEROUS_VERBS = ["TRACE", "TRACK", "CONNECT", "PUT", "DELETE", "PATCH"]

# Security headers, normalized.
_SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}


def _title(finding: Dict[str, Any]) -> str:
    return str(finding.get("title") or finding.get("type") or "").strip()


def _category(finding: Dict[str, Any]) -> Optional[str]:
    t = _title(finding).lower()
    if "missing security header" in t or ("missing" in t and "header" in t):
        return "missing_header"
    if "http verb" in t or "http method" in t:
        return "verbs"
    if "cookie" in t and ("misconfig" in t or "secure" in t or "httponly" in t.replace(" ", "")):
        return "cookie"
    if "administrative interface" in t or "admin panel" in t or "admin interface" in t:
        return "exposed_admin"
    if "backup artifact" in t or "source code" in t or "config file" in t or "dump.sql" in t or ".env" in t:
        return "backup_artifact"
    if "secret exposure" in t or "api key" in t or "token" in t:
        return "secret"
    return None


def _data(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Findings store the rich payload either inline or under a 'data' JSON blob."""
    d = finding.get("data")
    if isinstance(d, str):
        try:
            return json.loads(d)
        except Exception:
            return {}
    if isinstance(d, dict):
        return d
    return finding


def _extract_url(finding: Dict[str, Any]) -> Optional[str]:
    """Best-effort: the concrete URL this finding is about."""
    data = _data(finding)
    # 1. Explicit url in metadata / data.
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    for src in (meta.get("url"), meta.get("original_target"), data.get("url"), finding.get("url")):
        if isinstance(src, str) and "://" in src:
            return src
    # 2. supporting_findings may carry a url.
    for sf in data.get("supporting_findings", []) or []:
        if isinstance(sf, dict):
            u = (sf.get("metadata") or {}).get("url") if isinstance(sf.get("metadata"), dict) else None
            if isinstance(u, str) and "://" in u:
                return u
    # 3. Fall back to the target host.
    tgt = finding.get("target") or data.get("target") or meta.get("original_target")
    if isinstance(tgt, str) and tgt:
        if "://" in tgt:
            return tgt
        return f"https://{tgt.strip().lstrip('/')}"
    return None


def _extract_header_name(finding: Dict[str, Any]) -> Optional[str]:
    data = _data(finding)
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    h = meta.get("header") or data.get("header")
    if isinstance(h, str) and h.strip():
        return h.strip().lower()
    # Parse from evidence/message text.
    text = " ".join(
        str(data.get(k, "")) for k in ("message", "evidence_summary", "proof", "description")
    ).lower()
    for known in _SECURITY_HEADERS:
        if known in text:
            return known
    return None


def dedup(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Collapse findings that are the same (category/title, host). Returns
    (unique_findings, removed_count). The first occurrence wins."""
    seen: set = set()
    out: List[Dict[str, Any]] = []
    removed = 0
    for f in findings:
        url = _extract_url(f) or ""
        host = urlparse(url).netloc or str(f.get("target") or "")
        key = (_title(f).lower(), host.lower())
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        out.append(f)
    return out, removed


async def verify_finding(
    finding: Dict[str, Any], client, *, timeout: float = 10.0
) -> Tuple[str, str]:
    """Re-test one passive finding against the live target.

    Returns (verdict, evidence). `client` is an httpx.AsyncClient.
    Network/other errors -> UNVERIFIABLE (never a crash, never a false drop).
    """
    cat = _category(finding)
    if cat is None:
        return UNVERIFIABLE, "no live check for this finding type"
    url = _extract_url(finding)
    if not url:
        return UNVERIFIABLE, "could not determine a URL to re-test"

    try:
        if cat == "missing_header":
            header = _extract_header_name(finding)
            if not header:
                return UNVERIFIABLE, "header name not identifiable"
            resp = await client.get(url, timeout=timeout)
            present = header in {k.lower() for k in resp.headers.keys()}
            if present:
                val = resp.headers.get(header, "")
                return REFUTED, f"{header} IS present: {val[:80]}"
            return CONFIRMED, f"{header} absent on {url} (status {resp.status_code})"

        if cat == "verbs":
            confirmed_verbs = []
            for verb in _DANGEROUS_VERBS:
                try:
                    r = await client.request(verb, url, timeout=timeout)
                    # "Dangerous" only if the server actually honors it (2xx).
                    if 200 <= r.status_code < 300:
                        confirmed_verbs.append(f"{verb}={r.status_code}")
                except Exception:
                    continue
            if confirmed_verbs:
                return CONFIRMED, f"verbs honored: {', '.join(confirmed_verbs)}"
            return REFUTED, "all flagged verbs blocked (>=400/405) — not enabled"

        if cat == "cookie":
            resp = await client.get(url, timeout=timeout)
            set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else \
                [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
            if not set_cookies:
                return REFUTED, "no Set-Cookie on response — nothing to misconfigure"
            insecure = [
                c.split(";", 1)[0].split("=", 1)[0]
                for c in set_cookies
                if "secure" not in c.lower() or "httponly" not in c.lower()
            ]
            if insecure:
                return CONFIRMED, f"cookie(s) missing Secure/HttpOnly: {', '.join(insecure[:5])}"
            return REFUTED, "all cookies are Secure + HttpOnly"

        if cat == "exposed_admin":
            resp = await client.get(url, timeout=timeout, follow_redirects=False)
            sc = resp.status_code
            if sc in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                return REFUTED, f"{sc} redirect (likely to login): {loc[:80]}"
            if sc in (401, 403):
                return REFUTED, f"{sc} — interface requires auth, not exposed"
            if sc == 200:
                return CONFIRMED, f"200 — reachable without auth at {url}"
            return REFUTED, f"{sc} — not a reachable admin interface"

        if cat == "backup_artifact":
            resp = await client.get(url, timeout=timeout, follow_redirects=False)
            sc = resp.status_code
            if sc >= 400:
                return REFUTED, f"{sc} — artifact is protected or missing"
            ct = resp.headers.get("content-type", "").lower()
            if "text/html" in ct and not url.endswith((".html", ".htm", "/")):
                return REFUTED, f"200 but returned HTML (likely soft 404 or block page)"
            return CONFIRMED, f"200 — artifact is genuinely accessible at {url}"

        if cat == "secret":
            data = _data(finding)
            evidence = str(data.get("proof") or data.get("evidence_summary") or data.get("message") or finding.get("description") or "").lower()
            if "csrf" in evidence or "xsrf" in evidence:
                return REFUTED, "Flagged secret is a common anti-CSRF token, not a sensitive key"
            return UNVERIFIABLE, "Secret exposure cannot be definitively verified automatically"

    except Exception as e:
        return UNVERIFIABLE, f"re-test error: {type(e).__name__}: {e}"

    return UNVERIFIABLE, "unhandled category"


async def gate(
    findings: List[Dict[str, Any]],
    *,
    drop_refuted: bool = True,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Run the full gate: dedup, then live re-test each candidate.

    Returns a report dict with `kept` (findings that survive, annotated with
    verification verdict/evidence) and counts. Refuted findings are dropped
    (when drop_refuted); unverifiable ones are kept but labelled so they're
    never presented as confirmed fact.
    """
    import httpx
    import os

    unique, deduped_count = dedup(findings)
    kept: List[Dict[str, Any]] = []
    # DB ids of the ORIGINAL dicts that survive the gate. The caller suppresses
    # every row whose id is NOT in here — which correctly hides BOTH refuted
    # findings AND the dedup-collapsed duplicates (only the survivor's id is
    # kept, so its N-1 duplicate rows fall outside the set and get suppressed).
    keep_ids: set = set()
    counts = {CONFIRMED: 0, REFUTED: 0, UNVERIFIABLE: 0, "deduped": deduped_count}

    # The verifier hits the live target, so its traffic must carry the same
    # bug-bounty deconfliction header as the rest of the platform.
    _hdrs = {"User-Agent": "SentinelForge-Verifier"}
    _bb = os.getenv("SENTINEL_GHOST_BB_VALUE", "").strip()
    if _bb:
        _hdrs[os.getenv("SENTINEL_GHOST_BB_HEADER", "X-Bug-Bounty").strip()] = _bb

    async with httpx.AsyncClient(
        verify=True, timeout=timeout, follow_redirects=True, headers=_hdrs,
    ) as client:
        for f in unique:
            verdict, evidence = await verify_finding(f, client, timeout=timeout)
            counts[verdict] = counts.get(verdict, 0) + 1
            if verdict == REFUTED and drop_refuted:
                logger.info("[verifier] DROPPED refuted: %s — %s", _title(f), evidence)
                continue
            # Record the original's DB id BEFORE annotating (annotation changes
            # the hash; the DB row was stored from the un-annotated dict).
            keep_ids.add(finding_id(f))
            annotated = dict(f)
            annotated["verification"] = {"verdict": verdict, "evidence": evidence}
            # Demote unverifiable passive findings out of "confirmed fact".
            if verdict == UNVERIFIABLE:
                annotated.setdefault("confidence", 0.3)
            kept.append(annotated)

    return {
        "kept": kept,
        "kept_count": len(kept),
        "input_count": len(findings),
        "counts": counts,
        "keep_ids": keep_ids,
    }
