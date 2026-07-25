"""
core/wraith/waf_retry.py
Shared WAF-aware retry utility.

Provides a single async function that wraps MutationEngine requests with
automatic WAF detection → bypass technique selection → re-send logic.
Used by wraith_verify, wraith_oob_probe, and any future tool that sends
payloads through a WAF.

The adaptive bandit in WAFBypassEngine is updated on every attempt so
downstream tools benefit from each other's learning within a scan.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

from core.wraith.mutation_engine import (
    ActionOutcome,
    HttpMethod,
    MutationEngine,
    MutationPayload,
    MutationRequest,
    PayloadEncoding,
)
from core.wraith.waf_bypass import VulnerabilityClass, WAFBypassEngine

logger = logging.getLogger(__name__)

# Mapping from string vuln class tags to WAFBypassEngine enum values.
_VULN_CLASS_MAP: Dict[str, VulnerabilityClass] = {
    "sqli": VulnerabilityClass.SQLi,
    "sql": VulnerabilityClass.SQLi,
    "xss": VulnerabilityClass.XSS,
    "ssrf": VulnerabilityClass.SSRF,
    "rce": VulnerabilityClass.RCE,
    "xxe": VulnerabilityClass.XXE,
    "command_injection": VulnerabilityClass.COMMAND_INJECTION,
    "path_traversal": VulnerabilityClass.PATH_TRAVERSAL,
    "ldap": VulnerabilityClass.LDAP,
    "xpath": VulnerabilityClass.XPATH,
}


def resolve_vuln_class(raw: str) -> Optional[VulnerabilityClass]:
    """Resolve a free-text vuln class string to the WAFBypassEngine enum."""
    return _VULN_CLASS_MAP.get((raw or "").strip().lower())


def _extract_waf_name(response: Any) -> Optional[str]:
    """Extract WAF name from a blocked MutationResponse's evidence metadata."""
    for ev in getattr(response, "evidence", []) or []:
        meta = getattr(ev, "metadata", {}) or {}
        if isinstance(meta, dict) and meta.get("waf"):
            return str(meta["waf"])
    return None


def get_or_create_waf_engine(knowledge: Dict[str, Any]) -> Optional[WAFBypassEngine]:
    """
    Retrieve the WAFBypassEngine from scan knowledge, or create one if absent.

    Returns None only if construction fails (should not happen in practice).
    """
    existing = knowledge.get("waf_bypass_engine")
    if isinstance(existing, WAFBypassEngine):
        return existing
    try:
        engine = WAFBypassEngine()
        knowledge["waf_bypass_engine"] = engine
        return engine
    except Exception:
        logger.debug("Failed to construct WAFBypassEngine", exc_info=True)
        return None


async def waf_aware_send(
    engine: MutationEngine,
    url: str,
    payload: MutationPayload,
    *,
    method: HttpMethod = HttpMethod.GET,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    baseline_url: Optional[str] = None,
    waf_engine: Optional[WAFBypassEngine] = None,
    max_bypass_attempts: int = 2,
    queue: Optional[asyncio.Queue[str]] = None,
    tool_label: str = "waf_retry",
) -> Tuple[Any, ActionOutcome, bool]:
    """
    Send a mutation request with automatic WAF bypass retry.

    Args:
        engine: MutationEngine instance (caller owns lifecycle).
        url: Target URL (may contain {PAYLOAD} placeholder).
        payload: The MutationPayload to inject.
        method: HTTP method.
        headers: Optional auth/custom headers.
        cookies: Optional cookies.
        baseline_url: Original URL for baseline comparison (optional).
        waf_engine: WAFBypassEngine instance. If None, bypass is skipped.
        max_bypass_attempts: Maximum number of bypass retries after initial block.
        queue: Optional log queue for streaming to UI.
        tool_label: Label for log messages.

    Returns:
        (response, outcome, was_bypassed) — the final response,
        the final ActionOutcome, and whether a WAF bypass was used.
    """
    response, outcome = await engine.mutate_and_analyze(
        url=url,
        payload=payload,
        method=method,
        headers=headers or {},
        cookies=cookies or {},
        baseline_url=baseline_url,
    )

    if outcome != ActionOutcome.BLOCKED or waf_engine is None:
        return response, outcome, False

    # Blocked. Attempt bypass.
    waf_name = _extract_waf_name(response)
    if not waf_name:
        return response, outcome, False

    vuln_class = resolve_vuln_class(payload.vuln_class)
    if vuln_class is None:
        return response, outcome, False

    for attempt in range(max_bypass_attempts):
        technique = waf_engine.select_bypass_technique(waf_name, vuln_class)
        if technique is None:
            break

        transformed = waf_engine.apply_bypass_to_payload(payload.value, technique)
        bypass_payload = replace(
            payload,
            value=transformed,
            description=f"{payload.description} (bypass:{technique.id}#{attempt})",
        )

        if queue is not None:
            try:
                await queue.put(
                    f"[{tool_label}] WAF({waf_name}) blocked; retry #{attempt+1} bypass={technique.id}"
                )
            except asyncio.QueueFull:
                pass

        response, outcome = await engine.mutate_and_analyze(
            url=url,
            payload=bypass_payload,
            method=method,
            headers=headers or {},
            cookies=cookies or {},
            baseline_url=baseline_url,
        )

        bypass_success = outcome != ActionOutcome.BLOCKED
        waf_engine.record_bypass_result(waf_name, technique.id, bypass_success)

        if bypass_success:
            return response, outcome, True

    # All bypass attempts failed.
    return response, outcome, False


async def waf_aware_raw_send(
    engine: MutationEngine,
    request: MutationRequest,
    *,
    waf_engine: Optional[WAFBypassEngine] = None,
    vuln_class_hint: Optional[str] = None,
    max_bypass_attempts: int = 2,
    queue: Optional[asyncio.Queue[str]] = None,
    tool_label: str = "waf_retry",
) -> Tuple[Any, bool]:
    """
    Send a raw MutationRequest with WAF bypass retry for non-mutation-analyze flows.

    This variant is useful for tools (like OOB probe) that inject payloads via
    query params directly rather than through the mutate_and_analyze pipeline.

    Returns:
        (response, was_bypassed)
    """
    response = await engine.send(request)

    if waf_engine is None:
        return response, False

    # Check if blocked
    status = getattr(response, "status_code", 0) or 0
    if status not in (403, 406, 429, 503):
        return response, False

    waf_name = _extract_waf_name(response)
    if not waf_name:
        # Heuristic: 403 might still be WAF
        from core.wraith.waf_bypass import WAFDetector
        detector = WAFDetector()
        fingerprints = detector.detect_from_response(
            headers=dict(getattr(response, "headers", {}) or {}),
            body=str(getattr(response, "body", "") or ""),
            status_code=status,
        )
        if fingerprints:
            waf_name = fingerprints[0].name
        else:
            return response, False

    vuln_class = resolve_vuln_class(vuln_class_hint or "")
    if vuln_class is None:
        return response, False

    # Extract the payload value from the request to transform it
    original_payload = None
    if request.payload is not None:
        original_payload = request.payload.value

    if original_payload is None:
        return response, False

    for attempt in range(max_bypass_attempts):
        technique = waf_engine.select_bypass_technique(waf_name, vuln_class)
        if technique is None:
            break

        transformed = waf_engine.apply_bypass_to_payload(original_payload, technique)

        # Rebuild request with transformed payload in query params
        new_params = dict(request.query_params or {})
        if request.payload and request.payload.param_name and request.payload.param_name in new_params:
            new_params[request.payload.param_name] = transformed

        bypass_request = MutationRequest(
            url=request.url,
            method=request.method,
            headers=request.headers,
            cookies=request.cookies,
            query_params=new_params,
            body=request.body,
            timeout=request.timeout,
            payload=replace(request.payload, value=transformed) if request.payload else None,
        )

        if queue is not None:
            try:
                await queue.put(
                    f"[{tool_label}] WAF({waf_name}) blocked; retry #{attempt+1} bypass={technique.id}"
                )
            except asyncio.QueueFull:
                pass

        response = await engine.send(bypass_request)
        new_status = getattr(response, "status_code", 0) or 0
        bypass_success = new_status not in (403, 406, 429, 503)
        waf_engine.record_bypass_result(waf_name, technique.id, bypass_success)

        if bypass_success:
            return response, True

    return response, False
