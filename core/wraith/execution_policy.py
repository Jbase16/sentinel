"""
Centralized request execution policy runtime for Wraith internal tools.

This module provides a single enforcement layer for:
  - Capability gating (mode/tier)
  - Scope enforcement (same-origin by default)
  - Rate limiting
  - Request/retry budget ceilings
  - External service allowlisting (for OOB callback providers)

Design goals:
  - Keep enforcement out of individual tools
  - Be fail-closed on policy violations
  - Remain compatible with unit tests and standalone tool execution
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any, Dict, Mapping, Optional, Sequence, Set
from urllib.parse import urlparse

import httpx

from core.cortex.capability_tiers import (
    CapabilityGate,
    CapabilityTier,
    ExecutionMode,
    MODE_TIER_POLICIES,
    TOOL_TIER_CLASSIFICATION,
)


RETRYABLE_STATUS_CODES: Set[int] = {408, 425, 429, 500, 502, 503, 504}


class PolicyViolation(RuntimeError):
    """Raised when a request is blocked by enforcement policy."""


def _origin(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme
    netloc = parsed.netloc
    return f"{scheme}://{netloc}" if scheme and netloc else ""


def _host(url: str) -> str:
    return str(urlparse(url).hostname or "").lower()


def _to_mode(value: Any) -> ExecutionMode:
    raw = str(value or "").strip().lower()
    if raw == ExecutionMode.BOUNTY.value:
        return ExecutionMode.BOUNTY
    return ExecutionMode.RESEARCH


def _to_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
    return default


def _to_int(value: Any, default: int, minimum: int = 0) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    if parsed < minimum:
        return minimum
    return parsed


def _normalize_hosts(values: Any) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return out
    for value in values:
        text = str(value or "").strip().lower()
        if not text:
            continue
        # Accept either hostnames or full URLs in config.
        if "://" in text:
            parsed_host = _host(text)
            if parsed_host:
                out.add(parsed_host)
            continue
        out.add(text)
    return out


def _tier_from_required_int(value: int) -> CapabilityTier:
    if value <= 1:
        return CapabilityTier.T1_PROBE
    if value == 2:
        return CapabilityTier.T2a_SAFE_VERIFY
    if value == 3:
        return CapabilityTier.T2b_MUTATING_VERIFY
    if value == 4:
        return CapabilityTier.T3_EXPLOIT
    return CapabilityTier.T4_DESTRUCTIVE


class ExecutionPolicyRuntime:
    """Single enforcement layer for outbound HTTP requests."""

    def __init__(
        self,
        *,
        tool_name: str,
        scope_target: str,
        execution_mode: ExecutionMode,
        safe_mode: bool,
        same_origin_only: bool,
        rate_limit_ms: int,
        max_requests: int,
        max_retries_per_request: int,
        max_retries_total: int,
        capability_gate: Optional[CapabilityGate] = None,
        allowed_external_hosts: Optional[Set[str]] = None,
        max_external_calls: int = 4,
        scope_context: Any = None,
    ):
        self.tool_name = str(tool_name or "")
        self.scope_target = str(scope_target or "")
        self.scope_context = scope_context
        self.scope_origin = _origin(self.scope_target)
        self.execution_mode = execution_mode
        self.safe_mode = bool(safe_mode)
        self.same_origin_only = bool(same_origin_only)
        self.rate_limit_ms = max(0, int(rate_limit_ms))
        self.max_requests = max(1, int(max_requests))
        self.max_retries_per_request = max(0, int(max_retries_per_request))
        self.max_retries_total = max(0, int(max_retries_total))
        self.capability_gate = capability_gate if isinstance(capability_gate, CapabilityGate) else None

        self.allowed_external_hosts: Set[str] = set(allowed_external_hosts or set())
        self.max_external_calls = max(0, int(max_external_calls))

        self._tool_tier = TOOL_TIER_CLASSIFICATION.get(self.tool_name, CapabilityTier.T1_PROBE)
        self._rate_lock = asyncio.Lock()
        self._last_request_by_host: Dict[str, float] = {}

        self._attempts_total = 0
        self._retries_total = 0
        self._blocked_total = 0
        self._external_calls = 0
        self._capability_charges = 0

    def _resolve_tier(
        self,
        *,
        tier_hint: Optional[CapabilityTier] = None,
        payload_tier_required: Optional[int] = None,
    ) -> CapabilityTier:
        if isinstance(tier_hint, CapabilityTier):
            return tier_hint
        if payload_tier_required is not None:
            return _tier_from_required_int(int(payload_tier_required))
        return self._tool_tier

    def _block(self, reason: str) -> None:
        self._blocked_total += 1
        raise PolicyViolation(reason)

    def _enforce_http_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            self._block(f"Non-HTTP or malformed URL blocked: {url}")

    def _enforce_scope(self, url: str, *, allow_external: bool) -> None:
        self._enforce_http_url(url)
        if allow_external:
            return
        if not self.same_origin_only:
            return
        # If ScopeContext is active, it enforces ScopeRegistry boundaries at the adapter layer,
        # so same-origin checks here are supplementary.
        req_origin = _origin(url)
        if not self.scope_origin or not req_origin or req_origin != self.scope_origin:
            self._block(f"Out-of-scope request blocked: {url} (scope_origin={self.scope_origin})")

    def _enforce_tier_policy(self, tier: CapabilityTier) -> None:
        if self.safe_mode and tier >= CapabilityTier.T2b_MUTATING_VERIFY:
            self._block(f"safe_mode blocks {tier.name}")

        policy = MODE_TIER_POLICIES.get(self.execution_mode, {}).get(tier)
        if policy is None or not policy.allowed:
            self._block(f"{tier.name} not allowed in {self.execution_mode.value} mode")

    def _consume_capability_budget(self, tier: CapabilityTier) -> None:
        """
        Consume from the shared CapabilityGate budget at request-execution time.

        This is the canonical token debit path for request-accounted tools.
        """
        if self.capability_gate is None:
            return

        result = self.capability_gate.evaluate(
            self.scope_target,
            tier,
            tool_name=self.tool_name,
            dry_run=False,
        )
        if not result.approved:
            self._block(f"CapabilityGate blocked request: {result.reason}")
        self._capability_charges += 1

    def _consume_attempt(self) -> None:
        if self._attempts_total >= self.max_requests:
            self._block(
                f"Request budget exceeded for {self.tool_name}: "
                f"{self._attempts_total}/{self.max_requests}"
            )
        self._attempts_total += 1

    def _can_retry(self, retries_for_request: int) -> bool:
        if retries_for_request >= self.max_retries_per_request:
            return False
        if self._retries_total >= self.max_retries_total:
            return False
        return True

    def _mark_retry(self) -> None:
        self._retries_total += 1

    async def _backoff(self, attempt_index: int) -> None:
        # Capped exponential backoff with jitter.
        cap_s = min(3.0, 0.2 * (2 ** max(0, attempt_index)))
        await asyncio.sleep(random.uniform(0.05, cap_s))

    async def _rate_limit(self, host: str) -> None:
        if self.rate_limit_ms <= 0 or not host:
            return
        async with self._rate_lock:
            last = self._last_request_by_host.get(host, 0.0)
            elapsed_ms = (time.time() - last) * 1000.0
            if elapsed_ms < self.rate_limit_ms:
                await asyncio.sleep((self.rate_limit_ms - elapsed_ms) / 1000.0)
            self._last_request_by_host[host] = time.time()

    async def execute_http(
        self,
        *,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        request_kwargs: Dict[str, Any],
        tier_hint: Optional[CapabilityTier] = None,
        payload_tier_required: Optional[int] = None,
        allow_external: bool = False,
    ) -> httpx.Response:
        """
        Execute one HTTP request with centralized enforcement and bounded retries.

        Raises:
            PolicyViolation: request blocked by policy.
            httpx.RequestError: transport-level failure after retry ceiling reached.
        """
        tier = self._resolve_tier(
            tier_hint=tier_hint,
            payload_tier_required=payload_tier_required,
        )
        self._enforce_tier_policy(tier)
        self._enforce_scope(url, allow_external=allow_external)

        host = _host(url)
        retries_for_request = 0

        while True:
            if allow_external:
                # External endpoints are never in scan scope; enforce host allowlist
                # and external-call budget per outbound attempt.
                self.authorize_external_url(url)
            self._consume_attempt()
            self._consume_capability_budget(tier)
            await self._rate_limit(host)
            try:
                if getattr(self, "scope_context", None) and not allow_external:
                    from core.net.adapter import SentinelHTTPClient
                    # In external calls, scope_context might unnecessarily block it unless we selectively skip it.
                    # Since authorize_external_url already passed, we can bypass strict scope guard for external hosts,
                    # or wrap it. For safety on external calls, we bypass the internal ScopeRegistry but keep the policy.
                    safe_client = SentinelHTTPClient(context=self.scope_context, underlying_client=client)
                    response = await safe_client.request(method, url, **request_kwargs)
                else:
                    response = await client.request(method, url, **request_kwargs)
            except httpx.RequestError:
                if not self._can_retry(retries_for_request):
                    raise
                retries_for_request += 1
                self._mark_retry()
                await self._backoff(retries_for_request)
                continue

            if response.status_code in RETRYABLE_STATUS_CODES and self._can_retry(retries_for_request):
                retries_for_request += 1
                self._mark_retry()
                await self._backoff(retries_for_request)
                continue

            return response

    def authorize_external_url(self, url: str) -> None:
        """Allowlisted external endpoint check (e.g., OOB callback API)."""
        self._enforce_http_url(url)
        if self._external_calls >= self.max_external_calls:
            self._block(
                f"External call budget exceeded: {self._external_calls}/{self.max_external_calls}"
            )

        host = _host(url)
        if not host:
            self._block(f"External URL missing host: {url}")
        if not self.allowed_external_hosts:
            self._block("External calls blocked: no allowlisted hosts configured")

        allowed = any(host == allowed_host or host.endswith(f".{allowed_host}") for allowed_host in self.allowed_external_hosts)
        if not allowed:
            self._block(f"External host not allowlisted: {host}")

        self._external_calls += 1

    def metrics(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "scope_origin": self.scope_origin,
            "execution_mode": self.execution_mode.value,
            "safe_mode": self.safe_mode,
            "same_origin_only": self.same_origin_only,
            "attempts_total": self._attempts_total,
            "retries_total": self._retries_total,
            "blocked_total": self._blocked_total,
            "max_requests": self.max_requests,
            "max_retries_per_request": self.max_retries_per_request,
            "max_retries_total": self.max_retries_total,
            "external_calls": self._external_calls,
            "max_external_calls": self.max_external_calls,
            "allowed_external_hosts": sorted(self.allowed_external_hosts),
            "capability_charges": self._capability_charges,
        }


def build_policy_runtime(
    *,
    context: Any,
    tool_name: str,
    target: str,
    default_rate_limit_ms: int,
    default_request_budget: int,
    default_retry_ceiling: int,
    default_external_budget: int = 4,
) -> ExecutionPolicyRuntime:
    """
    Build runtime policy from InternalToolContext + knowledge overrides.

    Supported knowledge overrides:
      - policy_overrides: {tool_name: {...}}
      - policy_rate_limit_ms
      - policy_request_budget
      - policy_retry_ceiling
      - policy_retry_budget
      - policy_safe_mode
      - policy_same_origin_only
      - policy_external_hosts (list[str] or URLs)
      - policy_external_budget
    """
    knowledge = context.knowledge if isinstance(getattr(context, "knowledge", None), dict) else {}
    overrides = knowledge.get("policy_overrides")
    tool_overrides: Mapping[str, Any] = {}
    if isinstance(overrides, Mapping):
        maybe_tool = overrides.get(tool_name)
        if isinstance(maybe_tool, Mapping):
            tool_overrides = maybe_tool

    def _cfg(key: str, default: Any) -> Any:
        if key in tool_overrides:
            return tool_overrides[key]
        if key in knowledge:
            return knowledge[key]
        return default

    mode_raw = getattr(context, "mode", None) or knowledge.get("execution_mode", "research")
    execution_mode = _to_mode(mode_raw)

    safe_mode_default = execution_mode != ExecutionMode.BOUNTY
    safe_mode = _to_bool(_cfg("policy_safe_mode", safe_mode_default), safe_mode_default)
    same_origin_only = _to_bool(_cfg("policy_same_origin_only", True), True)

    rate_limit_ms = _to_int(_cfg("policy_rate_limit_ms", default_rate_limit_ms), default_rate_limit_ms, minimum=0)
    max_requests = _to_int(_cfg("policy_request_budget", default_request_budget), default_request_budget, minimum=1)
    max_retries_per_request = _to_int(
        _cfg("policy_retry_ceiling", default_retry_ceiling),
        default_retry_ceiling,
        minimum=0,
    )
    max_retries_total = _to_int(
        _cfg("policy_retry_budget", max_requests),
        max_requests,
        minimum=0,
    )

    external_hosts = _normalize_hosts(_cfg("policy_external_hosts", []))
    oob_cfg = knowledge.get("oob")
    if isinstance(oob_cfg, Mapping):
        api_url = str(oob_cfg.get("api_url") or "https://interactsh.com").strip()
        if api_url:
            host = _host(api_url)
            if host:
                external_hosts.add(host)

    max_external_calls = _to_int(
        _cfg("policy_external_budget", default_external_budget),
        default_external_budget,
        minimum=0,
    )

    capability_gate = getattr(context, "capability_gate", None)

    return ExecutionPolicyRuntime(
        tool_name=tool_name,
        scope_target=target,
        execution_mode=execution_mode,
        safe_mode=safe_mode,
        same_origin_only=same_origin_only,
        rate_limit_ms=rate_limit_ms,
        max_requests=max_requests,
        max_retries_per_request=max_retries_per_request,
        max_retries_total=max_retries_total,
        capability_gate=capability_gate if isinstance(capability_gate, CapabilityGate) else None,
        allowed_external_hosts=external_hosts,
        max_external_calls=max_external_calls,
        scope_context=getattr(context, "scope_context", getattr(getattr(context, "session", None), "scope_context", None)),
    )
