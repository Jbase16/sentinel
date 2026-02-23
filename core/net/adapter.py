"""
core/net/adapter.py
Unified HTTP Adapter for SentinelForge.

This is the SINGLE choke point for all outbound HTTP traffic from the agent.
It strictly enforces Scope bounds and Execution Policy. Direct use of `httpx`
or `requests` outside this module is prohibited by architectural mandate.
"""

from __future__ import annotations

import httpx
import logging
from typing import Any, Dict, Optional, Mapping

from core.base.context import ScopeContext
from core.base.scope import ScopeDecision
from core.base.exceptions import ScopePolicyViolationError, ExecutionPolicyViolationError

logger = logging.getLogger(__name__)

class SentinelHTTPClient:
    """
    A unified HTTP client that enforces scope invariant and execution policy.
    It wraps httpx.AsyncClient but intercepts requests before transportation.
    """
    def __init__(self, context: ScopeContext, underlying_client: Optional[httpx.AsyncClient] = None):
        self.context = context
        self.client = underlying_client or httpx.AsyncClient(verify=False, follow_redirects=True)
        
    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """
        Execute an HTTP request safely.
        
        1. Validates HTTP method against ExecutionPolicy.
        2. Injects required identity/bounty headers.
        3. Enforces payload size limits (rough estimation before sending).
        4. Validates the URI strictly against the ScopeRegistry invariant.
        """
        # --- 1. Execution Policy: Method Bounding ---
        method_upper = method.upper()
        if method_upper not in self.context.policy.allow_methods:
            raise ExecutionPolicyViolationError(
                f"HTTP Method {method_upper} is disabled by the current ExecutionPolicy.",
                violations=[f"Method {method_upper} not in {self.context.policy.allow_methods}"]
            )

        # --- 2. Identity Header Injection ---
        headers = kwargs.get("headers", {})
        if isinstance(headers, dict):
            headers = dict(headers)
        elif isinstance(headers, httpx.Headers):
            headers = dict(headers.items())
        else:
            headers = dict(headers)
            
        # Inject standard policy headers (e.g., X-HackerOne-Research)
        for k, v in self.context.policy.require_headers.items():
            headers[k] = v
        # Inject context identity headers
        for k, v in self.context.identity_headers.items():
            headers[k] = v
            
        kwargs["headers"] = headers

        # --- 3. Payload Size Estimation ---
        content = kwargs.get("content") or kwargs.get("data") or kwargs.get("json")
        if content:
            estimated_size = len(str(content).encode('utf-8')) if not isinstance(content, bytes) else len(content)
            if estimated_size > self.context.policy.allow_payload_size:
                 raise ExecutionPolicyViolationError(
                     f"Payload size {estimated_size} exceeds policy limit of {self.context.policy.allow_payload_size}."
                 )

        # --- 4. The Absolute Scope Invariant Guard ---
        decision = self.context.registry.resolve(url)
        
        # In BOUNTY mode or if strictly unknown -> deny by default.
        is_bounty = self.context.mode.upper() == "BOUNTY"
        if decision.verdict == ScopeDecision.DENY or (decision.verdict == ScopeDecision.UNKNOWN and is_bounty):
            # Log exact reason
            logger.warning(
                f"[SCOPE GUARD] Blocked {method_upper} to {url}. "
                f"Mode: {self.context.mode}, Verdict: {decision.verdict.value}, Reason: {decision.reason_code}"
            )
            
            # Record decision in DecisionLedger (will be handled by caller catching this if they want to log the specific tool failed, 
            # but we can optionally log here too. Generally, the proxy caller will catch ScopePolicyViolationError).
            raise ScopePolicyViolationError(
                f"Request to {url} blocked by ScopeRegistry. Verdict: {decision.verdict.value} ({decision.reason_code})",
                decision=decision
            )

        # --- Emit to transport layer ---
        try:
            return await self.client.request(method, url, **kwargs)
        except Exception as e:
            # Let transport errors bubble up to caller (like Timeout, ConnectError)
            raise e

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)
        
    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)
        
    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)
        
    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)
        
    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def aclose(self):
        await self.client.aclose()
