"""
core/executor/http_harness.py

Purpose:
    The "Hands" of the system.
    A production-grade HTTP execution engine that prioritizes correctness,
    safety, and observability over raw speed.

Magnum Opus Standards:
    - Retries: Exponential backoff with jitter for transient failures.
    - Safety: Bounded redirects, strict timeouts, no header leakage.
    - Telemetry: TTFB, Total Duration, Status Code analysis.
    - Architecture: Singleton client management to prevent fd exhaustion.
"""

from __future__ import annotations
import logging
import asyncio
import random
import httpx
from typing import Any, Dict, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass

from core.thanatos.models import LogicTestCase, MutationOpType
from .models import ExecutionOrder, ExecutionResult, ExecutionStatus
from .harness import Harness

log = logging.getLogger("executor.http_harness")

# Global configuration constants
MAX_RETRIES = 3
BASE_TIMEOUT = 10.0
MAX_REDIRECTS = 5
USER_AGENT = "SentinelForge/1.0 (Governor-Approved)"
VERIFY_TLS = False # Explicitly disabled for controlled security testing. Do not enable in prod without careful review.

class HttpHarness(Harness):
    """
    Production-grade HTTP Harness.
    Manages its own connection pool lifecycle and enforces strict execution bounds.
    """
    
    _client: Optional[httpx.AsyncClient] = None

    @classmethod
    async def get_client(cls) -> httpx.AsyncClient:
        """
        Singleton access to valid AsyncClient.
        Enforces connection limits and standardized headers.
        """
        if cls._client is None or cls._client.is_closed:
            limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
            cls._client = httpx.AsyncClient(
                limits=limits,
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True, 
                max_redirects=MAX_REDIRECTS,
                verify=VERIFY_TLS
            )
        return cls._client

    @classmethod
    async def close_client(cls):
        """
        Lifecycle hook: Gracefully close the singleton client.
        """
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()
            cls._client = None
            log.info("HttpHarness client closed.")

    async def execute(self, order: ExecutionOrder) -> ExecutionResult:
        """
        Executes a test case with defense-in-depth:
        1. Contextualizes the request (URL, Method, Payload).
        2. Applies the Mutation.
        3. Executes with Retry/Backoff.
        4. Captures Signals + Telemetry.
        """
        start_ts = datetime.now()
        test_case = order.test_case
        target = test_case.target
        
        # 1. Context Build
        url = self._normalize_url(target.endpoint)
        method = target.method
        payload = self._construct_payload(test_case.mutation)
        
        metrics = {"retries": 0.0}
        
        try:
            client = await self.get_client()
            
            # 2. Execution with Retries
            response, retries_used = await self._execute_with_retry(
                client=client,
                method=method,
                url=url,
                json=payload
            )
            metrics["retries"] = float(retries_used)
            
            # 3. Telemetry Capture
            end_ts = datetime.now()
            duration_ms = (end_ts - start_ts).total_seconds() * 1000
            
            # Simple TTFB approximation (not perfect without low-level hooks, but sufficient)
            # httpx doesn't expose TTFB easily on the high-level response object without extensions.
            # We treat duration as the primary metric.
            
            signals = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text, # Potential OOM risk for large bodies; should cap in future.
                "url": str(response.url),
                "http_version": response.http_version,
            }
            
            return ExecutionResult(
                order_id=str(id(order)),
                status=ExecutionStatus.EXECUTED,
                signals=signals,
                metrics=metrics,
                duration_ms=duration_ms
            )

        except httpx.RequestError as e:
            # Network level failure (DNS, Connection Refused)
            log.warning(f"Harness Network Error (Order {id(order)}): {e}")
            return ExecutionResult(
                order_id=str(id(order)),
                status=ExecutionStatus.ERROR,
                signals={"error_type": type(e).__name__},
                metrics=metrics,
                duration_ms=(datetime.now() - start_ts).total_seconds() * 1000,
                error_message=str(e)
            )
        except Exception as e:
            # Code level failure
            log.error(f"Harness Critical Failure: {e}", exc_info=True)
            return ExecutionResult(
                order_id=str(id(order)),
                status=ExecutionStatus.ERROR,
                signals={},
                metrics=metrics,
                duration_ms=(datetime.now() - start_ts).total_seconds() * 1000,
                error_message=f"Internal Harness Error: {e}"
            )

    async def _execute_with_retry(self, client: httpx.AsyncClient, method: str, url: str, json: Any) -> Tuple[httpx.Response, int]:
        """
        Executes request with exponential backoff and jitter.
        Returns: (Response, retries_used)
        """
        retries = 0
        while True:
            try:
                # Per-request timeout is strict
                response = await client.request(
                    method=method, 
                    url=url, 
                    json=json, 
                    timeout=BASE_TIMEOUT
                )
                
                # Check for transient server errors (502, 503, 504) or Rate Limits (429)
                if response.status_code in [429, 502, 503, 504]:
                    if retries < MAX_RETRIES:
                        await self._backoff(retries)
                        retries += 1
                        continue
                
                return response, retries

            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout) as e:
                # Transient network timeouts deserve a retry
                if retries < MAX_RETRIES:
                    log.info(f"Transient timeout ({type(e).__name__}) hitting {url}, retrying...")
                    await self._backoff(retries)
                    retries += 1
                    continue
                raise e # Reraise if out of retries
    
    async def _backoff(self, attempt: int):
        """
        Exponential backoff with Full Jitter.
        Sleep = random_between(0, min(cap, base * 2 ** attempt))
        """
        base_delay = 0.5 # 500ms
        max_delay = 5.0
        
        cap = min(max_delay, base_delay * (2 ** attempt))
        sleep_time = random.uniform(0, cap)
        await asyncio.sleep(sleep_time)

    def _normalize_url(self, endpoint: str) -> str:
        # V1: Assume config-based base if relative, or use localhost as fallback
        if endpoint.startswith("http"):
            return endpoint
        # TODO: Inject Config object to get real Scan Target Base URL
        base = "http://localhost:8000" 
        return f"{base.rstrip('/')}/{endpoint.lstrip('/')}"

    def _construct_payload(self, mutation) -> Dict[str, Any]:
        """
        Reifies the abstract mutation into a concrete payload.
        Future: This should use a 'Seed' from the LogicTestCase provenance.
        """
        # Base Mock Payload (In prod, this comes from a captured valid request)
        payload = {"amount": 100, "currency": "USD", "recipient": "bob"}
        
        op = mutation.op
        params = mutation.params
        
        if op == MutationOpType.SET_NUMERIC_BELOW_MIN:
            field = params.get("field", "amount")
            val = params.get("value", -1)
            payload[field] = val
            
        elif op == MutationOpType.REMOVE_REQUIRED_FIELD:
            field = params.get("field", "amount")
            payload.pop(field, None)
            
        elif op == MutationOpType.CROSS_TENANT_REFERENCE:
            field = params.get("field", "id")
            val = params.get("value", "tenant-b-uuid")
            payload[field] = val

        return payload
