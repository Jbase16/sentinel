from __future__ import annotations

import logging
import asyncio
import random
import httpx
from typing import Any, Dict, Optional, Tuple
from datetime import datetime

from core.thanatos.models import MutationOpType
from .models import ExecutionOrder, ExecutionResult, ExecutionStatus

log = logging.getLogger("executor.http_harness")

MAX_RETRIES = 3
BASE_TIMEOUT = 10.0
MAX_REDIRECTS = 5
USER_AGENT = "SentinelForge/1.0 (Governor-Approved)"
VERIFY_TLS = False

MAX_BODY_CHARS = 200_000  # cap evidence to keep memory sane


class HttpHarness:
    _client: Optional[httpx.AsyncClient] = None

    @classmethod
    async def get_client(cls) -> httpx.AsyncClient:
        if cls._client is None or cls._client.is_closed:
            limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
            cls._client = httpx.AsyncClient(
                limits=limits,
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
                max_redirects=MAX_REDIRECTS,
                verify=VERIFY_TLS,
            )
        return cls._client

    @classmethod
    async def close_client(cls) -> None:
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()
            cls._client = None
            log.info("HttpHarness client closed.")

    async def execute(self, order: ExecutionOrder) -> ExecutionResult:
        start_ts = datetime.now()
        test_case = order.test_case
        target = test_case.target

        url = self._normalize_url(target.endpoint)
        method = target.method
        payload = self._construct_payload(test_case.mutation)

        metrics: Dict[str, float] = {"retries": 0.0}

        try:
            client = await self.get_client()

            request_headers: Dict[str, str] = {}
            if order.auth_headers:
                request_headers.update(order.auth_headers)

            request_cookies: Dict[str, str] = {}
            if order.auth_cookies:
                request_cookies.update(order.auth_cookies)

            response, retries_used = await self._execute_with_retry(
                client=client,
                method=method,
                url=url,
                json=payload,
                headers=request_headers,
                cookies=request_cookies,
            )
            metrics["retries"] = float(retries_used)

            end_ts = datetime.now()
            duration_ms = (end_ts - start_ts).total_seconds() * 1000

            body_text = response.text
            if len(body_text) > MAX_BODY_CHARS:
                body_text = body_text[:MAX_BODY_CHARS] + "\n...<truncated>..."

            signals = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": body_text,
                "url": str(response.url),
                "http_version": response.http_version,
            }

            return ExecutionResult(
                order_id=order.idempotency_token,
                status=ExecutionStatus.EXECUTED,
                signals=signals,
                metrics=metrics,
                duration_ms=duration_ms,
            )

        except httpx.RequestError as e:
            duration_ms = (datetime.now() - start_ts).total_seconds() * 1000
            log.warning(f"Harness Network Error (Order {order.idempotency_token}): {e}")
            return ExecutionResult(
                order_id=order.idempotency_token,
                status=ExecutionStatus.ERROR,
                signals={"error_type": type(e).__name__, "status_code": None},
                metrics=metrics,
                duration_ms=duration_ms,
                error_message=str(e),
            )
        except Exception as e:
            duration_ms = (datetime.now() - start_ts).total_seconds() * 1000
            log.error(f"Harness Critical Failure: {e}", exc_info=True)
            return ExecutionResult(
                order_id=order.idempotency_token,
                status=ExecutionStatus.ERROR,
                signals={"status_code": None},
                metrics=metrics,
                duration_ms=duration_ms,
                error_message=f"Internal Harness Error: {e}",
            )

    async def _execute_with_retry(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        json: Any,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Tuple[httpx.Response, int]:
        retries = 0
        while True:
            try:
                resp = await client.request(
                    method=method,
                    url=url,
                    json=json,
                    headers=headers,
                    cookies=cookies,
                    timeout=BASE_TIMEOUT,
                )

                if resp.status_code in [429, 502, 503, 504]:
                    if retries < MAX_RETRIES:
                        await self._backoff(retries)
                        retries += 1
                        continue

                return resp, retries

            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout) as e:
                if retries < MAX_RETRIES:
                    log.info(f"Transient timeout ({type(e).__name__}) hitting {url}, retrying...")
                    await self._backoff(retries)
                    retries += 1
                    continue
                raise

    async def _backoff(self, attempt: int) -> None:
        base_delay = 0.5
        max_delay = 5.0
        cap = min(max_delay, base_delay * (2 ** attempt))
        await asyncio.sleep(random.uniform(0, cap))

    def _normalize_url(self, endpoint: str) -> str:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        base = "http://localhost:3000"
        return f"{base.rstrip('/')}/{endpoint.lstrip('/')}"

    def _construct_payload(self, mutation) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"amount": 100, "currency": "USD", "recipient": "bob"}
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
