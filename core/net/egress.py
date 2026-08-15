"""Per-hop admission broker for target-bound HTTP traffic.

Transports never follow redirects themselves.  The broker evaluates the
initial URL and every redirect destination before asking the transport to
connect, which makes redirect-based scope escapes structurally unreachable.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping
from urllib.parse import urljoin

import httpx

from core.base.exceptions import ScopePolicyViolationError
from core.base.scope import CanonicalOrigin, ScopeDecision, canonical_origin


ScopeAuthorizer = Callable[[str], bool]
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})


def scope_context_authorizer(context: Any) -> ScopeAuthorizer:
    """Bind a ScopeContext to a fail-closed URL admission callable."""

    def authorize(url: str) -> bool:
        try:
            decision = context.registry.resolve(url)
            return decision.verdict == ScopeDecision.ALLOW
        except Exception:
            return False

    return authorize


def same_origin_authorizer(seed_url: str) -> ScopeAuthorizer:
    """Admit only the canonical origin of ``seed_url``."""

    allowed = canonical_origin(seed_url)
    return lambda candidate: allowed is not None and canonical_origin(candidate) == allowed


def admit_egress(url: str, authorize: ScopeAuthorizer) -> CanonicalOrigin:
    """Fail closed before a transport connects to ``url``.

    This helper is also used at non-httpx boundaries (native browser and
    subprocess/aiohttp seams) whose transports cannot be wrapped directly.
    Those boundaries must disable their own redirect following.
    """

    origin = canonical_origin(url)
    try:
        allowed = origin is not None and bool(authorize(url))
    except Exception:
        allowed = False
    if not allowed:
        error = ScopePolicyViolationError(
            f"Outbound request blocked before connect: {url!r} is not admitted"
        )
        error.target_url = url
        raise error
    return origin


class EgressBroker:
    """Route asynchronous HTTP requests through per-hop scope admission."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        authorize: ScopeAuthorizer,
        *,
        max_redirects: int = 5,
    ) -> None:
        self.client = client
        self.authorize = authorize
        self.max_redirects = max(0, int(max_redirects))

    def admit(self, url: str) -> CanonicalOrigin:
        return admit_egress(url, self.authorize)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        follow_redirects = bool(kwargs.pop("follow_redirects", False))
        current_method = str(method).upper()
        current_url = str(url)
        request_kwargs = dict(kwargs)

        for redirect_count in range(self.max_redirects + 1):
            source_origin = self.admit(current_url)
            response = await _async_transport_request(
                self.client,
                current_method,
                current_url,
                request_kwargs,
            )
            if not follow_redirects or response.status_code not in _REDIRECT_STATUSES:
                return response

            location = response.headers.get("location")
            if not location:
                return response
            if redirect_count >= self.max_redirects:
                request = response.request
                raise httpx.TooManyRedirects(
                    f"Exceeded {self.max_redirects} admitted redirect hops",
                    request=request,
                )

            destination = urljoin(current_url, location)
            destination_origin = self.admit(destination)
            if destination_origin != source_origin:
                request_kwargs = _without_cross_origin_credentials(request_kwargs)

            if response.status_code == 303 or (
                response.status_code in {301, 302} and current_method == "POST"
            ):
                current_method = "GET"
                request_kwargs = _without_request_body(request_kwargs)
            current_url = destination

        raise AssertionError("redirect loop exhausted without returning")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)


class SyncEgressBroker:
    """Synchronous counterpart used by crawler threads and legacy probes."""

    def __init__(
        self,
        client: httpx.Client,
        authorize: ScopeAuthorizer,
        *,
        max_redirects: int = 5,
    ) -> None:
        self.client = client
        self.authorize = authorize
        self.max_redirects = max(0, int(max_redirects))

    def admit(self, url: str) -> CanonicalOrigin:
        return admit_egress(url, self.authorize)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        follow_redirects = bool(kwargs.pop("follow_redirects", False))
        current_method = str(method).upper()
        current_url = str(url)
        request_kwargs = dict(kwargs)

        for redirect_count in range(self.max_redirects + 1):
            source_origin = self.admit(current_url)
            response = _sync_transport_request(
                self.client,
                current_method,
                current_url,
                request_kwargs,
            )
            if not follow_redirects or response.status_code not in _REDIRECT_STATUSES:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            if redirect_count >= self.max_redirects:
                raise httpx.TooManyRedirects(
                    f"Exceeded {self.max_redirects} admitted redirect hops",
                    request=response.request,
                )
            destination = urljoin(current_url, location)
            destination_origin = self.admit(destination)
            if destination_origin != source_origin:
                request_kwargs = _without_cross_origin_credentials(request_kwargs)
            if response.status_code == 303 or (
                response.status_code in {301, 302} and current_method == "POST"
            ):
                current_method = "GET"
                request_kwargs = _without_request_body(request_kwargs)
            current_url = destination

        raise AssertionError("redirect loop exhausted without returning")

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)


def _without_cross_origin_credentials(kwargs: Mapping[str, Any]) -> dict[str, Any]:
    cleaned = dict(kwargs)
    headers = cleaned.get("headers")
    if headers is not None:
        cleaned["headers"] = {
            str(key): value
            for key, value in dict(headers).items()
            if str(key).lower() not in _SENSITIVE_HEADERS
        }
    cleaned.pop("cookies", None)
    return cleaned


async def _async_transport_request(
    client: Any,
    method: str,
    url: str,
    kwargs: Mapping[str, Any],
) -> Any:
    request = getattr(client, "request", None)
    if callable(request):
        return await request(method, url, follow_redirects=False, **dict(kwargs))
    method_call = getattr(client, method.lower())
    return await method_call(url, **dict(kwargs))


def _sync_transport_request(
    client: Any,
    method: str,
    url: str,
    kwargs: Mapping[str, Any],
) -> Any:
    request = getattr(client, "request", None)
    if callable(request):
        if isinstance(client, httpx.Client):
            return request(method, url, follow_redirects=False, **dict(kwargs))
        return request(method, url, allow_redirects=False, **dict(kwargs))
    method_call = getattr(client, method.lower())
    return method_call(url, **dict(kwargs))


def _without_request_body(kwargs: Mapping[str, Any]) -> dict[str, Any]:
    cleaned = dict(kwargs)
    for key in ("content", "data", "files", "json"):
        cleaned.pop(key, None)
    headers = cleaned.get("headers")
    if headers is not None:
        cleaned["headers"] = {
            str(key): value
            for key, value in dict(headers).items()
            if str(key).lower() not in {"content-length", "content-type", "transfer-encoding"}
        }
    return cleaned
