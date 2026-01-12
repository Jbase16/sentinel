from __future__ import annotations

import logging
import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Iterable

from fastapi import Request, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.base.config import get_config, is_network_exposed
from core.errors import SentinelError, ErrorCode

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)


class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window = 60.0
        with self._lock:
            self.requests[key] = [
                t for t in self.requests[key] if now - t < window
            ]
            if len(self.requests[key]) >= self.requests_per_minute:
                return False
            self.requests[key].append(now)
            return True


# ---------------------------------------------------------------------------
# Lazy-initialized rate limiters (NO import-time config access)
# ---------------------------------------------------------------------------

_rate_limiter: Optional[RateLimiter] = None
_ai_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        config = get_config()
        limit = getattr(config.security, "rate_limit_api", 60)
        _rate_limiter = RateLimiter(requests_per_minute=limit)
        logger.info(
            "API rate limiter initialized",
            extra={"requests_per_minute": limit},
        )
    return _rate_limiter


def get_ai_rate_limiter() -> RateLimiter:
    global _ai_rate_limiter
    if _ai_rate_limiter is None:
        config = get_config()
        limit = getattr(config.security, "rate_limit_ai", 30)
        _ai_rate_limiter = RateLimiter(requests_per_minute=limit)
        logger.info(
            "AI rate limiter initialized",
            extra={"requests_per_minute": limit},
        )
    return _ai_rate_limiter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

async def verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> bool:
    config = get_config()

    if not config.security.require_auth:
        return True

    if credentials is None:
        raise SentinelError(
            ErrorCode.AUTH_TOKEN_MISSING,
            "Authentication token required",
            details={"endpoint": str(request.url.path)},
        )

    if credentials.credentials != config.security.api_token:
        raise SentinelError(
            ErrorCode.AUTH_TOKEN_INVALID,
            "Invalid authentication token",
            details={"endpoint": str(request.url.path)},
        )

    return True


async def verify_sensitive_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> bool:
    config = get_config()
    is_exposed = is_network_exposed(config.api_host)
    require_token = is_exposed or config.security.require_auth

    if not require_token:
        return True

    if credentials is None:
        raise SentinelError(
            ErrorCode.AUTH_TOKEN_MISSING,
            "Authentication token required for sensitive endpoint",
            details={
                "endpoint": str(request.url.path),
                "reason": "network_exposed" if is_exposed else "require_auth_enabled",
            },
        )

    if credentials.credentials != config.security.api_token:
        raise SentinelError(
            ErrorCode.AUTH_TOKEN_INVALID,
            "Invalid authentication token",
            details={"endpoint": str(request.url.path)},
        )

    return True


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

async def check_rate_limit(request: Request) -> None:
    limiter = get_rate_limiter()
    client_ip = get_client_ip(request)

    if not limiter.is_allowed(client_ip):
        raise SentinelError(
            ErrorCode.AUTH_RATE_LIMIT_EXCEEDED,
            "Rate limit exceeded",
            details={
                "endpoint": str(request.url.path),
                "client_ip": client_ip,
            },
        )


async def check_ai_rate_limit(request: Request) -> None:
    limiter = get_ai_rate_limiter()
    client_ip = get_client_ip(request)

    if not limiter.is_allowed(client_ip):
        raise SentinelError(
            ErrorCode.AI_RATE_LIMIT_EXCEEDED,
            "AI rate limit exceeded",
            details={
                "endpoint": str(request.url.path),
                "client_ip": client_ip,
            },
        )


# ---------------------------------------------------------------------------
# Origin validation
# ---------------------------------------------------------------------------

def is_origin_allowed(origin: str, allowed_patterns: Iterable[str]) -> bool:
    """
    Check if an origin matches any of the allowed patterns.

    Patterns support:
    - Exact matches: "https://example.com"
    - Wildcard ports: "http://localhost:*"

    Args:
        origin: Origin header value
        allowed_patterns: Iterable of allowed origin patterns

    Returns:
        True if allowed, False otherwise
    """
    from urllib.parse import urlparse

    if not allowed_patterns:
        return False

    for pattern in allowed_patterns:
        if pattern == "*":
            return True

        if pattern == origin:
            return True

        # Wildcard port handling (e.g. http://localhost:*)
        if ":*" in pattern:
            base_pattern = pattern.split(":*")[0]
            if origin.startswith(base_pattern):
                try:
                    origin_parsed = urlparse(origin)
                    pattern_parsed = urlparse(base_pattern)

                    if (
                        origin_parsed.scheme == pattern_parsed.scheme
                        and origin_parsed.hostname == pattern_parsed.hostname
                    ):
                        return True
                except Exception:
                    continue

    return False