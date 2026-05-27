"""
core/wraith/persona_auth.py

Persona authenticator for the Phase 3 active-verification phase (Run #26).

Logs in with a persona definition and returns (headers, cookies) the verifier
can apply on subsequent probes. Designed for the IDOR / authenticated-SQLi
classes that need a credentialed identity context.

Schema (every login_* field is optional; a persona with only static_headers
or static_cookies bypasses the live-login flow entirely):

    {
      "name":            "admin",                    # required (by ScanRequest validator)
      "login_url":       "http://host/rest/user/login",
      "login_method":    "POST",                     # or "GET" (default POST)
      "login_kind":      "json",                     # how to encode body: "json"|"form" (default json)
      "login_body":      {"email": "...", "password": "..."},
      "login_headers":   {...},                      # extra headers for the login request
      "token_path":      "authentication.token",     # dotted-path into JSON response
      "auth_header":     "Authorization: Bearer {token}",  # template; {token} interpolated
      "static_headers":  {"X-API-Key": "..."},       # applied unconditionally
      "static_cookies":  {"sid": "..."},             # applied unconditionally
    }

Design rules:
  * Fail OPEN. Login errors → log warning, return whatever static creds we
    have. Never raise — the verify phase keeps probing unauthenticated.
  * Best-effort token extraction. If extraction fails, response cookies
    alone may still constitute a usable session.
  * Stateless. No persistent token cache (the verify phase is short-lived).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Tuple

import httpx

logger = logging.getLogger(__name__)


def _dotted_get(obj: Any, path: str) -> Any:
    """Navigate `obj` by dotted path (e.g. 'authentication.token'). Returns
    None on any miss — never raises."""
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError, TypeError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


def _apply_static(persona: Dict[str, Any]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Pull static_headers / static_cookies into mutable dicts (str-keyed/-valued)."""
    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    for k, v in (persona.get("static_headers") or {}).items():
        headers[str(k)] = str(v)
    for k, v in (persona.get("static_cookies") or {}).items():
        cookies[str(k)] = str(v)
    return headers, cookies


async def authenticate_persona(
    persona: Dict[str, Any],
    *,
    timeout: float = 10.0,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Log in with the persona, return (headers, cookies) for downstream probes.

    Never raises — falls back to static creds (or empty dicts) on any failure.
    """
    headers, cookies = _apply_static(persona)

    login_url = persona.get("login_url")
    if not login_url:
        # Static-only persona — return whatever we collected.
        return headers, cookies

    name = persona.get("name", "?")
    method = (persona.get("login_method") or "POST").upper()
    kind = (persona.get("login_kind") or "json").lower()
    body = persona.get("login_body") or {}
    login_headers = dict(persona.get("login_headers") or {})

    request_kwargs: Dict[str, Any] = {"headers": login_headers, "timeout": timeout}
    if kind == "json":
        request_kwargs["json"] = body
    elif kind == "form":
        request_kwargs["data"] = body
    else:
        logger.warning(
            f"[persona_auth] {name!r} unknown login_kind={kind!r}; defaulting to JSON"
        )
        request_kwargs["json"] = body

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            if method == "POST":
                resp = await client.post(login_url, **request_kwargs)
            else:
                resp = await client.request(method, login_url, **request_kwargs)
    except Exception as e:
        logger.warning(
            f"[persona_auth] login transport failure for {name!r}: "
            f"{type(e).__name__}: {e}"
        )
        return headers, cookies

    if resp.status_code >= 400:
        logger.warning(
            f"[persona_auth] login HTTP {resp.status_code} for {name!r} "
            f"(body[:120]: {resp.text[:120]!r})"
        )
        # Even on 4xx, sometimes a session cookie was set — surface what we got.

    # Session cookies set by the login response are always useful — keep them.
    for c_name, c_val in resp.cookies.items():
        cookies[str(c_name)] = str(c_val)

    # Optional token extraction → auth header template
    token_path = persona.get("token_path")
    auth_header_template = persona.get("auth_header")
    if token_path and auth_header_template:
        try:
            parsed = resp.json()
        except Exception:
            parsed = None
        token = _dotted_get(parsed, token_path) if parsed is not None else None
        if token:
            try:
                header_str = auth_header_template.format(token=token)
            except Exception as e:
                logger.warning(
                    f"[persona_auth] auth_header template failed for {name!r}: {e}"
                )
                header_str = ""
            if ":" in header_str:
                hname, _, hval = header_str.partition(":")
                headers[hname.strip()] = hval.strip()
            elif header_str:
                logger.warning(
                    f"[persona_auth] auth_header missing ':' for {name!r}: "
                    f"{auth_header_template!r}"
                )
        else:
            logger.warning(
                f"[persona_auth] could not extract token at {token_path!r} "
                f"for {name!r} (response keys: "
                f"{list(parsed.keys()) if isinstance(parsed, dict) else type(parsed).__name__})"
            )

    logger.info(
        f"[persona_auth] {name!r} authenticated: "
        f"{len(headers)} header(s), {len(cookies)} cookie(s)"
    )
    return headers, cookies
