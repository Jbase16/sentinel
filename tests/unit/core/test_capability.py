"""
Unit tests for capability acquisition (core/wraith/capability) — phase 4.

The hunt escalates past an auth wall by PERFORMING a login SQLi to capture a
session. These guard the token-extraction shapes and the bounded, scope-gated,
fail-closed acquisition loop.
"""

import json

import pytest

from core.wraith import capability as cap

_JWT = "eyJ" + "a" * 700  # JWT-ish, well over the 20-char floor


# ───────────────────────────── token extraction ─────────────────────────────

def test_extract_token_juiceshop_shape():
    body = json.dumps({"authentication": {"token": _JWT, "umail": "admin@juice-sh.op"}})
    assert cap._extract_token({}, body) == _JWT


@pytest.mark.parametrize("shape", [
    {"token": _JWT},
    {"accessToken": _JWT},
    {"access_token": _JWT},
    {"jwt": _JWT},
    {"data": {"token": _JWT}},
])
def test_extract_token_common_shapes(shape):
    assert cap._extract_token({}, json.dumps(shape)) == _JWT


def test_extract_token_none_when_absent_or_short():
    assert cap._extract_token({}, json.dumps({"message": "invalid"})) is None
    assert cap._extract_token({}, json.dumps({"token": "short"})) is None
    assert cap._extract_token({}, "not json") is None


def test_extract_cookie_session():
    headers = {"Set-Cookie": "connect.sid=s%3Aabcdefghijklmnop; Path=/; HttpOnly"}
    got = cap._extract_cookie(headers)
    assert got and got.startswith("connect.sid=")


# ──────────────────────────────── acquisition ───────────────────────────────

def _mock_send(token_on_path="/rest/user/login"):
    calls = []

    async def send(url, body):
        calls.append((url, body))
        if url.endswith(token_on_path) and "OR" in str(body):
            return 200, {}, json.dumps({"authentication": {"token": _JWT}})
        return 401, {}, json.dumps({"message": "Invalid credentials"})

    send.calls = calls  # type: ignore[attr-defined]
    return send


@pytest.mark.asyncio
async def test_acquire_captures_bearer_token():
    send = _mock_send()
    capdict = await cap.acquire_auth_via_login_sqli("http://h.example", None, send=send)
    assert capdict is not None
    assert capdict["headers"]["Authorization"] == f"Bearer {_JWT}"
    assert "SQLi auth bypass" in capdict["provenance"]


@pytest.mark.asyncio
async def test_acquire_returns_none_when_login_not_injectable():
    async def send(url, body):
        return 401, {}, json.dumps({"message": "Invalid credentials"})
    assert await cap.acquire_auth_via_login_sqli("http://h.example", None, send=send) is None


@pytest.mark.asyncio
async def test_acquire_fails_closed_on_scope():
    send = _mock_send()
    # scope_filter rejects everything → no token, and ideally no requests sent.
    out = await cap.acquire_auth_via_login_sqli(
        "http://h.example", scope_filter=lambda u: False, send=send,
    )
    assert out is None
    assert send.calls == []  # nothing was probed out of scope


@pytest.mark.asyncio
async def test_acquire_is_bounded():
    seen = {"n": 0}

    async def send(url, body):
        seen["n"] += 1
        return 401, {}, "{}"

    await cap.acquire_auth_via_login_sqli("http://h.example", None, send=send, max_attempts=7)
    assert seen["n"] <= 7


# ──────────────────────────── registry / acquirers ──────────────────────────

@pytest.mark.asyncio
async def test_acquire_capability_via_default_credentials():
    async def send(url, body):
        if url.endswith("/login") and body.get("username") == "admin" and body.get("password") == "admin":
            return 200, {}, json.dumps({"token": _JWT})
        return 401, {}, "{}"
    capobj = await cap.acquire_capability("http://h.example", None, send=send)
    assert capobj is not None
    assert capobj.acquirer == "default_credentials"
    assert capobj.headers["Authorization"] == f"Bearer {_JWT}"


@pytest.mark.asyncio
async def test_acquire_capability_login_sqli_takes_priority_over_default():
    # SQLi succeeds → registry returns it before trying default creds.
    async def send(url, body):
        if "OR" in str(body):
            return 200, {}, json.dumps({"authentication": {"token": _JWT}})
        return 401, {}, "{}"
    capobj = await cap.acquire_capability("http://h.example", None, send=send)
    assert capobj is not None and capobj.acquirer == "login_sqli"


# ─────────────────────────────── JWT helpers ────────────────────────────────

def test_jwt_encode_split_and_crack_weak_secret():
    tok = cap._jwt_encode({"user": "bob", "role": "user"}, alg="HS256", secret="secret")
    parts = tok.split(".")
    assert cap._crack_hs256(tok, parts) == "secret"          # "secret" is in the weak list
    strong = cap._jwt_encode({"x": 1}, alg="HS256", secret="b7f3-not-in-any-list-9931")
    assert cap._crack_hs256(strong, strong.split(".")) is None


def test_elevate_payload_sets_admin_claims():
    p = cap._elevate_payload({"user": "bob", "role": "user"})
    assert p["role"] == "admin" and p["isAdmin"] is True


# ─────────────────────────────── JWT forge ──────────────────────────────────

def _hs256_verify(secret: bytes):
    """A verifier that accepts ONLY a token validly HS256-signed with `secret`
    (i.e. rejects alg:none) — simulates a server that checks the signature."""
    async def verify(headers):
        import hashlib
        import hmac
        token = headers.get("Authorization", "").split(" ")[-1]
        parts = token.split(".")
        if len(parts) != 3 or not parts[2]:
            return False
        sig = hmac.new(secret, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        return parts[2] == cap._b64url_encode(sig)
    return verify


@pytest.mark.asyncio
async def test_jwt_forge_algnone_when_server_accepts_unsigned():
    tok = cap._jwt_encode({"role": "user"}, alg="HS256", secret="some-unknown-secret")
    async def accept_any(headers):
        return "Bearer " in headers.get("Authorization", "")
    capobj = await cap.acquire_capability(
        "http://h.example", None, prior_token=tok, verify=accept_any,
        acquirers=[cap.JwtForgeAcquirer()],
    )
    assert capobj is not None and capobj.acquirer == "jwt_forge"
    _h, payload, _p = cap._jwt_split(capobj.token)
    assert payload["role"] == "admin"           # elevated


@pytest.mark.asyncio
async def test_jwt_forge_cracks_weak_secret_and_resigns():
    tok = cap._jwt_encode({"role": "user"}, alg="HS256", secret="secret")
    capobj = await cap.acquire_capability(
        "http://h.example", None, prior_token=tok, verify=_hs256_verify(b"secret"),
        acquirers=[cap.JwtForgeAcquirer()],
    )
    assert capobj is not None
    assert "HS256" in capobj.provenance        # re-signed, not alg:none


@pytest.mark.asyncio
async def test_jwt_forge_refuses_without_verifier():
    # Honesty gate: a forged token we can't confirm is NOT a capability.
    tok = cap._jwt_encode({"role": "user"}, alg="HS256", secret="secret")
    capobj = await cap.acquire_capability(
        "http://h.example", None, prior_token=tok, verify=None,
        acquirers=[cap.JwtForgeAcquirer()],
    )
    assert capobj is None


@pytest.mark.asyncio
async def test_jwt_forge_refuses_when_server_rejects():
    tok = cap._jwt_encode({"role": "user"}, alg="HS256", secret="some-unknown-secret")
    async def reject_all(headers):
        return False
    capobj = await cap.acquire_capability(
        "http://h.example", None, prior_token=tok, verify=reject_all,
        acquirers=[cap.JwtForgeAcquirer()],
    )
    assert capobj is None


@pytest.mark.asyncio
async def test_jwt_forge_skipped_without_prior_token():
    # No token to elevate → forge no-ops, registry falls through.
    capobj = await cap.acquire_capability(
        "http://h.example", None, verify=lambda h: _async_true(),
        acquirers=[cap.JwtForgeAcquirer()],
    )
    assert capobj is None


async def _async_true():
    return True
