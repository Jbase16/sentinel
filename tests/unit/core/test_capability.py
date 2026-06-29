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
