"""
Unit tests for core/wraith/persona_auth.authenticate_persona (Run #26).

The persona authenticator is the gate between a ScanRequest.personas entry
and the per-identity (headers, cookies) the verify phase uses for IDOR /
authenticated-SQLi probes. Its contract is intentionally fail-OPEN: a broken
login must NEVER raise — the worst case is empty creds.

These tests pin:
  * Static-only personas bypass the network entirely.
  * Dotted-path token extraction navigates nested JSON correctly.
  * `auth_header` templates interpolate {token} and split on the first ':'.
  * Form vs JSON login body encoding goes to the right httpx kwarg.
  * Transport errors / 4xx / missing-token responses all fail OPEN (no raise).
  * Response cookies are always picked up, even on a 4xx login.
"""
from __future__ import annotations

import asyncio
import json
import pytest

from core.wraith import persona_auth
from core.wraith.persona_auth import authenticate_persona, _dotted_get


def _run(coro):
    return asyncio.run(coro)


# ─────────────────────────── _dotted_get ───────────────────────────

class TestDottedGet:
    def test_simple_key(self):
        assert _dotted_get({"a": 1}, "a") == 1

    def test_nested(self):
        assert _dotted_get({"a": {"b": {"c": "tok"}}}, "a.b.c") == "tok"

    def test_missing_key_returns_none(self):
        assert _dotted_get({"a": 1}, "b") is None

    def test_partial_miss_returns_none(self):
        assert _dotted_get({"a": {}}, "a.b.c") is None

    def test_list_index(self):
        assert _dotted_get({"a": ["x", "y", "z"]}, "a.1") == "y"

    def test_list_index_out_of_range(self):
        assert _dotted_get({"a": ["x"]}, "a.5") is None

    def test_traverses_into_scalar_returns_none(self):
        # Once we hit a scalar partway through, navigation must abort.
        assert _dotted_get({"a": "string"}, "a.b") is None

    def test_empty_path_returns_obj(self):
        assert _dotted_get({"a": 1}, "") == {"a": 1}


# ───────────────────── authenticate_persona (offline) ────────────────────

class TestStaticOnlyPersona:
    """No login_url → never touches the network, just returns static creds."""

    def test_no_login_url_returns_static_creds(self):
        persona = {
            "name": "static",
            "static_headers": {"X-API-Key": "abc"},
            "static_cookies": {"sid": "xyz"},
        }
        headers, cookies = _run(authenticate_persona(persona))
        assert headers == {"X-API-Key": "abc"}
        assert cookies == {"sid": "xyz"}

    def test_no_login_url_empty_creds(self):
        headers, cookies = _run(authenticate_persona({"name": "empty"}))
        assert headers == {}
        assert cookies == {}


# ───────────── authenticate_persona (httpx monkeypatched) ──────────────

class _FakeResponse:
    def __init__(self, status_code=200, json_body=None, cookies=None, text=""):
        self.status_code = status_code
        self._json_body = json_body
        # httpx exposes .cookies as a dict-like; a real dict is close enough
        # since persona_auth iterates resp.cookies.items().
        self.cookies = cookies or {}
        self.text = text

    def json(self):
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body


class _FakeClient:
    """Drop-in for httpx.AsyncClient used as an async context manager."""

    last_url = None
    last_kwargs = None
    last_method = None

    def __init__(self, *args, **kwargs):
        # Capture constructor kwargs (follow_redirects etc.) if a test wants them
        type(self).init_kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, **kwargs):
        type(self).last_url = url
        type(self).last_kwargs = kwargs
        type(self).last_method = "POST"
        return type(self).response_factory(url, kwargs)

    async def request(self, method, url, **kwargs):
        type(self).last_url = url
        type(self).last_kwargs = kwargs
        type(self).last_method = method
        return type(self).response_factory(url, kwargs)


def _install_fake_client(monkeypatch, response_factory):
    """Wire _FakeClient with a per-test response_factory(url, kwargs) -> _FakeResponse."""
    _FakeClient.response_factory = staticmethod(response_factory)
    _FakeClient.last_url = None
    _FakeClient.last_kwargs = None
    _FakeClient.last_method = None
    monkeypatch.setattr(persona_auth.httpx, "AsyncClient", _FakeClient)


class TestLoginFlows:
    def test_json_login_with_token_extraction(self, monkeypatch):
        """Juice-Shop-shaped login: nested token + Bearer template."""
        def factory(url, kwargs):
            assert "json" in kwargs, "JSON login_kind must use json= kwarg"
            return _FakeResponse(
                status_code=200,
                json_body={"authentication": {"token": "abc.def.ghi", "bid": 1}},
                cookies={"session": "s-123"},
            )
        _install_fake_client(monkeypatch, factory)

        persona = {
            "name": "admin",
            "login_url": "http://h/rest/user/login",
            "login_kind": "json",
            "login_body": {"email": "a@b", "password": "p"},
            "token_path": "authentication.token",
            "auth_header": "Authorization: Bearer {token}",
        }
        headers, cookies = _run(authenticate_persona(persona))

        assert headers.get("Authorization") == "Bearer abc.def.ghi"
        # Login response cookies are always captured.
        assert cookies.get("session") == "s-123"
        # POST is the default method.
        assert _FakeClient.last_method == "POST"

    def test_form_login_uses_data_kwarg(self, monkeypatch):
        def factory(url, kwargs):
            assert "data" in kwargs and "json" not in kwargs, \
                "form login_kind must use data= kwarg"
            return _FakeResponse(status_code=200, json_body={"t": "tok"})
        _install_fake_client(monkeypatch, factory)

        persona = {
            "name": "form",
            "login_url": "http://h/login",
            "login_kind": "form",
            "login_body": {"u": "user", "p": "pass"},
            "token_path": "t",
            "auth_header": "X-Token: {token}",
        }
        headers, _ = _run(authenticate_persona(persona))
        assert headers.get("X-Token") == "tok"

    def test_unknown_login_kind_defaults_to_json(self, monkeypatch):
        def factory(url, kwargs):
            assert "json" in kwargs, "unknown login_kind must fall back to JSON"
            return _FakeResponse(status_code=200, json_body={})
        _install_fake_client(monkeypatch, factory)

        _run(authenticate_persona({
            "name": "weird",
            "login_url": "http://h/login",
            "login_kind": "soap-over-pigeon",
            "login_body": {"x": 1},
        }))

    def test_get_login_method(self, monkeypatch):
        def factory(url, kwargs):
            return _FakeResponse(status_code=200, json_body={})
        _install_fake_client(monkeypatch, factory)

        _run(authenticate_persona({
            "name": "get-login",
            "login_url": "http://h/login",
            "login_method": "GET",
        }))
        assert _FakeClient.last_method == "GET"

    def test_static_creds_merge_with_login_creds(self, monkeypatch):
        """static_headers + token-derived header must coexist; cookies merge."""
        def factory(url, kwargs):
            return _FakeResponse(
                status_code=200,
                json_body={"t": "T"},
                cookies={"sess": "from-login"},
            )
        _install_fake_client(monkeypatch, factory)

        persona = {
            "name": "mixed",
            "login_url": "http://h/login",
            "token_path": "t",
            "auth_header": "Authorization: Bearer {token}",
            "static_headers": {"X-Static": "S"},
            "static_cookies": {"static-cookie": "C"},
        }
        headers, cookies = _run(authenticate_persona(persona))
        assert headers.get("X-Static") == "S"
        assert headers.get("Authorization") == "Bearer T"
        assert cookies.get("static-cookie") == "C"
        assert cookies.get("sess") == "from-login"


class TestFailOpen:
    """The contract: authenticate_persona MUST NEVER raise."""

    def test_transport_failure_fails_open(self, monkeypatch):
        class _BoomClient:
            def __init__(self, *a, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, *a, **kw):
                raise ConnectionError("simulated network down")
        monkeypatch.setattr(persona_auth.httpx, "AsyncClient", _BoomClient)

        persona = {
            "name": "victim",
            "login_url": "http://unreachable/login",
            "static_headers": {"X-Static": "still-here"},
        }
        # Must NOT raise — and the static creds must survive.
        headers, cookies = _run(authenticate_persona(persona))
        assert headers.get("X-Static") == "still-here"
        assert cookies == {}

    def test_4xx_still_captures_response_cookies(self, monkeypatch):
        # A 4xx response sometimes still sets a session cookie (e.g. a
        # CSRF cookie); the verifier may still use it productively.
        def factory(url, kwargs):
            return _FakeResponse(
                status_code=401, json_body={"error": "bad creds"},
                cookies={"csrf": "tok"}, text="bad creds",
            )
        _install_fake_client(monkeypatch, factory)
        _, cookies = _run(authenticate_persona({
            "name": "bad",
            "login_url": "http://h/login",
        }))
        assert cookies.get("csrf") == "tok"

    def test_token_path_miss_does_not_raise(self, monkeypatch):
        def factory(url, kwargs):
            return _FakeResponse(status_code=200, json_body={"other": "x"})
        _install_fake_client(monkeypatch, factory)

        headers, _ = _run(authenticate_persona({
            "name": "miss",
            "login_url": "http://h/login",
            "token_path": "nope.deep",
            "auth_header": "Authorization: Bearer {token}",
        }))
        # No token extracted → no auth header set, but no raise either.
        assert "Authorization" not in headers

    def test_non_json_response_with_token_path_does_not_raise(self, monkeypatch):
        def factory(url, kwargs):
            return _FakeResponse(status_code=200, json_body=None, text="<html/>")
        _install_fake_client(monkeypatch, factory)

        headers, _ = _run(authenticate_persona({
            "name": "html",
            "login_url": "http://h/login",
            "token_path": "t",
            "auth_header": "Authorization: Bearer {token}",
        }))
        assert "Authorization" not in headers

    def test_malformed_auth_header_template_does_not_raise(self, monkeypatch):
        # Template missing the ':' separator must be logged + skipped.
        def factory(url, kwargs):
            return _FakeResponse(status_code=200, json_body={"t": "T"})
        _install_fake_client(monkeypatch, factory)

        headers, _ = _run(authenticate_persona({
            "name": "broken-template",
            "login_url": "http://h/login",
            "token_path": "t",
            "auth_header": "NoColonHere{token}",  # missing ':'
        }))
        # No header parsed, but no raise.
        assert headers == {}
