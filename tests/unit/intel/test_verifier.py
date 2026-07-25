"""
Tests for CredentialVerifier (Phase 2A).

The verifier is the layer that turns "extracted credential candidates"
into "credential candidates with verified status." It mutates Persona
state in place; that mutation is what we assert on.

We mock the HTTP client. The pieces under test:

  1. Anonymous personas are left UNVERIFIED (nothing to verify)
  2. Personas without login_flow are left UNVERIFIED (can't verify)
  3. Personas with missing username/password are left UNVERIFIED
  4. Layer-1 success: token_extract_path resolves to a non-empty value
     in the JSON body → VERIFIED
  5. Layer-1 failure: token path absent or empty → FAILED
  6. Layer-2 success: named cookie is set on the response → VERIFIED
  7. Layer-3 fallback: 2xx status with no token/cookie spec → VERIFIED
  8. Non-2xx status (regardless of layer) → FAILED
  9. Network/HTTP exceptions → FAILED (graceful)
  10. JSON path extraction handles nested paths and missing keys
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest

from core.intel.program_scope import (
    LoginFlow,
    Persona,
    Platform,
    ProgramScope,
    VerificationStatus,
)
from core.intel.verifier import _extract_json_path, _is_login_successful, verify


# ─────────────────────────── Test doubles ──────────────────────────

class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        json_body: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ):
        self.status_code = status_code
        self._json_body = json_body
        self.cookies = cookies or {}

    def json(self):
        if self._json_body is None:
            raise ValueError("no JSON body")
        return self._json_body


class _FakeClient:
    """Async context manager that records calls and returns a programmed response."""

    def __init__(self, response):
        self.response = response
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _make_factory(response):
    client = _FakeClient(response)

    def factory():
        return client

    factory.client = client
    return factory


def _scope_with_personas(*personas: Persona) -> ProgramScope:
    return ProgramScope(
        handle=None,
        platform=Platform.DIRECT_URL,
        name="test",
        source_url="https://example.com",
        fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        personas=list(personas),
    )


# ─────────────────────────── Skip rules ────────────────────────────

class TestSkipRules:
    async def test_anonymous_persona_left_unverified(self):
        p = Persona(name="anon", persona_type="anonymous", base_url="https://x")
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(status_code=999)))
        assert p.verified == VerificationStatus.UNVERIFIED

    async def test_persona_without_login_flow_left_unverified(self):
        p = Persona(
            name="user",
            persona_type="user",
            base_url="https://x",
            username="a@b.c",
            password="x",
            # login_flow=None
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(status_code=999)))
        assert p.verified == VerificationStatus.UNVERIFIED

    async def test_persona_with_missing_password_left_unverified(self):
        p = Persona(
            name="user",
            persona_type="user",
            base_url="https://x",
            username="a@b.c",
            password=None,
            login_flow=LoginFlow(endpoint="/login"),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(status_code=999)))
        assert p.verified == VerificationStatus.UNVERIFIED


# ─────────────────────────── Layer 1: token extraction ─────────────

class TestTokenExtractionSuccess:
    async def test_token_at_dotted_path_returns_verified(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="hunter2",
            login_flow=LoginFlow(
                endpoint="/api/login",
                token_extract_path="data.token",
            ),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(
            status_code=200,
            json_body={"data": {"token": "abc123", "user_id": 42}},
        )))
        assert p.verified == VerificationStatus.VERIFIED

    async def test_token_path_absent_returns_failed(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="wrong",
            login_flow=LoginFlow(
                endpoint="/api/login",
                token_extract_path="data.token",
            ),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(
            status_code=401,
            json_body={"error": "bad credentials"},
        )))
        assert p.verified == VerificationStatus.FAILED

    async def test_token_path_empty_string_returns_failed(self):
        # Defensive: a literal empty token is not a successful login.
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(
                endpoint="/api/login",
                token_extract_path="token",
            ),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(
            status_code=200,
            json_body={"token": ""},
        )))
        assert p.verified == VerificationStatus.FAILED

    async def test_token_path_expects_json_but_body_is_html_returns_failed(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(
                endpoint="/api/login",
                token_extract_path="data.token",
            ),
        )
        scope = _scope_with_personas(p)
        # No json body — calling .json() raises.
        await verify(scope, http_factory=_make_factory(_FakeResponse(
            status_code=200,
            json_body=None,
        )))
        assert p.verified == VerificationStatus.FAILED


# ─────────────────────────── Layer 2: cookie extraction ────────────

class TestCookieExtraction:
    async def test_named_cookie_set_returns_verified(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="hunter2",
            login_flow=LoginFlow(
                endpoint="/login",
                cookie_extract_name="session_id",
            ),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(
            status_code=200,
            cookies={"session_id": "abc123"},
        )))
        assert p.verified == VerificationStatus.VERIFIED

    async def test_named_cookie_absent_returns_failed(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(
                endpoint="/login",
                cookie_extract_name="session_id",
            ),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(
            status_code=200,
            cookies={"some_other_cookie": "x"},
        )))
        assert p.verified == VerificationStatus.FAILED


# ─────────────────────────── Layer 3: status fallback ──────────────

class TestStatusCodeFallback:
    async def test_2xx_with_no_token_or_cookie_spec_returns_verified(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(endpoint="/login"),  # no token or cookie spec
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(status_code=204)))
        assert p.verified == VerificationStatus.VERIFIED

    async def test_4xx_returns_failed(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(endpoint="/login"),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(_FakeResponse(status_code=401)))
        assert p.verified == VerificationStatus.FAILED


# ─────────────────────────── Exception handling ────────────────────

class TestNetworkExceptions:
    async def test_connection_error_marks_failed_not_crashes(self):
        import httpx
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(endpoint="/login"),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(httpx.ConnectError("dns")))
        assert p.verified == VerificationStatus.FAILED

    async def test_timeout_marks_failed(self):
        import httpx
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(endpoint="/login"),
        )
        scope = _scope_with_personas(p)
        await verify(scope, http_factory=_make_factory(httpx.TimeoutException("slow")))
        assert p.verified == VerificationStatus.FAILED


# ─────────────────────────── Request construction ──────────────────

class TestRequestConstruction:
    async def test_absolute_endpoint_used_as_is(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://api.x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(endpoint="https://auth.x.com/login"),
        )
        scope = _scope_with_personas(p)
        factory = _make_factory(_FakeResponse(status_code=200))
        await verify(scope, http_factory=factory)
        assert factory.client.calls[0]["url"] == "https://auth.x.com/login"

    async def test_relative_endpoint_joins_to_base_url(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://api.x.com",
            username="a@b.c", password="x",
            login_flow=LoginFlow(endpoint="/api/login"),
        )
        scope = _scope_with_personas(p)
        factory = _make_factory(_FakeResponse(status_code=200))
        await verify(scope, http_factory=factory)
        assert factory.client.calls[0]["url"] == "https://api.x.com/api/login"

    async def test_base_url_with_trailing_slash_does_not_double(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://api.x.com/",
            username="a@b.c", password="x",
            login_flow=LoginFlow(endpoint="/login"),
        )
        scope = _scope_with_personas(p)
        factory = _make_factory(_FakeResponse(status_code=200))
        await verify(scope, http_factory=factory)
        assert factory.client.calls[0]["url"] == "https://api.x.com/login"

    async def test_json_content_type_sends_json_payload(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="user@example.com", password="pw",
            login_flow=LoginFlow(
                endpoint="/login",
                content_type="application/json",
                username_param="email",
                password_param="password",
            ),
        )
        scope = _scope_with_personas(p)
        factory = _make_factory(_FakeResponse(status_code=200))
        await verify(scope, http_factory=factory)
        # The request used json= (not data=) and the payload mapped
        # the username to "email", the password to "password".
        call = factory.client.calls[0]
        assert call.get("json") == {"email": "user@example.com", "password": "pw"}
        assert call.get("data") is None

    async def test_form_content_type_sends_form_payload(self):
        p = Persona(
            name="u", persona_type="user", base_url="https://x.com",
            username="user", password="pw",
            login_flow=LoginFlow(
                endpoint="/login",
                content_type="application/x-www-form-urlencoded",
                username_param="user",
                password_param="pw",
            ),
        )
        scope = _scope_with_personas(p)
        factory = _make_factory(_FakeResponse(status_code=200))
        await verify(scope, http_factory=factory)
        call = factory.client.calls[0]
        assert call.get("data") == {"user": "user", "pw": "pw"}
        assert call.get("json") is None


# ─────────────────────────── _extract_json_path helper ─────────────

class TestExtractJsonPath:
    def test_single_segment(self):
        assert _extract_json_path({"token": "abc"}, "token") == "abc"

    def test_nested_path(self):
        body = {"data": {"auth": {"token": "abc"}}}
        assert _extract_json_path(body, "data.auth.token") == "abc"

    def test_missing_segment_returns_none(self):
        assert _extract_json_path({"data": {}}, "data.token") is None
        assert _extract_json_path({}, "data.token") is None

    def test_non_dict_body_returns_none(self):
        assert _extract_json_path("not a dict", "x") is None
        assert _extract_json_path(None, "x") is None
        assert _extract_json_path([1, 2, 3], "0") is None

    def test_intermediate_non_dict_returns_none(self):
        # "data.token.x" where data.token is a string — can't traverse further.
        body = {"data": {"token": "string-not-dict"}}
        assert _extract_json_path(body, "data.token.x") is None


# ─────────────────────────── Mixed-persona summary ─────────────────

class TestMixedPersonas:
    async def test_multiple_personas_get_independent_statuses(self):
        # One anonymous, one will succeed, one will fail.
        anon = Persona(name="anon", persona_type="anonymous", base_url="https://x")
        good = Persona(
            name="good", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="ok",
            login_flow=LoginFlow(endpoint="/login", token_extract_path="token"),
        )
        bad = Persona(
            name="bad", persona_type="user", base_url="https://x.com",
            username="a@b.c", password="nope",
            login_flow=LoginFlow(endpoint="/login", token_extract_path="token"),
        )
        scope = _scope_with_personas(anon, good, bad)

        # Programmable client that returns success for the FIRST call,
        # failure for the second (and only good/bad will call — anon is
        # skipped before any HTTP).
        call_count = {"n": 0}

        class _AlternatingClient:
            calls: list[dict] = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return False

            async def request(self, method, url, **kwargs):
                call_count["n"] += 1
                if call_count["n"] == 1:
                    return _FakeResponse(status_code=200, json_body={"token": "ok"})
                return _FakeResponse(status_code=401, json_body={"error": "nope"})

        def factory():
            return _AlternatingClient()

        await verify(scope, http_factory=factory)

        assert anon.verified == VerificationStatus.UNVERIFIED  # skipped, never called
        assert good.verified == VerificationStatus.VERIFIED
        assert bad.verified == VerificationStatus.FAILED


# ─────────────────────────── Return value contract ─────────────────

class TestReturnValue:
    async def test_returns_same_object_in_place_mutation(self):
        # The verifier mutates ``scope.personas`` in place and returns
        # the same ``ProgramScope`` (for fluent chaining). Don't break
        # that contract — downstream code may compare by identity.
        p = Persona(name="anon", persona_type="anonymous", base_url="https://x")
        scope = _scope_with_personas(p)
        result = await verify(scope, http_factory=_make_factory(_FakeResponse()))
        assert result is scope


# ─────────────────────────── _is_login_successful direct ───────────

class TestIsLoginSuccessful:
    """Direct tests on the success heuristic — easier than going through
    the full HTTP stack for edge cases."""

    def test_token_path_value_truthy_is_success(self):
        flow = LoginFlow(endpoint="/x", token_extract_path="token")
        resp = _FakeResponse(json_body={"token": "abc"})
        assert _is_login_successful(resp, flow) is True

    def test_token_path_value_zero_is_failure(self):
        # Zero, empty string, None — none are real tokens.
        flow = LoginFlow(endpoint="/x", token_extract_path="token")
        for empty in (0, "", None, [], {}):
            resp = _FakeResponse(json_body={"token": empty})
            assert _is_login_successful(resp, flow) is False, f"Empty {empty!r} passed as success"

    def test_status_fallback_boundaries(self):
        flow = LoginFlow(endpoint="/x")
        assert _is_login_successful(_FakeResponse(status_code=200), flow) is True
        assert _is_login_successful(_FakeResponse(status_code=299), flow) is True
        assert _is_login_successful(_FakeResponse(status_code=300), flow) is False
        assert _is_login_successful(_FakeResponse(status_code=199), flow) is False
        assert _is_login_successful(_FakeResponse(status_code=401), flow) is False
