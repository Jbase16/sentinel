"""
Phase 5-VC1 tests for core/verify/console.py + core/server/routers/verify.py.

Coverage:
  * VerificationSession.is_in_scope — origin allowlist semantics + fail-closed.
  * VerificationSession.add_origin_to_scope — extracts origin from URL,
    no-op when already present, returns False on unparseable.
  * create_session_from_finding — happy path (finding hydrated), missing
    finding (404), missing target (400), unparseable target (400).
  * create_session_from_target — happy path, unparseable URL → ValueError.
  * Session registry — get / list / cross-session isolation.
  * Router endpoints (direct handler calls, like other routers):
    - POST /sessions: XOR validation, both modes work, error mapping.
    - GET  /sessions: empty list, populated list.
    - GET  /sessions/{id}: 404 + happy path.
    - POST /sessions/{id}/scope: adds, idempotent, returns full list.
    - POST /sessions/{id}/persona: persona_spec path, explicit-creds path.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import pytest

from core.verify.console import (
    VerificationSession,
    _reset_for_tests,
    create_session_from_finding,
    create_session_from_target,
    get_session,
    list_sessions,
)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_store():
    """In-memory session store leaks across tests; reset between."""
    _reset_for_tests()
    yield
    _reset_for_tests()


# ───────────────────────── VerificationSession ─────────────────────────


class TestScopeAllowlist:
    def test_target_origin_is_in_scope_by_default(self):
        s = VerificationSession(
            session_id="x", finding_id=None,
            target_url="http://h.example/api/users/1",
            target_origin="http://h.example",
            allowed_origins={"http://h.example"},
        )
        assert s.is_in_scope("http://h.example/api/users/2") is True
        assert s.is_in_scope("http://h.example/anything") is True

    def test_different_host_is_NOT_in_scope(self):
        s = VerificationSession(
            session_id="x", finding_id=None,
            target_url="http://target.example/",
            target_origin="http://target.example",
            allowed_origins={"http://target.example"},
        )
        # Different host — must be denied even if it looks similar.
        assert s.is_in_scope("http://other.example/anything") is False
        # Subdomain — also denied (origin = scheme + netloc, exact match).
        assert s.is_in_scope("http://sub.target.example/") is False

    def test_different_scheme_is_NOT_in_scope(self):
        s = VerificationSession(
            session_id="x", finding_id=None,
            target_url="http://h.example/",
            target_origin="http://h.example",
            allowed_origins={"http://h.example"},
        )
        # HTTPS not in allowlist — must be denied. Operator can add
        # it explicitly if they need it.
        assert s.is_in_scope("https://h.example/") is False

    def test_unparseable_url_is_NOT_in_scope_fail_closed(self):
        s = VerificationSession(
            session_id="x", finding_id=None,
            target_url="http://h.example/",
            target_origin="http://h.example",
            allowed_origins={"http://h.example"},
        )
        # Fail-closed: anything we can't parse is not in scope.
        assert s.is_in_scope("") is False
        assert s.is_in_scope("not-a-url") is False
        assert s.is_in_scope("//missing-scheme.example/") is False

    def test_add_origin_extends_allowlist(self):
        s = VerificationSession(
            session_id="x", finding_id=None,
            target_url="http://h.example/",
            target_origin="http://h.example",
            allowed_origins={"http://h.example"},
        )
        added = s.add_origin_to_scope("http://other.example/some/path?q=1")
        assert added is True
        # Origin extracted from the URL.
        assert "http://other.example" in s.allowed_origins
        # Now the other origin is in scope.
        assert s.is_in_scope("http://other.example/different/path") is True
        # And the original is still in scope.
        assert s.is_in_scope("http://h.example/anything") is True

    def test_add_origin_is_idempotent(self):
        s = VerificationSession(
            session_id="x", finding_id=None,
            target_url="http://h.example/",
            target_origin="http://h.example",
            allowed_origins={"http://h.example"},
        )
        # Already in set → second add is a no-op (returns False).
        assert s.add_origin_to_scope("http://h.example/something") is False
        assert s.allowed_origins == {"http://h.example"}

    def test_add_origin_returns_false_for_unparseable(self):
        s = VerificationSession(
            session_id="x", finding_id=None,
            target_url="http://h.example/",
            target_origin="http://h.example",
            allowed_origins={"http://h.example"},
        )
        assert s.add_origin_to_scope("not-a-url") is False
        assert s.add_origin_to_scope("") is False
        # Allowlist unchanged.
        assert s.allowed_origins == {"http://h.example"}


# ─────────────────────── create_session_from_finding ───────────────────────


class _FakeFindingStore:
    """Stand-in for FindingsStore.get()."""

    def __init__(self, findings):
        self._findings = findings  # dict by id

    def get(self, finding_id):
        return self._findings.get(finding_id)


class TestCreateFromFinding:
    def test_hydrates_target_and_scope(self):
        store = _FakeFindingStore({
            "f-1": {
                "id": "f-1",
                "target": "https://target.example/api/users/1",
                "type": "Cross-Principal IDOR",
                "severity": "HIGH",
                "metadata": {
                    "vuln_class": "IDOR",
                    "payload": "id: 1→2",
                    "confidence": 0.85,
                    "persona": "admin",
                },
                "message": "IDOR confirmed",
                "proof": "alice and bob both 200",
            }
        })
        s = create_session_from_finding("f-1", finding_store=store)
        assert s.finding_id == "f-1"
        assert s.target_url == "https://target.example/api/users/1"
        assert s.allowed_origins == {"https://target.example"}
        assert s.persona_name == "admin"
        # Original finding snapshot retained (for VC2/VC3 to consume).
        assert s.original_finding is not None
        assert s.original_finding["metadata"]["payload"] == "id: 1→2"
        # Registered in the store.
        assert get_session(s.session_id) is s

    def test_missing_finding_raises_value_error(self):
        store = _FakeFindingStore({})
        with pytest.raises(ValueError, match="not found"):
            create_session_from_finding("does-not-exist", finding_store=store)

    def test_finding_without_target_raises(self):
        store = _FakeFindingStore({
            "f-2": {"id": "f-2", "metadata": {}, "type": "X"}
        })
        with pytest.raises(ValueError, match="no usable target URL"):
            create_session_from_finding("f-2", finding_store=store)

    def test_finding_with_unparseable_target_raises(self):
        store = _FakeFindingStore({
            "f-3": {"id": "f-3", "target": "not-a-url", "metadata": {}}
        })
        with pytest.raises(ValueError, match="not a parseable URL"):
            create_session_from_finding("f-3", finding_store=store)


# ─────────────────────── create_session_from_target ───────────────────────


class TestCreateFromTarget:
    def test_happy_path(self):
        s = create_session_from_target("https://h.example/p?q=1", note="manual")
        assert s.finding_id is None
        assert s.target_url == "https://h.example/p?q=1"
        assert s.target_origin == "https://h.example"
        assert s.allowed_origins == {"https://h.example"}
        assert s.original_finding is None

    def test_unparseable_raises(self):
        with pytest.raises(ValueError):
            create_session_from_target("not-a-url")


# ─────────────────────── session registry ───────────────────────


class TestSessionRegistry:
    def test_list_starts_empty(self):
        assert list_sessions() == []

    def test_sessions_isolated_by_id(self):
        a = create_session_from_target("https://a.example/")
        b = create_session_from_target("https://b.example/")
        assert a.session_id != b.session_id
        sessions = list_sessions()
        assert len(sessions) == 2
        # Each session sees only its own scope.
        assert "https://a.example" in a.allowed_origins
        assert "https://a.example" not in b.allowed_origins
        # Lookup by id.
        assert get_session(a.session_id) is a
        assert get_session(b.session_id) is b
        assert get_session("nope") is None


# ─────────────────────── router endpoints ───────────────────────


class TestCreateSessionEndpoint:
    def test_xor_validation_rejects_both(self, monkeypatch):
        from core.server.routers.verify import (
            CreateSessionRequest, create_session,
        )
        from fastapi import HTTPException
        req = CreateSessionRequest(
            finding_id="f-1", target_url="https://h.example/"
        )
        with pytest.raises(HTTPException) as ei:
            _run(create_session(req, _=True))
        assert ei.value.status_code == 400
        assert "EITHER" in ei.value.detail

    def test_xor_validation_rejects_neither(self):
        from core.server.routers.verify import (
            CreateSessionRequest, create_session,
        )
        from fastapi import HTTPException
        req = CreateSessionRequest()
        with pytest.raises(HTTPException) as ei:
            _run(create_session(req, _=True))
        assert ei.value.status_code == 400

    def test_target_mode_returns_session_id_and_scope(self):
        from core.server.routers.verify import (
            CreateSessionRequest, create_session,
        )
        resp = _run(create_session(
            CreateSessionRequest(target_url="https://h.example/"),
            _=True,
        ))
        assert resp.session_id is not None
        assert resp.finding_id is None
        assert resp.target_url == "https://h.example/"
        assert resp.allowed_origins == ["https://h.example"]
        assert resp.has_persona_auth is False

    def test_finding_mode_dispatches_to_factory(self, monkeypatch):
        """When finding_id is provided, the handler must call
        create_session_from_finding (with the global FindingsStore)."""
        from core.server.routers import verify as vrouter
        # Inject a fake store via the real createsession_from_finding
        # path. The handler calls get_finding_store() internally; we
        # monkeypatch that.
        from core.data import findings_store as fs_mod

        fake_store = _FakeFindingStore({
            "f-7": {
                "id": "f-7",
                "target": "https://h.example/api/x",
                "type": "X",
                "metadata": {"persona": "admin"},
            },
        })
        monkeypatch.setattr(fs_mod, "get_finding_store", lambda: fake_store)

        resp = _run(vrouter.create_session(
            vrouter.CreateSessionRequest(finding_id="f-7"),
            _=True,
        ))
        assert resp.finding_id == "f-7"
        assert resp.target_url == "https://h.example/api/x"
        assert resp.allowed_origins == ["https://h.example"]


class TestAddScopeEndpoint:
    def test_adds_new_origin(self):
        from core.server.routers.verify import (
            AddScopeRequest, add_to_scope,
        )
        sess = create_session_from_target("https://h.example/")
        resp = _run(add_to_scope(
            sess.session_id,
            AddScopeRequest(url_or_origin="https://api.example/"),
            _=True,
        ))
        assert resp.added is True
        assert "https://api.example" in resp.allowed_origins
        assert "https://h.example" in resp.allowed_origins

    def test_idempotent_returns_added_false(self):
        from core.server.routers.verify import (
            AddScopeRequest, add_to_scope,
        )
        sess = create_session_from_target("https://h.example/")
        resp = _run(add_to_scope(
            sess.session_id,
            AddScopeRequest(url_or_origin="https://h.example/x"),
            _=True,
        ))
        assert resp.added is False
        assert resp.allowed_origins == ["https://h.example"]

    def test_unknown_session_returns_404(self):
        from core.server.routers.verify import (
            AddScopeRequest, add_to_scope,
        )
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(add_to_scope(
                "no-such-session",
                AddScopeRequest(url_or_origin="https://h.example/"),
                _=True,
            ))
        assert ei.value.status_code == 404


class TestBindPersonaEndpoint:
    def test_explicit_headers_path(self):
        from core.server.routers.verify import (
            BindPersonaRequest, bind_persona,
        )
        sess = create_session_from_target("https://h.example/")
        resp = _run(bind_persona(
            sess.session_id,
            BindPersonaRequest(
                persona_name="admin",
                headers={"Authorization": "Bearer TOK"},
            ),
            _=True,
        ))
        assert resp.persona_name == "admin"
        assert resp.has_headers is True
        # Session updated.
        s = get_session(sess.session_id)
        assert s.persona_name == "admin"
        assert s.persona_headers == {"Authorization": "Bearer TOK"}

    def test_persona_spec_path_calls_authenticate_persona(self, monkeypatch):
        from core.server.routers.verify import (
            BindPersonaRequest, bind_persona,
        )
        called = {"n": 0}

        async def fake_auth(persona):
            called["n"] += 1
            # Return fake creds derived from the spec name.
            return ({"Authorization": "Bearer FROM-SPEC"}, {"sid": "abc"})

        monkeypatch.setattr(
            "core.wraith.persona_auth.authenticate_persona", fake_auth
        )

        sess = create_session_from_target("https://h.example/")
        resp = _run(bind_persona(
            sess.session_id,
            BindPersonaRequest(
                persona_name="alice",
                persona_spec={
                    "name": "alice",
                    "login_url": "https://h.example/login",
                    "login_body": {"u": "x", "p": "y"},
                },
            ),
            _=True,
        ))
        assert called["n"] == 1
        assert resp.has_headers is True
        assert resp.has_cookies is True
        s = get_session(sess.session_id)
        assert s.persona_headers["Authorization"] == "Bearer FROM-SPEC"
        assert s.persona_cookies["sid"] == "abc"

    def test_unknown_session_returns_404(self):
        from core.server.routers.verify import (
            BindPersonaRequest, bind_persona,
        )
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(bind_persona(
                "no-such-session",
                BindPersonaRequest(persona_name="x"),
                _=True,
            ))
        assert ei.value.status_code == 404


class TestListAndGetSessions:
    def test_list_empty(self):
        from core.server.routers.verify import list_verify_sessions
        result = _run(list_verify_sessions(_=True))
        assert result == []

    def test_list_returns_summaries(self):
        from core.server.routers.verify import list_verify_sessions
        a = create_session_from_target("https://a.example/")
        b = create_session_from_target("https://b.example/")
        result = _run(list_verify_sessions(_=True))
        ids = {item["session_id"] for item in result}
        assert ids == {a.session_id, b.session_id}

    def test_get_returns_full_state(self):
        from core.server.routers.verify import get_verify_session
        sess = create_session_from_target("https://h.example/")
        result = _run(get_verify_session(sess.session_id, _=True))
        assert result["session_id"] == sess.session_id
        assert result["allowed_origins"] == ["https://h.example"]
        # Transcript is empty initially.
        assert result["transcript"] == []

    def test_get_unknown_returns_404(self):
        from core.server.routers.verify import get_verify_session
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(get_verify_session("nope", _=True))
        assert ei.value.status_code == 404


# ─────────────────────── VC2: structured exchange endpoint ───────────────────────


class TestExchangeEndpoint:
    """The critical correctness property: scope check happens BEFORE
    any network I/O. Out-of-scope URLs raise structurally — they
    cannot leave the harness."""

    def _patch_httpx(self, monkeypatch, handler):
        """Replace httpx.AsyncClient with one that uses a MockTransport
        for the actual sends. Tests that DON'T set this up should never
        succeed in 'sending' anything — if the scope gate is broken
        and a request slips through, httpx will try to hit the wire
        and that'll be a noisy failure in CI."""
        import httpx
        # We can't easily monkey-patch AsyncClient's __init__ because
        # the handler creates one via `async with`. Instead, patch the
        # transport kwarg on the AsyncClient class default via a
        # subclass. Easier: monkey-patch the module-level AsyncClient.
        original = httpx.AsyncClient

        class _MockedAsyncClient(original):
            def __init__(self, *args, **kwargs):
                # Inject the test's mock transport.
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _MockedAsyncClient)

    def test_in_scope_request_captures_step(self, monkeypatch):
        import httpx
        from core.server.routers.verify import (
            ExchangeRequest, send_exchange,
        )
        from core.verify.console import create_session_from_target, get_session

        observed = {"path": None, "auth": None, "body": None}

        def handler(req: httpx.Request) -> httpx.Response:
            observed["path"] = req.url.path
            observed["auth"] = req.headers.get("authorization")
            observed["body"] = req.content.decode("utf-8") if req.content else ""
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b'{"ok": true, "owner": "alice"}',
            )

        self._patch_httpx(monkeypatch, handler)

        sess = create_session_from_target("https://target.example/")
        sess.persona_name = "alice"
        sess.persona_headers = {"authorization": "Bearer ALICE-TOK"}

        resp = _run(send_exchange(
            sess.session_id,
            ExchangeRequest(
                method="POST",
                url="https://target.example/api/users/1",
                headers={"x-custom": "y"},
                body='{"hello": "world"}',
            ),
            _=True,
        ))

        # Captured step shape.
        assert resp.in_scope is True
        assert resp.transcript_length_after == 1
        step = resp.captured_step
        assert step["method"] == "POST"
        assert step["url"] == "https://target.example/api/users/1"
        assert step["request_body"] == '{"hello": "world"}'
        # Persona auth was applied to the outgoing request.
        assert observed["auth"] == "Bearer ALICE-TOK"
        # Per-request header was also sent (operator override semantics).
        assert step["headers"]["x-custom"] == "y"
        # Response captured.
        assert step["response_status"] == 200
        assert "owner" in step["response_body"]
        # And the session's transcript persists.
        s = get_session(sess.session_id)
        assert len(s.transcript) == 1

    def test_out_of_scope_url_raises_403_BEFORE_network_io(self, monkeypatch):
        """The most critical test. Even if httpx is wired to a panicking
        handler, an out-of-scope request must be rejected without ever
        invoking that handler. We use a handler that asserts False to
        make sure no network call sneaks through."""
        import httpx
        from core.server.routers.verify import (
            ExchangeRequest, send_exchange,
        )
        from core.verify.console import create_session_from_target

        def explosive_handler(req):
            raise AssertionError(
                "SCOPE GATE BROKEN: an out-of-scope request reached the "
                f"transport. URL was {req.url}. This is a critical bug."
            )

        self._patch_httpx(monkeypatch, explosive_handler)

        sess = create_session_from_target("https://target.example/")

        # Try to send to a DIFFERENT host. Must be rejected before any
        # network I/O — explosive_handler should NEVER fire.
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(send_exchange(
                sess.session_id,
                ExchangeRequest(
                    method="GET",
                    url="https://other.example/api/x",
                ),
                _=True,
            ))
        # 403 (forbidden by policy), NOT 400 (malformed input).
        assert ei.value.status_code == 403
        # Detail surfaces the rejection + the allowlist so the UI can
        # offer "add to scope?".
        assert ei.value.detail["code"] == "out_of_scope"
        assert ei.value.detail["rejected_url"] == "https://other.example/api/x"
        assert "https://target.example" in ei.value.detail["allowed_origins"]

    def test_per_request_header_overrides_persona_auth(self, monkeypatch):
        """Operator override: when they want to test with a DIFFERENT
        auth than the session's persona (e.g. testing 'what if I send
        the wrong token'), the per-request header wins."""
        import httpx
        from core.server.routers.verify import (
            ExchangeRequest, send_exchange,
        )
        from core.verify.console import create_session_from_target

        observed_auth = []

        def handler(req):
            observed_auth.append(req.headers.get("authorization"))
            return httpx.Response(200, content=b"")

        self._patch_httpx(monkeypatch, handler)

        sess = create_session_from_target("https://target.example/")
        sess.persona_headers = {"authorization": "Bearer ALICE-TOK"}

        _run(send_exchange(
            sess.session_id,
            ExchangeRequest(
                method="GET",
                url="https://target.example/api/x",
                # Operator explicitly overrides.
                headers={"Authorization": "Bearer DIFFERENT-TOK"},
            ),
            _=True,
        ))
        # Per-request header won.
        assert observed_auth == ["Bearer DIFFERENT-TOK"]

    def test_persona_cookies_become_cookie_header(self, monkeypatch):
        import httpx
        from core.server.routers.verify import (
            ExchangeRequest, send_exchange,
        )
        from core.verify.console import create_session_from_target

        observed_cookie = []

        def handler(req):
            observed_cookie.append(req.headers.get("cookie"))
            return httpx.Response(200, content=b"")

        self._patch_httpx(monkeypatch, handler)

        sess = create_session_from_target("https://target.example/")
        sess.persona_cookies = {"sid": "abc123", "csrf": "xyz"}

        _run(send_exchange(
            sess.session_id,
            ExchangeRequest(
                method="GET",
                url="https://target.example/api/x",
            ),
            _=True,
        ))
        # Both cookies appear in the encoded header.
        cookie = observed_cookie[0] or ""
        assert "sid=abc123" in cookie
        assert "csrf=xyz" in cookie

    def test_unknown_session_returns_404(self, monkeypatch):
        from core.server.routers.verify import (
            ExchangeRequest, send_exchange,
        )
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(send_exchange(
                "no-such-session",
                ExchangeRequest(method="GET", url="https://h.example/"),
                _=True,
            ))
        assert ei.value.status_code == 404

    def test_network_error_captured_as_status_zero_step(self, monkeypatch):
        """A connection error is captured as a step (status=0) and
        appended to the transcript — same convention as the Phase 4
        replay engine. The operator wants to see what they sent even
        if it failed; the request still happened (briefly)."""
        import httpx
        from core.server.routers.verify import (
            ExchangeRequest, send_exchange,
        )
        from core.verify.console import create_session_from_target

        def boom(req):
            raise httpx.ConnectError("simulated network failure")

        self._patch_httpx(monkeypatch, boom)

        sess = create_session_from_target("https://target.example/")
        resp = _run(send_exchange(
            sess.session_id,
            ExchangeRequest(
                method="GET",
                url="https://target.example/down",
            ),
            _=True,
        ))
        step = resp.captured_step
        assert step["response_status"] == 0
        assert "verify-error" in step["response_body"]
        # Still appended to transcript.
        assert resp.transcript_length_after == 1

    def test_multiple_exchanges_accumulate_in_transcript(self, monkeypatch):
        import httpx
        from core.server.routers.verify import (
            ExchangeRequest, send_exchange,
        )
        from core.verify.console import create_session_from_target, get_session

        def handler(req):
            return httpx.Response(
                200, content=f"resp for {req.url.path}".encode()
            )

        self._patch_httpx(monkeypatch, handler)

        sess = create_session_from_target("https://target.example/")
        for i in range(3):
            _run(send_exchange(
                sess.session_id,
                ExchangeRequest(
                    method="GET",
                    url=f"https://target.example/step{i}",
                ),
                _=True,
            ))
        s = get_session(sess.session_id)
        assert len(s.transcript) == 3
        # And they're in order.
        assert s.transcript[0].url.endswith("/step0")
        assert s.transcript[2].url.endswith("/step2")
