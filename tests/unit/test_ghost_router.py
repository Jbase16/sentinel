"""
Phase 4-G1 wiring tests for core/server/routers/ghost.py.

Before this commit, the Ghost router was 100% stubs (`_ghost_process = None`)
and there was no way for an operator to actually start/stop the proxy from
the API. Now the router wires the real `GhostInterceptor` from
core/ghost/proxy.py.

These tests use the same pattern as test_verify_endpoint.py — direct route-
handler calls with monkeypatched deps — because the project doesn't use
FastAPI's TestClient anywhere (verified by grep). The auth dependency is
satisfied by passing `_=True` explicitly (the dep is unused at runtime).

We monkeypatch `GhostInterceptor` so we don't actually start mitmproxy in
CI (mitmproxy has its own loop affinity and side effects we don't want
in a unit test). The substitute records calls + tracks lifecycle state.
"""
from __future__ import annotations

import asyncio
from typing import Optional
import pytest

from core.server.routers import ghost as ghost_router


def _run(coro):
    return asyncio.run(coro)


# ───────────────────────── fixtures / fakes ─────────────────────────


class _FakeInterceptor:
    """Stand-in for core.ghost.proxy.GhostInterceptor.

    Records every lifecycle call. Mimics the real shape so the router
    can read .port + .stop() + ._task without crashing."""

    instances_created = []  # class-level tally for assertions

    def __init__(self, session, port: int = 0):
        self.session = session
        # If port==0, simulate "OS picked a free one" — mitmproxy would
        # return the actual bound port; we fake 31337 to match the
        # real-port-can-differ-from-requested-port contract.
        self.port = port if port > 0 else 31337
        self.start_called = False
        self.stop_called = False
        self._task = None
        _FakeInterceptor.instances_created.append(self)

    async def start(self):
        self.start_called = True
        # Simulate a real long-running task (the addon's HTTP loop). We
        # make a task that just sleeps a beat so router's
        # `await asyncio.wait_for(task, ...)` has something to shield.
        async def _idle():
            await asyncio.sleep(60)
        self._task = asyncio.create_task(_idle())

    def stop(self):
        self.stop_called = True
        if self._task is not None and not self._task.done():
            self._task.cancel()


@pytest.fixture(autouse=True)
def _reset_router_globals(monkeypatch):
    """Ghost router state is module-global by design (one Ghost per
    process). Reset between tests so they don't poison each other."""
    monkeypatch.setattr(ghost_router, "_INTERCEPTOR", None)
    monkeypatch.setattr(ghost_router, "_GHOST_SESSION", None)
    monkeypatch.setattr(ghost_router, "_RECORDING_FLOW_IDS", {})
    # Also reset the FlowMapper singleton — its state leaks across tests.
    from core.ghost.flow import FlowMapper
    FlowMapper._instance = None
    _FakeInterceptor.instances_created.clear()
    yield


@pytest.fixture
def patched_interceptor(monkeypatch):
    """Replace the real GhostInterceptor import inside the router with
    our fake. We patch the import path the router uses (lazy import
    inside start_ghost), not the source module — monkeypatching
    `core.ghost.proxy.GhostInterceptor` would miss the lazy reload."""
    import core.ghost.proxy as proxy_mod
    monkeypatch.setattr(proxy_mod, "GhostInterceptor", _FakeInterceptor)
    return _FakeInterceptor


# ───────────────────────── start_ghost ─────────────────────────


def test_start_ghost_returns_real_port_and_running_status(patched_interceptor):
    resp = _run(ghost_router.start_ghost(port=8080, _=True))
    assert resp.status == "running"
    # Whatever port we asked for, the response surfaces what GhostInterceptor
    # ACTUALLY bound (the contract our fake honors via port=8080→port=8080).
    assert resp.port == 8080
    assert "127.0.0.1:8080" in resp.message
    # Only one interceptor created — module state is single-instance.
    assert len(_FakeInterceptor.instances_created) == 1
    # The interceptor was actually started (not just instantiated).
    assert _FakeInterceptor.instances_created[0].start_called is True


def test_start_ghost_picks_free_port_when_zero(patched_interceptor):
    resp = _run(ghost_router.start_ghost(port=0, _=True))
    # Fake reports 31337 for port=0 (the "OS picked one" sentinel).
    # The contract that matters: the router returns SOMETHING > 0 so
    # the operator's UI can show it.
    assert resp.port > 0
    assert resp.status == "running"


def test_start_ghost_is_idempotent_no_409_on_double_start(patched_interceptor):
    """Operator UX: clicking 'start' twice must NOT error.

    The old stub used to raise 409. Real systems should treat 'already
    running' as success-with-warning, not failure — otherwise every UI
    has to model 'is it running yet?' state which is fragile."""
    first = _run(ghost_router.start_ghost(port=8080, _=True))
    second = _run(ghost_router.start_ghost(port=8080, _=True))
    assert first.status == "running"
    assert second.status == "already_running"
    # And only ONE interceptor was created, not two.
    assert len(_FakeInterceptor.instances_created) == 1


def test_start_ghost_rolls_back_session_ghost_handle_on_failure(monkeypatch):
    """If GhostInterceptor.start() raises, session.ghost must be
    cleared — otherwise the addon would dangle pointing at a half-dead
    interceptor. Regression guard."""
    class _AngryInterceptor:
        def __init__(self, session, port):
            self.session = session
            self.port = port if port > 0 else 31337
            self._task = None
        async def start(self):
            raise RuntimeError("simulated boot failure")
        def stop(self):
            pass

    import core.ghost.proxy as proxy_mod
    monkeypatch.setattr(proxy_mod, "GhostInterceptor", _AngryInterceptor)

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        _run(ghost_router.start_ghost(port=8080, _=True))
    assert exc_info.value.status_code == 500
    assert "simulated boot failure" in exc_info.value.detail
    # Session was created; its .ghost handle must NOT be dangling.
    sess = ghost_router._GHOST_SESSION
    if sess is not None:
        assert getattr(sess, "ghost", None) is None


# ───────────────────────── stop_ghost ─────────────────────────


def test_stop_ghost_when_not_running_is_not_error(patched_interceptor):
    resp = _run(ghost_router.stop_ghost(_=True))
    # Not running → status='not_running', NOT a 4xx/5xx.
    assert resp.status == "not_running"


def test_stop_ghost_clears_state_and_calls_interceptor_stop(patched_interceptor):
    _run(ghost_router.start_ghost(port=8080, _=True))
    interceptor = _FakeInterceptor.instances_created[0]
    resp = _run(ghost_router.stop_ghost(_=True))
    assert resp.status == "stopped"
    assert interceptor.stop_called is True
    # Router state cleared.
    assert ghost_router._INTERCEPTOR is None
    # But the session SURVIVES — operator may want to inspect findings
    # after stopping. The contract is 'preserved' (see message).
    assert "preserved" in resp.message.lower()


# ───────────────────────── status ─────────────────────────


def test_status_when_idle_reports_not_running(patched_interceptor):
    resp = _run(ghost_router.get_ghost_status(_=True))
    assert resp.running is False
    assert resp.port is None
    assert resp.flow_count == 0
    assert resp.active_recordings == []


def test_status_when_running_reports_real_port_and_session_id(patched_interceptor):
    _run(ghost_router.start_ghost(port=8080, _=True))
    resp = _run(ghost_router.get_ghost_status(_=True))
    assert resp.running is True
    assert resp.port == 8080
    assert resp.session_id is not None
    assert len(resp.session_id) > 0


def test_status_reports_active_recordings(patched_interceptor):
    _run(ghost_router.start_ghost(port=8080, _=True))
    _run(ghost_router.start_ghost_recording("checkout-flow", _=True))
    _run(ghost_router.start_ghost_recording("admin-flow", _=True))
    resp = _run(ghost_router.get_ghost_status(_=True))
    assert "checkout-flow" in resp.active_recordings
    assert "admin-flow" in resp.active_recordings
    assert resp.flow_count == 2


# ───────────────────────── flow recording ─────────────────────────


def test_recording_blocked_when_proxy_not_running(patched_interceptor):
    """If the proxy isn't up, recording is meaningless — there's no
    traffic to record. Must 409 with a clear hint."""
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        _run(ghost_router.start_ghost_recording("never-runs", _=True))
    assert exc_info.value.status_code == 409
    assert "POST /v1/ghost/start" in exc_info.value.detail


def test_recording_creates_flow_id_in_FlowMapper(patched_interceptor):
    _run(ghost_router.start_ghost(port=8080, _=True))
    resp = _run(ghost_router.start_ghost_recording("checkout-flow", _=True))
    assert resp.status == "recording"
    assert resp.flow_name == "checkout-flow"
    assert resp.flow_id is not None
    # The flow must actually exist in FlowMapper now.
    from core.ghost.flow import FlowMapper
    fm = FlowMapper.instance()
    assert resp.flow_id in fm.active_flows
    assert fm.active_flows[resp.flow_id].name == "checkout-flow"


def test_recording_idempotent_on_same_name(patched_interceptor):
    _run(ghost_router.start_ghost(port=8080, _=True))
    first = _run(ghost_router.start_ghost_recording("dup", _=True))
    second = _run(ghost_router.start_ghost_recording("dup", _=True))
    assert second.status == "already_recording"
    assert second.flow_id == first.flow_id


def test_stop_recording_reports_step_count(patched_interceptor):
    _run(ghost_router.start_ghost(port=8080, _=True))
    start = _run(ghost_router.start_ghost_recording("checkout-flow", _=True))

    # Simulate the addon recording some steps into the flow.
    from core.ghost.flow import FlowMapper
    fm = FlowMapper.instance()
    fm.record_request(start.flow_id, "GET", "http://t/a", {}, {})
    fm.record_request(start.flow_id, "POST", "http://t/b", {"x": 1}, {})

    resp = _run(ghost_router.stop_ghost_recording("checkout-flow", _=True))
    assert resp.status == "stopped"
    assert resp.step_count == 2
    # And the flow_name is no longer in the active-recordings list.
    assert "checkout-flow" not in ghost_router._RECORDING_FLOW_IDS


def test_stop_recording_unknown_name_returns_404(patched_interceptor):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        _run(ghost_router.stop_ghost_recording("never-existed", _=True))
    assert exc_info.value.status_code == 404


# ───────────────────────── flow listing/detail ─────────────────────────


def test_list_flows_returns_summaries(patched_interceptor):
    _run(ghost_router.start_ghost(port=8080, _=True))
    a = _run(ghost_router.start_ghost_recording("alpha", _=True))
    b = _run(ghost_router.start_ghost_recording("beta", _=True))

    from core.ghost.flow import FlowMapper
    fm = FlowMapper.instance()
    fm.record_request(a.flow_id, "GET", "http://t/1", {}, {"Authorization": "Bearer X"})
    fm.record_request(b.flow_id, "POST", "http://t/2", {}, {})

    flows = _run(ghost_router.list_flows(_=True))
    names = {f.name for f in flows}
    assert names >= {"alpha", "beta"}
    # alpha had an Authorization header → has_auth_tokens=True.
    alpha = next(f for f in flows if f.name == "alpha")
    assert alpha.has_auth_tokens is True
    assert alpha.step_count == 1
    # beta had no auth headers.
    beta = next(f for f in flows if f.name == "beta")
    assert beta.has_auth_tokens is False


def test_get_flow_detail_returns_step_data(patched_interceptor):
    _run(ghost_router.start_ghost(port=8080, _=True))
    rec = _run(ghost_router.start_ghost_recording("test-flow", _=True))

    from core.ghost.flow import FlowMapper
    fm = FlowMapper.instance()
    fm.record_request(rec.flow_id, "GET", "http://t/a", {"id": "1"}, {})
    fm.record_request(rec.flow_id, "POST", "http://t/b", {}, {"Cookie": "sid=abc"})

    detail = _run(ghost_router.get_flow_detail(rec.flow_id, _=True))
    assert detail["flow_id"] == rec.flow_id
    assert detail["name"] == "test-flow"
    assert detail["step_count"] == 2
    assert len(detail["steps"]) == 2
    assert detail["steps"][0]["method"] == "GET"
    assert detail["steps"][0]["params"] == {"id": "1"}
    assert detail["steps"][1]["headers"].get("Cookie") == "sid=abc"


def test_get_flow_detail_unknown_id_returns_404(patched_interceptor):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        _run(ghost_router.get_flow_detail("no-such-flow-id", _=True))
    assert exc_info.value.status_code == 404


# ───────────────────────── CA cert endpoint ─────────────────────────


def test_get_cert_returns_404_when_proxy_never_started(monkeypatch, patched_interceptor):
    """If mitmproxy has never run, the CA cert doesn't exist yet. 404
    with a hint telling the operator to start the proxy first."""
    # Force the cert-path lookup to return None.
    monkeypatch.setattr(ghost_router, "_mitmproxy_cert_path", lambda: None)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        _run(ghost_router.get_ca_cert(_=True))
    assert exc_info.value.status_code == 404
    assert "POST /v1/ghost/start" in exc_info.value.detail


def test_get_cert_serves_file_when_available(monkeypatch, patched_interceptor, tmp_path):
    """When mitmproxy has generated the cert, /cert serves it as a
    downloadable PEM file."""
    fake_cert = tmp_path / "mitmproxy-ca-cert.pem"
    fake_cert.write_text("-----BEGIN CERTIFICATE-----\nFAKECONTENT\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(ghost_router, "_mitmproxy_cert_path", lambda: fake_cert)
    resp = _run(ghost_router.get_ca_cert(_=True))
    # FileResponse is the return type — check it points at our file.
    from fastapi.responses import FileResponse
    assert isinstance(resp, FileResponse)
    assert resp.path == str(fake_cert)
    assert resp.media_type == "application/x-pem-file"
