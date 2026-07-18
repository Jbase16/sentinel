import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.base.config import _SensitiveQueryLoggingFilter
from core.bounty.h1_client import HackerOneClient
from core.errors import ErrorCode, SentinelError
from core.server.routers.scans import ScanRequest, begin_scan_logic
from core.server.state import ApplicationState


@pytest.mark.asyncio
async def test_hackerone_admission_failure_does_not_create_session(monkeypatch):
    monkeypatch.setattr(ApplicationState, "_instance", ApplicationState())
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    monkeypatch.delenv("SENTINEL_H1_TOKEN", raising=False)

    handler_count = len(logging.getLogger().handlers)
    request = ScanRequest(
        target="https://example.test",
        mode="bug_bounty",
        bounty_handle="example-program",
    )

    with patch("core.base.session.ScanSession") as scan_session:
        with pytest.raises(SentinelError) as raised:
            await begin_scan_logic(request)

    assert raised.value.code == ErrorCode.SCAN_TARGET_INVALID
    assert raised.value.http_status == 400
    assert raised.value.details["integration"] == "hackerone"
    scan_session.assert_not_called()
    assert ApplicationState.instance().session_manager == {}
    assert len(logging.getLogger().handlers) == handler_count


def test_hackerone_client_accepts_legacy_ui_token_name(monkeypatch):
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    monkeypatch.setenv("SENTINEL_H1_TOKEN", "legacy-token")

    client = HackerOneClient()

    assert client.api_token == "legacy-token"


def test_sensitive_query_filter_redacts_uvicorn_access_arguments():
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='%s - "%s %s HTTP/%s" %d',
        args=(
            "127.0.0.1:1234",
            "WebSocket",
            "/v1/events?token=super-secret&scan_id=abc",
            "1.1",
            101,
        ),
        exc_info=None,
    )

    assert _SensitiveQueryLoggingFilter().filter(record)
    rendered = record.getMessage()

    assert "super-secret" not in rendered
    assert "token=[REDACTED]" in rendered
    assert "scan_id=abc" in rendered


class _ClosableSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_unregister_session_releases_owned_resources():
    state = ApplicationState()
    session = _ClosableSession()
    await state.register_session("scan-1", session)

    await state.unregister_session("scan-1")

    assert session.closed is True
    assert await state.get_session("scan-1") is None


class _EmptyStore:
    def get_all(self):
        return []


class _FakeScanSession:
    def __init__(self, target):
        self.id = "scan-failed-tools"
        self.target = target
        self.knowledge = {}
        self.findings = _EmptyStore()
        self.issues = _EmptyStore()
        self.status = "created"
        self.end_time = None
        self.logs = []

    def set_external_log_sink(self, _sink):
        return None

    def log(self, line):
        self.logs.append(line)

    def close_log_file(self):
        return None

    def close(self):
        return None

    def to_dict(self):
        return {"id": self.id, "target": self.target, "status": self.status}


class _FailingScannerEngine:
    def __init__(self, session):
        self.session = session

    async def scan(self, *_args, **_kwargs):
        if False:
            yield ""

    def get_last_results(self):
        return []

    def consume_last_tool_error(self):
        return {"tool": "httpx", "exit_code": 7, "stderr": "target unreachable"}


class _FakeEventBus:
    def __init__(self):
        self.events = []

    def emit_scan_started(self, *_args, **_kwargs):
        return None

    def emit_tool_invoked(self, *_args, **_kwargs):
        return None

    def emit_tool_completed(self, *_args, **_kwargs):
        return None

    def emit_scan_completed(self, *_args, **_kwargs):
        return None

    def emit(self, event):
        self.events.append(event)


@pytest.mark.asyncio
async def test_scan_with_only_failed_tools_finishes_as_error(monkeypatch):
    state = ApplicationState()
    monkeypatch.setattr(ApplicationState, "_instance", state)

    database = MagicMock()
    database.init = AsyncMock()
    database.blackbox.enqueue = AsyncMock()
    database.blackbox.flush = AsyncMock()
    monkeypatch.setattr("core.server.routers.scans.Database.instance", lambda: database)
    monkeypatch.setattr("core.base.session.ScanSession", _FakeScanSession)
    monkeypatch.setattr("core.engine.scanner_engine.ScannerEngine", _FailingScannerEngine)
    monkeypatch.setattr("core.toolkit.tools.get_installed_tools", lambda: {"httpx": object()})

    event_bus = _FakeEventBus()
    monkeypatch.setattr("core.cortex.events.get_event_bus", lambda: event_bus)
    monkeypatch.setattr(
        "core.cortex.events.GraphEvent",
        lambda **kwargs: SimpleNamespace(**kwargs),
    )

    async def run_failed_mission(**kwargs):
        with pytest.raises(Exception) as raised:
            await kwargs["dispatch_tool"]("httpx")
        assert getattr(raised.value, "code", None) == ErrorCode.TOOL_EXEC_FAILED
        return None

    monkeypatch.setattr(
        "core.cortex.reasoning.reasoning_engine.start_scan",
        run_failed_mission,
    )

    session_id = await begin_scan_logic(
        ScanRequest(target="http://localhost:9", modules=["httpx"])
    )
    await state.active_scan_task

    session = await state.get_session(session_id)
    assert state.scan_state["status"] == "error"
    assert session.status == "error"
    assert any(
        getattr(event, "payload", {}).get("error_code") == ErrorCode.TOOL_EXEC_FAILED.value
        for event in event_bus.events
    )
