"""Persona-scoped SND capture lifecycle tests."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from core.server.routers import driver

SOURCE_PERSONA_ID = "a" * 32
PEER_PERSONA_ID = "b" * 32


class _Request:
    def __init__(self, body):
        self.body = body

    async def json(self):
        return dict(self.body)


@pytest.fixture(autouse=True)
def _reset_capture_state(monkeypatch):
    driver.ACTIVE_CAPTURE_PATH = None
    driver.ACTIVE_CAPTURE_PERSONA_ID = None
    driver.ACTIVE_CAPTURE_OWNER_ID = None
    driver.ACTIVE_CAPTURE_SESSION_ID = None
    driver._reset_capture_counters()
    monkeypatch.setattr(driver.node_manager, "active_node", object())
    yield
    driver.ACTIVE_CAPTURE_PATH = None
    driver.ACTIVE_CAPTURE_PERSONA_ID = None
    driver.ACTIVE_CAPTURE_OWNER_ID = None
    driver.ACTIVE_CAPTURE_SESSION_ID = None
    driver._reset_capture_counters()


def _event(persona_id: str, marker: str):
    return {
        "event": "recorded_action",
        "action": {
            "action": "network_capture",
            "persona_id": persona_id,
            "url": "/api/private",
            "response_body": marker,
        },
    }


@pytest.mark.asyncio
async def test_driver_websocket_refuses_connection_when_shared_validator_denies(
    monkeypatch,
):
    async def deny(_websocket, endpoint_name):
        assert endpoint_name == "/v1/driver/bridge"
        return False

    async def forbidden(_websocket):
        raise AssertionError("denied WebSocket must not become the active SND node")

    monkeypatch.setattr(driver, "validate_websocket_connection", deny)
    monkeypatch.setattr(driver.node_manager, "connect", forbidden)

    await driver.driver_bridge_endpoint(object())


@pytest.mark.asyncio
async def test_node_command_timeout_is_typed_and_clears_pending_response():
    class _Node:
        async def send_text(self, _payload):
            return None

    manager = driver.NodeManager()
    manager.active_node = _Node()

    with pytest.raises(driver.DriverUnavailable, match="command timed out"):
        await manager.send_command(
            {"request_id": "request", "command": "current_url"},
            timeout=0,
        )

    assert manager.pending_responses == {}


def test_capture_events_are_ignored_without_active_capture(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("inactive capture must not open a file")

    monkeypatch.setattr("builtins.open", forbidden)
    driver._handle_node_event("recorded_action", _event("source", "secret"))


def test_only_active_persona_is_written(tmp_path):
    path = tmp_path / "source.jsonl"
    path.write_text("")
    path.chmod(0o600)
    driver.ACTIVE_CAPTURE_PATH = str(path)
    driver.ACTIVE_CAPTURE_PERSONA_ID = "source"

    driver._handle_node_event("recorded_action", _event("peer", "peer-secret"))
    driver._handle_node_event("recorded_action", _event("source", "source-secret"))

    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["persona_id"] == "source"
    assert records[0]["response_body"] == "source-secret"


def test_capture_nonce_rejects_late_events_and_tracks_current_inflight(tmp_path):
    path = tmp_path / "source.jsonl"
    path.write_text("")
    path.chmod(0o600)
    driver.ACTIVE_CAPTURE_PATH = str(path)
    driver.ACTIVE_CAPTURE_PERSONA_ID = "source"
    driver.ACTIVE_CAPTURE_SESSION_ID = "current-session"

    stale = _event("source", "stale-secret")
    stale["action"]["capture_session"] = "old-session"
    current = _event("source", "current-secret")
    current["action"]["capture_session"] = "current-session"
    driver._handle_node_event(
        "recorded_action",
        {
            "action": {
                "action": "network_activity",
                "persona_id": "source",
                "capture_session": "old-session",
                "phase": "start",
            }
        },
    )
    driver._handle_node_event(
        "recorded_action",
        {
            "action": {
                "action": "network_activity",
                "persona_id": "source",
                "capture_session": "current-session",
                "phase": "start",
            }
        },
    )
    driver._handle_node_event("recorded_action", stale)
    driver._handle_node_event("recorded_action", current)

    assert driver.ACTIVE_CAPTURE_INFLIGHT == 1
    driver._handle_node_event(
        "recorded_action",
        {
            "action": {
                "action": "network_activity",
                "persona_id": "source",
                "capture_session": "current-session",
                "phase": "end",
            }
        },
    )
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert driver.ACTIVE_CAPTURE_INFLIGHT == 0
    assert [record["response_body"] for record in records] == ["current-secret"]
    assert "capture_session" not in records[0]


@pytest.mark.asyncio
async def test_quiescence_waits_until_current_session_has_no_inflight_requests(
    monkeypatch,
):
    sleep_calls = 0

    async def fake_sleep(_seconds):
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 2:
            driver.ACTIVE_CAPTURE_INFLIGHT = 0

    monkeypatch.setattr(driver.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(driver, "_CAPTURE_MIN_SETTLE_SECONDS", 0.0)
    monkeypatch.setattr(driver, "_CAPTURE_QUIET_SECONDS", 0.0)
    monkeypatch.setattr(driver, "_CAPTURE_MAX_SETTLE_SECONDS", 10.0)
    driver.ACTIVE_CAPTURE_LAST_EVENT_AT = driver.time.monotonic()
    driver.ACTIVE_CAPTURE_RECORDS = 1
    driver.ACTIVE_CAPTURE_INFLIGHT = 1

    await driver._wait_for_capture_quiescence()

    assert sleep_calls == 2


def test_capture_event_is_schema_limited_and_marks_truncation(monkeypatch, tmp_path):
    monkeypatch.setattr(driver, "_MAX_CAPTURE_REQUEST_CHARS", 8)
    monkeypatch.setattr(driver, "_MAX_CAPTURE_RESPONSE_CHARS", 10)
    monkeypatch.setattr(driver, "_MAX_CAPTURE_HEADERS", 1)
    path = tmp_path / "source.jsonl"
    path.write_text("")
    path.chmod(0o600)
    driver.ACTIVE_CAPTURE_PATH = str(path)
    driver.ACTIVE_CAPTURE_PERSONA_ID = "source"
    event = _event("source", "response-is-too-long")
    event["action"].update({
        "method": "post",
        "request_body": "request-is-too-long",
        "request_headers": {"x-first": "one", "x-second": "two"},
        "unexpected_secret_field": "must-not-persist",
    })

    driver._handle_node_event("recorded_action", event)

    record = json.loads(path.read_text())
    assert record["method"] == "POST"
    assert record["request_body"] == "request-"
    assert record["response_body"] == "response-i"
    assert record["request_truncated"] is True
    assert record["response_truncated"] is True
    assert list(record["request_headers"]) == ["x-first"]
    assert "unexpected_secret_field" not in record


def test_capture_file_limit_fails_closed_without_partial_record(monkeypatch, tmp_path):
    monkeypatch.setattr(driver, "_MAX_CAPTURE_BYTES", 32)
    path = tmp_path / "source.jsonl"
    path.write_text("")
    driver.ACTIVE_CAPTURE_PATH = str(path)
    driver.ACTIVE_CAPTURE_PERSONA_ID = "source"

    driver._handle_node_event("recorded_action", _event("source", "too-large"))

    assert path.read_text() == ""
    assert driver.ACTIVE_CAPTURE_RECORDS == 0
    assert driver.ACTIVE_CAPTURE_BYTES == 0
    assert driver.ACTIVE_CAPTURE_LIMIT_REACHED is True


def test_capture_file_mutation_fails_closed_before_append(tmp_path):
    path = tmp_path / "source.jsonl"
    path.write_text("tampered")
    path.chmod(0o600)
    driver.ACTIVE_CAPTURE_PATH = str(path)
    driver.ACTIVE_CAPTURE_PERSONA_ID = "source"

    driver._handle_node_event("recorded_action", _event("source", "secret"))

    assert path.read_text() == "tampered"
    assert driver.ACTIVE_CAPTURE_RECORDS == 0
    assert driver.ACTIVE_CAPTURE_WRITE_FAILED is True


@pytest.mark.asyncio
async def test_persona_capture_routes_commands_without_launching_generic_window(
    monkeypatch, tmp_path
):
    calls = []

    async def send_command(payload, timeout=30.0):
        calls.append((payload, timeout))
        return "ok"

    monkeypatch.setattr(driver.node_manager, "send_command", send_command)
    capture_store = tmp_path / "captures"
    monkeypatch.setenv("SENTINELFORGE_CAPTURE_STORE", str(capture_store))
    result = await driver.start_capture(_Request({
        "url": "https://api.example.test/app",
        "persona_id": SOURCE_PERSONA_ID,
    }), _=True)

    path = Path(result["capture_file"])
    assert result == {
        "status": "ok",
        "persona_id": SOURCE_PERSONA_ID,
        "capture_file": str(path),
    }
    assert path.read_text() == ""
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert driver.ACTIVE_CAPTURE_PATH == str(path)
    assert driver.ACTIVE_CAPTURE_PERSONA_ID == SOURCE_PERSONA_ID
    assert driver.ACTIVE_CAPTURE_SESSION_ID
    commands = [payload["command"] for payload, _ in calls]
    assert commands == ["start_network_capture", "navigate"]
    assert all(payload["args"]["persona"] == SOURCE_PERSONA_ID for payload, _ in calls)
    assert calls[0][0]["args"]["capture_session"] == driver.ACTIVE_CAPTURE_SESSION_ID

    stopped = await driver.stop_capture(_=True)
    assert stopped == {
        "status": "ok",
        "records": 0,
        "bytes": 0,
        "limit_reached": False,
    }
    assert calls[-1][0]["command"] == "stop_network_capture"
    assert driver.ACTIVE_CAPTURE_PATH is None
    assert driver.ACTIVE_CAPTURE_PERSONA_ID is None
    assert driver.ACTIVE_CAPTURE_SESSION_ID is None


@pytest.mark.asyncio
async def test_failed_capture_start_resets_global_state(monkeypatch, tmp_path):
    from fastapi import HTTPException

    async def fail(_payload, timeout=30.0):
        raise RuntimeError("persona window missing")

    monkeypatch.setattr(driver.node_manager, "send_command", fail)
    capture_store = tmp_path / "captures"
    monkeypatch.setenv("SENTINELFORGE_CAPTURE_STORE", str(capture_store))
    with pytest.raises(HTTPException) as error:
        await driver.start_capture(_Request({
            "url": "https://api.example.test/app",
            "persona_id": SOURCE_PERSONA_ID,
        }), _=True)

    assert error.value.status_code == 503
    assert "persona window missing" in error.value.detail
    assert driver.ACTIVE_CAPTURE_PATH is None
    assert driver.ACTIVE_CAPTURE_PERSONA_ID is None
    assert not list(capture_store.glob("*.jsonl"))


@pytest.mark.asyncio
async def test_failed_navigation_stops_installed_capture_hook(monkeypatch, tmp_path):
    from fastapi import HTTPException

    commands = []

    async def send_command(payload, timeout=30.0):
        commands.append(payload["command"])
        if payload["command"] == "navigate":
            raise RuntimeError("navigation failed")
        return "ok"

    monkeypatch.setattr(driver.node_manager, "send_command", send_command)
    capture_store = tmp_path / "captures"
    monkeypatch.setenv("SENTINELFORGE_CAPTURE_STORE", str(capture_store))

    with pytest.raises(HTTPException) as error:
        await driver.start_capture(_Request({
            "url": "https://api.example.test/app",
            "persona_id": SOURCE_PERSONA_ID,
        }), _=True)

    assert error.value.status_code == 503
    assert commands == ["start_network_capture", "navigate", "stop_network_capture"]
    assert driver.ACTIVE_CAPTURE_PATH is None
    assert driver.ACTIVE_CAPTURE_PERSONA_ID is None
    assert not list(capture_store.glob("*.jsonl"))


@pytest.mark.asyncio
async def test_capture_path_is_backend_allocated_and_client_path_is_ignored(
    monkeypatch, tmp_path
):
    async def send_command(_payload, timeout=30.0):
        return "ok"

    monkeypatch.setattr(driver.node_manager, "send_command", send_command)
    capture_store = tmp_path / "captures"
    outside = tmp_path / "must-not-be-truncated.txt"
    outside.write_text("preserve me")
    monkeypatch.setenv("SENTINELFORGE_CAPTURE_STORE", str(capture_store))

    result = await driver.start_capture(_Request({
        "url": "https://api.example.test/app",
        "persona_id": SOURCE_PERSONA_ID,
        "capture_file": str(outside),
    }), _=True)

    assert outside.read_text() == "preserve me"
    assert Path(result["capture_file"]).parent == capture_store
    await driver.stop_capture(_=True)


@pytest.mark.asyncio
async def test_non_http_capture_url_is_rejected_before_driver_or_filesystem(
    monkeypatch, tmp_path
):
    from fastapi import HTTPException

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("invalid URL must not reach the driver")

    monkeypatch.setattr(driver.node_manager, "send_command", forbidden)
    capture_store = tmp_path / "captures"
    monkeypatch.setenv("SENTINELFORGE_CAPTURE_STORE", str(capture_store))

    with pytest.raises(HTTPException) as error:
        await driver.start_capture(_Request({
            "url": "file:///etc/passwd",
            "persona_id": SOURCE_PERSONA_ID,
        }), _=True)

    assert error.value.status_code == 400
    assert not capture_store.exists()


@pytest.mark.parametrize(
    "url",
    (
        "https://example.test:invalid/path",
        "https://example.test:0/path",
        "https://example.test/path with space",
        "https://example.test/path\u00a0with-space",
        "https://example.test\\@other.example/path",
        "https://user:password@example.test/path",
    ),
)
def test_capture_url_rejects_ambiguous_or_credentialed_authorities(url):
    with pytest.raises(ValueError):
        driver.validate_capture_url(url)


@pytest.mark.asyncio
async def test_paired_capture_is_sequential_persona_isolated_and_exclusive(
    monkeypatch, tmp_path
):
    calls = []

    async def send_command(payload, timeout=30.0):
        calls.append((payload, timeout))
        command = payload["command"]
        if command == "navigate":
            persona_id = payload["args"]["persona"]
            driver._handle_node_event(
                "recorded_action",
                {
                    "event": "recorded_action",
                    "action": {
                        "action": "network_capture",
                        "persona_id": persona_id,
                        "capture_session": driver.ACTIVE_CAPTURE_SESSION_ID,
                        "type": "navigation",
                        "url": payload["args"]["url"],
                        "response_status": 200,
                        "response_body": f"private-{persona_id}",
                    },
                },
            )
        if command == "script_resource_urls":
            return ["https://api.example.test/assets/app.js"]
        return "ok"

    monkeypatch.setattr(driver.node_manager, "send_command", send_command)
    monkeypatch.setattr(driver, "_CAPTURE_MIN_SETTLE_SECONDS", 0.0)
    monkeypatch.setattr(driver, "_CAPTURE_QUIET_SECONDS", 0.0)
    monkeypatch.setattr(driver, "_CAPTURE_MAX_SETTLE_SECONDS", 0.2)
    capture_store = tmp_path / "captures"
    monkeypatch.setenv("SENTINELFORGE_CAPTURE_STORE", str(capture_store))

    source, peer, script_urls = await driver.capture_persona_pair(
        target_url="https://api.example.test/app",
        source_persona_id=SOURCE_PERSONA_ID,
        peer_persona_id=PEER_PERSONA_ID,
    )

    assert [payload["command"] for payload, _ in calls] == [
        "validate_persona_windows",
        "start_network_capture",
        "navigate",
        "stop_network_capture",
        "start_network_capture",
        "navigate",
        "stop_network_capture",
        "script_resource_urls",
    ]
    capture_sessions = [
        payload["args"]["capture_session"]
        for payload, _ in calls
        if payload["command"] == "start_network_capture"
    ]
    assert len(capture_sessions) == len(set(capture_sessions)) == 2
    assert source.persona_id == SOURCE_PERSONA_ID
    assert peer.persona_id == PEER_PERSONA_ID
    assert source.records[0]["persona_id"] == SOURCE_PERSONA_ID
    assert peer.records[0]["persona_id"] == PEER_PERSONA_ID
    assert PEER_PERSONA_ID not in source.records[0]["response_body"]
    assert SOURCE_PERSONA_ID not in peer.records[0]["response_body"]
    assert stat.S_IMODE(Path(source.path).stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(peer.path).stat().st_mode) == 0o600
    assert script_urls == ("https://api.example.test/assets/app.js",)
    assert driver.ACTIVE_CAPTURE_OWNER_ID is None


@pytest.mark.asyncio
async def test_paired_capture_missing_window_fails_before_navigation_or_file(
    monkeypatch, tmp_path
):
    calls = []

    async def send_command(payload, timeout=30.0):
        calls.append(payload["command"])
        raise driver.DriverCommandError("peer window missing")

    monkeypatch.setattr(driver.node_manager, "send_command", send_command)
    capture_store = tmp_path / "captures"
    monkeypatch.setenv("SENTINELFORGE_CAPTURE_STORE", str(capture_store))

    with pytest.raises(driver.PersonaWindowUnavailable, match="peer window missing"):
        await driver.capture_persona_pair(
            target_url="https://api.example.test/app",
            source_persona_id=SOURCE_PERSONA_ID,
            peer_persona_id=PEER_PERSONA_ID,
        )

    assert calls == ["validate_persona_windows"]
    assert not capture_store.exists()
    assert driver.ACTIVE_CAPTURE_OWNER_ID is None


@pytest.mark.asyncio
async def test_manual_stop_cannot_release_capture_while_start_is_pending():
    from fastapi import HTTPException

    driver.ACTIVE_CAPTURE_OWNER_ID = "manual:pending"

    with pytest.raises(HTTPException) as error:
        await driver.stop_capture(_=True)

    assert error.value.status_code == 409
    assert error.value.detail == "capture is still starting"
    assert driver.ACTIVE_CAPTURE_OWNER_ID == "manual:pending"
