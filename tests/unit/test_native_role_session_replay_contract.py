"""Strict native-window session replay contracts for R5C5."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.wraith.bola_replay import ReplayRequest, SNDReplayTransport


ROOT = Path(__file__).resolve().parents[2]
DRIVER_BRIDGE = ROOT / "ui" / "Sources" / "Services" / "DriverBridgeClient.swift"


class _DriverCommandError(RuntimeError):
    pass


def test_python_transport_requests_and_rechecks_exact_native_session(
    monkeypatch,
):
    commands = []

    class NodeManager:
        async def send_command(self, command, *, timeout):
            commands.append((command, timeout))
            return {
                "status": 200,
                "body": '{"state":"active"}',
                "headers": {},
                "session_id": command["args"]["session_id"],
            }

    monkeypatch.setitem(
        sys.modules,
        "core.server.routers.driver",
        SimpleNamespace(
            DriverCommandError=_DriverCommandError,
            node_manager=NodeManager(),
        ),
    )

    async def exercise():
        transport = SNDReplayTransport(
            scope_filter=lambda value: value.startswith(
                "https://roles.example.test/"
            ),
        )
        return await transport.send_bound(
            "persona-owned",
            "native-window-session-1",
            ReplayRequest(
                "POST",
                "https://roles.example.test/api/memberships",
                body='{"member":"owned"}',
            ),
        )

    response = asyncio.run(exercise())

    assert response.response.status == 200
    assert response.persona == "persona-owned"
    assert response.session_id == "native-window-session-1"
    command, timeout = commands[0]
    assert timeout == 30.0
    assert command["command"] == "session_replay"
    assert command["args"]["persona"] == "persona-owned"
    assert command["args"]["session_id"] == "native-window-session-1"
    assert command["args"]["redirect_mode"] == "manual"


def test_python_transport_rejects_missing_native_session_attestation(
    monkeypatch,
):
    class NodeManager:
        async def send_command(self, _command, *, timeout):
            assert timeout == 30.0
            return {"status": 200, "body": "{}", "headers": {}}

    monkeypatch.setitem(
        sys.modules,
        "core.server.routers.driver",
        SimpleNamespace(
            DriverCommandError=_DriverCommandError,
            node_manager=NodeManager(),
        ),
    )
    transport = SNDReplayTransport(
        scope_filter=lambda value: value.startswith(
            "https://roles.example.test/"
        ),
    )

    with pytest.raises(
        _DriverCommandError,
        match="attestation mismatch",
    ):
        asyncio.run(
            transport.send_bound(
                "persona-owned",
                "native-window-session-1",
                ReplayRequest(
                    "GET",
                    "https://roles.example.test/api/memberships/owned",
                ),
            )
        )


def test_swift_session_check_precedes_fetch_and_echoes_actual_session():
    source = DRIVER_BRIDGE.read_text(encoding="utf-8")
    command = source.index('case "session_replay":')
    handler = source.index(
        "requiredSessionId: String? = nil",
        command,
    )
    identity_check = source.index(
        "window.eventSessionId != requiredSessionId",
        handler,
    )
    target_session_ref = source.index(
        'requestHeaders["X-Sentinel-Native-Session-Ref"]',
        identity_check,
    )
    fetch = source.index("await fetch(p.url", target_session_ref)
    attestation = source.index(
        'response["session_id"] = window.eventSessionId',
        fetch,
    )

    assert (
        command
        < handler
        < identity_check
        < target_session_ref
        < fetch
        < attestation
    )
    assert "session-bound replay refused before target dispatch" in source[
        identity_check:fetch
    ]
    assert '"native_session:\\(digest)"' in source[identity_check:fetch]


def test_swift_registry_preserves_distinct_sessions_for_one_persona():
    source = DRIVER_BRIDGE.read_text(encoding="utf-8")
    registry = source.index(
        "private var personaSessionWindows: [String: [String: GhostBrowserWindow]]"
    )
    retain = source.index("private func retainBrowser(for personaId: String)")
    register = source.index(
        "personaSessionWindows[personaId, default: [:]][sessionId] = window",
        retain,
    )
    replay = source.index("private func executeReplay(", register)
    exact_lookup = source.index(
        "personaSessionWindows[persona]?[$0]",
        replay,
    )
    identity_check = source.index(
        "window.eventSessionId != requiredSessionId",
        exact_lookup,
    )
    fetch = source.index("await fetch(p.url", identity_check)

    assert registry < retain < register < replay < exact_lookup < identity_check < fetch
    retain_body = source[retain:replay]
    assert "existing.eventSessionId.isEmpty || window.eventSessionId.isEmpty" in retain_body
