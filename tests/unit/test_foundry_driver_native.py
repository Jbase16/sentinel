from __future__ import annotations

import asyncio


def test_native_driver_close_sends_once_before_marking_closed(monkeypatch):
    from core.foundry.driver_native import GhostNativeDriver
    from core.server.routers import driver as driver_router

    sent = []

    async def send_command(payload, *, timeout):
        sent.append((payload, timeout))
        return "ok"

    monkeypatch.setattr(driver_router.node_manager, "send_command", send_command)
    native = GhostNativeDriver("session-1")

    asyncio.run(native.close())
    asyncio.run(native.close())

    assert len(sent) == 1
    assert sent[0][0]["command"] == "close"
    assert sent[0][0]["session_id"] == "session-1"
    assert native._is_closed is True


def test_retained_native_driver_transfers_ownership_without_closing(monkeypatch):
    from core.foundry.driver_native import GhostNativeDriver
    from core.server.routers import driver as driver_router

    sent = []

    async def send_command(payload, *, timeout):
        sent.append((payload, timeout))
        return "ok"

    monkeypatch.setattr(driver_router.node_manager, "send_command", send_command)
    native = GhostNativeDriver("session-2")

    asyncio.run(native.retain_for_persona("persona-2"))
    asyncio.run(native.close())

    assert [item[0]["command"] for item in sent] == ["retain_for_persona"]
    assert sent[0][0]["args"] == {"persona_id": "persona-2"}
    assert native._retained_for_persona is True
