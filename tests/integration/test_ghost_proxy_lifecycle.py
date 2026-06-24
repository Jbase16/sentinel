"""
Integration test: Ghost proxy lifecycle — the port MUST be released on stop.

REGRESSION GUARD for the zombie-listener bug:
    GhostInterceptor.stop() used to call master.shutdown() then immediately
    task.cancel(), cancelling the run task before mitmproxy finished closing
    its listening socket. In mitmproxy 12 the socket is owned by the
    proxyserver addon and is NOT freed just by the master exiting — so every
    Start/Stop leaked a listener that still accepted connections but RESET
    every upstream TLS handshake (SSL_ERROR_SYSCALL). A capture browser
    pointed at such a zombie loaded nothing / rendered a dead page.

These tests assert that after stop():
    1. the port is RELEASED (no leaked listener), and
    2. the SAME port can be re-bound immediately (proving a clean release,
       which is also what lets the stable-port capture browser keep working
       across restarts).
"""

import asyncio
import socket

import pytest
from unittest.mock import MagicMock

# A high port unlikely to collide on a dev box or CI runner. We drive the
# interceptor on an EXPLICIT port so the "re-bind same port" assertion is
# deterministic regardless of the stable-default-port availability.
TEST_PORT = 8799


def _is_listening(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


@pytest.mark.asyncio
async def test_ghost_proxy_releases_port_on_stop(monkeypatch):
    """A start/stop cycle must leave the port free and immediately re-usable."""
    from core.ghost import proxy as gp

    # Isolate the interceptor's listener lifecycle from the heavyweight
    # GhostAddon (which pulls in Lazarus / ShadowSpec / reasoning engine).
    # We only care about the proxy server's socket here.
    monkeypatch.setattr(gp, "GhostAddon", lambda session: type("NoopAddon", (), {})())

    session = MagicMock()

    # --- Cycle 1 ---
    interceptor = gp.GhostInterceptor(session, port=TEST_PORT)
    await interceptor.start()
    await asyncio.sleep(0.8)  # let mitmproxy bind the listener
    assert _is_listening(TEST_PORT), "proxy should be listening after start()"

    await interceptor.stop()
    await asyncio.sleep(0.5)
    assert not _is_listening(TEST_PORT), (
        f"port {TEST_PORT} MUST be released after stop() — a leaked listener "
        "is the zombie-proxy bug that reset all TLS and broke captured pages"
    )

    # --- Cycle 2 on the SAME port: only possible if cycle 1 truly released it ---
    interceptor2 = gp.GhostInterceptor(session, port=TEST_PORT)
    await interceptor2.start()
    await asyncio.sleep(0.8)
    assert _is_listening(TEST_PORT), (
        "second start() on the same port failed — the port was not cleanly "
        "released by the first stop()"
    )
    await interceptor2.stop()
    await asyncio.sleep(0.5)
    assert not _is_listening(TEST_PORT), "port must be released after the second stop() too"


@pytest.mark.asyncio
async def test_find_free_port_prefers_stable_default(monkeypatch):
    """_find_free_port() prefers the stable default when it's free.

    The stable port is what lets a capture-browser window (which pins
    --proxy-server at launch) survive proxy restarts instead of being
    orphaned on a fresh random port each time.
    """
    from core.ghost import proxy as gp

    # Only meaningful if the default port happens to be free on this machine.
    if _is_listening(gp.DEFAULT_GHOST_PORT):
        pytest.skip(f"default port {gp.DEFAULT_GHOST_PORT} busy on this host")

    assert gp.GhostInterceptor._find_free_port() == gp.DEFAULT_GHOST_PORT
