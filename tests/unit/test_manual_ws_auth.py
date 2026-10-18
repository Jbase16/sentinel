"""The manual WebSocket probe must not print its authentication token."""

import importlib.util
from io import StringIO
from pathlib import Path

import pytest


@pytest.mark.parametrize("fails", [False, True])
async def test_manual_probe_keeps_token_out_of_url_and_output(monkeypatch, capsys, fails):
    path = Path(__file__).resolve().parents[1] / "manual" / "test_ws_auth.py"
    spec = importlib.util.spec_from_file_location("manual_ws_auth", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    token = "top-secret-token"
    monkeypatch.setattr(module.os.path, "exists", lambda _: True)
    monkeypatch.setattr(module, "open", lambda *args, **kwargs: StringIO(token), raising=False)

    class FakeWebSocket:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def close(self):
            pass

    calls = []

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        def ws_connect(self, url, headers):
            calls.append((url, headers))
            if fails:
                raise RuntimeError(f"secret={token}")
            return FakeWebSocket()

    monkeypatch.setattr(module.aiohttp, "ClientSession", FakeSession)
    await module.test_connect()

    assert calls == [
        ("ws://127.0.0.1:8765/v1/ws/events", {"Authorization": f"Bearer {token}"})
    ]
    assert token not in capsys.readouterr().out
