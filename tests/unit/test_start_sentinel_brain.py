"""Local request and bind contracts for the optional brain server."""

import http.client
import json
import sys
import threading
from http.server import HTTPServer
from pathlib import Path
from types import ModuleType

from tools.ops import start_sentinel_brain as brain


def test_brain_uses_root_models_and_loopback_bind():
    assert Path(brain.MODELS_DIR) == Path(__file__).resolve().parents[2] / "models"

    addresses = []

    class CapturingServer:
        def __init__(self, address, handler):
            addresses.append(address)

        def serve_forever(self):
            pass

    brain.run(server_class=CapturingServer, port=0)
    assert addresses == [("127.0.0.1", 0)]


def test_brain_rejects_oversized_body_before_model_load(monkeypatch):
    monkeypatch.setattr(brain, "MAX_BODY_BYTES", 32)

    def fail_model_load():
        raise AssertionError("model loaded")

    monkeypatch.setattr(brain, "ensure_model_loaded", fail_model_load)

    server = HTTPServer(("127.0.0.1", 0), brain.SentinelHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/generate", body=b"x" * 33)
        response = connection.getresponse()
        assert response.status == 413
        response.read()
        connection.close()

        fake_mlx_lm = ModuleType("mlx_lm")
        fake_mlx_lm.generate = lambda *args, **kwargs: "ok"
        monkeypatch.setitem(sys.modules, "mlx_lm", fake_mlx_lm)
        monkeypatch.setattr(brain, "ensure_model_loaded", lambda: None)

        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/generate", body=b'{"prompt":"ok"}')
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["response"] == "ok"
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
