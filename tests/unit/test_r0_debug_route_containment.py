from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest


@pytest.fixture
async def protected_client(monkeypatch):
    from core.server.routers import auth

    config = SimpleNamespace(
        api_host="127.0.0.1",
        security=SimpleNamespace(
            require_auth=True,
            api_token="r0-test-token",
        ),
    )
    monkeypatch.setattr(auth, "get_config", lambda: config)

    from core.server.api import app

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://sentinel.test",
    ) as client:
        yield client


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("GET", "/v1/ping", None),
        ("GET", "/v1/status", None),
        ("GET", "/v1/health", None),
        ("GET", "/health", None),
        (
            "POST",
            "/v1/cortex/analysis/topology",
            {"graph_data": {}},
        ),
        (
            "POST",
            "/v1/cortex/analysis/insights",
            {
                "graph_hash": "local-graph",
                "target_nodes": [],
                "insight_type": "bridge",
                "graph_data": {},
            },
        ),
        (
            "POST",
            "/v1/cortex/reporting/generate",
            {
                "target": "http://owned.local",
                "session_id": "session-a",
            },
        ),
        (
            "GET",
            "/v1/cortex/reporting/poc/finding-a?session_id=session-a",
            None,
        ),
    ],
)
@pytest.mark.asyncio
async def test_sensitive_routes_reject_missing_token(
    protected_client,
    method,
    path,
    payload,
):
    response = await protected_client.request(method, path, json=payload)

    assert response.status_code in {401, 403}, response.text


@pytest.mark.asyncio
async def test_cookie_debug_route_is_gone(protected_client):
    response = await protected_client.get("/v1/test_cookies")

    assert response.status_code == 404

    from core.server.api import app

    assert "/v1/test_cookies" not in {
        getattr(route, "path", None) for route in app.routes
    }


@pytest.mark.asyncio
async def test_ghost_cookie_self_heal_is_quarantined(monkeypatch):
    from core.foundry.driver_native import GhostNativeDriver
    from core.net.ghost_gateway import GhostGatewayTransport

    launch = AsyncMock(side_effect=AssertionError("browser launch must stay quarantined"))
    monkeypatch.setattr(GhostNativeDriver, "launch", launch)

    transport = object.__new__(GhostGatewayTransport)
    healed = await asyncio.wait_for(transport._trigger_self_heal(), timeout=0.1)

    assert healed is False
    launch.assert_not_awaited()


def test_preflight_health_probe_uses_bearer_token(monkeypatch, tmp_path):
    from scripts import preflight

    token_path = tmp_path / "api_token"
    token_path.write_text("local-preflight-token\n", encoding="utf-8")
    monkeypatch.setattr(preflight, "TOKEN_PATH", token_path)

    captured = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"status":"ready"}'

    def fake_urlopen(request, timeout):
        captured["authorization"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        return _Response()

    monkeypatch.setattr(preflight.urllib.request, "urlopen", fake_urlopen)

    result = preflight.check_backend("127.0.0.1", 8765)

    assert result.passed is True
    assert captured == {
        "authorization": "Bearer local-preflight-token",
        "timeout": 2.0,
    }


class _BoundFakeDB:
    def __init__(self):
        self.finding_reads: list[str] = []
        self.sessions = {
            "session-a": {"id": "session-a", "target": "http://a.local"},
            "session-b": {"id": "session-b", "target": "http://b.local"},
        }
        self.findings = {
            "session-a": [],
            "session-b": [{"id": "finding-b", "title": "B-only finding"}],
        }

    async def get_session(self, session_id):
        return self.sessions.get(session_id)

    async def get_findings(self, session_id):
        self.finding_reads.append(session_id)
        return list(self.findings.get(session_id, []))

    async def get_evidence(self, session_id):
        return []


@pytest.fixture(autouse=True)
def isolate_database_singleton(monkeypatch):
    """Keep route-table imports from opening the operator's real test DB."""
    from core.data.db import Database

    fake_db = _BoundFakeDB()
    monkeypatch.setattr(Database, "instance", staticmethod(lambda: fake_db))
    return fake_db


@pytest.mark.asyncio
async def test_report_rejects_target_outside_named_session(
    protected_client,
    monkeypatch,
):
    from core.data.db import Database

    fake_db = _BoundFakeDB()
    monkeypatch.setattr(Database, "instance", staticmethod(lambda: fake_db))

    response = await protected_client.post(
        "/v1/cortex/reporting/generate",
        headers={"Authorization": "Bearer r0-test-token"},
        json={
            "target": "http://b.local",
            "session_id": "session-a",
        },
    )

    assert response.status_code == 403, response.text
    assert fake_db.finding_reads == []


@pytest.mark.asyncio
async def test_poc_cannot_read_finding_from_another_session(
    protected_client,
    monkeypatch,
):
    from core.data.db import Database

    fake_db = _BoundFakeDB()
    monkeypatch.setattr(Database, "instance", staticmethod(lambda: fake_db))

    response = await protected_client.get(
        "/v1/cortex/reporting/poc/finding-b?session_id=session-a",
        headers={"Authorization": "Bearer r0-test-token"},
    )

    assert response.status_code == 404, response.text
    assert fake_db.finding_reads == ["session-a"]
