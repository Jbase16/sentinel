"""
Unit tests for the autonomous business-logic orchestrator (core/wraith/logic_probe).

Drives the full loop against a mock app: learn an object schema from a GET,
resolve its foreign-key references, create an object we own, then confirm an
invariant violation on its update endpoint.
"""

from urllib.parse import urlparse

import pytest

from core.wraith import logic_probe as lp


def _mock_app(trusted_fields):
    """A tiny REST app. /api/Things has an OwnerId reference (resolved via
    /api/Owners) and a quantity. PUT persists only `trusted_fields` as-given."""
    state = {"next_id": 100}

    async def request(method, url, body=None):
        path = urlparse(url).path
        if method == "GET" and path == "/api/Things":
            return 200, {"data": [{"id": 1, "OwnerId": 7, "quantity": 1, "name": "x"}]}
        if method == "GET" and path == "/api/Owners":
            return 200, {"data": [{"id": 7}]}
        if method == "POST" and path == "/api/Things":
            oid = state["next_id"]; state["next_id"] += 1
            return 201, {"data": {"id": oid, **(body or {})}}
        if method == "PUT" and path.startswith("/api/Things/"):
            out = {k: (v if k in trusted_fields else 1) for k, v in (body or {}).items()}
            return 200, {"data": out}
        return 404, {}

    return request


@pytest.mark.asyncio
async def test_full_loop_finds_trusted_quantity():
    findings = await lp.probe_business_logic(
        "http://h.test", _mock_app({"quantity"}), ["/api/Things"],
    )
    assert len(findings) == 1
    f = findings[0]["metadata"]
    assert f["field"] == "quantity" and f["vuln_class"] == "business_logic"
    assert "/api/Things/100" in findings[0]["target"]   # probed the created object


@pytest.mark.asyncio
async def test_no_flaw_when_update_sanitizes():
    findings = await lp.probe_business_logic(
        "http://h.test", _mock_app(set()), ["/api/Things"],
    )
    assert findings == []


@pytest.mark.asyncio
async def test_skips_collection_when_reference_unresolvable():
    # /api/Owners returns nothing → OwnerId can't be satisfied → no creation, no probe.
    async def request(method, url, body=None):
        path = urlparse(url).path
        if method == "GET" and path == "/api/Things":
            return 200, {"data": [{"id": 1, "OwnerId": 7, "quantity": 1}]}
        return 404, {}   # /api/Owners 404 → reference unresolvable
    findings = await lp.probe_business_logic("http://h.test", request, ["/api/Things"])
    assert findings == []


@pytest.mark.asyncio
async def test_seeded_context_satisfies_reference():
    # No /api/Owners, but the caller seeds OwnerId from a known session value.
    async def request(method, url, body=None):
        path = urlparse(url).path
        if method == "GET" and path == "/api/Things":
            return 200, {"data": [{"id": 1, "OwnerId": 7, "quantity": 1}]}
        if method == "POST" and path == "/api/Things":
            return 201, {"data": {"id": 100, **(body or {})}}
        if method == "PUT" and path.startswith("/api/Things/"):
            return 200, {"data": dict(body or {})}   # trusts everything
        return 404, {}
    findings = await lp.probe_business_logic(
        "http://h.test", request, ["/api/Things"], context={"OwnerId": 7},
    )
    assert any(f["metadata"]["field"] == "quantity" for f in findings)


@pytest.mark.asyncio
async def test_empty_collection_is_skipped():
    async def request(method, url, body=None):
        return 200, {"data": []}   # nothing to learn a schema from
    findings = await lp.probe_business_logic("http://h.test", request, ["/api/Things"])
    assert findings == []
