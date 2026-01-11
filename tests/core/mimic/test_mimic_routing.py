"""
tests/core/mimic/test_mimic_routing.py
Verification suite for Mimic Route Miner.
"""
import pytest
from core.mimic.miners.routes import mine_routes

def test_route_extraction_from_fetch_and_axios():
    js = """
      fetch("/api/v1/users");
      axios.get("/internal/admin/stats");
      const x = "https://example.com/graphql";
    """
    routes = mine_routes("a1", js)
    got = {(r.route, r.hidden) for r in routes}

    assert ("/api/v1/users", False) in got
    assert ("/internal/admin/stats", True) in got
    assert ("https://example.com/graphql", True) in got

def test_xhr_open_detection():
    js = 'xhr.open("POST", "/v1/login");'
    routes = mine_routes("a1", js)
    assert any(r.route == "/v1/login" and r.method == "POST" for r in routes)

def test_ajax_detection():
    js = '$.ajax({url: "/api/legacy", method: "GET"})'
    routes = mine_routes("a1", js)
    assert any(r.route == "/api/legacy" for r in routes)
