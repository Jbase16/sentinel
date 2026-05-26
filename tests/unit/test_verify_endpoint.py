"""
Phase 3 wiring test (Run #26): the `POST /v1/ai/verify` endpoint must call
VulnVerifier.verify_finding and surface its confirmations in the response.

These tests monkeypatch the verifier so they prove the wiring (request shape,
class-mapping, response shape, error path) without needing a live lab.
"""
from __future__ import annotations

import asyncio
import pytest


def _run(coro):
    """Run an async coroutine to completion in a sync test."""
    return asyncio.run(coro)


def test_verify_handler_calls_verifier_and_shapes_response(monkeypatch):
    from core.server.routers.ai import verify_vulnerability, VerifyRequest
    from core.wraith.vuln_verifier import VulnVerifier

    # Fake the verifier: it returns one confirmation + 2 probes sent.
    async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
        return ([(0.92, 'SQLITE_ERROR: near "\'))%": syntax error', "'))", "SQLi")], 2)

    monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

    req = VerifyRequest(target_url="http://example.com/api?q=test", vuln_class="sqli", budget=5)
    result = _run(verify_vulnerability(req))

    assert result["target_url"] == "http://example.com/api?q=test"
    assert result["vuln_class"] == "sqli"
    assert result["probes_sent"] == 2
    assert len(result["confirmed"]) == 1
    c = result["confirmed"][0]
    assert c["kind"] == "SQLi"
    assert c["confidence"] == pytest.approx(0.92)
    assert c["payload"] == "'))"
    assert "SQLITE_ERROR" in c["evidence"]


def test_verify_handler_returns_empty_confirmations_when_nothing_detected(monkeypatch):
    from core.server.routers.ai import verify_vulnerability, VerifyRequest
    from core.wraith.vuln_verifier import VulnVerifier

    async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
        return ([], 5)  # 5 probes sent, zero confirmations

    monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

    req = VerifyRequest(target_url="http://example.com/?q=test", vuln_class="sqli")
    result = _run(verify_vulnerability(req))
    assert result["probes_sent"] == 5
    assert result["confirmed"] == []


def test_verify_handler_accepts_aliased_vuln_class(monkeypatch):
    # `sql_injection` must map to the same canonical SQLI handler — the
    # request schema is stable even if user-facing names vary.
    from core.server.routers.ai import verify_vulnerability, VerifyRequest
    from core.wraith.vuln_verifier import VulnVerifier
    from core.web.contracts.enums import VulnerabilityClass

    captured = {}

    async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
        captured["vuln_class"] = vuln_class
        return ([], 1)

    monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

    req = VerifyRequest(target_url="http://example.com/?q=t", vuln_class="sql_injection")
    _run(verify_vulnerability(req))
    assert captured["vuln_class"] == VulnerabilityClass.SQLI


def test_verify_handler_rejects_unknown_vuln_class():
    from core.server.routers.ai import verify_vulnerability, VerifyRequest
    from core.errors import SentinelError

    req = VerifyRequest(target_url="http://example.com/?q=t", vuln_class="totally-fake")
    with pytest.raises(SentinelError) as exc:
        _run(verify_vulnerability(req))
    msg = str(exc.value)
    assert "Unsupported" in msg or "vuln_class" in msg


def test_verify_handler_passes_headers_cookies_budget_through(monkeypatch):
    # Headers, cookies, and budget must reach the verifier unchanged — they're
    # what enables authenticated IDOR/auth testing once personas are wired in.
    from core.server.routers.ai import verify_vulnerability, VerifyRequest
    from core.wraith.vuln_verifier import VulnVerifier

    seen = {}

    async def fake_verify(self, *, engine, finding, url, vuln_class, headers, cookies, budget=5):
        seen["headers"] = dict(headers)
        seen["cookies"] = dict(cookies)
        seen["budget"] = budget
        seen["url"] = url
        return ([], 0)

    monkeypatch.setattr(VulnVerifier, "verify_finding", fake_verify)

    req = VerifyRequest(
        target_url="http://example.com/api?id=1",
        vuln_class="idor",
        headers={"Authorization": "Bearer abc"},
        cookies={"session": "xyz"},
        budget=7,
    )
    _run(verify_vulnerability(req))
    assert seen["url"] == "http://example.com/api?id=1"
    assert seen["headers"] == {"Authorization": "Bearer abc"}
    assert seen["cookies"] == {"session": "xyz"}
    assert seen["budget"] == 7
