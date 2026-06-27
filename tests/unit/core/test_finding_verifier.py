"""
Unit tests for the passive-finding verification gate (core/toolkit/finding_verifier).

REGRESSION GUARD for "Sentinel blends in with generic scanners": a passive
finding must be re-tested against the live target before it's surfaced as fact.
A target that actually sends the header / blocks the verb / secures its cookies
must REFUTE the corresponding finding, and duplicate findings must collapse.
"""

import httpx
import pytest

from core.toolkit import finding_verifier as fv


# ---------------------------------------------------------------- dedup

def test_dedup_collapses_same_title_and_host():
    findings = [
        {"title": "Dangerous HTTP Verbs Enabled", "target": "gitlab.com"},
        {"title": "Dangerous HTTP Verbs Enabled", "target": "gitlab.com"},
        {"title": "Dangerous HTTP Verbs Enabled", "target": "gitlab.com"},
        {"title": "Missing Security Header", "target": "gitlab.com"},
    ]
    unique, removed = fv.dedup(findings)
    assert removed == 2
    assert len(unique) == 2  # one verbs + one header


# ------------------------------------------------- verify_finding (mocked)

def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_missing_header_refuted_when_present():
    # Server actually sends the header the scanner claimed missing.
    def handler(req):
        return httpx.Response(200, headers={"strict-transport-security": "max-age=63072000"})

    finding = {
        "title": "Missing Security Header",
        "target": "gitlab.com",
        "data": {"metadata": {"header": "strict-transport-security",
                              "original_target": "https://gitlab.com"}},
    }
    async with _client(handler) as c:
        verdict, evidence = await fv.verify_finding(finding, c)
    assert verdict == fv.REFUTED
    assert "present" in evidence.lower()


@pytest.mark.asyncio
async def test_missing_header_confirmed_when_absent():
    def handler(req):
        return httpx.Response(200, headers={"content-type": "text/html"})

    finding = {
        "title": "Missing Security Header",
        "target": "example.test",
        "data": {"metadata": {"header": "content-security-policy",
                              "original_target": "https://example.test"}},
    }
    async with _client(handler) as c:
        verdict, _ = await fv.verify_finding(finding, c)
    assert verdict == fv.CONFIRMED


@pytest.mark.asyncio
async def test_dangerous_verbs_refuted_when_blocked():
    # Every dangerous verb returns 405 -> not actually enabled.
    def handler(req):
        return httpx.Response(405)

    finding = {"title": "Dangerous HTTP Verbs Enabled", "target": "gitlab.com"}
    async with _client(handler) as c:
        verdict, evidence = await fv.verify_finding(finding, c)
    assert verdict == fv.REFUTED
    assert "blocked" in evidence.lower()


@pytest.mark.asyncio
async def test_dangerous_verbs_confirmed_when_honored():
    # TRACE returns 200 -> real cross-site-tracing exposure.
    def handler(req):
        return httpx.Response(200 if req.method == "TRACE" else 405)

    finding = {"title": "Dangerous HTTP Verbs Enabled", "target": "vuln.test"}
    async with _client(handler) as c:
        verdict, evidence = await fv.verify_finding(finding, c)
    assert verdict == fv.CONFIRMED
    assert "TRACE" in evidence


@pytest.mark.asyncio
async def test_exposed_admin_refuted_on_redirect_to_login():
    def handler(req):
        return httpx.Response(302, headers={"location": "/users/sign_in"})

    finding = {"title": "Exposed Administrative Interface", "target": "https://gitlab.com/admin"}
    async with _client(handler) as c:
        verdict, _ = await fv.verify_finding(finding, c)
    assert verdict == fv.REFUTED


@pytest.mark.asyncio
async def test_unknown_category_is_unverifiable_not_dropped():
    finding = {"title": "Exposed Management Service", "target": "scanme.nmap.org"}
    async with _client(lambda r: httpx.Response(200)) as c:
        verdict, _ = await fv.verify_finding(finding, c)
    # HTTP can't re-test an SSH/RDP service finding — keep it, but never as fact.
    assert verdict == fv.UNVERIFIABLE
