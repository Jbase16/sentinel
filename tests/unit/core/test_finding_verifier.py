"""
Unit tests for the passive-finding verification gate (core/toolkit/finding_verifier).

REGRESSION GUARD for "Sentinel blends in with generic scanners": a passive
finding must be re-tested against the live target before it's surfaced as fact.
A target that actually sends the header / blocks the verb / secures its cookies
must REFUTE the corresponding finding, and duplicate findings must collapse.
"""

import hashlib
import json

import httpx
import pytest

from core.toolkit import finding_verifier as fv


# ---------------------------------------------------------------- id parity

def test_finding_id_matches_db_content_hash():
    # finding_id MUST equal core.data.db's id derivation, or suppression
    # UPDATEs target nothing. Lock the formula down.
    issue = {"title": "Dangerous HTTP Verbs Enabled", "severity": "MEDIUM",
             "target": "gitlab.com", "data": {"k": [1, 2, 3]}}
    expected = hashlib.sha256(json.dumps(issue, sort_keys=True).encode()).hexdigest()
    assert fv.finding_id(issue) == expected


def test_finding_id_is_order_independent():
    a = {"title": "X", "target": "h", "severity": "LOW"}
    b = {"severity": "LOW", "target": "h", "title": "X"}  # different key order
    assert fv.finding_id(a) == fv.finding_id(b)


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


# ------------------------------------------------- gate keep_ids (suppression)

@pytest.mark.asyncio
async def test_gate_keep_ids_drops_refuted_and_collapses_duplicates(monkeypatch):
    # Server sends the header AND blocks the verbs => both categories refuted.
    def handler(req):
        if req.method in ("TRACE", "TRACK", "CONNECT", "PUT", "DELETE", "PATCH"):
            return httpx.Response(405)
        return httpx.Response(200, headers={"strict-transport-security": "max-age=1"})

    # Force the gate to use our mocked transport instead of a live client.
    real_async_client = httpx.AsyncClient

    def fake_async_client(*a, **kw):
        kw.pop("transport", None)
        return real_async_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)

    verbs = {"title": "Dangerous HTTP Verbs Enabled", "target": "gitlab.com"}
    header = {"title": "Missing Security Header", "target": "gitlab.com",
              "data": {"metadata": {"header": "strict-transport-security",
                                    "original_target": "https://gitlab.com"}}}
    # 5 identical verb dupes + 1 header finding (all refuted) + 1 unknown (kept).
    unknown = {"title": "Exposed Management Service (SSH)", "target": "gitlab.com"}
    findings = [dict(verbs) for _ in range(5)] + [header, unknown]

    rep = await fv.gate(findings, drop_refuted=True)

    # Only the unverifiable unknown survives; its id is the sole keeper.
    assert rep["kept_count"] == 1
    assert fv.finding_id(unknown) in rep["keep_ids"]
    assert fv.finding_id(verbs) not in rep["keep_ids"]
    assert fv.finding_id(header) not in rep["keep_ids"]

    # The suppression set = every original whose id isn't a keeper. All 6
    # refuted/duplicate rows must be suppressed; the unknown must not.
    suppress = [f for f in findings if fv.finding_id(f) not in rep["keep_ids"]]
    assert len(suppress) == 6
    assert unknown not in suppress
