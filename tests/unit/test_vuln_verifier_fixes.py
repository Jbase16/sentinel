"""
Regression tests for the three Phase 3 fixes to core.wraith.vuln_verifier
(found by lab-verifying against OWASP Juice Shop, Run #26):

  1. `PayloadEncoding.NONE` was referenced but didn't exist → every
     `_confirm_*` method crashed on construction. Added NONE to the enum.

  2. `_get_resp_body` looked for `outcome.response.body`, but the value the
     verifier captures from `waf_aware_send` is a `MutationResponse`
     directly (with `.body` as a direct attribute) — so body extraction
     silently returned "" and no SQL-error regex could ever match.

  3. `_SQLI_ERROR_PATTERNS` had no SQLite signature, so even when a real
     SQLite-backed app (Juice Shop, OWASP) returned `SQLITE_ERROR: near
     "X": syntax error`, the regex didn't match → false negatives on a
     known-vulnerable target.

These tests pin all three so the verifier can't silently regress to "sends
probes, never detects anything."
"""
from __future__ import annotations

from core.wraith.mutation_engine import PayloadEncoding
from core.wraith.vuln_verifier import VulnVerifier, _SQLI_ERROR_RE


def test_payload_encoding_NONE_exists():
    # The verifier uses NONE to mean "request is pre-built; do not re-inject"
    # — every _confirm_* method built a MutationPayload(encoding=NONE), which
    # crashed AttributeError before any probe was sent.
    assert hasattr(PayloadEncoding, "NONE")
    assert PayloadEncoding.NONE.value == "none"


def test_get_resp_body_reads_body_off_mutation_response():
    # `waf_aware_send` returns (MutationResponse, ActionOutcome, bypassed).
    # The MutationResponse has .body directly — NOT under an inner .response.
    class FakeMutationResponse:
        body = 'Error: SQLITE_ERROR: near "\'))%": syntax error'

    extracted = VulnVerifier._get_resp_body(None, FakeMutationResponse())
    assert "SQLITE_ERROR" in extracted, "body extraction regressed"
    # Defensive: must not crash on a None or empty response
    assert VulnVerifier._get_resp_body(None, None) == ""


def test_sqli_error_regex_matches_sqlite_signature():
    # The single most-important detection regression check: a real Juice
    # Shop response body must match the SQLi error regex. Before Run #26
    # this did NOT match (no SQLite signature in the pattern set).
    juice_shop_body = (
        '<html><head><title>'
        'Error: SQLITE_ERROR: near "\'))%": syntax error'
        '</title></head></html>'
    )
    m = _SQLI_ERROR_RE.search(juice_shop_body)
    assert m is not None, "Juice Shop SQLITE_ERROR body must match SQLi regex"


def test_sqli_error_regex_still_catches_classic_signatures():
    # Defensive: adding SQLite signatures must not have broken the original
    # MySQL/PG/Oracle/MSSQL/ODBC detections.
    for body in (
        "You have an error in your SQL syntax; check the manual for...",
        "ERROR:  syntax error at or near \"FROM\"",
        "ORA-00933: SQL command not properly ended",
        "Unclosed quotation mark after the character string ''",
    ):
        assert _SQLI_ERROR_RE.search(body), f"regression on classic signature: {body!r}"


# ─────────────────────── Run #26 follow-up: outcome.response → outcome ──────
#
# The previously-fixed `_get_resp_body` was only ONE site of a wider bug
# pattern. Four other `_confirm_*` paths still read `outcome.response.X` —
# which silently returned None because MutationResponse has these attrs
# directly. Symptom (live calibration, Juice Shop): /rest/basket/2 returned
# HTTP 200 but `_confirm_idor` saw 0 and never fired. These tests pin the
# helper-based extraction (status_code, headers) so the bug can't regress.


class _FakeMR:
    """Stand-in for MutationResponse — the verifier helpers read attrs DIRECTLY
    off this object (no inner `.response`)."""
    def __init__(self, status_code=200, body="", headers=None, body_hash=""):
        self.status_code = status_code
        self.body = body
        self.headers = headers or {}
        self.body_hash = body_hash


def test_get_resp_status_reads_directly_off_mutation_response():
    v = VulnVerifier.__new__(VulnVerifier)  # bypass __init__ — only need helpers
    assert v._get_resp_status(_FakeMR(status_code=200)) == 200
    assert v._get_resp_status(_FakeMR(status_code=500)) == 500
    assert v._get_resp_status(None) == 0
    # Must NOT look up an inner `.response` — older code path returned 0
    # because `getattr(outcome, "response", None)` was None.


def test_get_resp_headers_is_case_insensitive():
    v = VulnVerifier.__new__(VulnVerifier)
    # Server returned PascalCase Location — many do.
    h = v._get_resp_headers(_FakeMR(headers={"Location": "https://evil.example.com/"}))
    assert h.get("location") == "https://evil.example.com/"
    # Same call shape returns dict for a None outcome (no AttributeError).
    assert v._get_resp_headers(None) == {}


# ────────────────────────── IDOR heuristic ──────────────────────────────


def _baseline_neighbor_factory(baseline_mr, neighbor_mr):
    """Build a fake waf_aware_send that returns baseline first, then neighbor.

    Subsequent calls (the verifier may try multiple neighbor deltas under
    its remaining budget) reuse the same neighbor — that way a single
    test parameterization covers any budget value."""
    call_count = {"n": 0}
    async def fake_send(engine, url, payload, *, method, headers):
        n = call_count["n"]
        call_count["n"] += 1
        return (baseline_mr if n == 0 else neighbor_mr, None, False)
    return fake_send


def _run_idor(monkeypatch, baseline_mr, neighbor_mr, *, url="http://h/api/users/5", budget=3):
    """Drive _confirm_idor end-to-end with mocked waf_aware_send."""
    import asyncio
    import core.wraith.vuln_verifier as vv
    monkeypatch.setattr(
        vv, "waf_aware_send",
        _baseline_neighbor_factory(baseline_mr, neighbor_mr),
    )
    v = VulnVerifier.__new__(VulnVerifier)
    return asyncio.run(v._confirm_idor(engine=None, url=url, headers={}, cookies={}, budget=budget))


def test_idor_confirmed_when_neighbor_returns_distinct_json(monkeypatch):
    """Canonical IDOR shape: same JSON template, different IDs — high confidence."""
    baseline = _FakeMR(
        status_code=200,
        body='{"id": 5, "owner": "alice", "items": []}',
        body_hash="aaaaaa",
    )
    neighbor = _FakeMR(
        status_code=200,
        body='{"id": 6, "owner": "bob", "items": [{"name": "x"}]}',
        body_hash="bbbbbb",
    )
    results, probes = _run_idor(monkeypatch, baseline, neighbor)
    assert results, "high-confidence IDOR was not flagged"
    confidence, evidence, payload_str, kind = results[0]
    assert kind == "IDOR"
    assert confidence >= 0.80, f"expected high-confidence (0.85), got {confidence}"
    assert probes == 2, f"expected 2 probes (baseline + 1 neighbor), got {probes}"


def test_idor_not_flagged_when_neighbor_body_identical(monkeypatch):
    """SPA shell: both IDs return the same boilerplate HTML — NOT IDOR."""
    shell = '<html><body>App shell — loading...</body></html>'
    baseline = _FakeMR(status_code=200, body=shell, body_hash="shell0")
    neighbor = _FakeMR(status_code=200, body=shell, body_hash="shell0")
    results, _ = _run_idor(monkeypatch, baseline, neighbor)
    assert results == [], "identical bodies must NOT trigger an IDOR finding"


def test_idor_not_flagged_when_neighbor_returns_403(monkeypatch):
    """Access control is working — neighbor request rejected. That's the
    OPPOSITE of IDOR."""
    baseline = _FakeMR(
        status_code=200,
        body='{"id": 5, "owner": "alice"}',
        body_hash="aaaaaa",
    )
    forbidden = _FakeMR(status_code=403, body='{"error":"forbidden"}', body_hash="ffffff")
    results, _ = _run_idor(monkeypatch, baseline, forbidden)
    assert results == [], "403 on neighbor must NOT be flagged as IDOR"


def test_idor_not_flagged_when_baseline_itself_fails(monkeypatch):
    """If baseline doesn't 200, we have nothing to compare against; bail."""
    baseline = _FakeMR(status_code=404, body="not found", body_hash="x")
    neighbor = _FakeMR(status_code=200, body='{"id":6}', body_hash="y")
    results, probes = _run_idor(monkeypatch, baseline, neighbor)
    assert results == []
    # We must short-circuit after the baseline failure — only 1 probe sent.
    assert probes == 1


def test_idor_low_confidence_when_non_json_distinct_body(monkeypatch):
    """HTML pages with different content (e.g. different user profiles
    rendered server-side) — suspicious but not high-confidence."""
    baseline = _FakeMR(
        status_code=200,
        body="<html>Alice's profile — favorite color: blue. ID 5.</html>",
        body_hash="aaa",
    )
    neighbor = _FakeMR(
        status_code=200,
        body="<html>Bob's profile — favorite color: red. ID 6.</html>",
        body_hash="bbb",
    )
    results, _ = _run_idor(monkeypatch, baseline, neighbor)
    assert results, "distinct non-JSON bodies must still emit a lower-confidence finding"
    confidence, _evidence, _payload, kind = results[0]
    assert kind == "IDOR"
    assert 0.50 <= confidence < 0.80, (
        f"expected mid-confidence (0.60) for non-JSON IDOR, got {confidence}"
    )


def test_idor_skipped_when_no_numeric_path_segment(monkeypatch):
    """_confirm_idor only runs when the URL ends in a numeric / UUID segment."""
    baseline = _FakeMR(status_code=200, body='{"x":1}', body_hash="a")
    neighbor = _FakeMR(status_code=200, body='{"x":2}', body_hash="b")
    # /api/users (no ID segment) — verifier has no segment to enumerate.
    results, probes = _run_idor(
        monkeypatch, baseline, neighbor, url="http://h/api/users"
    )
    assert results == []
    assert probes == 0, "verifier must not probe when no ID segment is present"
