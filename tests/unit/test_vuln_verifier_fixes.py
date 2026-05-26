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
