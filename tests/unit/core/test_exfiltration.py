"""
Unit tests for UNION-based credential exfiltration (core/wraith/exfiltration).

Makes the data_exfiltration goal real: a confirmed SQLi → actually dump a
credentials table. Guards the column-count discovery, the (table, position)
search, and the honesty gate (no credential-shaped data → no claim).
"""

import re
from urllib.parse import parse_qs, urlparse

import pytest

from core.wraith import exfiltration as ex


# ──────────────────────────── credential parsing ────────────────────────────

def test_parse_credentials_pairs_email_with_hash():
    body = '{"data":[{"name":"admin@x.test","description":"0192023a7bbd73250516f069df18b500"}]}'
    creds = ex._parse_credentials(body, baseline_emails=set())
    assert creds == [("admin@x.test", "0192023a7bbd73250516f069df18b500")]


def test_parse_credentials_skips_baseline_and_hashless():
    # An email already on the page (baseline) and an email with no nearby hash.
    body = 'support@x.test contact us. user@x.test 5f4dcc3b5aa765d61d8327deb882cf99'
    creds = ex._parse_credentials(body, baseline_emails={"support@x.test"})
    assert creds == [("user@x.test", "5f4dcc3b5aa765d61d8327deb882cf99")]


# ─────────────────────────── end-to-end extraction ──────────────────────────

def _mock_target(ncols=3, table="Users"):
    """A search endpoint whose products query has `ncols` columns and a
    `table` of credentials reachable via UNION. Models the real Juice Shop
    behaviour: column-mismatch error at the wrong arity, creds at the right
    (table, position)."""
    creds = [("admin@x.test", "0192023a7bbd73250516f069df18b500"),
             ("bob@x.test", "e541ca7ecf72b8d1286474fc613e5e45")]

    async def fetch(url):
        q = parse_qs(urlparse(url).query, keep_blank_values=True).get("q", [""])[0]
        # Column discovery: UNION SELECT N NULLs (no FROM).
        m = re.search(r"UNION SELECT ((?:NULL,?)+)\s*--", q)
        if m:
            n = m.group(1).rstrip(",").count("NULL")
            if n != ncols:
                return 500, "Error: SQLITE_ERROR: SELECTs ... same number of result columns"
            return 500, "Error: Unexpected token"          # right arity, other error
        # Extraction: email,password into a real table.
        if "email,password" in q and f"FROM {table}" in q:
            rows = ",".join(f'{{"name":"{e}","description":"{h}"}}' for e, h in creds)
            return 200, '{"status":"success","data":[' + rows + "]}"
        if "FROM " in q and f"FROM {table}" not in q:
            return 500, "Error: SQLITE_ERROR: no such table"
        return 200, '{"status":"success","data":[]}'       # baseline

    return fetch


@pytest.mark.asyncio
async def test_exfiltrates_credentials_end_to_end():
    res = await ex.exfiltrate_credentials(
        "http://h.test/search?q=apple", "q", _mock_target(ncols=3, table="Users"),
    )
    assert res is not None
    assert res.table == "Users"
    assert res.row_count == 2
    assert ("admin@x.test", "0192023a7bbd73250516f069df18b500") in res.rows
    # Discovered the right column count.
    assert res.payload.count(",") == 2  # 3 columns → 2 commas


@pytest.mark.asyncio
async def test_proof_redacts_secret():
    res = await ex.exfiltrate_credentials(
        "http://h.test/search?q=apple", "q", _mock_target(ncols=3),
    )
    proof = res.to_proof()
    assert proof["technique"].startswith("UNION")
    assert proof["rows_extracted"] == 2
    # Secret is fingerprinted, not dumped in clear.
    assert all("chars]" in s["secret"] for s in proof["sample"])
    assert all("0192023a7bbd7325" not in s["secret"] for s in proof["sample"])


@pytest.mark.asyncio
async def test_no_claim_when_nothing_extractable():
    # Endpoint where the table never yields credentials → honest None.
    async def fetch(url):
        q = parse_qs(urlparse(url).query, keep_blank_values=True).get("q", [""])[0]
        if re.search(r"UNION SELECT ((?:NULL,?)+)\s*--", q):
            return 500, "Error: Unexpected"  # any arity "works" but…
        return 200, '{"status":"success","data":[]}'  # …no creds ever
    res = await ex.exfiltrate_credentials("http://h.test/search?q=a", "q", fetch)
    assert res is None


@pytest.mark.asyncio
async def test_bounded_by_max_attempts():
    seen = {"n": 0}

    async def fetch(url):
        seen["n"] += 1
        return 500, "Error: SQLITE_ERROR: same number of result columns"  # never resolves

    await ex.exfiltrate_credentials("http://h.test/search?q=a", "q", fetch, max_attempts=10)
    assert seen["n"] <= 11  # max_attempts + the one benign baseline probe
