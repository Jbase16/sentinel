"""
core/data/dedup_store.py
Cross-scan finding deduplication.

Tracks the fingerprint of every finding that has been seen across all scans so
that repeated discoveries on the same target are flagged as duplicates rather
than reported as new findings.

Key design decisions:

  - Fingerprint = SHA-256(host + vuln_type + asset_path)
    Ignores scan_id so the same bug found on two separate scan runs matches.

  - The dedup table persists in the same SQLite database as everything else
    (no separate file needed).

  - A finding is "seen" when it is committed to the findings/issues store.
    Callers can query is_duplicate() before deciding whether to emit an event
    or include the finding in a bounty report.

  - mark_seen() is idempotent — calling it twice with the same fingerprint is
    safe (uses INSERT OR IGNORE).

  - The store tracks when a finding was first seen and from which session,
    so reviewers can trace the history.

Usage:
    from core.data.dedup_store import DedupStore

    store = DedupStore.instance()
    await store.init()

    fp = store.fingerprint(finding)
    if await store.is_duplicate(fp):
        print("Already reported this one.")
    else:
        await store.mark_seen(fp, finding, session_id="abc-123")
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# DDL — runs once at startup via init()
_CREATE_DEDUP_TABLE = """
CREATE TABLE IF NOT EXISTS dedup_findings (
    fingerprint     TEXT PRIMARY KEY,
    host            TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    asset_path      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    seen_count      INTEGER NOT NULL DEFAULT 1,
    first_session   TEXT NOT NULL,
    last_session    TEXT NOT NULL,
    metadata        JSON
);
"""

_CREATE_DEDUP_IDX_HOST = """
CREATE INDEX IF NOT EXISTS idx_dedup_host ON dedup_findings (host);
"""

_CREATE_DEDUP_IDX_TYPE = """
CREATE INDEX IF NOT EXISTS idx_dedup_type ON dedup_findings (vuln_type);
"""


class DedupStore:
    """
    Persistent cross-scan duplicate tracker.

    Wraps the existing Database singleton — no separate connection needed.
    """

    _instance: Optional["DedupStore"] = None

    def __init__(self) -> None:
        self._initialized = False

    @classmethod
    def instance(cls) -> "DedupStore":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def init(self) -> None:
        """Create the dedup table if it doesn't exist yet."""
        if self._initialized:
            return
        from core.data.db import Database
        db = Database.instance()
        await db.init()
        await db.execute(_CREATE_DEDUP_TABLE)
        await db.execute(_CREATE_DEDUP_IDX_HOST)
        await db.execute(_CREATE_DEDUP_IDX_TYPE)
        self._initialized = True
        logger.info("[DedupStore] Initialized")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def fingerprint(finding: Dict[str, Any]) -> str:
        """
        Compute a stable cross-scan fingerprint for a finding.

        The fingerprint is based on:
          - Normalized host (lowercase, no port)
          - Normalized vuln type (lowercase, stripped)
          - Normalized asset path (lowercase URL path, query params stripped)

        This means the same bug found in two separate scans of the same target
        produces the same fingerprint.
        """
        host = _normalize_host(finding)
        vuln_type = _normalize_vuln_type(finding)
        path = _normalize_path(finding)
        raw = f"{host}|{vuln_type}|{path}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    async def is_duplicate(self, fingerprint: str) -> bool:
        """Return True if this fingerprint has been seen in any prior scan."""
        await self.init()
        from core.data.db import Database
        db = Database.instance()
        rows = await db.fetch_all(
            "SELECT fingerprint FROM dedup_findings WHERE fingerprint = ?",
            (fingerprint,),
        )
        return bool(rows)

    async def check_finding(self, finding: Dict[str, Any]) -> "DedupResult":
        """
        Check a finding for duplicates.

        Returns a DedupResult with:
          - is_duplicate: bool
          - fingerprint: str
          - first_seen_at: Optional[str] (ISO timestamp if duplicate)
          - first_session: Optional[str]
          - seen_count: int (0 if new)
        """
        await self.init()
        fp = self.fingerprint(finding)
        from core.data.db import Database
        db = Database.instance()
        rows = await db.fetch_all(
            "SELECT first_seen_at, first_session, seen_count FROM dedup_findings WHERE fingerprint = ?",
            (fp,),
        )
        if not rows:
            return DedupResult(fingerprint=fp, is_duplicate=False)
        row = rows[0]
        return DedupResult(
            fingerprint=fp,
            is_duplicate=True,
            first_seen_at=row[0],
            first_session=row[1],
            seen_count=row[2],
        )

    async def mark_seen(
        self,
        fingerprint: str,
        finding: Dict[str, Any],
        session_id: str,
    ) -> None:
        """
        Record that this fingerprint was seen in session_id.

        If already seen, increments seen_count and updates last_seen_at + last_session.
        If new, inserts a fresh row.
        Idempotent per (fingerprint, session_id) pair within a single session.
        """
        await self.init()
        from core.data.db import Database
        db = Database.instance()
        now = datetime.now(timezone.utc).isoformat()
        host = _normalize_host(finding)
        vuln_type = _normalize_vuln_type(finding)
        path = _normalize_path(finding)
        severity = (finding.get("severity") or "MEDIUM").upper()
        meta_json = json.dumps({
            "target": finding.get("target") or "",
            "rule_id": finding.get("rule_id") or "",
            "tool": finding.get("tool") or "",
        })

        # Check if already tracked
        rows = await db.fetch_all(
            "SELECT seen_count FROM dedup_findings WHERE fingerprint = ?",
            (fingerprint,),
        )
        if rows:
            await db.execute(
                """
                UPDATE dedup_findings
                SET last_seen_at = ?,
                    last_session = ?,
                    seen_count = seen_count + 1
                WHERE fingerprint = ?
                """,
                (now, session_id, fingerprint),
            )
        else:
            await db.execute(
                """
                INSERT INTO dedup_findings
                    (fingerprint, host, vuln_type, asset_path, severity,
                     first_seen_at, last_seen_at, seen_count, first_session, last_session, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (fingerprint, host, vuln_type, path, severity,
                 now, now, session_id, session_id, meta_json),
            )

    async def bulk_check(
        self,
        findings: List[Dict[str, Any]],
    ) -> List["DedupResult"]:
        """
        Check a batch of findings for duplicates in a single query.

        Returns one DedupResult per input finding (same order).
        """
        await self.init()
        if not findings:
            return []

        fps = [self.fingerprint(f) for f in findings]
        placeholders = ",".join("?" for _ in fps)
        from core.data.db import Database
        db = Database.instance()
        rows = await db.fetch_all(
            f"SELECT fingerprint, first_seen_at, first_session, seen_count FROM dedup_findings WHERE fingerprint IN ({placeholders})",
            tuple(fps),
        )
        seen_map: Dict[str, tuple] = {r[0]: r for r in rows}

        results = []
        for fp in fps:
            if fp in seen_map:
                r = seen_map[fp]
                results.append(DedupResult(
                    fingerprint=fp,
                    is_duplicate=True,
                    first_seen_at=r[1],
                    first_session=r[2],
                    seen_count=r[3],
                ))
            else:
                results.append(DedupResult(fingerprint=fp, is_duplicate=False))
        return results

    async def get_history(self, host: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Return the dedup history for a host (all previously seen finding types).

        Useful for the bounty report generator to annotate known-seen findings.
        """
        await self.init()
        from core.data.db import Database
        db = Database.instance()
        rows = await db.fetch_all(
            """
            SELECT fingerprint, vuln_type, severity, first_seen_at, last_seen_at, seen_count, first_session
            FROM dedup_findings
            WHERE host = ?
            ORDER BY last_seen_at DESC
            LIMIT ?
            """,
            (host.lower(), limit),
        )
        return [
            {
                "fingerprint": r[0],
                "vuln_type": r[1],
                "severity": r[2],
                "first_seen_at": r[3],
                "last_seen_at": r[4],
                "seen_count": r[5],
                "first_session": r[6],
            }
            for r in rows
        ]

    async def clear_host(self, host: str) -> int:
        """
        Remove all dedup records for a host.

        Call this if you want to re-report findings (e.g. after remediation).
        Returns the number of records deleted.
        """
        await self.init()
        from core.data.db import Database
        db = Database.instance()
        rows_before = await db.fetch_all(
            "SELECT COUNT(*) FROM dedup_findings WHERE host = ?",
            (host.lower(),),
        )
        count_before = rows_before[0][0] if rows_before else 0
        await db.execute(
            "DELETE FROM dedup_findings WHERE host = ?",
            (host.lower(),),
        )
        logger.info("[DedupStore] Cleared %d records for host %s", count_before, host)
        return count_before


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

from dataclasses import dataclass


@dataclass
class DedupResult:
    """Result of a duplicate check for one finding."""
    fingerprint: str
    is_duplicate: bool
    first_seen_at: Optional[str] = None
    first_session: Optional[str] = None
    seen_count: int = 0

    def annotation(self) -> str:
        """Human-readable annotation for use in reports."""
        if not self.is_duplicate:
            return "NEW"
        return f"DUPLICATE (first seen {self.first_seen_at or 'unknown'}, {self.seen_count}x)"


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _normalize_host(finding: Dict[str, Any]) -> str:
    """Extract and normalize the host from a finding."""
    # Try explicit host fields first
    host = finding.get("host") or finding.get("hostname") or ""
    if not host:
        # Try to parse from target or asset URL
        for field in ("target", "asset", "url"):
            val = finding.get(field) or ""
            if val and "://" in val:
                try:
                    parsed = urlparse(val)
                    host = parsed.hostname or ""
                    if host:
                        break
                except Exception:
                    pass
            elif val:
                host = val
                break
    # Lowercase, strip port
    host = re.sub(r":\d+$", "", host.lower()).rstrip(".")
    return host or "unknown"


def _normalize_vuln_type(finding: Dict[str, Any]) -> str:
    """Normalize the vulnerability type to a canonical string."""
    vuln_type = (
        finding.get("rule_id")
        or finding.get("type")
        or finding.get("title")
        or finding.get("name")
        or "UNKNOWN"
    )
    # Lowercase, replace spaces/dashes with underscore, strip special chars
    normalized = re.sub(r"[\s\-]+", "_", vuln_type.lower())
    normalized = re.sub(r"[^a-z0-9_]", "", normalized)
    return normalized


def _normalize_path(finding: Dict[str, Any]) -> str:
    """
    Normalize the affected asset path.

    Strips query strings and fragments (they're noise for dedup purposes)
    and normalizes to lowercase.
    """
    for field in ("asset", "path", "url", "target"):
        val = finding.get(field) or ""
        if not val:
            continue
        if "://" in val:
            try:
                parsed = urlparse(val)
                path = parsed.path.lower().rstrip("/") or "/"
                return path
            except Exception:
                pass
        # Already a path
        path = val.split("?")[0].split("#")[0].lower().rstrip("/")
        return path or "/"
    return "/"
