"""
core/data/findings_store.py

In-memory findings store backed by SQLite via async persistence.

Key improvements over the original:
  - DedupStore is wired in: add_finding() and add() call dedup before persisting.
    Duplicate findings are annotated with duplicate_info and still stored (so the
    UI shows them), but they are flagged so the report can filter or annotate them.
  - scan_sequence is now properly allocated via db.next_scan_sequence() per scan
    session rather than always being written as 0.
  - add_finding_async() is the canonical async path that does dedup + sequence
    allocation atomically before the BlackBox write.
  - add_finding() (sync) fires the async path as a background task so callers
    that can't await still get correct behavior.
"""

from __future__ import annotations

import threading
import asyncio
import logging
import sqlite3
from typing import List, Dict, Optional

import aiosqlite

from core.utils.observer import Observable, Signal
from core.data.db import Database
from core.utils.async_helpers import create_safe_task

logger = logging.getLogger(__name__)


class FindingsStore(Observable):
    """
    Stores all structured findings extracted by scanners and AI engines.
    Emits signals so the UI updates automatically.
    Persists data to SQLite with proper scan_sequence allocation and dedup tracking.
    """

    findings_changed = Signal()

    def __init__(self, session_id: Optional[str] = None):
        super().__init__()
        self._lock = threading.Lock()
        self._findings: List[Dict] = []
        self.session_id = session_id
        self.db = Database.instance()

        # Per-store scan sequence counter — allocated from DB on first use.
        # This ensures findings within a scan session have monotonically
        # increasing sequence numbers without requiring a DB round-trip per finding.
        self._seq_lock = asyncio.Lock() if False else threading.Lock()  # sync fallback
        self._seq_base: Optional[int] = None   # base allocated from DB
        self._seq_offset: int = 0              # local increment within this store

        # Initialize DB load in background if event loop exists
        try:
            asyncio.get_running_loop()
            create_safe_task(self._init_load(), name="findings_init_load")
        except RuntimeError:
            # No loop yet — safe to ignore
            pass

    # ------------------------------------------------------------------
    # Lifecycle / loading
    # ------------------------------------------------------------------

    async def _init_load(self) -> None:
        """Load findings from database into memory."""
        try:
            await self.db.init()

            if self.session_id:
                loaded = await self.db.get_findings(self.session_id)
            else:
                loaded = await self.db.get_all_findings()

            with self._lock:
                # Preserve any findings added before DB load completed
                if self._findings:
                    self._findings = loaded + self._findings
                else:
                    self._findings = loaded

            self.findings_changed.emit()

        except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
            if "closed" in str(e).lower():
                logger.debug("[FindingsStore] DB closed during init load")
                return
            logger.error("[FindingsStore] DB error during init load: %s", e)

        except Exception as e:
            logger.error("[FindingsStore] Failed to load findings: %s", e)

    async def refresh(self) -> None:
        """Reload findings from database and emit change signal."""
        if not self.db._initialized:
            await self.db.init()

        if self.session_id:
            loaded = await self.db.get_findings(self.session_id)
        else:
            loaded = await self.db.get_all_findings()

        with self._lock:
            self._findings = loaded

        self.findings_changed.emit()

    # ------------------------------------------------------------------
    # Scan sequence allocation
    # ------------------------------------------------------------------

    async def _next_sequence(self) -> int:
        """
        Allocate the next scan_sequence for this store.

        On first call, grabs a base from db.next_scan_sequence() (which uses
        an atomic counter in system_state). Subsequent calls increment locally.
        This means all findings within one store instance share a contiguous
        block of sequence numbers without hammering the DB.
        """
        if self._seq_base is None:
            try:
                self._seq_base = await self.db.next_scan_sequence()
                self._seq_offset = 0
                logger.debug("[FindingsStore] Allocated scan_sequence base %d", self._seq_base)
            except Exception as e:
                logger.warning(
                    "[FindingsStore] Could not allocate scan_sequence from DB, using 0: %s", e
                )
                self._seq_base = 0
                self._seq_offset = 0

        seq = self._seq_base + self._seq_offset
        self._seq_offset += 1
        return seq

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    async def add_finding_async(self, finding: Dict, persist: bool = True) -> Dict:
        """
        Async-native add path. Does dedup check, annotates the finding, assigns
        scan_sequence, persists to DB, updates in-memory list, and emits signal.

        Returns the (possibly annotated) finding dict.
        """
        # ── Dedup check ──────────────────────────────────────────────────
        annotated = dict(finding)
        try:
            from core.data.dedup_store import DedupStore
            dedup = DedupStore.instance()
            result = await dedup.check_finding(finding)
            annotated["fingerprint"] = result.fingerprint
            annotated["is_duplicate"] = result.is_duplicate
            annotated["duplicate_info"] = result.annotation()

            if result.is_duplicate:
                logger.info(
                    "[FindingsStore] Duplicate finding detected: %s (first seen %s, seen %dx)",
                    result.fingerprint[:12],
                    result.first_seen_at or "unknown",
                    result.seen_count,
                )
                # Update seen count in dedup table
                await dedup.mark_seen(result.fingerprint, finding, self.session_id or "unknown")
            else:
                # Mark as seen for future scans
                await dedup.mark_seen(result.fingerprint, finding, self.session_id or "unknown")

        except Exception as e:
            logger.warning("[FindingsStore] Dedup check failed, proceeding without it: %s", e)
            annotated.setdefault("is_duplicate", False)
            annotated.setdefault("duplicate_info", "NEW")

        # ── Scan sequence allocation ──────────────────────────────────────
        if persist:
            try:
                seq = await self._next_sequence()
                annotated["scan_sequence"] = seq
            except Exception as e:
                logger.warning("[FindingsStore] Sequence allocation failed: %s", e)
                annotated["scan_sequence"] = 0

        # ── In-memory update ──────────────────────────────────────────────
        with self._lock:
            self._findings.append(annotated)

        # ── Persist ───────────────────────────────────────────────────────
        if persist:
            seq = annotated.get("scan_sequence", 0)
            self.db.save_finding(annotated, self.session_id, scan_sequence=seq)

        self.findings_changed.emit()
        return annotated

    def add_finding(self, finding: Dict, persist: bool = True) -> None:
        """
        Sync-compatible add path. Schedules add_finding_async() as a background
        task if an event loop is running; otherwise falls back to a direct
        in-memory append with legacy fire-and-forget persistence.

        Callers with an active event loop should prefer add_finding_async() directly.
        """
        try:
            loop = asyncio.get_running_loop()
            # We're inside an async context — schedule as a task
            create_safe_task(
                self.add_finding_async(finding, persist=persist),
                name="findings_store_add",
            )
        except RuntimeError:
            # No event loop — synchronous fallback (startup, tests, etc.)
            logger.debug("[FindingsStore] Sync fallback add (no event loop)")
            with self._lock:
                annotated = dict(finding)
                annotated.setdefault("is_duplicate", False)
                annotated.setdefault("duplicate_info", "NEW")
                self._findings.append(annotated)

            if persist:
                self.db.save_finding(finding, self.session_id, scan_sequence=0)

            self.findings_changed.emit()

    def add(self, finding: Dict, persist: bool = True) -> None:
        """Alias for add_finding (compatibility)."""
        self.add_finding(finding, persist=persist)

    def bulk_add(self, items: List[Dict], persist: bool = True) -> None:
        """
        Add multiple findings. Schedules an async bulk task so each finding
        goes through dedup and sequence allocation.
        """
        try:
            asyncio.get_running_loop()
            create_safe_task(
                self._bulk_add_async(items, persist=persist),
                name="findings_store_bulk_add",
            )
        except RuntimeError:
            # Synchronous fallback
            with self._lock:
                self._findings.extend(items)
            if persist:
                for item in items:
                    self.db.save_finding(item, self.session_id, scan_sequence=0)
            self.findings_changed.emit()

    async def _bulk_add_async(self, items: List[Dict], persist: bool = True) -> None:
        """Async implementation of bulk_add — deduplicates each finding."""
        for item in items:
            await self.add_finding_async(item, persist=persist)

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def get_all(self) -> List[Dict]:
        """Return a copy of all findings."""
        with self._lock:
            return list(self._findings)

    def get(self, finding_id: str) -> Optional[Dict]:
        """Best-effort lookup by finding_id."""
        with self._lock:
            for f in self._findings:
                if f.get("id") == finding_id:
                    return f
        return None

    def clear(self) -> None:
        """Clear in-memory findings (UI reset only — does not remove from DB)."""
        with self._lock:
            self._findings.clear()
        # Reset sequence so next scan gets a fresh base
        self._seq_base = None
        self._seq_offset = 0
        self.findings_changed.emit()


# ---------------------------------------------------------------------------
# Global singleton + FastAPI dependency provider
# ---------------------------------------------------------------------------

findings_store = FindingsStore()


def get_finding_store() -> FindingsStore:
    """
    FastAPI dependency provider.

    Intentionally returns the global singleton.
    """
    return findings_store
