"""
Module findings_store: inline documentation for
/Users/jason/Developer/sentinelforge/core/data/findings_store.py.
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
    Persists data to SQLite.
    """

    findings_changed = Signal()

    def __init__(self, session_id: Optional[str] = None):
        super().__init__()
        self._lock = threading.Lock()
        self._findings: List[Dict] = []
        self.session_id = session_id
        self.db = Database.instance()

        # Initialize DB load in background if event loop exists
        try:
            asyncio.get_running_loop()
            create_safe_task(self._init_load(), name="findings_init_load")
        except RuntimeError:
            # No loop yet — safe to ignore
            pass

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
            logger.error(f"[FindingsStore] DB error during init load: {e}")

        except Exception as e:
            logger.error(f"[FindingsStore] Failed to load findings: {e}")

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

    def add_finding(self, finding: Dict, persist: bool = True) -> None:
        """Add a single finding."""
        with self._lock:
            self._findings.append(finding)

        if persist:
            # Fire-and-forget persistence (BlackBox-backed)
            self.db.save_finding(finding, self.session_id)

        self.findings_changed.emit()

    def add(self, finding: Dict, persist: bool = True) -> None:
        """Alias for add_finding (compatibility)."""
        self.add_finding(finding, persist=persist)

    def bulk_add(self, items: List[Dict], persist: bool = True) -> None:
        """Add multiple findings at once."""
        with self._lock:
            self._findings.extend(items)

        if persist:
            for item in items:
                self.db.save_finding(item, self.session_id)

        self.findings_changed.emit()

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
        """Clear in-memory findings (UI reset only)."""
        with self._lock:
            self._findings.clear()

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