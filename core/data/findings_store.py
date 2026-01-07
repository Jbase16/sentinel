"""Module findings_store: inline documentation for /Users/jason/Developer/sentinelforge/core/data/findings_store.py."""
#
# PURPOSE:
# Manages all discovered vulnerabilities with both in-memory caching and
# database persistence. Acts as the central repository for scan findings.
#
# WHAT ARE FINDINGS:
# Findings are potential security issues discovered by tools:
# - Open ports (nmap finds port 22 open)
# - Exposed services (httpx finds admin panel at /admin)
# - Misconfigurations (TLS 1.0 enabled, weak ciphers)
# - Information disclosure (server version leaked)
# - Vulnerabilities (known CVEs in detected software)
#
# FINDINGS VS. ISSUES:
# - **Finding**: Something potentially risky (needs investigation)
# - **Issue**: Confirmed exploit (has been validated/tested)
#
# ARCHITECTURE:
# - In-memory list for fast access during scan
# - Async writes to SQLite for persistence
# - Observable pattern (emits signals when findings change)
# - Session scoping (findings belong to specific scans)
#
# KEY CONCEPTS:
# - **Observable Pattern**: Emits signals when data changes
# - **Dual Storage**: Memory (fast) + Database (permanent)
# - **Session Scoping**: Each scan's findings kept separate
#

# core/findings_store.py — central findings store with UI signals

from __future__ import annotations

import threading
import asyncio
import logging
import sqlite3
import aiosqlite
from core.utils.observer import Observable, Signal
from core.data.db import Database
from core.utils.async_helpers import create_safe_task

logger = logging.getLogger(__name__)

class FindingsStore(Observable):
    """
    Stores all structured findings extracted by AIEngine.
    Emits signals so the UI updates automatically.
    Persists data to SQLite.
    """

    findings_changed = Signal()

    def __init__(self, session_id: str = None):
        """Function __init__."""
        super().__init__()
        self._lock = threading.Lock()
        self._findings = []
        self.session_id = session_id
        self.db = Database.instance()
        
        # Initialize DB in background if loop exists
        try:
            asyncio.get_running_loop()
            create_safe_task(self._init_load(), name="findings_init_load")
        except RuntimeError:
            pass  # No loop yet

    # ... Ensure loaded ...

    async def _init_load(self):
        """AsyncFunction _init_load."""
        try:
            await self.db.init()
            # Load only for this session if ID provided
            if self.session_id:
                loaded = await self.db.get_findings(self.session_id)
            else:
                loaded = await self.db.get_all_findings()
            
            # Context-managed operation.
            with self._lock:
                # Race Condition Fix: Preserve findings added while loading
                if self._findings:
                    # Deduplicate? For now, just append loaded to existing (or vice versa)
                    # Ideally, loaded is 'old' state, _findings is 'new' state.
                    self._findings = loaded + self._findings
                else:
                    self._findings = loaded
            self.findings_changed.emit()
        except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
            if "closed" in str(e).lower():
                logger.debug("[FindingsStore] DB closed during init_load")
                return
            logger.error(f"[FindingsStore] DB error during init_load: {e}")
        except Exception as e:
            logger.error(f"[FindingsStore] Failed to load findings: {e}")

    async def refresh(self):
        """Reload findings from database and emit signal."""
        if not self.db._initialized:
            await self.db.init()
        if self.session_id:
            loaded = await self.db.get_findings(self.session_id)
        else:
            loaded = await self.db.get_all_findings()
        with self._lock:
            self._findings = loaded
        # Emit signal so listeners (e.g., PressureGraphManager) update
        self.findings_changed.emit()

    def add_finding(self, finding: dict, persist: bool = True):
        """Function add_finding."""
        # Context-managed operation.
        with self._lock:
            self._findings.append(finding)
        
        # Persist asynchronously (fire-and-forget via BlackBox)
        if persist:
            # save_finding is fire-and-forget - it uses BlackBox internally
            self.db.save_finding(finding, self.session_id)
        self.findings_changed.emit()

    def add(self, finding: dict, persist: bool = True):
        """Alias for add_finding to maintain compatibility."""
        self.add_finding(finding, persist=persist)

    def bulk_add(self, items: list[dict], persist: bool = True):
        """Add multiple findings at once."""
        # Context-managed operation.
        with self._lock:
            self._findings.extend(items)
        
        # Persist asynchronously (fire-and-forget via BlackBox)
        if persist:
            for item in items:
                self.db.save_finding(item, self.session_id)
            
        self.findings_changed.emit()

    def get_all(self):
        """Return a copy of the current findings list."""
        # Context-managed operation.
        with self._lock:
            return list(self._findings)

    def clear(self):
        """Remove all findings and notify UI."""
        # Context-managed operation.
        with self._lock:
            self._findings.clear()
        # Note: We currently don't wipe the DB on clear(), 
        # treating clear() as a UI reset. 
        self.findings_changed.emit()


# Global singleton
findings_store = FindingsStore()
