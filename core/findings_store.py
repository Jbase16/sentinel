# core/findings_store.py — central findings store with UI signals

from __future__ import annotations

import threading
import asyncio
from core.utils.observer import Observable, Signal
from core.db import Database

class FindingsStore(Observable):
    """
    Stores all structured findings extracted by AIEngine.
    Emits signals so the UI updates automatically.
    Persists data to SQLite.
    """

    findings_changed = Signal()

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._findings = []
        self.db = Database.instance()
        
        # Initialize DB in background if loop exists
        try:
            asyncio.get_running_loop()
            asyncio.create_task(self._init_load())
        except RuntimeError:
            pass # No loop yet, will be loaded on first async access or by app startup

    async def ensure_loaded(self):
        """Call this to ensure DB is loaded if it wasn't during init"""
        if not self._findings:
            await self._init_load()

    async def _init_load(self):
        await self.db.init()
        loaded = await self.db.get_all_findings()
        with self._lock:
            self._findings = loaded
        self.findings_changed.emit()

    def add_finding(self, finding: dict):
        with self._lock:
            self._findings.append(finding)
        
        # Persist asynchronously
        asyncio.create_task(self.db.save_finding(finding))
        self.findings_changed.emit()

    def add(self, finding: dict):
        """Alias for add_finding to maintain compatibility."""
        self.add_finding(finding)

    def bulk_add(self, items: list[dict]):
        """Add multiple findings at once."""
        with self._lock:
            self._findings.extend(items)
        
        for item in items:
            asyncio.create_task(self.db.save_finding(item))
            
        self.findings_changed.emit()

    def get_all(self):
        """Return a copy of the current findings list."""
        with self._lock:
            return list(self._findings)

    def clear(self):
        """Remove all findings and notify UI."""
        with self._lock:
            self._findings.clear()
        # Note: We currently don't wipe the DB on clear(), 
        # treating clear() as a UI reset. 
        self.findings_changed.emit()


# Global singleton
findings_store = FindingsStore()
