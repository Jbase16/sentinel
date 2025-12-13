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

    def __init__(self, session_id: str = None):
        super().__init__()
        self._lock = threading.Lock()
        self._findings = []
        self.session_id = session_id
        self.db = Database.instance()
        
        # Initialize DB in background if loop exists
        try:
            asyncio.get_running_loop()
            asyncio.create_task(self._init_load())
        except RuntimeError:
            pass # No loop yet

    # ... Ensure loaded ...

    async def _init_load(self):
        await self.db.init()
        # Load only for this session if ID provided
        if self.session_id:
            loaded = await self.db.get_findings(self.session_id)
        else:
            loaded = await self.db.get_all_findings()
        
        with self._lock:
            # Race Condition Fix: Preserve findings added while loading
            if self._findings:
                # Deduplicate? For now, just append loaded to existing (or vice versa)
                # Ideally, loaded is 'old' state, _findings is 'new' state.
                self._findings = loaded + self._findings
            else:
                self._findings = loaded
        self.findings_changed.emit()

    async def refresh(self):
        if not self.db._initialized:
            await self.db.init()
        if self.session_id:
            loaded = await self.db.get_findings(self.session_id)
        else:
            loaded = await self.db.get_all_findings()
        with self._lock:
            self._findings = loaded

    def add_finding(self, finding: dict):
        with self._lock:
            self._findings.append(finding)
        
        # Persist asynchronously with session ID
        asyncio.create_task(self.db.save_finding(finding, self.session_id))
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
