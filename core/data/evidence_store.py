"""Module evidence_store: inline documentation for /Users/jason/Developer/sentinelforge/core/data/evidence_store.py."""
#
# PURPOSE:
# Saves raw tool outputs and artifacts as files for audit trail and later review.
# Think of this as the "crime scene photos" of a penetration test.
#
# WHAT GETS SAVED:
# - Raw tool outputs (nmap XML, httpx JSON)
# - Screenshots of vulnerabilities
# - Network packet captures
# - SSL/TLS certificates
# - Source code snippets
# - HTTP request/response pairs
#
# WHY FILE-BASED STORAGE:
# - Database bloat prevention (tool outputs can be huge)
# - Easy external access (can open files in other tools)
# - Archival compliance (some regulations require raw evidence)
# - Re-analysis capability (can reprocess with updated parsers)
#
# FILE ORGANIZATION:
# ~/AraUltra_Evidence/
#   ├── nmap/target_com_timestamp.txt
#   ├── httpx/target_com_timestamp.json
#   └── screenshots/target_com_timestamp.png
#
# KEY CONCEPTS:
# - **Evidence Chain**: Maintaining provable audit trail
# - **Sanitization**: Cleaning filenames for filesystem safety
# - **Timestamping**: Ensuring unique filenames per run
#

import asyncio
import logging
import sqlite3
import aiosqlite
from core.utils.observer import Observable, Signal
from core.data.db import Database
from core.utils.async_helpers import create_safe_task

logger = logging.getLogger(__name__)


class EvidenceStore(Observable):
    """
    Stores all evidence generated from tool output before and after AI analysis.
    Emits signals for UI updates.
    Persists data to SQLite database.
    Can be instantiated for session-specific use or accessed as global singleton.
    """

    evidence_changed = Signal()

    _instance = None

    @staticmethod
    def instance():
        """Legacy global singleton access."""
        # Conditional branch.
        if EvidenceStore._instance is None:
            EvidenceStore._instance = EvidenceStore()
        return EvidenceStore._instance

    # ---------------------------------------------------------

    def __init__(self, session_id: str = None):
        """Function __init__."""
        super().__init__()
        self._evidence = {}
        self._counter = 0
        self.session_id = session_id
        self.db = Database.instance()
        
        # Load existing evidence in background if loop exists
        try:
            asyncio.get_running_loop()
            create_safe_task(self._init_load(), name="evidence_init_load")
        except RuntimeError:
            pass  # No loop yet

    async def _init_load(self):
        """Load existing evidence from database."""
        try:
            await self.db.init()
            loaded = await self.db.get_evidence(self.session_id)
            # Loop over items.
            for item in loaded:
                eid = item.get('id', self._counter + 1)
                self._counter = max(self._counter, eid)
                self._evidence[eid] = item
            self.evidence_changed.emit()
        except (sqlite3.ProgrammingError, aiosqlite.Error, ValueError) as e:
            if "closed" in str(e).lower():
                return
            logger.error(f"[EvidenceStore] DB error during init_load: {e}")
        except Exception as e:
            logger.error(f"[EvidenceStore] Failed to load evidence: {e}")

    def add_evidence(self, tool: str, raw_output: str, metadata: dict, persist: bool = True, session_id: str = None):
        """Function add_evidence."""
        try:
            from core.base.config import get_config
            max_mb = get_config().storage.max_evidence_size_mb
        except Exception:
            max_mb = 100

        max_bytes = max_mb * 1024 * 1024
        if raw_output is None:
            raw_output = ""
        if not isinstance(raw_output, str):
            raw_output = str(raw_output)
        raw_bytes = raw_output.encode("utf-8", errors="ignore")
        truncated = False
        if len(raw_bytes) > max_bytes:
            raw_output = raw_bytes[:max_bytes].decode("utf-8", errors="ignore")
            truncated = True

        self._counter += 1
        eid = self._counter

        meta = metadata if isinstance(metadata, dict) else {}
        evidence_data = {
            "id": eid,
            "tool": tool,
            "raw_output": raw_output,
            "metadata": {
                **meta,
                "evidence_truncated": truncated,
                "evidence_bytes": len(raw_bytes),
                "evidence_max_bytes": max_bytes,
            },
            "summary": None,
            "findings": []
        }
        
        self._evidence[eid] = evidence_data

        # Persist to database asynchronously (fire-and-forget via BlackBox)
        if persist:
            # save_evidence is fire-and-forget - it uses BlackBox internally
            # No need for create_safe_task wrapper
            target_session = session_id or self.session_id
            self.db.save_evidence(evidence_data, target_session)

        self.evidence_changed.emit()
        return eid

    def update_evidence(self, evidence_id: int, summary=None, findings=None, persist: bool = True):
        """Function update_evidence."""
        # Conditional branch.
        if evidence_id not in self._evidence:
            return

        # Conditional branch.
        if summary:
            self._evidence[evidence_id]["summary"] = summary
        # Conditional branch.
        if findings:
            self._evidence[evidence_id]["findings"] = findings

        # Persist update to database (fire-and-forget via BlackBox)
        if persist:
            # update_evidence is fire-and-forget - it uses BlackBox internally
            self.db.update_evidence(evidence_id, summary, findings, self.session_id)

        self.evidence_changed.emit()

    def get_all(self):
        """Function get_all."""
        return dict(self._evidence)
    
    def clear(self):
        """Clear all evidence from memory (does not delete from DB)."""
        self._evidence.clear()
        self._counter = 0
        self.evidence_changed.emit()
