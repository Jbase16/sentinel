# ============================================================================
# core/data/evidence_store.py  
# Evidence Store - File-Based Artifact Preservation
# ============================================================================
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
# ============================================================================

import asyncio
import logging
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
        if EvidenceStore._instance is None:
            EvidenceStore._instance = EvidenceStore()
        return EvidenceStore._instance

    # ---------------------------------------------------------

    def __init__(self, session_id: str = None):
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
        await self.db.init()
        loaded = await self.db.get_evidence(self.session_id)
        for item in loaded:
            eid = item.get('id', self._counter + 1)
            self._counter = max(self._counter, eid)
            self._evidence[eid] = item
        self.evidence_changed.emit()

    def add_evidence(self, tool: str, raw_output: str, metadata: dict):
        self._counter += 1
        eid = self._counter

        evidence_data = {
            "id": eid,
            "tool": tool,
            "raw_output": raw_output,
            "metadata": metadata,
            "summary": None,
            "findings": []
        }
        
        self._evidence[eid] = evidence_data

        # Persist to database asynchronously
        try:
            asyncio.get_running_loop()
            create_safe_task(
                self.db.save_evidence(evidence_data, self.session_id),
                name="save_evidence"
            )
        except RuntimeError:
            logger.warning("[EvidenceStore] No event loop for async save")

        self.evidence_changed.emit()
        return eid

    def update_evidence(self, evidence_id: int, summary=None, findings=None):
        if evidence_id not in self._evidence:
            return

        if summary:
            self._evidence[evidence_id]["summary"] = summary
        if findings:
            self._evidence[evidence_id]["findings"] = findings

        # Persist update to database
        try:
            asyncio.get_running_loop()
            create_safe_task(
                self.db.update_evidence(evidence_id, summary, findings, self.session_id),
                name="update_evidence"
            )
        except RuntimeError:
            logger.warning("[EvidenceStore] No event loop for async update")

        self.evidence_changed.emit()

    def get_all(self):
        return dict(self._evidence)
    
    def clear(self):
        """Clear all evidence from memory (does not delete from DB)."""
        self._evidence.clear()
        self._counter = 0
        self.evidence_changed.emit()
