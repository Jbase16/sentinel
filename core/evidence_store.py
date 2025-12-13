import asyncio
import logging
from core.utils.observer import Observable, Signal
from core.db import Database
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
