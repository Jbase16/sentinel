from core.utils.observer import Observable, Signal


class EvidenceStore(Observable):
    """
    Stores all evidence generated from tool output before and after AI analysis.
    Emits signals for UI updates.
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

    def add_evidence(self, tool: str, raw_output: str, metadata: dict):
        self._counter += 1
        eid = self._counter

        self._evidence[eid] = {
            "tool": tool,
            "raw_output": raw_output,
            "metadata": metadata,
            "summary": None,
            "findings": []
        }

        self.evidence_changed.emit()
        return eid

    def update_evidence(self, evidence_id: int, summary=None, findings=None):
        if evidence_id not in self._evidence:
            return

        if summary:
            self._evidence[evidence_id]["summary"] = summary
        if findings:
            self._evidence[evidence_id]["findings"] = findings

        self.evidence_changed.emit()

    def get_all(self):
        return dict(self._evidence)