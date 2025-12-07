try:
    from PyQt6.QtCore import QObject, pyqtSignal
except ImportError:
    class QObject:
        def __init__(self): pass
    class pyqtSignal:
        def __init__(self, *args): pass
        def emit(self, *args): pass


class EvidenceStore(QObject):
    """
    Stores all evidence generated from tool output before and after AI analysis.
    Emits signals for UI updates.
    """

    try:
        evidence_changed = pyqtSignal()
    except NameError:
        evidence_changed = pyqtSignal()

    _instance = None

    @staticmethod
    def instance():
        if EvidenceStore._instance is None:
            EvidenceStore._instance = EvidenceStore()
        return EvidenceStore._instance

    # ---------------------------------------------------------

    def __init__(self):
        super().__init__()
        self._evidence = {}
        self._counter = 0
        if not hasattr(self, 'evidence_changed'):
            self.evidence_changed = pyqtSignal()

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

        if hasattr(self.evidence_changed, 'emit'):
            self.evidence_changed.emit()
        return eid

    def update_evidence(self, evidence_id: int, summary=None, findings=None):
        if evidence_id not in self._evidence:
            return

        if summary:
            self._evidence[evidence_id]["summary"] = summary
        if findings:
            self._evidence[evidence_id]["findings"] = findings

        if hasattr(self.evidence_changed, 'emit'):
            self.evidence_changed.emit()

    def get_all(self):
        return dict(self._evidence)