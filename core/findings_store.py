try:
    from PyQt6.QtCore import QObject, pyqtSignal
except ImportError:
    class QObject:
        def __init__(self): pass
    class pyqtSignal:
        def __init__(self, *args): pass
        def emit(self, *args): pass


class FindingsStore(QObject):
    """
    Stores all structured findings extracted by AIEngine.
    Emits signals so the UI updates automatically.
    """

    try:
        findings_changed = pyqtSignal()
    except NameError:
        findings_changed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._findings = []
        if not hasattr(self, 'findings_changed'):
            self.findings_changed = pyqtSignal()

    def add_finding(self, finding: dict):
        self._findings.append(finding)
        if hasattr(self.findings_changed, 'emit'):
            self.findings_changed.emit()

    def get_all(self):
        return list(self._findings)

    def clear(self):
        self._findings = []
        if hasattr(self.findings_changed, 'emit'):
            self.findings_changed.emit()


# Singleton instance
findings_store = FindingsStore()