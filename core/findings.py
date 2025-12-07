# core/findings.py — central findings store with UI signals

from __future__ import annotations

try:
    from PyQt6.QtCore import QObject, pyqtSignal
except ImportError:
    class QObject:
        def __init__(self): pass
    class pyqtSignal:
        def __init__(self, *args): pass
        def emit(self, *args): pass
import threading


class FindingsStore(QObject):
    findings_changed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._findings = []

    def add(self, item: dict):
        """Add a single finding and notify UI."""
        with self._lock:
            self._findings.append(item)
        self.findings_changed.emit()

    def bulk_add(self, items: list[dict]):
        """Add multiple findings at once."""
        with self._lock:
            self._findings.extend(items)
        self.findings_changed.emit()

    def get_all(self):
        """Return a copy of the current findings list."""
        with self._lock:
            return list(self._findings)

    def clear(self):
        """Remove all findings and notify UI."""
        with self._lock:
            self._findings.clear()
        self.findings_changed.emit()


# Global singleton
findings_store = FindingsStore()