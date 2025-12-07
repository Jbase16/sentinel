try:
    from PyQt6.QtCore import QObject, pyqtSignal
except ImportError:
    class QObject:
        def __init__(self): pass
    class pyqtSignal:
        def __init__(self, *args): pass
        def emit(self, *args): pass


class KillchainStore(QObject):
    """
    Tracks the MITRE Kill Chain phases triggered by discovered findings.
    Simple and extensible store used by TaskRouter and the UI.
    """
    
    try:
        edges_changed = pyqtSignal()
    except NameError:
        edges_changed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._edges = []
        if not hasattr(self, 'edges_changed'):
            self.edges_changed = pyqtSignal()

    def replace_all(self, edges: list):
        self._edges = edges
        if hasattr(self.edges_changed, 'emit'):
            self.edges_changed.emit()

    def get_all(self):
        return list(self._edges)

# Singleton
killchain_store = KillchainStore()