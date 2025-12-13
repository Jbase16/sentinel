from core.utils.observer import Observable, Signal


class KillchainStore(Observable):
    """
    Tracks the MITRE Kill Chain phases triggered by discovered findings.
    Simple and extensible store used by TaskRouter and the UI.
    Can be instantiated for session-specific use or accessed as global singleton.
    """
    
    edges_changed = Signal()

    def __init__(self, session_id: str = None):
        super().__init__()
        self._edges = []
        self.session_id = session_id

    def replace_all(self, edges: list):
        self._edges = edges
        self.edges_changed.emit()

    def get_all(self):
        return list(self._edges)

# Singleton
killchain_store = KillchainStore()