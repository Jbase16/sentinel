# core/task_router.py
# Central event bus connecting tools, AI engine, and UI panels.

try:
    from PyQt6.QtCore import QObject, pyqtSignal
except ImportError:
    class QObject:
        def __init__(self): pass
    class pyqtSignal:
        def __init__(self, *args): pass
        def emit(self, *args): pass

from .ai_engine import AIEngine
from .findings_store import findings_store
from .killchain_store import killchain_store


class TaskRouter(QObject):
    """
    Core event bus for AraUltra.
    All tool output → AIEngine → FindingsStore / Killchain / Evidence → UI
    """

    ui_event = pyqtSignal(str, dict)

    _instance = None

    @staticmethod
    def instance():
        if TaskRouter._instance is None:
            TaskRouter._instance = TaskRouter()
        return TaskRouter._instance

    # -------------------------------------------------------
    # Initialization
    # -------------------------------------------------------
    def __init__(self):
        super().__init__()

        self.ai = AIEngine.instance()

        # Lazy-loaded to avoid circular imports
        from core.evidence_store import EvidenceStore
        self.evidence = EvidenceStore.instance()

        # UI callbacks registry
        self._ui_callbacks = {}

    # -------------------------------------------------------
    # UI callback registration
    # -------------------------------------------------------
    def register_ui_callback(self, event_type: str, func):
        """
        UI files register for updates (e.g., findings_update, evidence_update,
        ai_live_comment, etc.)
        """
        if event_type not in self._ui_callbacks:
            self._ui_callbacks[event_type] = []
        self._ui_callbacks[event_type].append(func)

    def emit_ui_event(self, event_type: str, payload: dict):
        """
        Fires callbacks inside UI.
        """
        if event_type in self._ui_callbacks:
            for cb in self._ui_callbacks[event_type]:
                cb(payload)

    # -------------------------------------------------------
    # Primary tool output handler
    # -------------------------------------------------------
    def handle_tool_output(
        self,
        tool_name: str,
        stdout: str,
        stderr: str,
        rc: int,
        metadata: dict,
    ):
        """
        Called by ExecutionEngine via tool_callback_factory.
        Runs AI analysis and updates stores + UI panels.
        """

        result = self.ai.process_tool_output(
            tool_name=tool_name,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            metadata=metadata,
        )

        # Update dashboard & findings viewers
        self.emit_ui_event("evidence_update", {
            "tool": tool_name,
            "summary": result["summary"],
            "evidence_id": result["evidence_id"],
        })

        self.emit_ui_event("findings_update", {
            "tool": tool_name,
            "findings": result["findings"],
            "next_steps": result.get("next_steps", []),
            "killchain_phases": result["killchain_phases"],
        })

        # Live AI commentary stream
        live_comment = result.get("live_comment")
        if live_comment:
            self.emit_ui_event("ai_live_comment", {
                "tool": tool_name,
                "target": metadata.get("target") if metadata else None,
                "comment": live_comment,
            })