# core/task_router.py
# Central event bus connecting tools, AI engine, and UI panels.

from core.utils.observer import Observable, Signal

from .ai_engine import AIEngine
# from .findings_store import findings_store
# from .killchain_store import killchain_store


class TaskRouter(Observable):
    """
    Core event bus for AraUltra.
    All tool output → AIEngine → FindingsStore / Killchain / Evidence → UI
    """

    ui_event = Signal()

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
    # UI signal emission
    # -------------------------------------------------------
    def emit_ui_event(self, event_type: str, payload: dict):
        """
        Fires callbacks inside UI via the generic Signal.
        """
        self.ui_event.emit(event_type, payload)

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