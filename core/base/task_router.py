"""Module task_router: inline documentation for /Users/jason/Developer/sentinelforge/core/base/task_router.py."""
#
# PURPOSE:
# TaskRouter is the central nervous system of Sentinel. It receives output
# from security tools, sends it to the AI engine for analysis, and broadcasts
# findings to the UI in real-time.
#
# DATA FLOW:
# Tool executes → Scanner captures output → TaskRouter.handle_tool_output()
# → AIEngine.process_tool_output() → Findings extracted → UI events emitted
#
# KEY CONCEPTS FOR JUNIOR DEVELOPERS:
# - Event Bus: A central hub that routes messages between components
# - Signals: Observer pattern implementation (pub/sub system)
# - Singleton: One global instance shared across the application
# - Lazy Loading: Import dependencies only when needed (avoids circular imports)
#

import logging
from core.utils.observer import Observable, Signal

# CRITICAL: We import AIEngine here (not at the top of the file)
# This is because AIEngine might import other modules that depend on TaskRouter
# Importing here breaks the circular dependency chain
from core.ai.ai_engine import AIEngine

logger = logging.getLogger(__name__)


class TaskRouter(Observable):
    """
    Central event bus for the SentinelForge/AraUltra architecture.
    
    Responsibilities:
    1. Receive tool output from scanner engine
    2. Send output to AIEngine for semantic analysis
    3. Distribute findings/events to UI via signals
    4. Maintain evidence store for all tool executions
    
    Design Pattern: Singleton (one instance per application)
    Thread Safety: Yes (AIEngine and stores handle their own locking)
    """

    # Signal emitted for UI events (findings, logs, status updates)
    # Subscribers connect to this signal to receive real-time updates
    # Example: ui_event.emit("finding_discovered", {"finding": {...}})
    ui_event = Signal()

    # Singleton instance (shared across all modules)
    _instance = None

    @staticmethod
    def instance():
        """
        Get the global TaskRouter singleton.
        
        Why singleton?
        - Only one event bus should exist (ensures all events go through one path)
        - Avoids creating multiple AIEngine/EvidenceStore instances
        - Makes it easy to access from anywhere: TaskRouter.instance()
        
        Returns:
            The global TaskRouter instance (creates it if it doesn't exist)
        """
        # Conditional branch.
        if TaskRouter._instance is None:
            TaskRouter._instance = TaskRouter()
        return TaskRouter._instance

    # ============================================================================
    # Initialization
    # ============================================================================
    
    def __init__(self):
        """
        Initialize the TaskRouter.
        
        IMPORTANT: This should only be called once (by instance() method).
        Don't call TaskRouter() directly - use TaskRouter.instance() instead.
        """
        # Initialize Observable base class (handles signal management)
        super().__init__()

        # Get the global AIEngine singleton
        # The AI engine will analyze tool output and extract findings
        self.ai = AIEngine.instance()

        # Lazy-load EvidenceStore to avoid circular imports
        # EvidenceStore might import modules that depend on TaskRouter
        # By importing here (not at module level), we break the cycle
        from core.data.evidence_store import EvidenceStore
        from core.epistemic.ledger import EvidenceLedger
        
        self.evidence = EvidenceStore.instance()
        self.ledger = EvidenceLedger()

        # Registry for UI callbacks (currently unused, kept for backward compatibility)
        # Modern code uses signals instead of direct callbacks
        self._ui_callbacks = {}
        
        logger.info("[TaskRouter] Initialized - AI and Evidence stores connected")

    # ============================================================================
    # UI Signal Emission
    # ============================================================================
    
    def emit_ui_event(self, event_type: str, payload: dict):
        """
        Fire a UI event that subscribers can listen to.
        
        This is the primary way to send data from the backend to the frontend.
        The UI subscribes to these events via SSE (Server-Sent Events) or WebSockets.
        
        Args:
            event_type: Type of event (e.g., "finding_discovered", "tool_completed")
            payload: Dictionary containing event data
        
        Example:
            router.emit_ui_event("scan_progress", {
                "tool": "nmap",
                "target": "example.com",
                "percent_complete": 75
            })
        
        Error Handling:
        - If signal emission fails, we log but don't crash
        - This ensures one bad subscriber doesn't break the whole system
        """
        # Error handling block.
        try:
            # Inject run_id for epoch tracking
            from core.base.sequence import GlobalSequenceAuthority
            if isinstance(payload, dict) and "run_id" not in payload:
                payload["run_id"] = GlobalSequenceAuthority.instance().run_id

            # Emit the signal to all connected subscribers
            # The Signal class handles calling each subscriber's callback function
            self.ui_event.emit(event_type, payload)
            
        except Exception as e:
            # Don't crash if UI event emission fails
            # Log the error so we can debug, but continue processing
            logger.error(f"[TaskRouter] Failed to emit UI event '{event_type}': {e}", exc_info=True)

    # ============================================================================
    # Primary Tool Output Handler
    # ============================================================================
    
    async def handle_tool_output(
        self,
        tool_name: str,
        stdout: str,
        stderr: str,
        rc: int,
        metadata: dict,
    ):
        """
        Process the output from a security tool.
        
        This is called by the scanner engine after a tool finishes running.
        It orchestrates the full analysis pipeline:
        1. Send raw output to AIEngine for analysis
        2. Store evidence in the database
        3. Extract and store findings
        4. Emit UI events for real-time updates
        
        Args:
            tool_name: Name of the tool that was run (e.g., "nmap", "httpx")
            stdout: Standard output from the tool (the actual results)
            stderr: Standard error from the tool (warnings/errors)
            rc: Return code (0 = success, non-zero = error)
            metadata: Additional context (target, session_id, timestamp, etc.)
        
        Example:
            await router.handle_tool_output(
                tool_name="nmap",
                stdout="PORT    STATE SERVICE\\n22/tcp  open  ssh\\n80/tcp  open  http",
                stderr="",
                rc=0,
                metadata={"target": "192.168.1.1", "session_id": "abc123"}
            )
        
        Error Handling:
        - If AIEngine fails, we catch the exception and log it
        - We still emit error events to the UI so the user knows what happened
        - This ensures one tool failure doesn't crash the entire scan
        """
        
        # Detailed logging for debugging tool execution issues
        logger.debug(f"[TaskRouter] Processing output from {tool_name} (rc={rc}, stdout={len(stdout)} bytes)")
        
        # Error handling block.
        try:
            # STEP 0: Record immutable observation in Epistemic Ledger (The Truth Engine)
            observation = self.ledger.record_observation(
                tool_name=tool_name,
                tool_args=metadata.get("args", []),
                target=metadata.get("target", "unknown"),
                raw_output=stdout.encode("utf-8", errors="replace"), # Store bytes
                exit_code=rc
            )
            
            # STEP 1: Send output to AIEngine for semantic analysis
            # AIEngine return PROPOSALS, not final findings.
            result = await self.ai.process_tool_output(
                tool_name=tool_name,
                stdout=stdout,
                stderr=stderr,
                rc=rc,
                metadata=metadata,
                observation_id=observation.id, # Cite the evidence
            )
            
            proposals = result.get("proposals", [])
            promoted_findings = []
            
            # STEP 2: Epistemic Gatekeeping (The Inversion)
            # Pass proposals to Ledger for validation and promotion
            for proposal in proposals:
                finding = self.ledger.evaluate_and_promote(proposal)
                if finding:
                    promoted_findings.append(finding)
                else:
                    logger.info(f"[TaskRouter] Logic Refusal: Proposal '{proposal.title}' rejected by Ledger.")
            
        except Exception as e:
            # AIEngine analysis failed (LLM offline, parsing error, etc.)
            # Log the full error with stack trace for debugging
            logger.error(
                f"[TaskRouter] AIEngine failed to process {tool_name} output: {e}",
                exc_info=True
            )
            
            # Create a fallback/error state
            result = {
                "summary": f"Analysis failed: {str(e)}",
                "proposals": [],
                "next_steps": [],
            }
            promoted_findings = []
            
            # Emit error event to UI so the user knows something went wrong
            try:
                self.emit_ui_event("analysis_error", {
                    "tool": tool_name,
                    "error": str(e),
                    "target": metadata.get("target") if metadata else None
                })
            except Exception:
                pass

        # STEP 3: Emit events to UI for real-time updates
        
        # Emit evidence update (raw tool output stored in database)
        try:
            self.emit_ui_event("evidence_update", {
                "tool": tool_name,
                "summary": result.get("summary", "No summary available"),
                "evidence_id": result.get("evidence_id"),
                "return_code": rc,
                "success": rc == 0,
            })
        except Exception as e:
            logger.warning(f"[TaskRouter] Failed to emit evidence_update: {e}")

        # Emit findings update (ONLY show PROMOTED findings)
        try:
            # We need to construct a serializable representation of findings for the UI
            findings_payload = []
            for f in promoted_findings:
                findings_payload.append({
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "citations": [c.observation_id for c in f.citations]
                })

            self.emit_ui_event("findings_update", {
                "tool": tool_name,
                "findings": findings_payload,
                "next_steps": result.get("next_steps", []),
                # Include metadata so UI can filter by target/session
                "metadata": metadata,
            })
        except Exception as e:
            logger.warning(f"[TaskRouter] Failed to emit findings_update: {e}")

        # STEP 3: Emit live AI commentary (optional, for chat-like UI updates)
        # This provides a natural language explanation of what was discovered
        live_comment = result.get("live_comment")
        # Conditional branch.
        if live_comment:
            try:
                self.emit_ui_event("ai_live_comment", {
                    "tool": tool_name,
                    "target": metadata.get("target") if metadata else None,
                    "comment": live_comment,
                    # Include timestamp so UI can show when this happened
                    "timestamp": metadata.get("timestamp") if metadata else None,
                })
            except Exception as e:
                logger.warning(f"[TaskRouter] Failed to emit ai_live_comment: {e}")
        
        # Log successful completion
        logger.info(
            f"[TaskRouter] Processed {tool_name}: "
            f"{len(result.get('findings', []))} findings, "
            f"{len(result.get('next_steps', []))} next steps"
        )


# ============================================================================
# Module-Level Documentation
# ============================================================================
"""
USAGE EXAMPLES:

1. Basic usage (from scanner engine):
   
   from core.base.task_router import TaskRouter
   
   router = TaskRouter.instance()
   router.handle_tool_output(
       tool_name="nmap",
       stdout="...",
       stderr="",
       rc=0,
       metadata={"target": "example.com"}
   )

2. Subscribing to UI events (from API server):
   
   def my_callback(event_type: str, payload: dict):
       print(f"Event: {event_type}, Data: {payload}")
   
   router = TaskRouter.instance()
   router.ui_event.connect(my_callback)

3. Emitting custom events:
   
   router = TaskRouter.instance()
   router.emit_ui_event("custom_event", {
       "message": "Something interesting happened",
       "data": {...}
   })

THREAD SAFETY:
- TaskRouter itself is thread-safe (uses Signal class which handles threading)
- AIEngine and EvidenceStore have their own locking mechanisms
- You can call handle_tool_output() from multiple threads safely

ERROR HANDLING PHILOSOPHY:
- Never crash the event bus (catch all exceptions)
- Always log errors with full stack traces
- Emit error events to UI so users know what went wrong
- Provide fallback behavior (degraded functionality > no functionality)

CIRCULAR IMPORT PREVENTION:
- Import AIEngine at top of file (since it's used in __init__)
- Import EvidenceStore in __init__ (lazy loading)
- Import this module at bottom of other files (avoid top-level cycles)
"""
