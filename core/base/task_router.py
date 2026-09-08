"""Module task_router: inline documentation for /Users/jason/Developer/sentinelforge/core/base/task_router.py."""
#
# PURPOSE:
# TaskRouter is the central nervous system of Sentinel. It receives output
# from security tools, sends it to the AI engine for analysis, and broadcasts
# findings to the UI in real-time.
#
# DATA FLOW:
# Tool executes → Scanner captures output → TaskRouter.handle_tool_output()
# → canonical EvidenceLedger observation → AI/scanner proposals → UI projections
#
# KEY CONCEPTS FOR JUNIOR DEVELOPERS:
# - Event Bus: A central hub that routes messages between components
# - Signals: Observer pattern implementation (pub/sub system)
# - Singleton: One global instance shared across the application
# - Canonical admission: identity and operation atoms are mandatory
#

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from core.behavior.compiler import OperationFamily, OperationInstance
from core.epistemic.ledger import (
    ActiveProofCitation,
    Citation,
    ConfirmationLevel,
    EvidenceLedger,
    Finding,
    FindingProposal,
)
from core.identity import AssessmentIdentityContext
from core.utils.observer import Observable, Signal

# CRITICAL: We import AIEngine here (not at the top of the file)
# This is because AIEngine might import other modules that depend on TaskRouter
# Importing here breaks the circular dependency chain
from core.ai.ai_engine import AIEngine

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompletedBehavioralProof:
    """Terminal receipt material relayed by a behavioral evidence producer."""

    receipt_id: str
    provenance_root: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"behavioral-[0-9a-f]{64}", self.receipt_id) is None:
            raise ValueError("completed behavioral proof receipt is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", self.provenance_root) is None:
            raise ValueError("completed behavioral proof provenance is invalid")


class TaskRouter(Observable):
    """
    Central event bus for the SentinelForge/AraUltra architecture.
    
    Responsibilities:
    1. Receive tool output from scanner engine
    2. Send output to AIEngine for semantic analysis
    3. Distribute findings/events to UI via signals
    4. Admit evidence and findings through the canonical EvidenceLedger
    
    Design Pattern: Singleton (one instance per application)
    Concurrency: scanner calls are serialized by the scan lifecycle
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
        - Avoids creating multiple AIEngine/EvidenceLedger instances
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
    
    def __init__(
        self,
        *,
        ai: Optional[Any] = None,
        ledger: Optional[EvidenceLedger] = None,
    ):
        """
        Initialize the TaskRouter.
        
        IMPORTANT: This should only be called once (by instance() method).
        Don't call TaskRouter() directly - use TaskRouter.instance() instead.
        """
        # Initialize Observable base class (handles signal management)
        super().__init__()

        # Get the global AIEngine singleton
        # The AI engine will analyze tool output and extract findings
        self.ai = ai or AIEngine.instance()
        self.ledger = ledger or EvidenceLedger()

        # Registry for UI callbacks (currently unused, kept for backward compatibility)
        # Modern code uses signals instead of direct callbacks
        self._ui_callbacks = {}
        
        logger.info("[TaskRouter] Initialized - AI connected to canonical EvidenceLedger")

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
        *,
        identity: AssessmentIdentityContext,
        operation_family: OperationFamily,
        operation_instance: OperationInstance,
        scanner_findings: Optional[Sequence[Dict[str, Any]]] = None,
        completed_behavioral_proof: Optional[CompletedBehavioralProof] = None,
    ) -> Dict[str, Any]:
        """Route one identity-bound tool output through the canonical ledger."""

        metadata = dict(metadata or {})
        raw_scanner_findings = tuple(scanner_findings or ())
        if completed_behavioral_proof is not None:
            if rc != 0:
                raise ValueError("completed behavioral proof requires successful output")
            if len(raw_scanner_findings) != 1:
                raise ValueError(
                    "completed behavioral proof requires exactly one finding payload"
                )
        supplied_session = metadata.get("session_id")
        if supplied_session not in {None, identity.session_id}:
            raise ValueError("tool output metadata session does not match identity")
        metadata["session_id"] = identity.session_id
        target = metadata.get("target")
        if not isinstance(target, str):
            raise ValueError("tool output requires an absolute target")

        logger.debug(
            "[TaskRouter] Processing output from %s (rc=%s, stdout=%d bytes)",
            tool_name,
            rc,
            len(stdout),
        )
        observation = self.ledger.record_canonical_observation(
            tool_name=tool_name,
            tool_args=list(metadata.get("args", [])),
            target=target,
            raw_output=stdout.encode("utf-8", errors="replace"),
            identity=identity,
            operation_family=operation_family,
            operation_instance=operation_instance,
            exit_code=rc,
        )

        assessed_proposals: List[FindingProposal] = []
        canonical_findings: List[Finding] = []
        behavioral_proposal: Optional[FindingProposal] = None
        for raw_finding in raw_scanner_findings:
            proposal = self._scanner_proposal(
                raw_finding,
                observation.id,
                tool_name,
                source=(
                    "behavioral_receipt"
                    if completed_behavioral_proof is not None
                    else "scanner"
                ),
            )
            assessed = self.ledger.assess_proposal(proposal)
            assessed_proposals.append(assessed)
            if completed_behavioral_proof is not None:
                behavioral_proposal = assessed
            # Scanner classification is passive evidence.  It remains an assessed
            # proposal until a completed R0 receipt and conduct provenance bind an
            # active proof; TaskRouter must not manufacture that authority.

        if completed_behavioral_proof is not None:
            if behavioral_proposal is None:
                raise ValueError("completed behavioral proof proposal is unavailable")
            citation = ActiveProofCitation(
                observation_id=observation.id,
                receipt_id=completed_behavioral_proof.receipt_id,
                provenance_root=completed_behavioral_proof.provenance_root,
            )
            canonical_findings.append(
                self.ledger.promote_canonical_finding(
                    title=behavioral_proposal.title,
                    severity=behavioral_proposal.severity,
                    citations=list(behavioral_proposal.citations),
                    description=behavioral_proposal.description,
                    remediation=behavioral_proposal.remediation,
                    confirmation_level=ConfirmationLevel.CONFIRMED.value,
                    metadata=behavioral_proposal.metadata,
                    active_proof=[citation],
                )
            )

        if rc != 0:
            logger.info(
                "[TaskRouter] Tool %s failed (rc=%s), skipping AI analysis",
                tool_name,
                rc,
            )
            result: Dict[str, Any] = {
                "summary": f"Tool {tool_name} failed with exit code {rc}",
                "proposals": [],
                "next_steps": [],
            }
        else:
            try:
                result = await self.ai.process_tool_output(
                    tool_name=tool_name,
                    stdout=stdout,
                    stderr=stderr,
                    rc=rc,
                    metadata=metadata,
                    observation_id=observation.id,
                )
            except Exception as exc:
                logger.error(
                    "[TaskRouter] AIEngine failed to process %s output: %s",
                    tool_name,
                    exc,
                    exc_info=True,
                )
                result = {
                    "summary": f"Analysis failed: {exc}",
                    "proposals": [],
                    "next_steps": [],
                }
                self.emit_ui_event(
                    "analysis_error",
                    {"tool": tool_name, "error": str(exc), "target": target},
                )

        for proposal in result.get("proposals", []):
            if not isinstance(proposal, FindingProposal):
                logger.warning("[TaskRouter] Ignoring untyped AI proposal")
                continue
            if not proposal.citations:
                proposal = FindingProposal(
                    title=proposal.title,
                    severity=proposal.severity,
                    description=proposal.description,
                    citations=[Citation(observation_id=observation.id)],
                    remediation=proposal.remediation,
                    source=proposal.source,
                    metadata=proposal.metadata,
                    confirmation_level=proposal.confirmation_level,
                )
            assessed_proposals.append(self.ledger.assess_proposal(proposal))

        finding_views = [self._finding_view(item) for item in canonical_findings]
        result = {
            **result,
            "observation_id": observation.id,
            "evidence_id": observation.id,
            "proposals": assessed_proposals,
            "findings": finding_views,
        }
        self._emit_tool_result(
            tool_name=tool_name,
            rc=rc,
            metadata=metadata,
            result=result,
            findings=canonical_findings,
        )
        logger.info(
            "[TaskRouter] Processed %s: %d canonical findings, %d proposals, %d next steps",
            tool_name,
            len(canonical_findings),
            len(assessed_proposals),
            len(result.get("next_steps", [])),
        )
        return result

    def _emit_tool_result(
        self,
        *,
        tool_name: str,
        rc: int,
        metadata: Dict[str, Any],
        result: Dict[str, Any],
        findings: Sequence[Finding],
    ) -> None:
        self.emit_ui_event(
            "evidence_update",
            {
                "tool": tool_name,
                "summary": result.get("summary", "No summary available"),
                "evidence_id": result["evidence_id"],
                "return_code": rc,
                "success": rc == 0,
            },
        )
        self.emit_ui_event(
            "findings_update",
            {
                "tool": tool_name,
                "findings": [self._finding_view(item) for item in findings],
                "next_steps": result.get("next_steps", []),
                "metadata": metadata,
            },
        )
        live_comment = result.get("live_comment")
        if live_comment:
            self.emit_ui_event(
                "ai_live_comment",
                {
                    "tool": tool_name,
                    "target": metadata.get("target"),
                    "comment": live_comment,
                    "timestamp": metadata.get("timestamp"),
                },
            )

    @staticmethod
    def _scanner_proposal(
        raw_finding: Dict[str, Any],
        observation_id: str,
        tool_name: str,
        *,
        source: str = "scanner",
    ) -> FindingProposal:
        finding = json.loads(json.dumps(raw_finding, sort_keys=True, default=str))
        title = str(finding.get("title") or finding.get("type") or "Scanner finding")
        severity = str(finding.get("severity") or "INFO").upper()
        description = str(
            finding.get("description")
            or finding.get("message")
            or finding.get("value")
            or finding.get("proof")
            or "Deterministic scanner classification."
        )
        return FindingProposal(
            title=title,
            severity=severity,
            description=description,
            citations=[Citation(observation_id=observation_id)],
            remediation=(
                str(finding["remediation"])
                if finding.get("remediation") is not None
                else None
            ),
            source=source,
            metadata={
                "tool": tool_name,
                "type": finding.get("type", title),
                "scanner_finding": finding,
            },
        )

    @staticmethod
    def _finding_view(finding: Finding) -> Dict[str, Any]:
        view = dict(finding.metadata.get("scanner_finding") or {})
        metadata = dict(view.get("metadata") or {})
        metadata.update(
            {
                "canonical_finding_id": finding.id,
                "canonical_commitment": finding.commitment,
                "session_id": finding.session_id,
            }
        )
        view.update(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description,
                "confirmation_level": finding.confirmation_level,
                "citations": [item.observation_id for item in finding.citations],
                "metadata": metadata,
            }
        )
        return view


# ============================================================================
# Module-Level Documentation
# ============================================================================
"""
USAGE:

1. ScannerEngine supplies a ScannerEvidenceContext to handle_tool_output.

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
- ScannerEngine serializes canonical evidence routing within each scan lifecycle

ERROR HANDLING PHILOSOPHY:
- Never crash the event bus (catch all exceptions)
- Always log errors with full stack traces
- Emit error events to UI so users know what went wrong
- Provide fallback behavior (degraded functionality > no functionality)

CIRCULAR IMPORT PREVENTION:
- Import AIEngine at top of file (since it's used in __init__)
- Import this module at bottom of other files (avoid top-level cycles)
"""
