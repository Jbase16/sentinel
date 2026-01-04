"""Module events: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/events.py."""
#
# PURPOSE:
# The central nervous system of Strategos.
# Decouples emission (Strategos/Decisions) from consumption (UI/Logs).
#
# LOGIC:
# - EventBus: Singleton-like observable.
# - emit_*: Helper methods for structured event emission.
#
# EVENT SEQUENCE PERSISTENCE:
# The global event sequence counter is persisted to the database to maintain
# continuity across process restarts. This ensures:
# - Event IDs (derived from sequence) remain unique across restarts
# - Swift client deduplication via lastSequence works correctly
# - Causal ordering is preserved as "one continuous logical brain"
#
# RUN_ID (FORENSICS):
# Each process startup generates a unique run_id (UUID v4) for debugging.
# This is NOT used for event identity (sequence serves that purpose).
# It helps answer "Which runtime generated this event?" during post-mortem analysis.
#
# SCHEMA UNIFICATION (P1 #10):
# GraphEventType is now an ALIAS for EventType from core.contracts.events.
# This ensures a single source of truth for all event types across the system.
# The contracts module defines the authoritative taxonomy with 49+ event types,
# schema validation, causal tracking, and Swift code generation.
#

from __future__ import annotations

import logging
import time
import uuid
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, field

# ============================================================================
# SCHEMA UNIFICATION: Import from authoritative source
# ============================================================================
# EventType in contracts/events.py is the SINGLE SOURCE OF TRUTH.
# GraphEventType is kept as an alias for backward compatibility.
# All existing code (imports, comparisons) continues to work unchanged.
# ============================================================================
from core.contracts.events import EventType, EventContract, ContractViolation

# BACKWARD COMPATIBILITY ALIAS:
# This allows existing code like `from core.cortex.events import GraphEventType`
# to keep working without modification.
GraphEventType = EventType

logger = logging.getLogger(__name__)

# ============================================================================
# SEQUENCE AUTHORITY DELEGATION
# ============================================================================
# The event sequence counter has been centralized into GlobalSequenceAuthority
# (core/base/sequence.py). This ensures a single, unified timeline across:
# - GraphEvents (this module)
# - DecisionPoints (core/scheduler/decisions.py)
# - Any future temporal data types
#
# The old module-level counter (_event_sequence_counter) has been removed.
# All sequence operations now delegate to GlobalSequenceAuthority.
# ============================================================================

# Global run_id for forensics - identifies which runtime generated events
# Generated once per process startup, persisted for debugging
_run_id: Optional[str] = None


def get_run_id() -> str:
    """
    Get the unique run_id for this process instance.

    The run_id is a UUID v4 generated on first call, uniquely identifying
    this specific runtime/process. This is useful for forensics to answer
    "Which runtime generated this event?" during post-mortem analysis.

    NOTE: This is NOT used for event identity (sequence serves that purpose).
    It is purely a debugging/observability aid.

    Returns:
        The UUID v4 run_id string for this process instance

    Side effects:
        - Generates a new UUID on first call
    """
    global _run_id
    if _run_id is None:
        _run_id = str(uuid.uuid4())
        logger.info(f"[EventBus] Generated new run_id: {_run_id}")
    return _run_id


def reset_run_id() -> None:
    """
    Reset the run_id.

    WARNING: This should ONLY be used in tests!
    In production, the run_id should never be reset.
    """
    global _run_id
    _run_id = None


async def initialize_event_sequence_from_db() -> int:
    """
    Initialize the global event sequence counter from the database.

    This MUST be called during application startup (before any events are emitted)
    to ensure the counter starts from the last persisted value, maintaining
    continuity across restarts.

    IMPLEMENTATION NOTE:
    This function now delegates to GlobalSequenceAuthority, which provides
    a unified timeline shared by both EventStore and DecisionLedger.

    Returns:
        The loaded sequence number (0 if no persisted value exists)

    Side effects:
        - Initializes GlobalSequenceAuthority from database
        - Future calls to get_next_sequence() will work
    """
    from core.base.sequence import GlobalSequenceAuthority
    return await GlobalSequenceAuthority.initialize_from_db()


def get_next_sequence() -> int:
    """
    Get the next global event sequence number.

    This is a monotonically increasing counter that provides:
    - Total ordering of all events (even with identical timestamps)
    - Cross-correlation between events and decisions
    - Debugging capability to reconstruct exact event flow
    - Continuity across process restarts (via persistence)

    IMPLEMENTATION NOTE:
    This function now delegates to GlobalSequenceAuthority, which provides
    a unified timeline shared by both EventStore and DecisionLedger.
    The authority uses itertools.count() for atomic, lock-free increments.

    Returns:
        The next sequence number

    Raises:
        RuntimeError: If initialize_event_sequence_from_db() was not called first

    Side effects:
        - Persists the new sequence number to the database (fire-and-forget)
    """
    from core.base.sequence import GlobalSequenceAuthority
    return GlobalSequenceAuthority.instance().next_id()

# ============================================================================
# GraphEventType REMOVED - Now imported from core.contracts.events
# ============================================================================
# The old 11-type enum has been replaced by the 49-type EventType enum.
# The alias `GraphEventType = EventType` ensures backward compatibility.
# See core/contracts/events.py for the authoritative type definitions.
# ============================================================================

@dataclass
class GraphEvent:
    """
    Immutable event record with global sequence number.

    Fields:
        type: Event classification from GraphEventType enum
        payload: Event-specific data (findings, decisions, etc.)
        timestamp: When event occurred (epoch time)
        event_sequence: Global monotonically increasing sequence number
        run_id: UUID v4 identifying the runtime/process that generated this event

    The event_sequence enables:
    - Total ordering of events regardless of clock skew
    - Cross-correlation: decisions can reference specific events
    - Debugging: reconstruct exact event flow from logs

    The run_id enables:
    - Forensics: identify which runtime generated a specific event
    - Post-mortem analysis: correlate events across restarts
    - Debugging: distinguish between events from different process lifetimes
    """
    type: GraphEventType
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    event_sequence: int = field(default_factory=get_next_sequence)
    run_id: str = field(default_factory=get_run_id)

class EventBus:
    """
    Synchronous Event Bus for strategic observability.

    CONTRACT VALIDATION (P1 #10):
    ─────────────────────────────
    The EventBus now validates all emitted events against the EventContract.
    This ensures:
    1. Events have required fields (schema validation)
    2. Events follow causal ordering (tool_completed after tool_started)
    3. Invalid events are caught early in development

    Validation behavior is controlled by EventContract.set_strict_mode():
    - strict=True (dev): Raises ContractViolation on invalid events
    - strict=False (prod): Logs warning but continues execution
    """
    def __init__(self, validate: bool = True):
        """
        Initialize EventBus.

        Args:
            validate: Enable contract validation (default True).
                      Set False for legacy code or performance-critical paths.
        """
        self._subscribers: List[Callable[[GraphEvent], None]] = []
        self._last_event_sequence: int = 0  # Track last sequence for diagnostics
        self._validate = validate

    def subscribe(self, callback: Callable[[GraphEvent], None]):
        """Function subscribe."""
        self._subscribers.append(callback)

    @property
    def last_event_sequence(self) -> int:
        """Get the sequence number of the last emitted event."""
        return self._last_event_sequence

    def emit(self, event: GraphEvent):
        """
        Broadcast event to all subscribers.

        CONTRACT VALIDATION:
        Before broadcasting, the event is validated against the EventContract.
        In strict mode (development), invalid events raise ContractViolation.
        In non-strict mode (production), invalid events log warnings.
        """
        # Track last sequence for diagnostics
        self._last_event_sequence = event.event_sequence

        # CONTRACT VALIDATION: Ensure event conforms to schema and causal rules
        if self._validate:
            try:
                EventContract.validate(event.type, event.payload)
            except ContractViolation as e:
                # In strict mode, this raises. In non-strict, it only logs.
                # The validate() method already handles logging for non-strict.
                logger.warning(f"[EventBus] Contract violation: {e}")
                # Re-raise if we're in strict mode
                if EventContract._strict_mode:
                    raise

        # Loop over items.
        for callback in self._subscribers:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"[EventBus] Subscriber failed: {e}")

    # --- Convenience Methods ---

    def emit_decision_made(self, intent: str, reason: str, context: Dict, source: str = "strategos"):
        """Function emit_decision_made."""
        self.emit(GraphEvent(
            type=GraphEventType.DECISION_MADE,
            payload={
                "intent": intent,
                "reason": reason,
                "context": context,
                "source": source
            }
        ))

    def emit_narrative_emitted(self, narrative: str, decision_id: str, decision_type: str, context: Dict):
        """Function emit_narrative_emitted."""
        self.emit(GraphEvent(
            type=GraphEventType.NARRATIVE_EMITTED,
            payload={
                "narrative": narrative,
                "decision_id": decision_id,
                "decision_type": decision_type,
                "context": context
            }
        ))

    def emit_scan_phase_changed(self, phase: str, previous_phase: Optional[str] = None):
        """Function emit_scan_phase_changed."""
        self.emit(GraphEvent(
            type=GraphEventType.SCAN_PHASE_CHANGED,
            payload={
                "phase": phase,
                "previous_phase": previous_phase
            }
        ))

    def emit_scan_started(self, target: str, allowed_tools: List[str], session_id: str):
        """Function emit_scan_started."""
        self.emit(GraphEvent(
            type=GraphEventType.SCAN_STARTED,
            payload={
                "target": target,
                "allowed_tools": allowed_tools,
                "session_id": session_id
            }
        ))

    def emit_scan_completed(self, status: str, findings_count: int, duration: float):
        """Function emit_scan_completed."""
        self.emit(GraphEvent(
            type=GraphEventType.SCAN_COMPLETED,
            payload={
                "status": status,
                "findings_count": findings_count,
                "duration_seconds": duration
            }
        ))

    def emit_tool_invoked(self, tool: str, target: str, args: List[str]):
        """Function emit_tool_invoked."""
        self.emit(GraphEvent(
            type=GraphEventType.TOOL_STARTED,
            payload={
                "tool": tool,
                "target": target,
                "args": args
            }
        ))

    def emit_tool_completed(self, tool: str, exit_code: int, findings_count: int):
        """Function emit_tool_completed."""
        self.emit(GraphEvent(
            type=GraphEventType.TOOL_COMPLETED,
            payload={
                "tool": tool,
                "exit_code": exit_code,
                "findings_count": findings_count
            }
        ))

    # --- CRONUS Event Convenience Methods ---

    def emit_cronus_query_started(
        self,
        target: str,
        sources: List[str],
        timestamp_start: Optional[str] = None,
        timestamp_end: Optional[str] = None
    ):
        """Emit CRONUS_QUERY_STARTED event when TimeMachine begins archive query."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_QUERY_STARTED,
            payload={
                "target": target,
                "sources": sources,
                "timestamp_start": timestamp_start,
                "timestamp_end": timestamp_end,
            }
        ))

    def emit_cronus_query_completed(
        self,
        target: str,
        snapshots_found: int,
        duration_ms: Optional[int] = None
    ):
        """Emit CRONUS_QUERY_COMPLETED event when TimeMachine finishes."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_QUERY_COMPLETED,
            payload={
                "target": target,
                "snapshots_found": snapshots_found,
                "duration_ms": duration_ms,
            }
        ))

    def emit_cronus_query_failed(self, target: str, error: str, source: Optional[str] = None):
        """Emit CRONUS_QUERY_FAILED event when archive query fails."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_QUERY_FAILED,
            payload={
                "target": target,
                "error": error,
                "source": source,
            }
        ))

    def emit_cronus_snapshot_found(
        self,
        url: str,
        timestamp: str,
        source: str,
        status_code: Optional[int] = None
    ):
        """Emit CRONUS_SNAPSHOT_FOUND event when historical snapshot is discovered."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_SNAPSHOT_FOUND,
            payload={
                "url": url,
                "timestamp": timestamp,
                "source": source,
                "status_code": status_code,
            }
        ))

    def emit_cronus_diff_started(self, target: str, old_count: int, new_count: int):
        """Emit CRONUS_DIFF_STARTED event when sitemap comparison begins."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_DIFF_STARTED,
            payload={
                "target": target,
                "old_count": old_count,
                "new_count": new_count,
            }
        ))

    def emit_cronus_diff_completed(
        self,
        target: str,
        deleted_count: int,
        stable_count: int,
        added_count: int,
        modified_count: int,
        confidence: Optional[float] = None
    ):
        """Emit CRONUS_DIFF_COMPLETED event when sitemap comparison finishes."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_DIFF_COMPLETED,
            payload={
                "target": target,
                "deleted_count": deleted_count,
                "stable_count": stable_count,
                "added_count": added_count,
                "modified_count": modified_count,
                "confidence": confidence,
            }
        ))

    def emit_cronus_hunt_started(self, target: str, candidate_count: int):
        """Emit CRONUS_HUNT_STARTED event when zombie hunting begins."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_HUNT_STARTED,
            payload={
                "target": target,
                "candidate_count": candidate_count,
            }
        ))

    def emit_cronus_hunt_completed(
        self,
        target: str,
        confirmed: int,
        denied: int,
        dead: int,
        duration_ms: Optional[int] = None
    ):
        """Emit CRONUS_HUNT_COMPLETED event when zombie hunting finishes."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_HUNT_COMPLETED,
            payload={
                "target": target,
                "confirmed": confirmed,
                "denied": denied,
                "dead": dead,
                "duration_ms": duration_ms,
            }
        ))

    def emit_cronus_zombie_confirmed(
        self,
        path: str,
        status_code: int,
        method: Optional[str] = None,
        confidence: Optional[float] = None
    ):
        """Emit CRONUS_ZOMBIE_CONFIRMED event when zombie endpoint is verified active."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_ZOMBIE_CONFIRMED,
            payload={
                "path": path,
                "method": method,
                "status_code": status_code,
                "confidence": confidence,
            }
        ))

    def emit_cronus_zombie_denied(
        self,
        path: str,
        status_code: int,
        method: Optional[str] = None
    ):
        """Emit CRONUS_ZOMBIE_DENIED event when zombie endpoint requires auth."""
        self.emit(GraphEvent(
            type=GraphEventType.CRONUS_ZOMBIE_DENIED,
            payload={
                "path": path,
                "method": method,
                "status_code": status_code,
            }
        ))

# --- Singleton Accessor ---

_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Function get_event_bus."""
    global _event_bus
    # Conditional branch.
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def reset_event_sequence() -> None:
    """
    Reset the global event sequence counter.

    WARNING: This should ONLY be used in tests!
    In production, the sequence counter should never be reset.

    IMPLEMENTATION NOTE:
    Delegates to GlobalSequenceAuthority.reset_for_testing().
    """
    from core.base.sequence import GlobalSequenceAuthority
    GlobalSequenceAuthority.reset_for_testing()


# ============================================================================
# CONTRACT CONFIGURATION
# ============================================================================
# By default, contract validation is NON-STRICT in production to avoid
# breaking existing code during the migration period. Tests can enable
# strict mode to catch contract violations early.
#
# To enable strict mode (recommended for development):
#     from core.cortex.events import set_strict_contract_mode
#     set_strict_contract_mode(True)
# ============================================================================

def set_strict_contract_mode(strict: bool) -> None:
    """
    Enable or disable strict contract validation mode.

    Args:
        strict: True = raise ContractViolation on invalid events (dev)
                False = log warning but continue (prod, default)
    """
    EventContract.set_strict_mode(strict)


def reset_contract_state() -> None:
    """
    Reset the causal tracker state.

    WARNING: This should ONLY be used in tests!
    Resets the tracker that enforces tool_started → tool_completed ordering.
    """
    EventContract.reset_causal_state()


# Initialize contract to non-strict mode for backward compatibility
# Tests should call set_strict_contract_mode(True) to enable strict validation
EventContract.set_strict_mode(False)
