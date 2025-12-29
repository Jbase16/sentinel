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

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, field
from enum import Enum

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

class GraphEventType(str, Enum):
    """
    Taxonomy of observable events.
    """
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_PHASE_CHANGED = "scan_phase_changed"
    DECISION_MADE = "decision_made"
    TOOL_STARTED = "tool_started"
    TOOL_COMPLETED = "tool_completed"
    FINDING_CREATED = "finding_created"
    NARRATIVE_EMITTED = "narrative_emitted"
    LOG = "log"  # System/session logging

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
    """
    def __init__(self):
        """Function __init__."""
        self._subscribers: List[Callable[[GraphEvent], None]] = []
        self._last_event_sequence: int = 0  # Track last sequence for diagnostics

    def subscribe(self, callback: Callable[[GraphEvent], None]):
        """Function subscribe."""
        self._subscribers.append(callback)

    @property
    def last_event_sequence(self) -> int:
        """Get the sequence number of the last emitted event."""
        return self._last_event_sequence

    def emit(self, event: GraphEvent):
        """Broadcast event to all subscribers."""
        # Track last sequence for diagnostics
        self._last_event_sequence = event.event_sequence

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
