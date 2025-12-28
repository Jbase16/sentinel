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

from __future__ import annotations

import logging
import threading
import time
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# Global event sequence counter - thread-safe singleton with persistence
_event_sequence_lock = threading.Lock()
_event_sequence_counter = 0
_event_sequence_initialized = False  # Track if we've loaded from DB


async def initialize_event_sequence_from_db() -> int:
    """
    Initialize the global event sequence counter from the database.

    This MUST be called during application startup (before any events are emitted)
    to ensure the counter starts from the last persisted value, maintaining
    continuity across restarts.

    Returns:
        The loaded sequence number (0 if no persisted value exists)

    Side effects:
        - Sets the global _event_sequence_counter from the database
        - Marks the counter as initialized
    """
    global _event_sequence_counter, _event_sequence_initialized

    with _event_sequence_lock:
        if _event_sequence_initialized:
            return _event_sequence_counter

        try:
            from core.data.db import Database
            db = Database.instance()
            # The database needs to be initialized first
            persisted = await db.get_event_sequence()
            _event_sequence_counter = persisted
            _event_sequence_initialized = True

            if persisted > 0:
                logger.info(f"[EventBus] Loaded event sequence from database: {persisted}")
            else:
                logger.debug("[EventBus] No persisted event sequence found, starting from 0")

            return _event_sequence_counter
        except Exception as e:
            logger.warning(f"[EventBus] Failed to load event sequence from DB: {e}, starting from 0")
            _event_sequence_counter = 0
            _event_sequence_initialized = True
            return 0


def get_next_sequence() -> int:
    """
    Get the next global event sequence number.

    This is a monotonically increasing counter that provides:
    - Total ordering of all events (even with identical timestamps)
    - Cross-correlation between events and decisions
    - Debugging capability to reconstruct exact event flow
    - Continuity across process restarts (via persistence)

    Thread-safe via lock to ensure no sequence numbers are skipped/duplicated.

    Returns:
        The next sequence number

    Raises:
        RuntimeError: If initialize_event_sequence_from_db() was not called first

    Side effects:
        - Persists the new sequence number to the database (fire-and-forget)
        - This is async but non-blocking; if persistence fails, we still return the sequence
    """
    global _event_sequence_counter, _event_sequence_initialized

    # Enforce initialization to prevent silent corruption
    # If events are emitted before startup completes, we want to fail loudly
    # rather than produce duplicate IDs after restart
    if not _event_sequence_initialized:
        raise RuntimeError(
            "Event sequence not initialized. "
            "Call initialize_event_sequence_from_db() during startup."
        )

    with _event_sequence_lock:
        _event_sequence_counter += 1
        sequence = _event_sequence_counter

    # Persist asynchronously (fire-and-forget to avoid blocking event emission)
    # If this fails, we still have the correct in-memory value
    try:
        from core.data.db import Database
        Database.instance().save_event_sequence(sequence)
    except Exception as e:
        # Log but don't fail - the in-memory counter is still correct
        logger.debug(f"[EventBus] Failed to persist sequence {sequence}: {e}")

    return sequence

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

    The event_sequence enables:
    - Total ordering of events regardless of clock skew
    - Cross-correlation: decisions can reference specific events
    - Debugging: reconstruct exact event flow from logs
    """
    type: GraphEventType
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    event_sequence: int = field(default_factory=get_next_sequence)

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
    """
    global _event_sequence_counter
    with _event_sequence_lock:
        _event_sequence_counter = 0
