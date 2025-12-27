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

from __future__ import annotations

import logging
import threading
import time
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# Global event sequence counter - thread-safe singleton
_event_sequence_lock = threading.Lock()
_event_sequence_counter = 0


def _next_event_sequence() -> int:
    """
    Get the next global event sequence number.

    This is a monotonically increasing counter that provides:
    - Total ordering of all events (even with identical timestamps)
    - Cross-correlation between events and decisions
    - Debugging capability to reconstruct exact event flow

    Thread-safe via lock to ensure no sequence numbers are skipped/duplicated.
    """
    global _event_sequence_counter
    with _event_sequence_lock:
        _event_sequence_counter += 1
        return _event_sequence_counter

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
    event_sequence: int = field(default_factory=_next_event_sequence)

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
