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
import time
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

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
    """Class GraphEvent."""
    type: GraphEventType
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

class EventBus:
    """
    Synchronous Event Bus for strategic observability.
    """
    def __init__(self):
        self._subscribers: List[Callable[[GraphEvent], None]] = []

    def subscribe(self, callback: Callable[[GraphEvent], None]):
        """Function subscribe."""
        self._subscribers.append(callback)

    def emit(self, event: GraphEvent):
        """Broadcast event to all subscribers."""
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

# --- Singleton Accessor ---

_event_bus: Optional[EventBus] = None

def get_event_bus() -> EventBus:
    """Function get_event_bus."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus
