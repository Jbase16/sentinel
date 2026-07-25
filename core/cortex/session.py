"""
core/cortex/session.py
NexusSession: The Per-Scan Nervous System.

This module defines the isolated state container for a single scan.
It holds the knowledge graph, hypotheses, and observer state for exactly ONE scan_id.

INVARIANTS:
1. No global access. Created/owned by NexusManager.
2. Event-driven. Only mutates state via apply_event().
3. No side effects. Emits events via a callback.
"""

import logging
import time
from typing import Dict, Any, Optional, Callable, List
from asyncio import TimerHandle, get_running_loop

from core.contracts.events import EventType

logger = logging.getLogger(__name__)

class NexusSession:
    """
    Isolated state for a single scan's reasoning engine.
    """
    def __init__(
        self, 
        scan_id: str, 
        emit_fn: Callable[[EventType, Dict[str, Any]], None]
    ):
        self.scan_id = scan_id
        self._emit = emit_fn
        
        # Lifecycle Metadata
        self.created_at = time.time()
        self.last_event_at = self.created_at
        self.event_seq_last_seen = 0
        
        # Knowledge State (Placeholder for full graph)
        # In a real implementation, this would be a networkx graph or similar structure
        self.knowledge = {
            "findings": set(),
            "hypotheses": {},
            "entities": set()
        }
        
        # Observer State
        self.last_progress_at = self.created_at
        self.last_progress_event_type = EventType.SCAN_STARTED.value
        self._silence_timer: Optional[TimerHandle] = None
        
        # Churn Tracking
        # List of (timestamp, tool_name)
        self._tool_starts: List[tuple[float, str]] = []

    def apply(self, event_type: EventType, payload: Dict[str, Any], sequence: int) -> None:
        """
        Apply an event to the session state.
        
        Args:
            event_type: Type of event
            payload: Event data
            sequence: Global event sequence number
        """
        # 1. Update Metadata
        self.last_event_at = time.time()
        
        # Detect out-of-order (optional, but good for diagnostics)
        if sequence <= self.event_seq_last_seen and sequence > 0:
            logger.warning(
                f"[Nexus:{self.scan_id}] Out-of-order event: {sequence} <= {self.event_seq_last_seen}"
            )
        self.event_seq_last_seen = sequence
        
        # 2. Progress Tracking (Observer)
        if self._is_progress_event(event_type):
            self._record_progress(event_type)
            
        # 3. Churn Tracking (Observer)
        if event_type == EventType.TOOL_STARTED:
            self._record_tool_start(payload.get("tool", "unknown"))
            
        if event_type == EventType.FINDING_CREATED:
            # Findings reset churn worry
            # In a real implementation, we might be more sophisticated
            pass

        # 4. Domain Logic (Delegated)
        self._route_domain_logic(event_type, payload)

    def shutdown(self):
        """Cleanup resources (timers, etc)."""
        if self._silence_timer:
            self._silence_timer.cancel()
            self._silence_timer = None
        logger.info(f"[Nexus:{self.scan_id}] Session destroyed. Lifespan: {time.time() - self.created_at:.2f}s")

    # --- Observer Logic ---

    def _is_progress_event(self, event_type: EventType) -> bool:
        """Does this event constitute 'progress'?"""
        return event_type in {
            EventType.FINDING_CREATED,
            EventType.TOOL_COMPLETED,
            EventType.NEXUS_HYPOTHESIS_FORMED,
            EventType.SCAN_STARTED # Initial progress
        }

    def _record_progress(self, event_type: EventType):
        """Update progress timestamp and reset silence timer."""
        self.last_progress_at = time.time()
        self.last_progress_event_type = event_type.value
        
        # Reset Silence Timer
        if self._silence_timer:
            self._silence_timer.cancel()
        
        # Schedule next check (e.g., 30 seconds silence threshold)
        # In prod, this might be configurable per scan profile
        TIMEOUT = 30.0 
        loop = get_running_loop()
        self._silence_timer = loop.call_later(TIMEOUT, self._on_silence_timeout)

    def _on_silence_timeout(self):
        """Callback when silence threshold is reached."""
        # Double check strictly
        now = time.time()
        silence_duration = now - self.last_progress_at
        
        if silence_duration >= 29.0: # Allow small jitter
            self._emit(EventType.EVENT_SILENCE, {
                "scan_id": self.scan_id,
                "mode": "omega", # In Phase 4 we'll get this from config
                "silence_seconds": silence_duration,
                "last_progress_event_type": self.last_progress_event_type,
                "last_progress_at": self.last_progress_at
            })

    def _record_tool_start(self, tool: str):
        """Track high frequency tool starts."""
        now = time.time()
        self._tool_starts.append((now, tool))
        
        # Prune old entries (Window = 10s)
        WINDOW = 10.0
        cutoff = now - WINDOW
        self._tool_starts = [t for t in self._tool_starts if t[0] > cutoff]
        
        # Check Churn logic: Only if we have implicit context of "0 findings"
        # Since this class doesn't strictly track finding counts per window yet,
        # we'll implement a simple heuristic: > 5 tools in 10s is suspicious
        if len(self._tool_starts) > 5:
             self._emit(EventType.TOOL_CHURN, {
                "scan_id": self.scan_id,
                "mode": "omega",
                "tool_started_count": len(self._tool_starts),
                "window_seconds": WINDOW,
                "findings_in_window": 0, # Placeholder
                "is_assumed_zero_findings": True
            })

    # --- Domain Logic ---

    def _route_domain_logic(self, event_type: EventType, payload: Dict[str, Any]):
        """Route to specific handlers."""
        # This is where we will eventually plug in the Attack Path synthesis
        # For Phase 1, we just maintain the graph state stubs
        if event_type == EventType.FINDING_CREATED:
            self.knowledge["findings"].add(payload.get("finding_id"))
