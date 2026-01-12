"""
core/cortex/manager.py
NexusManager: The Kernel Scheduler for Reasoning.

This module provides the singleton manager that:
1. Subscribes to the EventBus.
2. Manages the lifecycle of NexusSessions (creation/destruction).
3. Routes events safely to the correct session based on scan_id.
"""

import logging
import time
from typing import Dict, Optional, Any
from core.cortex.events import EventBus, GraphEvent, get_event_bus
from core.contracts.events import EventType, EventContract
from core.cortex.session import NexusSession

logger = logging.getLogger(__name__)

class NexusManager:
    """
    Singleton service that routes events to isolated NexusSessions.
    """
    def __init__(self, event_bus: Optional[EventBus] = None):
        self.bus = event_bus or get_event_bus()
        self.sessions: Dict[str, NexusSession] = {}
        self._subscribed = False

    def start(self):
        """Start the manager and subscribe to events."""
        if not self._subscribed:
            self.bus.subscribe(self._handle_event)
            self._subscribed = True
            logger.info("[NexusManager] Started and subscribed to EventBus.")

    def stop(self):
        """Stop the manager and cleanup all sessions."""
        self.close_all_sessions(reason="Shutdown")
        # Note: EventBus doesn't support unsubscribe easily, 
        # so we rely on the fact that the process is likely dying.
        # Ideally we would unsubscribe here.
        self._subscribed = False

    def close_all_sessions(self, reason: str = ""):
        """Force close all active sessions."""
        for scan_id, session in list(self.sessions.items()):
            session.shutdown()
            del self.sessions[scan_id]
        if reason:
            logger.info(f"[NexusManager] Closed all sessions. Reason: {reason}")

    def _handle_event(self, event: GraphEvent):
        """
        Main Event Handler / Router.
        
        Strictly enforces isolation:
        1. Extract scan_id from payload.
        2. If missing -> Drop/Violate.
        3. Route to session.
        """
        try:
            event_type = event.type
            payload = event.payload
            
            # --- Global Lifecycle Events ---
            # These determine session creation/destruction
            
            if event_type == EventType.SCAN_STARTED:
                scan_id = payload.get("session_id")
                if not scan_id:
                     self._emit_violation(event, "Missing session_id in SCAN_STARTED")
                     return
                
                # Check for duplicate
                if scan_id in self.sessions:
                     self._emit_violation(event, f"Duplicate SCAN_STARTED for {scan_id}")
                     return

                # Create Session (Lifecycle Hook)
                self._create_session(scan_id)
                # Apply the event to the new session
                self.sessions[scan_id].apply(event_type, payload, event.event_sequence)
                return

            if event_type == EventType.SCAN_COMPLETED:
                scan_id = payload.get("session_id")
                if not scan_id:
                     # Attempt to find from context? No, strict.
                     return
                
                session = self.sessions.get(scan_id)
                if session:
                    session.apply(event_type, payload, event.event_sequence)
                    session.shutdown()
                    del self.sessions[scan_id]
                return

            # --- Routing Logic for Standard Events ---
            
            # Extract scan_id (We check 'session_id' and 'scan_id')
            scan_id = payload.get("scan_id") or payload.get("session_id")
            
            if not scan_id:
                # Some events are truly global (e.g. LOG, SYSTEM_STARTUP). 
                # We ignore those safely, but specifically monitor "operational" events
                # that SHOULD have a context.
                if "target" in payload or "tool" in payload or event_type in {EventType.TOOL_STARTED, EventType.FINDING_CREATED}:
                     self._emit_orphan(event_type, scan_id, "Missing scan_id in payload")
                return

            session = self.sessions.get(scan_id)
            if session:
                session.apply(event_type, payload, event.event_sequence)
            else:
                # Event for a scan that doesn't exist (orphaned or late)
                # This prevents "zombie" events allowing logic to run context-free
                self._emit_orphan(event_type, scan_id, f"Session {scan_id} not found (zombie/late event)")

        except Exception as e:
            logger.error(f"[NexusManager] Error handling event: {e}", exc_info=True)

    def _emit_orphan(self, original_type: EventType, scan_id: Optional[str], reason: str):
        """
        Emit a diagnostic event for dropped orphans.
        
        NOTE: This event is marked as _internal=True to prevent recursion loops.
        The ORPHAN_EVENT_DROPPED event bypasses wildcard subscribers, preventing
        the feedback loop where orphan handlers re-emit events that become orphans.
        """
        try:
            self.bus.emit(GraphEvent(
                type=EventType.ORPHAN_EVENT_DROPPED,
                payload={
                    "original_event_type": original_type.value,
                    "scan_id": scan_id,
                    "reason": reason,
                    "source_component": "NexusManager",
                    "mode": "omega" # Default
                },
                _internal=True  # Prevent recursion by bypassing wildcard subscribers
            ))
        except Exception as e:
            logger.warning(f"[NexusManager] Failed to emit orphan event: {e}")

    def _create_session(self, scan_id: str):
        """Initialize a new NexusSession."""
        session = NexusSession(
            scan_id=scan_id,
            emit_fn=self._emit_from_session
        )
        self.sessions[scan_id] = session
        
        # Emit Context Attached Event (Phase 0 Requirement)
        self._emit_from_session(EventType.NEXUS_CONTEXT_ATTACHED, {
            "scan_id": scan_id,
            "timestamp": time.time(),
            "mode": "omega" # TODO: get from scan config
        })
        logger.info(f"[NexusManager] Created session for {scan_id}")

    def _emit_from_session(self, event_type: EventType, payload: Dict[str, Any]):
        """Callback for sessions to emit events safely."""
        self.bus.emit(GraphEvent(
            type=event_type,
            payload=payload
        ))

    def _emit_violation(self, source_event: GraphEvent, reason: str):
        """Emit a contract violation for routing failures."""
        # Use the manager's bus access to emit
        self.bus.emit(GraphEvent(
            type=EventType.CONTRACT_VIOLATION,
            payload={
                "offending_event_type": source_event.type.value,
                "violations": [reason],
                "context": {"router": "NexusManager"}
            }
        ))
