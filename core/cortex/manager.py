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
from core.contracts.events import EventType
from core.cortex.session import NexusSession

logger = logging.getLogger(__name__)


class NexusManager:
    """
    Singleton service that routes events to isolated NexusSessions.
    """

    def __init__(self, event_bus: Optional[EventBus] = None):
        self.bus: EventBus = event_bus or get_event_bus()
        self.sessions: Dict[str, NexusSession] = {}
        self._subscription = None

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------
    def start(self) -> None:
        """Start the manager and subscribe to the EventBus."""
        if self._subscription is not None:
            return

        self._subscription = self.bus.subscribe_sync(
            self._handle_event,
            event_types=None,  # wildcard — routing logic enforces isolation
            name="nexus.manager",
            critical=True,
        )

        logger.info("[NexusManager] Started and subscribed to EventBus")

    def stop(self) -> None:
        """Stop the manager and cleanup all sessions."""
        if self._subscription is not None:
            self._subscription.unsubscribe()
            self._subscription = None

        self.close_all_sessions(reason="Shutdown")
        logger.info("[NexusManager] Stopped")

    def close_all_sessions(self, reason: str = "") -> None:
        """Force close all active sessions."""
        for scan_id, session in list(self.sessions.items()):
            session.shutdown()
            del self.sessions[scan_id]

        if reason:
            logger.info(f"[NexusManager] Closed all sessions. Reason: {reason}")

    # ---------------------------------------------------------------------
    # Event Routing
    # ---------------------------------------------------------------------
    def _handle_event(self, event: GraphEvent) -> None:
        """
        Main Event Handler / Router.

        Strict guarantees:
        - Session lifecycle is driven ONLY by SCAN_STARTED / SCAN_COMPLETED
        - All routed events MUST carry scan_id
        - Orphans are detected and explicitly emitted
        """
        try:
            event_type = event.type
            scan_id = event.scan_id

            # -------------------------------------------------------------
            # Lifecycle events
            # -------------------------------------------------------------
            if event_type == EventType.SCAN_STARTED:
                if not scan_id:
                    self._emit_violation(event, "SCAN_STARTED missing scan_id")
                    return

                if scan_id in self.sessions:
                    self._emit_violation(event, f"Duplicate SCAN_STARTED for {scan_id}")
                    return

                self._create_session(scan_id)
                self.sessions[scan_id].apply(event_type, event.payload, event.event_sequence)
                return

            if event_type == EventType.SCAN_COMPLETED:
                if not scan_id:
                    return

                session = self.sessions.get(scan_id)
                if session:
                    session.apply(event_type, event.payload, event.event_sequence)
                    session.shutdown()
                    del self.sessions[scan_id]
                return

            # -------------------------------------------------------------
            # Standard routed events
            # -------------------------------------------------------------
            if not scan_id:
                # Global or malformed event — detect only meaningful orphans
                if event_type in {
                    EventType.TOOL_STARTED,
                    EventType.TOOL_COMPLETED,
                    EventType.FINDING_CREATED,
                }:
                    self._emit_orphan(event_type, None, "Missing scan_id on routable event")
                return

            session = self.sessions.get(scan_id)
            if session:
                session.apply(event_type, event.payload, event.event_sequence)
            else:
                self._emit_orphan(
                    event_type,
                    scan_id,
                    f"Session {scan_id} not found (late or zombie event)",
                )

        except Exception as e:
            logger.error("[NexusManager] Error handling event", exc_info=True)

    # ---------------------------------------------------------------------
    # Session Management
    # ---------------------------------------------------------------------
    def _create_session(self, scan_id: str) -> None:
        """Initialize a new NexusSession."""
        session = NexusSession(
            scan_id=scan_id,
            emit_fn=self._emit_from_session,
        )
        self.sessions[scan_id] = session

        # Phase-0 invariant: context attachment is explicit and observable
        self._emit_from_session(
            EventType.NEXUS_CONTEXT_ATTACHED,
            {
                "scan_id": scan_id,
                "timestamp": time.time(),
                "mode": "omega",
            },
        )

        logger.info(f"[NexusManager] Created session for scan_id={scan_id}")

    # ---------------------------------------------------------------------
    # Emission Helpers
    # ---------------------------------------------------------------------
    def _emit_from_session(self, event_type: EventType, payload: Dict[str, Any]) -> None:
        """Emit events originating from a NexusSession."""
        self.bus.emit(
            GraphEvent(
                type=event_type,
                payload=payload,
                scan_id=payload.get("scan_id"),
                source="nexus",
            )
        )

    def _emit_orphan(self, original_type: EventType, scan_id: Optional[str], reason: str) -> None:
        """Emit a diagnostic orphan event (internal, non-recursive)."""
        try:
            self.bus.emit(
                GraphEvent(
                    type=EventType.ORPHAN_EVENT_DROPPED,
                    payload={
                        "original_event_type": original_type.value,
                        "scan_id": scan_id,
                        "reason": reason,
                        "source_component": "NexusManager",
                        "mode": "omega",
                    },
                    scan_id=scan_id,
                    source="nexus",
                    _internal=True,
                )
            )
        except Exception as e:
            logger.warning(f"[NexusManager] Failed to emit orphan event: {e}")

    def _emit_violation(self, source_event: GraphEvent, reason: str) -> None:
        """Emit a contract violation without recursion."""
        self.bus.emit(
            GraphEvent(
                type=EventType.CONTRACT_VIOLATION,
                payload={
                    "offending_event_type": source_event.type.value,
                    "violations": [reason],
                    "context": {"router": "NexusManager"},
                },
                scan_id=source_event.scan_id,
                source="nexus",
                _internal=True,
            )
        )
