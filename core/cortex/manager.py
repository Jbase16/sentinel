# core/cortex/manager.py

"""
core/cortex/manager.py
NexusManager: The Kernel Scheduler for Reasoning.

This module provides the singleton manager that:
1. Subscribes to the EventBus.
2. Manages the lifecycle of NexusSessions (creation/destruction).
3. Routes events safely to the correct session based on scan_id.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from core.contracts.events import EventType
from core.cortex.events import EventBus, GraphEvent, get_event_bus
from core.cortex.session import NexusSession
from core.cortex.subscriptions import SubscriptionHandle, subscribe_safe

logger = logging.getLogger(__name__)


class NexusManager:
    """
    Singleton service that routes events to isolated NexusSessions.
    """

    def __init__(self, event_bus: Optional[EventBus] = None):
        self.bus = event_bus or get_event_bus()
        self.sessions: Dict[str, NexusSession] = {}
        self._subscription: Optional[SubscriptionHandle] = None

    def start(self) -> None:
        """Start the manager and subscribe to events."""
        if self._subscription is not None:
            return

        self._subscription = subscribe_safe(
            self.bus,
            self._handle_event,
            event_types=None,  # wildcard routing
            name="nexus.manager",
            critical=True,
        )
        logger.info("[NexusManager] Started and subscribed to EventBus")

    def stop(self) -> None:
        """Stop the manager and cleanup all sessions."""
        self.close_all_sessions(reason="Shutdown")
        if self._subscription is not None:
            try:
                self._subscription.unsubscribe()
            finally:
                self._subscription = None

    def close_all_sessions(self, reason: str = "") -> None:
        """Force close all active sessions."""
        for scan_id, session in list(self.sessions.items()):
            try:
                session.shutdown()
            finally:
                self.sessions.pop(scan_id, None)
        if reason:
            logger.info(f"[NexusManager] Closed all sessions. Reason: {reason}")

    async def _handle_event(self, event: GraphEvent) -> None:
        """
        Main Event Handler / Router.

        Strictly enforces isolation:
        1. Extract scan_id from payload.
        2. If missing -> Drop/Orphan/Violation.
        3. Route to session.
        """
        try:
            event_type = event.type
            payload = event.payload or {}

            # --- Global Lifecycle Events ---
            if event_type == EventType.SCAN_STARTED:
                scan_id = payload.get("session_id") or payload.get("scan_id")
                if not scan_id:
                    self._emit_violation(event, "Missing session_id/scan_id in SCAN_STARTED")
                    return

                if scan_id in self.sessions:
                    self._emit_violation(event, f"Duplicate SCAN_STARTED for {scan_id}")
                    return

                self._create_session(scan_id)
                self.sessions[scan_id].apply(event_type, payload, event.event_sequence)
                return

            if event_type == EventType.SCAN_COMPLETED:
                scan_id = payload.get("session_id") or payload.get("scan_id")
                if not scan_id:
                    return

                session = self.sessions.get(scan_id)
                if session:
                    session.apply(event_type, payload, event.event_sequence)
                    session.shutdown()
                    del self.sessions[scan_id]
                return

            # --- Routing Logic for Standard Events ---
            scan_id = payload.get("scan_id") or payload.get("session_id") or getattr(event, "scan_id", None)

            if not scan_id:
                # Drop truly global noise. Flag operational orphans.
                if (
                    "target" in payload
                    or "tool" in payload
                    or event_type in {EventType.TOOL_STARTED, EventType.FINDING_CREATED}
                ):
                    self._emit_orphan(event_type, None, "Missing scan_id in payload")
                return

            session = self.sessions.get(scan_id)
            if session:
                session.apply(event_type, payload, event.event_sequence)
            else:
                self._emit_orphan(event_type, scan_id, f"Session {scan_id} not found (zombie/late event)")

        except Exception as e:
            logger.error(f"[NexusManager] Error handling event: {e}", exc_info=True)

    def _emit_orphan(self, original_type: EventType, scan_id: Optional[str], reason: str) -> None:
        """
        Emit a diagnostic event for dropped orphans.

        Marked _internal=True to prevent recursion loops.
        """
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
                    _internal=True,
                )
            )
        except Exception as e:
            logger.warning(f"[NexusManager] Failed to emit orphan event: {e}")

    def _create_session(self, scan_id: str) -> None:
        """Initialize a new NexusSession."""
        session = NexusSession(scan_id=scan_id, emit_fn=self._emit_from_session)
        self.sessions[scan_id] = session

        # Emit Context Attached Event
        self._emit_from_session(
            EventType.NEXUS_CONTEXT_ATTACHED,
            {"scan_id": scan_id, "timestamp": time.time(), "mode": "omega"},
        )
        logger.info(f"[NexusManager] Created session for scan_id={scan_id}")

    def _emit_from_session(self, event_type: EventType, payload: Dict[str, Any]) -> None:
        """Callback for sessions to emit events safely."""
        self.bus.emit(GraphEvent(type=event_type, payload=payload))

    def _emit_violation(self, source_event: GraphEvent, reason: str) -> None:
        """
        Emit a contract violation for routing failures.

        Marked _internal=True to prevent recursion loops.
        """
        self.bus.emit(
            GraphEvent(
                type=EventType.CONTRACT_VIOLATION,
                payload={
                    "offending_event_type": source_event.type.value,
                    "violations": [reason],
                    "context": {"router": "NexusManager"},
                },
                _internal=True,
            )
        )