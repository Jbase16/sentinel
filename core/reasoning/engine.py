"""
core/reasoning/engine.py

ReasoningEngine
---------------
High-level reasoning coordinator that consumes Cortex + Mimic signals
and produces hypotheses, insights, and escalations.

This engine is NON-CAUSAL:
- It must never block the EventBus
- All handlers are async
"""

from __future__ import annotations

import logging
from typing import Optional, Dict, Any, List

from core.contracts.events import EventType
from core.cortex.events import (
    EventBus,
    GraphEvent,
    get_event_bus,
    SubscriptionHandle,
)

logger = logging.getLogger(__name__)


class ReasoningEngine:
    """
    Singleton reasoning engine.
    """

    _instance: Optional["ReasoningEngine"] = None

    def __init__(self, bus: EventBus):
        self._bus = bus
        self._subscriptions: List[SubscriptionHandle] = []
        self._started: bool = False

    # ------------------------------------------------------------------
    # Singleton access
    # ------------------------------------------------------------------

    @classmethod
    def get(cls, bus: Optional[EventBus] = None) -> "ReasoningEngine":
        if cls._instance is None:
            cls._instance = cls(bus=bus or get_event_bus())
        return cls._instance

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._started:
            return

        self._subscriptions.append(
            self._bus.subscribe_async(
                self._on_mimic_route,
                [EventType.MIMIC_ROUTE_FOUND, EventType.MIMIC_HIDDEN_ROUTE_FOUND],
                name="reasoning.mimic_routes",
                critical=False,
            )
        )

        self._subscriptions.append(
            self._bus.subscribe_async(
                self._on_mimic_secret,
                [EventType.MIMIC_SECRET_FOUND],
                name="reasoning.mimic_secrets",
                critical=False,
            )
        )

        self._started = True
        logger.info("[ReasoningEngine] Started and subscribed to EventBus")

    def shutdown(self) -> None:
        for sub in self._subscriptions:
            sub.unsubscribe()
        self._subscriptions.clear()
        self._started = False
        logger.info("[ReasoningEngine] Shutdown complete")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _on_mimic_route(self, event: GraphEvent) -> None:
        """
        Handle discovered routes (static or hidden).
        """
        scan_id = event.scan_id
        payload = event.payload or {}

        if not scan_id:
            return

        route = payload.get("route")
        source = payload.get("source")

        if not isinstance(route, str):
            return

        logger.info(
            "[ReasoningEngine] Route observed",
            extra={
                "scan_id": scan_id,
                "route": route,
                "source": source,
            },
        )

        # Placeholder: future hypothesis generation goes here

    async def _on_mimic_secret(self, event: GraphEvent) -> None:
        """
        Handle discovered secrets.
        """
        scan_id = event.scan_id
        payload = event.payload or {}

        if not scan_id:
            return

        secret_type = payload.get("type")
        confidence = payload.get("confidence")

        logger.warning(
            "[ReasoningEngine] Potential secret detected",
            extra={
                "scan_id": scan_id,
                "type": secret_type,
                "confidence": confidence,
            },
        )

        # Placeholder: escalation / correlation logic goes here