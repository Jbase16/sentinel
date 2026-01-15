# core/aegis/nexus/recoil.py

from __future__ import annotations

import logging
from typing import Optional

from core.cortex.events import EventBus, GraphEvent, get_event_bus
from core.contracts.events import EventType

logger = logging.getLogger(__name__)


class Recoil:
    """
    Recoil is the reflex / reactive layer of Nexus.

    It listens to high-signal events and triggers secondary reasoning,
    escalation, or stabilization behaviors.

    IMPORTANT:
    - Recoil must NEVER block the EventBus.
    - All handlers are async and non-causal.
    """

    def __init__(self, bus: Optional[EventBus] = None):
        self.bus = bus or get_event_bus()
        self._subscription = None

    def start(self) -> None:
        """
        Attach Recoil to the EventBus.

        This MUST use subscribe_async — the old subscribe() API no longer exists.
        """
        if self._subscription is not None:
            return

        subscribe_async = getattr(self.bus, "subscribe_async", None)
        if subscribe_async is None:
            raise RuntimeError("EventBus has no subscribe_async() method")

        self._subscription = subscribe_async(
            self._handle_event,
            event_types=None,  # wildcard
            name="nexus.recoil",
            critical=True,
        )

        logger.info("[Recoil] Subscribed to EventBus")

    def stop(self) -> None:
        if self._subscription is not None:
            try:
                self._subscription.unsubscribe()
            finally:
                self._subscription = None
            logger.info("[Recoil] Unsubscribed from EventBus")

    async def _handle_event(self, event: GraphEvent) -> None:
        """
        Async reflex handler.

        NEVER raise from here — failures are tracked by EventBus metrics.
        """
        try:
            # -----------------------------------------------------------------
            # IMPORTANT: No speculative EventTypes. If it isn't in the contract,
            # it doesn't exist. Guard optional/legacy events explicitly.
            # -----------------------------------------------------------------

            # Example pattern for an optional event type:
            # if hasattr(EventType, "BREACH_DETECTED") and event.type == EventType.BREACH_DETECTED:
            #     logger.warning(f"[Recoil] Breach detected: scan_id={event.scan_id} entity={event.entity_id}")

            # Add real reflex rules here, using ONLY contract-defined EventTypes.

            return

        except Exception as e:
            logger.exception(f"[Recoil] Handler failure: {e}")