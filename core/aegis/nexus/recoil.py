# core/aegis/nexus/recoil.py

from __future__ import annotations

import logging
from typing import Optional

from core.cortex.events import EventBus, GraphEvent, get_event_bus

logger = logging.getLogger(__name__)


class Recoil:
    """
    Recoil is the reflex / reactive layer of Nexus.

    It listens to high-signal events and triggers secondary reasoning,
    escalation, or stabilization behaviors.

    IMPORTANT:
    - Recoil must NEVER block the EventBus.
    - All handlers are async and non-causal.
    - Recoil MUST NOT reference EventType members that may not exist.
      (This module must be safe against enum drift.)
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

        self._subscription = self.bus.subscribe_async(
            self._handle_event,
            event_types=None,  # wildcard
            name="nexus.recoil",
            critical=True,
        )

        logger.info("[Recoil] Subscribed to EventBus")

    def stop(self) -> None:
        if self._subscription is not None:
            self._subscription.unsubscribe()
            self._subscription = None
            logger.info("[Recoil] Unsubscribed from EventBus")

    async def _handle_event(self, event: GraphEvent) -> None:
        """
        Async reflex handler.

        NEVER raise from here — failures are tracked by EventBus metrics.

        NOTE:
        This handler intentionally avoids referencing EventType.* attributes directly
        to prevent crashes when enums evolve. If you want to add reflex rules, do it
        using string comparisons on event.type/value, or guarded getattr checks.
        """
        try:
            # Normalize event type to a stable string without assuming enum members exist.
            et = getattr(event, "type", None)

            if et is None:
                return

            # `event.type` may be an Enum or a raw string depending on caller.
            if isinstance(et, str):
                et_name = et
            else:
                et_name = getattr(et, "value", None) or getattr(et, "name", None) or str(et)

            # ----------------------------
            # Reflex rules (SAFE / GUARDED)
            # ----------------------------
            # Only handle events we can identify without importing unknown enum members.
            # Keep this list tight; expand deliberately.

            if et_name in {"CONTRACT_VIOLATION", "ORPHAN_EVENT_DROPPED"}:
                scan_id = getattr(event, "scan_id", None)
                seq = getattr(event, "event_sequence", None)
                logger.warning(
                    "[Recoil] Governance signal: %s scan_id=%s seq=%s payload=%s",
                    et_name,
                    scan_id,
                    seq,
                    getattr(event, "payload", None),
                )
                return

            # Example: tool churn / silence (if present in your EventType set)
            if et_name in {"EVENT_SILENCE", "TOOL_CHURN"}:
                scan_id = getattr(event, "scan_id", None)
                logger.info(
                    "[Recoil] Operational signal: %s scan_id=%s payload=%s",
                    et_name,
                    scan_id,
                    getattr(event, "payload", None),
                )
                return

            # Default: ignore everything else (wildcard subscription is intentional)
            return

        except Exception as e:
            # Never let Recoil crash the pipeline
            logger.exception("[Recoil] Handler failure: %s", e)