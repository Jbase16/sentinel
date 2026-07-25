"""
core/mimic/manager.py

MimicManager
------------
Asset ingestion + mining coordinator for downloaded artifacts.

This manager listens for download events, spins up MimicSessions,
and ensures all heavy work is performed asynchronously without
blocking the EventBus.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional, Dict, List

from core.contracts.events import EventType
from core.cortex.events import (
    EventBus,
    GraphEvent,
    get_event_bus,
    SubscriptionHandle,
)
from core.mimic.session import MimicSession

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MimicConfig (authoritative, local)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class MimicConfig:
    """
    Configuration for Mimic ingestion.
    """
    max_asset_size_mb: int = 50
    enable_entropy_scan: bool = True
    enable_route_mining: bool = True
    enable_secret_mining: bool = True


# ---------------------------------------------------------------------------
# MimicManager
# ---------------------------------------------------------------------------

class MimicManager:
    """
    Singleton manager for Mimic.

    Responsibilities:
    - Subscribe to download-related events
    - Manage MimicSession lifecycle
    - Ensure async ingestion does not block the EventBus
    """

    _instance: Optional["MimicManager"] = None

    def __init__(self, bus: EventBus, config: MimicConfig):
        self._bus = bus
        self._config = config
        self._sessions: Dict[str, MimicSession] = {}
        self._subscriptions: List[SubscriptionHandle] = []
        self._started: bool = False

    # ------------------------------------------------------------------
    # Singleton access
    # ------------------------------------------------------------------

    @classmethod
    def get(
        cls,
        bus: Optional[EventBus] = None,
        config: Optional[MimicConfig] = None,
    ) -> "MimicManager":
        if cls._instance is None:
            cls._instance = cls(
                bus=bus or get_event_bus(),
                config=config or MimicConfig(),
            )
        return cls._instance

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._started:
            return

        self._subscriptions.append(
            self._bus.subscribe_async(
                self._on_download_started,
                [EventType.MIMIC_DOWNLOAD_STARTED],
                name="mimic.download_started",
                critical=True,
            )
        )

        self._started = True
        logger.info("[MimicManager] Started and subscribed to EventBus")

    def shutdown(self) -> None:
        for sub in self._subscriptions:
            sub.unsubscribe()
        self._subscriptions.clear()

        for session in list(self._sessions.values()):
            session.shutdown()
        self._sessions.clear()

        self._started = False
        logger.info("[MimicManager] Shutdown complete")

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    async def _on_download_started(self, event: GraphEvent) -> None:
        scan_id = event.scan_id
        payload = event.payload or {}

        if not scan_id:
            return

        asset_id = payload.get("asset_id")
        path = payload.get("path")

        if not isinstance(asset_id, str) or not isinstance(path, str):
            return

        session = self._sessions.get(scan_id)
        if session is None:
            session = MimicSession(
                scan_id=scan_id,
                config=self._config,
                bus=self._bus,
            )
            self._sessions[scan_id] = session
            logger.info(
                "[MimicManager] Created MimicSession",
                extra={"scan_id": scan_id},
            )

        try:
            await session.ingest_asset(asset_id=asset_id, path=path)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "[MimicManager] Asset ingestion failed",
                extra={"scan_id": scan_id, "asset_id": asset_id},
            )