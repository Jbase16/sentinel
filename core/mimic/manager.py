from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, Optional, List

from core.cortex.events import EventBus, GraphEvent, get_event_bus
from core.contracts.events import EventType
from core.contracts.budget import Budget
from core.mimic.downloader import AssetDownloader
from core.mimic.session import MimicSession

logger = logging.getLogger(__name__)


@dataclass
class MimicConfig:
    max_assets: int = 200
    max_bytes_total: int = 20_000_000
    max_bytes_per_asset: int = 2_000_000
    concurrency: int = 6
    timeout_s: float = 15.0


class MimicManager:
    _instance: Optional["MimicManager"] = None

    @classmethod
    def get(cls, bus: EventBus, *, config: Optional[MimicConfig] = None) -> "MimicManager":
        if cls._instance is None:
            cls._instance = cls(bus=bus, config=config or MimicConfig())
        return cls._instance

    def __init__(self, *, bus: EventBus, config: MimicConfig) -> None:
        self._bus = bus
        self._config = config
        self._sessions: Dict[str, MimicSession] = {}

        # Subscribe once (singleton)
        self._bus.subscribe(self._handle_event)
        
    def start(self):
        logger.info("MimicManager initialized (Source Reconstruction active)")
        
    def stop(self):
        self._sessions.clear()

    def _handle_event(self, event: GraphEvent):
        try:
            if event.type == EventType.MIMIC_DOWNLOAD_STARTED:
                self._on_download_started(event)
        except Exception as e:
            logger.error(f"[MimicManager] Error handling event: {e}", exc_info=True)

    def get_session(self, scan_id: str) -> MimicSession:
        if scan_id not in self._sessions:
            self._sessions[scan_id] = MimicSession(scan_id=scan_id, bus=self._bus)
        return self._sessions[scan_id]

    def drop_session(self, scan_id: str) -> None:
        self._sessions.pop(scan_id, None)

    def _on_download_started(self, event: GraphEvent) -> None:
        scan_id = getattr(event, "scan_id", None) or (event.payload or {}).get("scan_id")
        if not scan_id:
            return

        payload = event.payload or {}
        root_urls = payload.get("root_urls") or []
        if not isinstance(root_urls, list):
            return

        # Budget should ideally be in payload since Mimic doesn't own Cronus logic.
        # But if it's missing, we MUST have a fallback or we crash.
        # Ideally, CronusManager creates the budget.
        # For now, we decode if present, else default.
        budget_data = payload.get("budget")
        budget = None
        if isinstance(budget_data, Budget):
            budget = budget_data
            
        if not budget:
             # Create default budget (local safety only)
             budget = Budget(max_time_ms=60000, max_findings=100)

        asyncio.create_task(self._run_pipeline(scan_id=scan_id, root_urls=root_urls, budget=budget))

    async def _run_pipeline(self, *, scan_id: str, root_urls: List[str], budget: Budget) -> None:
        session = self.get_session(scan_id)

        downloader = AssetDownloader(
            budget=budget,
            max_assets=self._config.max_assets,
            max_bytes_total=self._config.max_bytes_total,
            max_bytes_per_asset=self._config.max_bytes_per_asset,
            concurrency=self._config.concurrency,
            timeout_s=self._config.timeout_s,
        )

        results = await downloader.download_many(root_urls)

        total_bytes = 0
        for r in results:
            asset = r.asset
            total_bytes += asset.size_bytes
            session.assets[asset.asset_id] = asset

            self._bus.emit(
                GraphEvent(
                    type=EventType.MIMIC_ASSET_DOWNLOADED,
                    payload={
                        "scan_id": scan_id,
                        "asset_id": asset.asset_id,
                        "url": asset.url,
                        "content_type": asset.content_type,
                        "size_bytes": asset.size_bytes,
                        "sha256": asset.sha256,
                        "discovered_from": asset.discovered_from,
                    },
                )
            )

            # immediate processing (deterministic order: download order)
            session.ingest_asset(asset)

        self._bus.emit(
            GraphEvent(
                type=EventType.MIMIC_DOWNLOAD_COMPLETED,
                payload={
                    "scan_id": scan_id,
                    "assets_downloaded": len(results),
                    "total_bytes": total_bytes,
                },
            )
        )

        session.finalize()
        # Keep session for replay/UI inspection; drop on SCAN_COMPLETED elsewhere if desired.
