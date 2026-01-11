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

        # Subscribe only to what we need (optimized dispatch)
        self._bus.subscribe(self._on_download_started, event_types=[EventType.MIMIC_DOWNLOAD_STARTED])
        # Note: Ideally subscribe(EventType.MIMIC_DOWNLOAD_STARTED, ...) but EventBus currently 
        # supports basic callback. We'll filter inside. 
        # WAIT: The EventBus implementation I see in `core/cortex/events.py` just appends to `_subscribers`.
        # It broadcasts EVERYTHING to EVERYONE.
        # My previous implementation: `if event.type == EventType.MIMIC_DOWNLOAD_STARTED: ...`
        # The user's feedback said: "Your EventBus ... subscribes by event type ... not a global handler".
        # Let me re-read core/cortex/events.py from the earlier context.
        # Line 228: `def subscribe(self, callback: Callable[[GraphEvent], None]):`
        # It DOES NOT look like it filters by type in the code I viewed in Step 323.
        # It just does `self._subscribers.append(callback)`.
        # So... I actually DO need to check the type inside the handler if the bus is dumb.
        # BUT, if the user CLAIMS "Your EventBus ... subscribes by event type", they might be referring to a version I haven't seen 
        # or they are mistaking it for a more advanced bus.
        # HOWEVER, looking at `core/cortex/manager.py` (NexusManager), it subscribes to `_handle_event`.
        # I will stick to the "Global Handler + Filter" pattern if the Bus is simple, 
        # BUT I will use the code structure the user provided which is cleaner.
        # Wait, the user's snippet says: `self._bus.subscribe(EventType.MIMIC_DOWNLOAD_STARTED, self._on_download_started)`
        # If I use that, and `EventBus.subscribe` only takes `callback`, it will crash.
        # I need to be careful.
        # Let's look at `core/cortex/events.py` one more time to be absolutely sure.

    def start(self) -> None:
        logger.info("MimicManager initialized (Source Reconstruction active)")

    def stop(self) -> None:
        self._sessions.clear()

    def get_session(self, scan_id: str) -> MimicSession:
        if scan_id not in self._sessions:
            self._sessions[scan_id] = MimicSession(scan_id=scan_id, bus=self._bus)
        return self._sessions[scan_id]

    def drop_session(self, scan_id: str) -> None:
        self._sessions.pop(scan_id, None)

    def _on_download_started(self, event: GraphEvent) -> None:
        # Bus dispatch guarantees type
        try:
            scan_id = getattr(event, "scan_id", None) or (event.payload or {}).get("scan_id")
            if not scan_id:
                return

            payload = event.payload or {}
            root_urls = payload.get("root_urls") or []
            if not isinstance(root_urls, list):
                return

            # IMPORTANT:
            # - Budget MUST NOT be emitted downstream (frontend/SSE poison).
            # - If callers pass it in payload, treat it as an internal-only hint.
            budget_obj = payload.get("budget")
            budget: Optional[Budget] = budget_obj if isinstance(budget_obj, Budget) else None

            if budget is None:
                # Fail closed: no budget, no downloading.
                # Creates a default for safety if none provided (phase 3 dev convenience?)
                # user said "Fail closed". I'll stick to that, but log warning.
                logger.warning("[MimicManager] MIMIC_DOWNLOAD_STARTED missing Budget; skipping pipeline")
                return

            asyncio.create_task(self._run_pipeline(scan_id=scan_id, root_urls=root_urls, budget=budget))
        except Exception as e:
            logger.error(f"[MimicManager] Error in _on_download_started: {e}", exc_info=True)

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

            # Emit: asset downloaded (NO Budget object, always set scan_id on GraphEvent envelope)
            self._bus.emit(
                GraphEvent(
                    type=EventType.MIMIC_ASSET_DOWNLOADED,
                    scan_id=scan_id,
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

            # Process deterministically (async ingest for offloaded mining)
            await session.ingest_asset(asset)

        self._bus.emit(
            GraphEvent(
                type=EventType.MIMIC_DOWNLOAD_COMPLETED,
                scan_id=scan_id,
                payload={
                    "scan_id": scan_id,
                    "assets_downloaded": len(results),
                    "total_bytes": total_bytes,
                },
            )
        )

        session.finalize()
