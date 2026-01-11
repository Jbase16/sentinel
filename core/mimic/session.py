from __future__ import annotations

import json
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from functools import partial

from core.cortex.events import EventBus, GraphEvent
from core.contracts.events import EventType
from core.mimic.models import Asset, Route, Secret, MimicSummary
from core.mimic.miners.routes import mine_routes
from core.mimic.miners.secrets import mine_secrets


@dataclass
class MimicSession:
    scan_id: str
    bus: EventBus

    assets: Dict[str, Asset] = field(default_factory=dict)
    routes: Set[str] = field(default_factory=set)
    hidden_routes: Set[str] = field(default_factory=set)
    secrets: List[Secret] = field(default_factory=list)

    async def ingest_asset(self, asset: Asset) -> None:
        self.assets[asset.asset_id] = asset

        text = self._decode(asset.content)
        if text is None:
            return

        if asset.url.lower().endswith(".map"):
            # SourceMap parsing is also CPU heavy, offload it
            await self._process_sourcemap(asset.asset_id, text)
            return

        # Offload Mining to ThreadPool to prevent EventLoop blocking
        # This is critical for high-throughput scanning of large JS bundles
        loop = asyncio.get_running_loop()
        
        # Run Route Mining
        routes = await loop.run_in_executor(None, mine_routes, asset.asset_id, text)
        for r in routes:
            if r.hidden:
                if r.route not in self.hidden_routes:
                    self.hidden_routes.add(r.route)
                    self.bus.emit(
                        GraphEvent(
                            type=EventType.MIMIC_HIDDEN_ROUTE_FOUND,
                            scan_id=self.scan_id,
                            payload={
                                "scan_id": self.scan_id,
                                "asset_id": asset.asset_id,
                                "route": r.route,
                                "method": r.method,
                                "confidence": r.confidence,
                                "evidence": r.evidence,
                            },
                        )
                    )
            else:
                if r.route not in self.routes:
                    self.routes.add(r.route)
                    self.bus.emit(
                        GraphEvent(
                            type=EventType.MIMIC_ROUTE_FOUND,
                            scan_id=self.scan_id,
                            payload={
                                "scan_id": self.scan_id,
                                "asset_id": asset.asset_id,
                                "route": r.route,
                                "method": r.method,
                                "confidence": r.confidence,
                                "evidence": r.evidence,
                            },
                        )
                    )

        # Run Secret Mining
        secrets = await loop.run_in_executor(None, mine_secrets, asset.asset_id, text)
        for s in secrets:
            self.secrets.append(s)
            self.bus.emit(
                GraphEvent(
                    type=EventType.MIMIC_SECRET_FOUND,
                    scan_id=self.scan_id,
                    payload={
                        "scan_id": self.scan_id,
                        "asset_id": asset.asset_id,
                        "secret_type": s.secret_type,
                        "confidence": s.confidence,
                        "redacted_preview": s.redacted_preview,
                        "evidence": s.evidence,
                    },
                )
            )

    def finalize(self) -> MimicSummary:
        summary = MimicSummary(
            assets_analyzed=len(self.assets),
            routes_found=len(self.routes),
            hidden_routes_found=len(self.hidden_routes),
            secrets_found=len(self.secrets),
            notes=[],
        )
        self.bus.emit(
            GraphEvent(
                type=EventType.MIMIC_ANALYSIS_COMPLETED,
                scan_id=self.scan_id,
                payload={
                    "scan_id": self.scan_id,
                    "assets_analyzed": summary.assets_analyzed,
                    "routes_found": summary.routes_found,
                    "hidden_routes_found": summary.hidden_routes_found,
                    "secrets_found": summary.secrets_found,
                    "notes": summary.notes,
                },
            )
        )
        return summary

    def _decode(self, b: bytes) -> str | None:
        if not b:
            return ""
        try:
            return b.decode("utf-8", errors="replace")
        except Exception:
            return None

    async def _process_sourcemap(self, asset_id: str, text: str) -> None:
        try:
            obj = json.loads(text)
        except Exception:
            return

        sources_content = obj.get("sourcesContent")
        if not isinstance(sources_content, list):
            return

        loop = asyncio.get_running_loop()

        for i, src in enumerate(sources_content):
            if not isinstance(src, str) or not src.strip():
                continue

            # Offload map-based mining as well
            routes = await loop.run_in_executor(None, mine_routes, asset_id, src)
            for r in routes:
                dest = self.hidden_routes if r.hidden else self.routes
                if r.route in dest:
                    continue

                dest.add(r.route)
                self.bus.emit(
                    GraphEvent(
                        type=EventType.MIMIC_HIDDEN_ROUTE_FOUND if r.hidden else EventType.MIMIC_ROUTE_FOUND,
                        scan_id=self.scan_id,
                        payload={
                            "scan_id": self.scan_id,
                            "asset_id": asset_id,
                            "route": r.route,
                            "method": r.method,
                            "confidence": min(90, max(r.confidence, 60)),
                            "evidence": {**r.evidence, "sourcemap_sourcesContent_index": i},
                        },
                    )
                )

            secrets = await loop.run_in_executor(None, mine_secrets, asset_id, src)
            for s in secrets:
                self.secrets.append(s)
                self.bus.emit(
                    GraphEvent(
                        type=EventType.MIMIC_SECRET_FOUND,
                        scan_id=self.scan_id,
                        payload={
                            "scan_id": self.scan_id,
                            "asset_id": asset_id,
                            "secret_type": s.secret_type,
                            "confidence": min(95, max(s.confidence, 60)),
                            "redacted_preview": s.redacted_preview,
                            "evidence": {**s.evidence, "sourcemap_sourcesContent_index": i},
                        },
                    )
                )
