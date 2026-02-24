from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol

from .contracts.events import EventEnvelope, EventType, WebEndpointRegisteredPayload
from .contracts.models import EndpointCandidate, WebMission
from .contracts.enums import SurfaceSource
from .context import WebContext
from .surface_registry import SurfaceRegistry


class ExecutionPolicy(Protocol):
    def assert_url_allowed(self, mission: WebMission, url: str) -> None: ...
    def http_get(self, mission: WebMission, ctx: WebContext, url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]: ...


class EventBus(Protocol):
    def emit(self, event: EventEnvelope) -> None: ...


@dataclass(frozen=True)
class JsIntelResult:
    endpoints: List[EndpointCandidate]
    assets_processed: int


class JsIntelEngine:
    """
    JS bundle analysis. Extract endpoint candidates (not vulnerabilities).
    """
    def __init__(self, policy: ExecutionPolicy, bus: EventBus, max_asset_bytes: int = 5_000_000) -> None:
        self._policy = policy
        self._bus = bus
        self._max_asset_bytes = max_asset_bytes

    def analyze(self, mission: WebMission, ctx: WebContext, registry: SurfaceRegistry, js_assets: List[str]) -> JsIntelResult:
        endpoints: List[EndpointCandidate] = []
        processed = 0

        # Agent implements:
        # - download JS assets within size bounds
        # - extract endpoints (regex heuristics + string constant mining)
        # - emit WEB_ENDPOINT_REGISTERED
        # - add to registry
        for asset in js_assets:
            self._policy.assert_url_allowed(mission, asset)
            status, headers, body = self._policy.http_get(mission, ctx, asset)
            if len(body) > self._max_asset_bytes:
                continue
            processed += 1

            # parse body -> endpoints list (deterministic ordering)
            # endpoints.append(...)

        payload = WebEndpointRegisteredPayload(
            source=SurfaceSource.JS_INTEL,
            endpoints=endpoints,
            js_asset=None,
        )
        self._bus.emit(
            EventEnvelope(
                event_type=EventType.WEB_ENDPOINT_REGISTERED,
                mission_id=mission.mission_id,
                scan_id=mission.scan_id,
                session_id=mission.session_id,
                principal_id=ctx.principal_id,
                payload=payload.model_dump(mode="json"),
            )
        )
        return JsIntelResult(endpoints=endpoints, assets_processed=processed)
