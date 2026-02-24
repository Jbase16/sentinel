from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol, Set, Tuple
from urllib.parse import urljoin

from pydantic import HttpUrl

from .contracts.errors import BudgetExceeded, PolicyViolation, ScopeViolation
from .contracts.events import EventEnvelope, EventType, WebSurfaceDiscoveredPayload
from .contracts.models import WebMission
from .contracts.enums import SurfaceSource
from .surface_registry import SurfaceRegistry
from .context import WebContext


class ExecutionPolicy(Protocol):
    """
    Protocol so we don't invent your real ExecutionPolicy API.
    Agent must implement adapter if necessary.
    """
    def assert_url_allowed(self, mission: WebMission, url: str) -> None: ...
    def http_get(self, mission: WebMission, ctx: WebContext, url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]: ...


class EventBus(Protocol):
    def emit(self, event: EventEnvelope) -> None: ...


@dataclass(frozen=True)
class CrawlResult:
    urls: List[str]
    assets: List[str]
    forms: List[str]
    pages_fetched: int


class HttpCrawler:
    """
    HTML-only crawler. No JS execution.
    """
    def __init__(self, policy: ExecutionPolicy, bus: EventBus) -> None:
        self._policy = policy
        self._bus = bus

    def crawl(self, mission: WebMission, ctx: WebContext, registry: SurfaceRegistry) -> CrawlResult:
        # Deterministic crawl strategy: BFS with fixed ordering.
        origin = str(mission.origin)
        queue: List[tuple[str, int]] = [(origin, 0)]
        seen: Set[str] = set()
        discovered_urls: List[str] = []
        discovered_assets: List[str] = []
        discovered_forms: List[str] = []
        pages = 0

        while queue:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)

            if depth > mission.max_depth:
                continue
            if pages >= mission.max_pages:
                raise BudgetExceeded(f"Crawler exceeded max_pages={mission.max_pages}")

            self._policy.assert_url_allowed(mission, url)

            status, headers, body = self._policy.http_get(mission, ctx, url)
            pages += 1

            # NOTE: parsing intentionally not implemented here; Agent implements safely.
            # Must extract: href/src links, form actions, script src.
            # Must enqueue in deterministic sorted order.
            # discovered_urls/assets/forms must be absolute.
            # This method MUST still emit event with whatever was found so far.
            # Agent fills in parsing and adds to registry.

        payload = WebSurfaceDiscoveredPayload(
            source=SurfaceSource.CRAWLER,
            discovered_urls=discovered_urls,      # type: ignore[arg-type]
            discovered_assets=discovered_assets,  # type: ignore[arg-type]
            discovered_forms=discovered_forms,    # type: ignore[arg-type]
            depth=mission.max_depth,
            page_count=pages,
        )
        self._bus.emit(
            EventEnvelope(
                event_type=EventType.WEB_SURFACE_DISCOVERED,
                mission_id=mission.mission_id,
                scan_id=mission.scan_id,
                session_id=mission.session_id,
                principal_id=ctx.principal_id,
                payload=payload.model_dump(mode="json"),
            )
        )
        return CrawlResult(discovered_urls, discovered_assets, discovered_forms, pages)
