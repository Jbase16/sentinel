from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol, Set, Tuple
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

from pydantic import HttpUrl

from .contracts.errors import BudgetExceeded, PolicyViolation, ScopeViolation
from .contracts.events import EventEnvelope, EventType, WebSurfaceDiscoveredPayload, WebEndpointRegisteredPayload
from .contracts.models import WebMission, EndpointCandidate
from .contracts.enums import SurfaceSource, WebMethod
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

            # Deterministic, minimal parsing using stdlib. No JS, no execution.
            class MinimalExtractor(HTMLParser):
                def __init__(self, base: str):
                    super().__init__()
                    self.base = base
                    self.links = []
                    self.forms = []
                    
                def handle_starttag(self, tag, attrs):
                    attr_dict = dict(attrs)
                    if tag == "a" and "href" in attr_dict:
                        href = attr_dict["href"].strip()
                        if href and not href.startswith(("javascript:", "mailto:", "tel:")):
                            self.links.append(urljoin(self.base, href))
                    elif tag == "form" and "action" in attr_dict:
                        action = attr_dict["action"].strip()
                        method = attr_dict.get("method", "get").upper()
                        if action:
                            self.forms.append((urljoin(self.base, action), method))
                            
            extractor = MinimalExtractor(url)
            try:
                # Use ignore on decode to prevent utf-8 failure crashing deterministic loop
                extractor.feed(body.decode("utf-8", errors="ignore"))
            except Exception:
                pass
                
            new_urls = []
            for link in extractor.links:
                # Very basic origin constraint: must be on allowed origin
                parsed_link = urlparse(link)
                link_origin = f"{parsed_link.scheme}://{parsed_link.netloc}"
                if link_origin in mission.allowed_origins:
                    if not registry.has_url(link):
                        new_urls.append(link)
                        discovered_urls.append(link)
            
            # Enqueue discovered links in deterministic order to the back of BFS queue
            for link in sorted(new_urls):
                queue.append((link, depth + 1))
                
            registry.add_urls(new_urls)
            
            new_endpoints = []
            
            # 1. Links with query parameters are GET endpoint candidates
            for link in new_urls:
                if "?" in link:
                    new_endpoints.append(EndpointCandidate(
                        url=link, # type: ignore
                        method=WebMethod.GET,
                        source=SurfaceSource.CRAWLER,
                        confidence=0.9
                    ))
                    
            # 2. Forms are endpoint candidates
            for form_action, form_method in extractor.forms:
                discovered_forms.append(form_action)
                wm = WebMethod.POST if form_method == "POST" else WebMethod.GET
                new_endpoints.append(EndpointCandidate(
                    url=form_action, # type: ignore
                    method=wm,
                    source=SurfaceSource.CRAWLER,
                    confidence=1.0
                ))
                
            # Sort endpoints for determinism before registry insertion
            new_endpoints.sort(key=lambda e: f"{e.method.value}|{str(e.url)}")
            
            if new_endpoints:
                registry.add_endpoints(new_endpoints)
                self._bus.emit(EventEnvelope(
                    event_type=EventType.WEB_ENDPOINT_REGISTERED,
                    mission_id=mission.mission_id,
                    scan_id=mission.scan_id,
                    session_id=mission.session_id,
                    principal_id=ctx.principal_id,
                    payload=WebEndpointRegisteredPayload(
                        source=SurfaceSource.CRAWLER,
                        endpoints=new_endpoints
                    ).model_dump(mode="json")
                ))

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
