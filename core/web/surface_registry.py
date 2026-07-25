from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from pydantic import HttpUrl

from .contracts.models import EndpointCandidate


from urllib.parse import urlparse, urlunparse

def _surface_key(url: str) -> str:
    # Deterministic dedup key. Normalize elsewhere if needed.
    # Strip fragments for deduplication
    parsed = urlparse(url.strip())
    # Rebuild without fragment
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))


@dataclass(frozen=True)
class SurfaceDelta:
    new_urls: int
    new_endpoints: int


class SurfaceRegistry:
    """
    Concurrency-safe inventory of discovered URLs/assets/endpoints.
    Strictly data: no crawling logic in here.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._urls: Dict[str, str] = {}
        self._assets: Dict[str, str] = {}
        self._endpoints: Dict[str, EndpointCandidate] = {}

    def add_urls(self, urls: List[str]) -> SurfaceDelta:
        with self._lock:
            before = len(self._urls)
            for u in urls:
                k = _surface_key(u)
                if k:
                    self._urls.setdefault(k, u)
            after = len(self._urls)
            return SurfaceDelta(new_urls=after - before, new_endpoints=0)

    def add_assets(self, assets: List[str]) -> None:
        with self._lock:
            for a in assets:
                k = _surface_key(a)
                if k:
                    self._assets.setdefault(k, a)

    def add_endpoints(self, endpoints: List[EndpointCandidate]) -> SurfaceDelta:
        with self._lock:
            before = len(self._endpoints)
            for e in endpoints:
                k = _surface_key(str(e.url)) + "|" + e.method.value
                self._endpoints.setdefault(k, e)
            after = len(self._endpoints)
            return SurfaceDelta(new_urls=0, new_endpoints=after - before)

    def snapshot(self) -> Tuple[List[str], List[str], List[EndpointCandidate]]:
        with self._lock:
            return (list(self._urls.values()), list(self._assets.values()), list(self._endpoints.values()))

    def has_url(self, url: str) -> bool:
        with self._lock:
            return _surface_key(url) in self._urls
