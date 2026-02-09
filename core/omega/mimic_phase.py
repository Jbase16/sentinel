"""
OMEGA MIMIC Phase Implementation

Manifest-first asset collection with deterministic fallback.
No guessing. No crawling. Explicit decisions, auditable actions.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from core.cortex.events import GraphEvent, GraphEventType, get_event_bus
from core.sentient.mimic.downloader import AssetDownloader, AssetType
from core.sentient.mimic.shadow_spec import ShadowSpec

logger = logging.getLogger(__name__)


class ManifestType(str, Enum):
    """Types of build manifests we recognize."""
    WEBPACK_STATS = "webpack-stats"
    CRA_MANIFEST = "cra-manifest"
    VITE_MANIFEST = "vite-manifest"
    NEXT_DATA = "next-data"
    GENERIC_MANIFEST = "generic-manifest"
    NONE = "none"


@dataclass
class AssetGraphNode:
    """A node in the asset dependency graph."""
    url: str
    asset_type: AssetType
    parent: Optional[str] = None  # URL of parent that referenced this
    children: Set[str] = field(default_factory=set)
    downloaded: bool = False


@dataclass
class MIMICPhaseResult:
    """Result of MIMIC phase execution."""
    target: str
    manifest_type: ManifestType
    assets_downloaded: int
    routes_discovered: int
    secrets_found: int
    hidden_endpoints: List[Dict[str, Any]]
    asset_graph: Dict[str, AssetGraphNode]
    shadow_spec: ShadowSpec
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    fallback_used: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "manifest_type": self.manifest_type.value,
            "assets_downloaded": self.assets_downloaded,
            "routes_discovered": self.routes_discovered,
            "secrets_found": self.secrets_found,
            "hidden_endpoints": self.hidden_endpoints,
            "fallback_used": self.fallback_used,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


class MIMICPhaseOrchestrator:
    """
    Orchestrates MIMIC phase: manifest-first asset collection.

    Strategy:
    1. Probe for framework manifests (webpack, vite, CRA, Next.js)
    2. If found: trust manifest, build asset graph, fetch exactly what's listed
    3. If not found: fallback to main bundles + source maps
    4. Parse assets for routes, secrets, endpoints
    5. Update ShadowSpec with discovered API structure

    Every decision emits an event for audit trail.
    """

    # Common manifest paths to probe
    MANIFEST_PROBES = [
        "/webpack-stats.json",
        "/manifest.json",
        "/asset-manifest.json",
        "/vite-manifest.json",
        "/_next/static/chunks/webpack-stats.json",
        "/static/manifest.json",
        "/build/manifest.json",
    ]

    # Fallback: common bundle patterns
    FALLBACK_BUNDLE_PATTERNS = [
        "/main.*.js",
        "/app.*.js",
        "/bundle.*.js",
        "/index.*.js",
        "/vendor.*.js",
        "/runtime.*.js",
    ]

    def __init__(self, target: str, safe_mode: bool = True):
        self.target = target.rstrip("/")
        self.safe_mode = safe_mode
        self.event_bus = get_event_bus()
        self.downloader = AssetDownloader(safe_mode=safe_mode)
        self.shadow_spec = ShadowSpec()
        self.asset_graph: Dict[str, AssetGraphNode] = {}
        self._parsed_routes: List[Dict[str, Any]] = []

    async def execute(self) -> MIMICPhaseResult:
        """Execute MIMIC phase with manifest-first strategy."""
        started_at = datetime.utcnow()

        self.event_bus.emit(GraphEvent(
            type=GraphEventType.LOG,
            payload={"message": f"[MIMIC] Phase started: {self.target}"},
        ))

        # Step 1: Probe for manifests
        manifest_type, manifest_data = await self._probe_manifests()

        if manifest_type != ManifestType.NONE:
            # Manifest-driven collection
            self.event_bus.emit(GraphEvent(
                type=GraphEventType.LOG,
                payload={
                    "message": f"[MIMIC] Manifest detected: {manifest_type.value}",
                    "manifest_type": manifest_type.value,
                },
            ))

            await self._collect_from_manifest(manifest_type, manifest_data)
            fallback_used = False
        else:
            # Fallback to heuristic collection
            self.event_bus.emit(GraphEvent(
                type=GraphEventType.LOG,
                payload={"message": "[MIMIC] No manifest found, using fallback strategy"},
            ))

            await self._collect_fallback()
            fallback_used = True

        # Step 2: Parse collected assets
        routes_discovered = await self._parse_assets()

        # Step 3: Extract secrets and endpoints
        secrets_found, hidden_endpoints = await self._analyze_assets()

        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        self.event_bus.emit(GraphEvent(
            type=GraphEventType.LOG,
            payload={
                "message": f"[MIMIC] Phase completed: {len(self.asset_graph)} assets, {routes_discovered} routes",
                "assets": len(self.asset_graph),
                "routes": routes_discovered,
            },
        ))

        return MIMICPhaseResult(
            target=self.target,
            manifest_type=manifest_type,
            assets_downloaded=len([n for n in self.asset_graph.values() if n.downloaded]),
            routes_discovered=routes_discovered,
            secrets_found=secrets_found,
            hidden_endpoints=hidden_endpoints,
            asset_graph=self.asset_graph,
            shadow_spec=self.shadow_spec,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            fallback_used=fallback_used,
        )

    async def _probe_manifests(self) -> tuple[ManifestType, Optional[Dict[str, Any]]]:
        """
        Probe for build manifests in priority order.
        Returns (ManifestType, manifest_data) or (NONE, None).
        """
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            for probe_path in self.MANIFEST_PROBES:
                url = urljoin(self.target, probe_path)
                try:
                    resp = await client.get(url, timeout=5.0)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            manifest_type = self._detect_manifest_type(probe_path, data)
                            logger.info(f"[MIMIC] Found manifest: {manifest_type.value} at {url}")
                            return manifest_type, data
                        except json.JSONDecodeError:
                            continue
                except (httpx.RequestError, httpx.HTTPError):
                    continue

        # Check for Next.js __NEXT_DATA__ in HTML
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                resp = await client.get(self.target, timeout=5.0)
                if resp.status_code == 200 and "__NEXT_DATA__" in resp.text:
                    # Extract __NEXT_DATA__ from script tag
                    match = re.search(r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
                    if match:
                        try:
                            data = json.loads(match.group(1))
                            logger.info(f"[MIMIC] Found Next.js __NEXT_DATA__")
                            return ManifestType.NEXT_DATA, data
                        except json.JSONDecodeError:
                            pass
        except (httpx.RequestError, httpx.HTTPError):
            pass

        return ManifestType.NONE, None

    def _detect_manifest_type(self, path: str, data: Dict) -> ManifestType:
        """Detect manifest type from path and structure."""
        path_lower = path.lower()

        if "webpack-stats" in path_lower:
            return ManifestType.WEBPACK_STATS
        elif "vite-manifest" in path_lower:
            return ManifestType.VITE_MANIFEST
        elif "asset-manifest" in path_lower and "files" in data:
            return ManifestType.CRA_MANIFEST
        else:
            return ManifestType.GENERIC_MANIFEST

    async def _collect_from_manifest(self, manifest_type: ManifestType, manifest_data: Dict):
        """Build asset graph from manifest and download assets."""
        asset_urls = self._extract_urls_from_manifest(manifest_type, manifest_data)

        logger.info(f"[MIMIC] Manifest contains {len(asset_urls)} assets")

        # Build asset graph
        for url in asset_urls:
            full_url = urljoin(self.target, url)
            asset_type = AssetDownloader.detect_type_from_url(full_url)
            self.asset_graph[full_url] = AssetGraphNode(
                url=full_url,
                asset_type=asset_type,
            )

        # Download assets (prioritize JS and source maps)
        priority_assets = [
            url for url, node in self.asset_graph.items()
            if node.asset_type in (AssetType.JAVASCRIPT, AssetType.SOURCE_MAP)
        ]

        await self._download_assets(priority_assets)

    def _extract_urls_from_manifest(self, manifest_type: ManifestType, data: Dict) -> List[str]:
        """Extract asset URLs from manifest based on type."""
        urls = []

        if manifest_type == ManifestType.WEBPACK_STATS:
            # Webpack stats format: { "chunks": [...], "assets": [...] }
            if "assets" in data:
                urls.extend([asset.get("name", "") for asset in data["assets"] if isinstance(asset, dict)])
            elif "assetsByChunkName" in data:
                for chunk_assets in data["assetsByChunkName"].values():
                    if isinstance(chunk_assets, list):
                        urls.extend(chunk_assets)
                    elif isinstance(chunk_assets, str):
                        urls.append(chunk_assets)

        elif manifest_type == ManifestType.CRA_MANIFEST:
            # CRA format: { "files": { "main.js": "/static/js/main.hash.js" } }
            if "files" in data:
                urls.extend(data["files"].values())

        elif manifest_type == ManifestType.VITE_MANIFEST:
            # Vite format: { "index.html": { "file": "assets/index.hash.js" } }
            for entry in data.values():
                if isinstance(entry, dict) and "file" in entry:
                    urls.append(entry["file"])

        elif manifest_type == ManifestType.NEXT_DATA:
            # Next.js format: { "buildId": "...", "page": "..." }
            # Extract build ID and construct chunk URLs
            build_id = data.get("buildId", "")
            if build_id:
                urls.append(f"/_next/static/{build_id}/_buildManifest.js")
                urls.append(f"/_next/static/{build_id}/_ssgManifest.js")

        elif manifest_type == ManifestType.GENERIC_MANIFEST:
            # Generic: try common keys
            for key in ["assets", "files", "chunks", "modules"]:
                if key in data:
                    value = data[key]
                    if isinstance(value, list):
                        urls.extend([str(v) for v in value if isinstance(v, str)])
                    elif isinstance(value, dict):
                        urls.extend([str(v) for v in value.values() if isinstance(v, str)])

        return [url for url in urls if url]  # Filter empty strings

    async def _collect_fallback(self):
        """Fallback: collect main bundles and source maps."""
        logger.info("[MIMIC] Using fallback: probing for main bundles")

        # Fetch root HTML to find script tags
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                resp = await client.get(self.target, timeout=5.0)
                if resp.status_code == 200:
                    # Extract script src attributes
                    script_srcs = re.findall(r'<script[^>]*src=["\'](.*?)["\']', resp.text)
                    for src in script_srcs:
                        if any(pattern in src for pattern in [".js", ".mjs"]):
                            full_url = urljoin(self.target, src)
                            asset_type = AssetDownloader.detect_type_from_url(full_url)
                            self.asset_graph[full_url] = AssetGraphNode(
                                url=full_url,
                                asset_type=asset_type,
                            )
        except (httpx.RequestError, httpx.HTTPError) as e:
            logger.warning(f"[MIMIC] Fallback HTML fetch failed: {e}")

        # Download discovered bundles
        await self._download_assets(list(self.asset_graph.keys()))

    async def _download_assets(self, urls: List[str]):
        """Download assets and mark as downloaded in graph."""
        for url in urls:
            try:
                asset = await self.downloader.download(url)
                if url in self.asset_graph:
                    self.asset_graph[url].downloaded = True

                # Check for source map references
                if asset.asset_type == AssetType.JAVASCRIPT:
                    content_str = asset.content if isinstance(asset.content, str) else asset.content.decode("utf-8", errors="ignore")
                    sourcemap_match = re.search(r'//# sourceMappingURL=(.+)', content_str)
                    if sourcemap_match:
                        sourcemap_url = urljoin(url, sourcemap_match.group(1))
                        if sourcemap_url not in self.asset_graph:
                            self.asset_graph[sourcemap_url] = AssetGraphNode(
                                url=sourcemap_url,
                                asset_type=AssetType.SOURCE_MAP,
                                parent=url,
                            )
                            self.asset_graph[url].children.add(sourcemap_url)
                            # Download source map
                            try:
                                await self.downloader.download(sourcemap_url)
                                self.asset_graph[sourcemap_url].downloaded = True
                            except Exception:
                                pass
            except Exception as e:
                logger.debug(f"[MIMIC] Failed to download {url}: {e}")

    async def _parse_assets(self) -> int:
        """Parse downloaded assets for routes. Returns route count."""
        seen_routes: Set[tuple[str, str]] = set()
        self._parsed_routes = []

        for url, node in self.asset_graph.items():
            if not node.downloaded or node.asset_type != AssetType.JAVASCRIPT:
                continue

            try:
                content = self._asset_text(url)
                if not content:
                    continue

                route_patterns = [
                    # router.get("/api/foo")
                    (re.compile(r'router\.(get|post|put|patch|delete|options|head)\(\s*["\']([^"\']+)["\']', re.IGNORECASE), 1, 2, "router"),
                    # axios.post("/api/foo")
                    (re.compile(r'axios\.(get|post|put|patch|delete)\(\s*["\']([^"\']+)["\']', re.IGNORECASE), 1, 2, "axios"),
                    # fetch("/api/foo")
                    (re.compile(r'fetch\(\s*["\']([^"\']+)["\']', re.IGNORECASE), None, 1, "fetch"),
                    # Generic API-like literals
                    (re.compile(r'["\'](/(?:api|v\d+|admin|internal|debug|graphql)[^"\']*)["\']', re.IGNORECASE), None, 1, "literal"),
                ]

                for pattern, method_group, path_group, source_kind in route_patterns:
                    for match in pattern.finditer(content):
                        raw_path = match.group(path_group) if path_group else ""
                        route = self._normalize_route(raw_path)
                        if not route:
                            continue
                        method = (
                            match.group(method_group).upper()
                            if method_group and match.group(method_group)
                            else "GET"
                        )
                        key = (method, route)
                        if key in seen_routes:
                            continue
                        seen_routes.add(key)

                        is_hidden = any(token in route.lower() for token in ("/admin", "/internal", "/debug", "/private"))
                        self._parsed_routes.append(
                            {
                                "route": route,
                                "method": method,
                                "source_url": url,
                                "source_kind": source_kind,
                                "hidden": is_hidden,
                            }
                        )

                        # Feed discovered structure into ShadowSpec.
                        try:
                            self.shadow_spec.observe(method=method, url=urljoin(self.target + "/", route))
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"[MIMIC] Failed to parse {url}: {e}")

        return len(self._parsed_routes)

    async def _analyze_assets(self) -> tuple[int, List[Dict[str, Any]]]:
        """Analyze assets for secrets and endpoints. Returns (secrets_count, endpoints)."""
        secrets_found = 0
        hidden_endpoints: List[Dict[str, Any]] = []
        hidden_seen: Set[tuple[str, str]] = set()
        secret_seen: Set[tuple[str, str, str]] = set()

        # Secret patterns
        SECRET_PATTERNS = [
            (re.compile(r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']'), "api_key"),
            (re.compile(r'(?i)secret["\']?\s*[:=]\s*["\']([^"\']+)["\']'), "secret"),
            (re.compile(r'(?i)password["\']?\s*[:=]\s*["\']([^"\']+)["\']'), "password"),
            (re.compile(r'(?i)token["\']?\s*[:=]\s*["\']([^"\']+)["\']'), "token"),
            (re.compile(r'(?i)aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']'), "aws_key"),
        ]

        HIDDEN_ENDPOINT_PATTERNS = [
            re.compile(r'["\'](/(?:admin|internal|debug|private|_next|api/internal)[^"\']*)["\']', re.IGNORECASE),
        ]

        for url, node in self.asset_graph.items():
            if not node.downloaded or node.asset_type != AssetType.JAVASCRIPT:
                continue

            content = self._asset_text(url)
            if not content:
                continue

            for pattern, secret_type in SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    secret_value = match.group(1).strip()
                    if len(secret_value) < 8:
                        continue
                    lowered = secret_value.lower()
                    if lowered in {"changeme", "example", "test", "placeholder", "your_api_key"}:
                        continue

                    key = (secret_type, secret_value[:16], url)
                    if key in secret_seen:
                        continue
                    secret_seen.add(key)
                    secrets_found += 1

                    preview = f"{secret_value[:4]}***{secret_value[-4:]}" if len(secret_value) > 8 else "***"
                    self.event_bus.emit(
                        GraphEvent(
                            type=GraphEventType.LOG,
                            payload={
                                "message": f"[MIMIC] Potential secret found in {url}",
                                "secret_type": secret_type,
                                "preview": preview,
                            },
                        )
                    )

            for pattern in HIDDEN_ENDPOINT_PATTERNS:
                for match in pattern.finditer(content):
                    route = self._normalize_route(match.group(1))
                    if not route:
                        continue
                    key = ("GET", route)
                    if key in hidden_seen:
                        continue
                    hidden_seen.add(key)
                    hidden_endpoints.append(
                        {
                            "route": route,
                            "method": "GET",
                            "source_url": url,
                            "reason": "hidden_pattern",
                        }
                    )

        # Include hidden routes detected during route parsing.
        for route_info in self._parsed_routes:
            if not route_info.get("hidden"):
                continue
            method = route_info.get("method", "GET")
            route = route_info.get("route", "")
            key = (method, route)
            if key in hidden_seen:
                continue
            hidden_seen.add(key)
            hidden_endpoints.append(
                {
                    "route": route,
                    "method": method,
                    "source_url": route_info.get("source_url"),
                    "reason": "route_parse_hidden",
                }
            )

        return secrets_found, hidden_endpoints

    def _asset_text(self, url: str) -> str:
        asset = self.downloader.get_cached_asset(url)
        if asset is None:
            return ""
        if isinstance(asset.content, str):
            return asset.content
        try:
            return asset.content.decode("utf-8")
        except UnicodeDecodeError:
            return asset.content.decode("latin-1", errors="replace")

    @staticmethod
    def _normalize_route(raw_route: str) -> str:
        route = (raw_route or "").strip()
        if not route:
            return ""
        if route.startswith("http://") or route.startswith("https://"):
            parsed = urlparse(route)
            route = parsed.path or "/"
        if not route.startswith("/"):
            route = "/" + route
        if len(route) > 300:
            return ""
        return route
