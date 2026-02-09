"""
MIMIC Asset Downloader - Client-Side Asset Collection

PURPOSE:
Download frontend assets (JavaScript bundles, CSS, Source Maps) from target applications
for analysis. This enables grey-box visibility into application structure.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Audit their own exposed assets for sensitive information
- Identify unintended source map exposures
- Test asset hygiene during red team exercises
- Discover what an attacker can learn from public code

ASSUMPTIONS:
1. Target assets are publicly accessible (no authentication required)
2. Standard asset paths (/static/, /assets/, /js/, etc.)
3. Manifest files follow standard conventions
4. Download rate limits will be respected

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, respects robots.txt disallow rules
- Rate limiting enforced (max 20 requests per second)
- No modification of downloaded assets
- No execution of downloaded JavaScript code
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits MIMIC_DOWNLOAD_STARTED, MIMIC_DOWNLOAD_COMPLETED events
- DecisionLedger: Logs download decisions and skipped assets
- EvidenceStore: Stores downloaded assets for analysis

DEPENDENCIES (Future):
- aiohttp: Async HTTP client for efficient downloading
- robotexclusionrulesparser: For robots.txt parsing
- pathlib: For local file system caching
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx
from core.base.config import get_config

# Safety fuse: prevents unsafe operations
# Default to true, but overridden by config in factory
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class AssetType(str, Enum):
    """
    Types of frontend assets that may be downloaded.

    Each type has different analysis value:
    - JAVASCRIPT: Contains route definitions, API endpoints
    - SOURCE_MAP: Maps minified code to original structure
    - CSS: May contain API endpoints in url() references
    - MANIFEST: Lists all build assets and their hashes
    - FONT: Sometimes contains embedded metadata
    - IMAGE: Occasionally contains steganography/exif data
    """
    JAVASCRIPT = "javascript"
    SOURCE_MAP = "source_map"
    CSS = "css"
    MANIFEST = "manifest"
    FONT = "font"
    IMAGE = "image"
    OTHER = "other"


@dataclass
class DownloadedAsset:
    """
    A downloaded frontend asset.

    Attributes:
        url: Where this asset was downloaded from
        asset_type: What type of asset this is
        content: Raw asset content (bytes or string)
        size_bytes: Size of the asset
        content_hash: SHA256 hash of content
        downloaded_at: When this was downloaded
        headers: HTTP response headers
    """
    url: str
    asset_type: AssetType
    content: bytes | str
    size_bytes: int
    content_hash: str
    downloaded_at: datetime = field(default_factory=lambda: datetime.utcnow())
    headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize asset to dict."""
        return {
            "url": self.url,
            "asset_type": self.asset_type.value,
            "size_bytes": self.size_bytes,
            "content_hash": self.content_hash,
            "downloaded_at": self.downloaded_at.isoformat(),
            "headers": self.headers,
            # Content is excluded from dict to save space
        }

    @classmethod
    def from_response(
        cls,
        url: str,
        content: bytes | str,
        headers: Dict[str, str],
        asset_type: Optional[AssetType] = None,
    ) -> "DownloadedAsset":
        """
        Create DownloadedAsset from HTTP response.

        Args:
            url: Asset URL
            content: Response content
            headers: Response headers
            asset_type: Detected or inferred asset type

        Returns:
            DownloadedAsset instance
        """
        # Detect asset type from URL if not provided
        if asset_type is None:
            asset_type = AssetDownloader.detect_type_from_url(url)

        # Calculate size
        if isinstance(content, str):
            size_bytes = len(content.encode("utf-8"))
            content_bytes = content.encode("utf-8")
        else:
            size_bytes = len(content)
            content_bytes = content

        # Calculate hash
        content_hash = hashlib.sha256(content_bytes).hexdigest()

        return cls(
            url=url,
            asset_type=asset_type,
            content=content,
            size_bytes=size_bytes,
            content_hash=content_hash,
            headers=headers,
        )


@dataclass
class AssetManifest:
    """
    Manifest of frontend assets for a target application.

    This represents the collection of all discoverable assets,
    typically parsed from manifest.json or build-assets.json.

    Attributes:
        target: Domain these assets belong to
        base_url: Base URL for asset resolution
        assets: List of discovered asset URLs
        discovered_at: When manifest was created
    """
    target: str
    base_url: str
    assets: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=lambda: datetime.utcnow())

    def add_asset(self, asset_url: str) -> None:
        """Add an asset URL to the manifest."""
        if asset_url not in self.assets:
            self.assets.append(asset_url)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize manifest to dict."""
        return {
            "target": self.target,
            "base_url": self.base_url,
            "asset_count": len(self.assets),
            "discovered_at": self.discovered_at.isoformat(),
            "assets": self.assets,
        }


class AssetDownloader:
    """
    Downloads frontend assets from target applications.

    This class handles:
    - Spidering /static/, /assets/, /js/ directories
    - Parsing manifest.json or build-assets.json
    - Fetching Source Maps when available
    - Respecting robots.txt and rate limits

    DOWNLOAD STRATEGY:
    1. Fetch manifest file if available
    2. Spider common asset paths
    3. Check for .map files corresponding to JS bundles
    4. Download discovered assets with rate limiting

    EXAMPLE USAGE:
        ```python
        downloader = AssetDownloader()
        manifest = await downloader.discover("https://example.com")
        assets = await downloader.download_bundle(manifest)
        print(f"Downloaded {len(assets)} assets")
        ```
    """

    # Event names for integration with EventBus
    EVENT_DOWNLOAD_STARTED = "mimic_download_started"
    EVENT_DOWNLOAD_COMPLETED = "mimic_download_completed"
    EVENT_ASSET_DOWNLOADED = "mimic_asset_downloaded"
    EVENT_DOWNLOAD_FAILED = "mimic_download_failed"

    # Rate limiting
    DEFAULT_MAX_CONCURRENT = 10
    DEFAULT_RATE_LIMIT = 20  # requests per second

    # Common asset paths to spider
    COMMON_PATHS = [
        "/static/js/",
        "/static/css/",
        "/assets/",
        "/js/",
        "/css/",
        "/dist/",
        "/build/",
        "/_next/static/",  # Next.js
        "/_next/",  # Next.js chunks
    ]

    def __init__(
        self,
        safe_mode: bool = SAFE_MODE,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        cache_dir: Optional[Path] = None,
    ):
        """
        Initialize AssetDownloader.

        Args:
            safe_mode: If True, respects robots.txt
            max_concurrent: Maximum concurrent downloads
            rate_limit: Maximum requests per second
            cache_dir: Optional directory for caching downloads
        """
        self._safe_mode = safe_mode
        self._max_concurrent = max_concurrent
        self._rate_limit = rate_limit
        self._cache_dir = cache_dir
        self._download_count = 0
        self._robots_disallow: Set[str] = set()
        self._downloaded_assets: Dict[str, DownloadedAsset] = {}
        self._robots_loaded_for: Set[str] = set()

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def download_count(self) -> int:
        """Get number of downloads performed."""
        return self._download_count

    @staticmethod
    def detect_type_from_url(url: str) -> AssetType:
        """
        Detect asset type from URL extension.

        TODO: Implement extension-based type detection.
        TODO: Handle content-type headers as fallback.
        TODO: Detect webpack chunk naming patterns.

        Args:
            url: Asset URL

        Returns:
            Detected AssetType

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        path = urlparse(url).path.lower()

        if path.endswith(".map"):
            return AssetType.SOURCE_MAP
        if path.endswith((".js", ".mjs", ".cjs")) or ".js?" in path:
            return AssetType.JAVASCRIPT
        if path.endswith(".css"):
            return AssetType.CSS
        if path.endswith((".woff", ".woff2", ".ttf", ".otf", ".eot")):
            return AssetType.FONT
        if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".avif")):
            return AssetType.IMAGE
        if any(name in path for name in ("manifest", "webpack-stats", "asset-manifest")):
            return AssetType.MANIFEST
        return AssetType.OTHER

    async def download(self, url: str, timeout: float = 10.0) -> DownloadedAsset:
        """
        Download a single asset and cache it in-memory.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid asset URL scheme: {parsed.scheme}")

        if self._safe_mode:
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base not in self._robots_loaded_for:
                await self._load_robots_txt(base)
            if not self._is_allowed_path(parsed.path):
                raise PermissionError(f"robots.txt disallow for {parsed.path}")

        if url in self._downloaded_assets:
            return self._downloaded_assets[url]

        # Lightweight rate limit: spread requests over configured RPS.
        if self._rate_limit > 0:
            await asyncio.sleep(1.0 / float(self._rate_limit))

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            response = await client.get(url, timeout=timeout)
            response.raise_for_status()
            content_bytes = response.content

        max_size_mb = get_config().mimic.max_asset_size_mb
        max_bytes = int(max_size_mb * 1024 * 1024)
        if len(content_bytes) > max_bytes:
            raise ValueError(
                f"Asset too large ({len(content_bytes)} bytes) exceeds limit {max_bytes} bytes"
            )

        asset_type = self.detect_type_from_url(url)
        content: bytes | str = content_bytes
        if asset_type in (AssetType.JAVASCRIPT, AssetType.CSS, AssetType.MANIFEST, AssetType.SOURCE_MAP):
            try:
                content = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                content = content_bytes.decode("latin-1", errors="replace")

        asset = DownloadedAsset.from_response(
            url=url,
            content=content,
            headers={k: v for k, v in response.headers.items()},
            asset_type=asset_type,
        )
        self._downloaded_assets[url] = asset
        self._download_count += 1
        return asset

    def get_cached_asset(self, url: str) -> Optional[DownloadedAsset]:
        """Return an already-downloaded asset from in-memory cache."""
        return self._downloaded_assets.get(url)

    async def discover(self, target: str) -> AssetManifest:
        """
        Discover all frontend assets for a target.

        This method:
        1. Fetches manifest.json if available
        2. Spiders common asset paths
        3. Checks for Source Map references

        TODO: Implement manifest fetching.
        TODO: Implement directory spidering with rate limiting.
        TODO: Parse HTML for <script src="..."> references.

        Args:
            target: Base URL of target application

        Returns:
            AssetManifest with discovered asset URLs

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Validate target
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid target scheme: {parsed.scheme}")

        # Check robots.txt in safe mode
        if self._safe_mode:
            await self._load_robots_txt(target)

        # Emit event (integration point)
        logger.debug(
            f"[AssetDownloader] {self.EVENT_DOWNLOAD_STARTED}: target={target}"
        )

        # Create manifest skeleton
        manifest = AssetManifest(
            target=parsed.netloc,
            base_url=target.rstrip("/"),
        )
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            try:
                response = await client.get(target, timeout=8.0)
                if response.status_code == 200:
                    text = response.text
                    # JavaScript sources from script tags.
                    for src in re.findall(r'<script[^>]*src=["\'](.*?)["\']', text, flags=re.IGNORECASE):
                        manifest.add_asset(urljoin(manifest.base_url + "/", src))
                    # CSS sources from link tags.
                    for href in re.findall(
                        r'<link[^>]*href=["\'](.*?)["\']',
                        text,
                        flags=re.IGNORECASE,
                    ):
                        if href.lower().endswith(".css"):
                            manifest.add_asset(urljoin(manifest.base_url + "/", href))
            except Exception as exc:
                logger.debug("[AssetDownloader] discover root fetch failed: %s", exc)

            # Probe common manifests.
            for probe in ("/manifest.json", "/asset-manifest.json", "/vite-manifest.json", "/webpack-stats.json"):
                probe_url = urljoin(manifest.base_url + "/", probe)
                try:
                    resp = await client.get(probe_url, timeout=4.0)
                    if resp.status_code == 200:
                        manifest.add_asset(probe_url)
                except Exception:
                    continue

        return manifest

    async def download_bundle(
        self,
        manifest: AssetManifest
    ) -> List[DownloadedAsset]:
        """
        Download all assets from a manifest.

        TODO: Implement concurrent downloading with semaphore.
        TODO: Implement rate limiting (token bucket).
        TODO: Cache results to local filesystem.
        TODO: Handle download errors gracefully.

        Args:
            manifest: AssetManifest from discover()

        Returns:
            List of DownloadedAsset objects

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Update statistics
        self._download_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[AssetDownloader] Downloading {len(manifest.assets)} assets "
            f"from {manifest.target}"
        )

        semaphore = asyncio.Semaphore(max(1, self._max_concurrent))
        downloaded: List[DownloadedAsset] = []

        async def _fetch(url: str) -> None:
            async with semaphore:
                try:
                    asset = await self.download(url)
                    downloaded.append(asset)
                except Exception as exc:
                    logger.debug("[AssetDownloader] download failed url=%s err=%s", url, exc)

        await asyncio.gather(*(_fetch(asset_url) for asset_url in manifest.assets), return_exceptions=True)
        return downloaded

    async def save_to_cache(
        self,
        asset: DownloadedAsset,
        path: Optional[Path] = None
    ) -> Path:
        """
        Save downloaded asset to local cache.

        TODO: Implement file system caching.
        TODO: Organize by target and content hash.
        TODO: Handle large files efficiently.

        Args:
            asset: The asset to cache
            path: Optional custom path (uses cache_dir if not provided)

        Returns:
            Path where asset was saved

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        cache_base = path or self._cache_dir
        if cache_base is None:
            cache_base = Path(get_config().storage.base_dir) / "mimic-cache"
        cache_base.mkdir(parents=True, exist_ok=True)

        suffix_map = {
            AssetType.JAVASCRIPT: ".js",
            AssetType.SOURCE_MAP: ".map",
            AssetType.CSS: ".css",
            AssetType.MANIFEST: ".json",
            AssetType.FONT: ".font",
            AssetType.IMAGE: ".img",
        }
        suffix = suffix_map.get(asset.asset_type, ".bin")
        output_path = cache_base / f"{asset.content_hash}{suffix}"

        if isinstance(asset.content, str):
            payload = asset.content.encode("utf-8")
        else:
            payload = asset.content
        output_path.write_bytes(payload)
        return output_path

    async def fetch_source_map(
        self,
        js_url: str
    ) -> Optional[DownloadedAsset]:
        """
        Try to fetch Source Map for a JavaScript bundle.

        Source Maps typically have .map extension and are referenced
        in the JS file via sourceMappingURL comment.

        TODO: Parse sourceMappingURL from JS content.
        TODO: Fetch corresponding .map file.
        TODO: Handle inline source maps.

        Args:
            js_url: URL of JavaScript bundle

        Returns:
            DownloadedAsset if found, None otherwise

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        js_asset = self._downloaded_assets.get(js_url)
        candidate_urls: List[str] = []

        if js_asset is not None:
            content = js_asset.content if isinstance(js_asset.content, str) else js_asset.content.decode("utf-8", errors="ignore")
            match = re.search(r"sourceMappingURL=(.+)", content)
            if match:
                source_map_ref = match.group(1).strip()
                candidate_urls.append(urljoin(js_url, source_map_ref))

        # Fallback: assume conventional ".map" sibling.
        if not candidate_urls:
            candidate_urls.append(f"{js_url}.map")

        for candidate in candidate_urls:
            try:
                asset = await self.download(candidate)
                if asset.asset_type == AssetType.SOURCE_MAP or candidate.endswith(".map"):
                    return asset
            except Exception:
                continue
        return None

    async def _load_robots_txt(self, target: str) -> None:
        """
        Load robots.txt to respect crawl rules.

        TODO: Fetch /robots.txt from target.
        TODO: Parse disallow rules.
        TODO: Store rules for checking during spider.

        Args:
            target: Base URL of target

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return
        base = f"{parsed.scheme}://{parsed.netloc}"

        if base in self._robots_loaded_for:
            return

        self._robots_loaded_for.add(base)
        robots_url = urljoin(base + "/", "robots.txt")
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                response = await client.get(robots_url, timeout=4.0)
            if response.status_code != 200:
                return

            for line in response.text.splitlines():
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                if clean.lower().startswith("disallow:"):
                    path = clean.split(":", 1)[1].strip()
                    if path and path != "/":
                        self._robots_disallow.add(path)
        except Exception as exc:
            logger.debug("[AssetDownloader] robots.txt fetch failed for %s: %s", base, exc)

    def _is_allowed_path(self, path: str) -> bool:
        normalized = path or "/"
        for disallowed in self._robots_disallow:
            if disallowed == "/":
                return False
            if normalized.startswith(disallowed):
                return False
        return True

    def replay(self, recorded_assets: Dict[str, Any]) -> List[DownloadedAsset]:
        """
        Replay previously downloaded assets for analysis.

        Enables replayability without re-downloading.

        Args:
            recorded_assets: Serialized assets from cache

        Returns:
            List of DownloadedAsset objects

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        payload = recorded_assets.get("assets", recorded_assets)
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return []

        restored: List[DownloadedAsset] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            try:
                asset_type = AssetType(item.get("asset_type", AssetType.OTHER.value))
            except Exception:
                asset_type = AssetType.OTHER
            content = item.get("content", b"")
            if isinstance(content, list):
                try:
                    content = bytes(content)
                except Exception:
                    content = b""
            if not isinstance(content, (bytes, str)):
                content = str(content)
            restored.append(
                DownloadedAsset(
                    url=str(item.get("url", "")),
                    asset_type=asset_type,
                    content=content,
                    size_bytes=int(item.get("size_bytes", 0)),
                    content_hash=str(item.get("content_hash", "")),
                    headers=item.get("headers", {}) if isinstance(item.get("headers"), dict) else {},
                )
            )
        return restored

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this AssetDownloader instance.

        Returns:
            Dictionary with download statistics
        """
        return {
            "download_count": self._download_count,
            "safe_mode": self._safe_mode,
            "max_concurrent": self._max_concurrent,
            "rate_limit": self._rate_limit,
            "robots_disallow_count": len(self._robots_disallow),
        }


def create_asset_downloader(
    safe_mode: bool = SAFE_MODE,
    max_concurrent: int = AssetDownloader.DEFAULT_MAX_CONCURRENT,
    rate_limit: int = AssetDownloader.DEFAULT_RATE_LIMIT,
    cache_dir: Optional[Path] = None,
) -> AssetDownloader:
    """
    Factory function to create AssetDownloader instance.

    This is the recommended way to create AssetDownloader objects in production code.

    Args:
        safe_mode: Safety mode flag
        max_concurrent: Maximum concurrent downloads
        rate_limit: Maximum requests per second
        cache_dir: Optional cache directory

    Returns:
        Configured AssetDownloader instance
    """
    # Use config defaults if not provided (or if they match the hardcoded defaults)
    config = get_config()
    mimic_cfg = config.mimic
    
    # If the caller passed the hardcoded default (likely from a CLI default arg),
    # we prefer the config value.
    if safe_mode == SAFE_MODE:
        safe_mode = mimic_cfg.safe_mode
        
    if max_concurrent == AssetDownloader.DEFAULT_MAX_CONCURRENT:
        max_concurrent = mimic_cfg.max_download_concurrent
        
    if rate_limit == AssetDownloader.DEFAULT_RATE_LIMIT:
        rate_limit = mimic_cfg.download_rate_limit

    return AssetDownloader(
        safe_mode=safe_mode,
        max_concurrent=max_concurrent,
        rate_limit=rate_limit,
        cache_dir=cache_dir,
    )


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    # Verify AssetType enum
    assert AssetType.JAVASCRIPT.value == "javascript"
    assert AssetType.SOURCE_MAP.value == "source_map"
    print("✓ AssetType enum works")

    # Verify DownloadedAsset dataclass
    asset = DownloadedAsset.from_response(
        url="https://example.com/app.js",
        content=b"console.log('test');",
        headers={"Content-Type": "application/javascript"},
    )

    assert asset.asset_type == AssetType.JAVASCRIPT
    assert asset.size_bytes == 23
    assert asset.to_dict()["asset_type"] == "javascript"
    print("✓ DownloadedAsset structure works")

    # Verify AssetManifest dataclass
    manifest = AssetManifest(
        target="example.com",
        base_url="https://example.com",
    )
    manifest.add_asset("/static/app.js")
    manifest.add_asset("/static/app.js")  # Duplicate
    manifest.add_asset("/static/chunk.js")

    assert len(manifest.assets) == 2  # Duplicate filtered
    assert manifest.to_dict()["asset_count"] == 2
    print("✓ AssetManifest structure works")

    # Verify AssetDownloader creation
    downloader = create_asset_downloader()
    assert downloader.safe_mode is True
    assert downloader.download_count == 0
    print("✓ AssetDownloader factory works")

    print("\n✅ All AssetDownloader design invariants verified!")
