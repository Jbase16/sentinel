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

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
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
        raise NotImplementedError(
            "Wrapper-only: Asset type detection deferred. "
            "Future implementation should check file extensions."
        )

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

        raise NotImplementedError(
            "Wrapper-only: Asset discovery implementation deferred. "
            "Future implementation should spider and parse HTML."
        )

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

        raise NotImplementedError(
            "Wrapper-only: Bundle download implementation deferred. "
            "Future implementation should use asyncio.gather with semaphore."
        )

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
        raise NotImplementedError(
            "Wrapper-only: Asset caching implementation deferred. "
            "Future implementation should write to cache_dir with hash-based naming."
        )

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
        raise NotImplementedError(
            "Wrapper-only: Source Map fetching deferred. "
            "Future implementation should parse sourceMappingURL comments."
        )

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
        raise NotImplementedError(
            "Wrapper-only: robots.txt parsing deferred. "
            "Future implementation should use robotexclusionrulesparser."
        )

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
        raise NotImplementedError(
            "Wrapper-only: Asset replay implementation deferred. "
            "Future implementation should load from evidence store."
        )

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
