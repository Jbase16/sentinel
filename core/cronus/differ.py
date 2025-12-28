"""
CRONUS Sitemap Differ - Temporal Change Detection

PURPOSE:
Compare historical sitemaps against current sitemaps to identify "zombie" endpoints -
paths that existed in the past but have been removed from documentation while potentially
remaining active on servers.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Identify incomplete deprecation processes
- Detect documentation drift from implementation
- Audit their own API surface changes over time
- Test proper endpoint removal during red team exercises

ASSUMPTIONS:
1. Sitemaps can be extracted from historical snapshots
2. Current sitemap is accessible via standard discovery
3. Endpoints are identified by path (not full URL)
4. Parameters within paths are significant

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, refuses to analyze non-HTTPS targets
- No modification of target sitemaps (read-only comparison)
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits DIFF_ANALYSIS_STARTED, DIFF_ANALYSIS_COMPLETED events
- DecisionLedger: Logs comparison decisions and confidence scores
- KnowledgeGraph: Stores temporal relationships between endpoints

DEPENDENCIES (Future):
- difflib: Built-in Python for sequence comparison
- urllib.parse: For URL normalization
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class EndpointStatus(str, Enum):
    """
    Classification of endpoint status across time periods.

    These categories help prioritize which "zombie" endpoints to investigate:
    - DELETED: High priority - may be forgotten but still active
    - STABLE: Low priority - intentionally maintained
    - MODIFIED: Medium priority - behavior may have changed
    """
    DELETED = "deleted"      # Existed in past, missing in present
    STABLE = "stable"        # Exists in both past and present
    MODIFIED = "modified"    # Path exists but parameters changed
    ADDED = "added"          # New in present (not in past)


@dataclass(frozen=True)
class Endpoint:
    """
    Representation of a single API/HTTP endpoint.

    Attributes:
        path: The URL path (e.g., "/api/v1/users")
        method: HTTP method (GET, POST, etc.)
        parameters: List of query/body parameter names
        first_seen: When this endpoint was first observed
        last_seen: When this endpoint was last observed
        source: Where this endpoint was discovered (sitemap, code, etc.)
    """
    path: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source: str = "unknown"

    def __post_init__(self):
        """Normalize path format."""
        # Ensure path starts with /
        raw_path = self.path
        if not raw_path.startswith("/"):
            object.__setattr__(self, "path", f"/{raw_path}")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize endpoint to dict."""
        return {
            "path": self.path,
            "method": self.method,
            "parameters": self.parameters,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "source": self.source,
        }

    @property
    def signature(self) -> str:
        """
        Get unique signature for this endpoint.

        Returns:
            String like "GET:/api/v1/users"
        """
        return f"{self.method}:{self.path}"


@dataclass
class DiffReport:
    """
    Report comparing historical and current sitemaps.

    Attributes:
        target: Domain that was analyzed
        timestamp_past: When historical sitemap was captured
        timestamp_present: When current sitemap was captured
        deleted: Endpoints that existed in past but not present
        stable: Endpoints that exist in both
        added: Endpoints that are new in present
        modified: Endpoints that exist but changed
        confidence: How confident we are in this diff (0.0-1.0)
    """
    target: str
    timestamp_past: datetime
    timestamp_present: datetime
    deleted: List[Endpoint] = field(default_factory=list)
    stable: List[Endpoint] = field(default_factory=list)
    added: List[Endpoint] = field(default_factory=list)
    modified: List[Endpoint] = field(default_factory=list)
    confidence: float = 1.0

    def get_zombie_candidates(self) -> List[Endpoint]:
        """
        Get high-priority zombie endpoint candidates.

        These are endpoints that were deleted from documentation
        but may still be active on the server.

        Returns:
            List of deleted endpoints
        """
        return self.deleted

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to dict."""
        return {
            "target": self.target,
            "timestamp_past": self.timestamp_past.isoformat(),
            "timestamp_present": self.timestamp_present.isoformat(),
            "summary": {
                "deleted_count": len(self.deleted),
                "stable_count": len(self.stable),
                "added_count": len(self.added),
                "modified_count": len(self.modified),
            },
            "deleted": [e.to_dict() for e in self.deleted],
            "stable": [e.to_dict() for e in self.stable],
            "added": [e.to_dict() for e in self.added],
            "modified": [e.to_dict() for e in self.modified],
            "confidence": self.confidence,
        }


class SitemapDiffer:
    """
    Compares historical and current sitemaps to identify zombie endpoints.

    This class performs set-based analysis to find:
    - Deleted endpoints (A - B)
    - Stable endpoints (A & B)
    - Added endpoints (B - A)
    - Modified endpoints (path same, params different)

    EXAMPLE USAGE:
        ```python
        differ = SitemapDiffer()
        past = [Endpoint("/api/v1/old"), Endpoint("/api/v1/stable")]
        present = [Endpoint("/api/v1/stable"), Endpoint("/api/v2/new")]
        report = differ.compare_sets(past, present, "example.com")
        zombies = report.get_zombie_candidates()
        ```
    """

    # Event names for integration with EventBus
    EVENT_DIFF_STARTED = "cronus_diff_started"
    EVENT_DIFF_COMPLETED = "cronus_diff_completed"
    EVENT_DIFF_FAILED = "cronus_diff_failed"

    def __init__(self, safe_mode: bool = SAFE_MODE):
        """
        Initialize SitemapDiffer.

        Args:
            safe_mode: If True, enforces HTTPS-only targets
        """
        self._safe_mode = safe_mode
        self._comparison_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def comparison_count(self) -> int:
        """Get number of comparisons performed."""
        return self._comparison_count

    def compare_sets(
        self,
        old_sitemap: List[Endpoint],
        new_sitemap: List[Endpoint],
        target: str,
        timestamp_past: Optional[datetime] = None,
        timestamp_present: Optional[datetime] = None,
    ) -> DiffReport:
        """
        Compare historical and current sitemaps.

        TODO: Implement set difference calculation.
        TODO: Implement parameter change detection for "modified" status.
        TODO: Implement confidence scoring based on sample size.

        Args:
            old_sitemap: Endpoints from historical snapshot
            new_sitemap: Endpoints from current state
            target: Domain being analyzed
            timestamp_past: When old sitemap was captured
            timestamp_present: When new sitemap was captured

        Returns:
            DiffReport with categorized endpoints

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Validate target in safe mode
        if self._safe_mode:
            parsed = urlparse(target if "://" in target else f"https://{target}")
            if parsed.scheme != "https":
                raise ValueError(
                    f"SAFE_MODE: Only HTTPS targets allowed. Got: {parsed.scheme}"
                )

        # Update statistics
        self._comparison_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[SitemapDiffer] {self.EVENT_DIFF_STARTED}: "
            f"target={target}, old_count={len(old_sitemap)}, new_count={len(new_sitemap)}"
        )

        raise NotImplementedError(
            "Wrapper-only: Set comparison implementation deferred. "
            "Future implementation should use set operations for O(n) complexity."
        )

    def get_deleted_paths(
        self,
        old_sitemap: List[Endpoint],
        new_sitemap: List[Endpoint]
    ) -> List[Endpoint]:
        """
        Find endpoints that existed in past but are missing in present.

        These are the "zombie" candidates - endpoints removed from
        documentation but potentially still active.

        TODO: Implement A - B set difference.
        TODO: Filter by method (GET vs POST matters).
        TODO: Return sorted by risk score (if available).

        Args:
            old_sitemap: Historical endpoints
            new_sitemap: Current endpoints

        Returns:
            List of deleted endpoints

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Deleted path extraction deferred. "
            "Future implementation should use set(old_sitemap) - set(new_sitemap)."
        )

    def get_stable_paths(
        self,
        old_sitemap: List[Endpoint],
        new_sitemap: List[Endpoint]
    ) -> List[Endpoint]:
        """
        Find endpoints that exist in both past and present.

        These represent stable, maintained API surfaces.

        TODO: Implement A & B set intersection.

        Args:
            old_sitemap: Historical endpoints
            new_sitemap: Current endpoints

        Returns:
            List of stable endpoints

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Stable path extraction deferred. "
            "Future implementation should use set(old_sitemap) & set(new_sitemap)."
        )

    def detect_parameter_changes(
        self,
        old_endpoint: Endpoint,
        new_endpoint: Endpoint
    ) -> bool:
        """
        Check if an endpoint's parameters have changed.

        This identifies cases where the path remains the same but
        the interface has evolved (e.g., added required parameters).

        TODO: Implement parameter comparison logic.
        TODO: Detect parameter type changes (string -> int).
        TODO: Detect parameter requirement changes (optional -> required).

        Args:
            old_endpoint: Historical endpoint definition
            new_endpoint: Current endpoint definition

        Returns:
            True if parameters differ significantly

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Parameter change detection deferred. "
            "Future implementation should compare parameter lists and metadata."
        )

    def calculate_confidence(
        self,
        old_sample_size: int,
        new_sample_size: int,
        overlap_ratio: float
    ) -> float:
        """
        Calculate confidence score for the diff report.

        Higher confidence when:
        - Large sample sizes (more endpoints = better comparison)
        - High overlap ratio (stable comparison baseline)

        TODO: Implement confidence scoring algorithm.
        TODO: Adjust based on source reliability (sitemap vs scraped).

        Args:
            old_sample_size: Number of historical endpoints
            new_sample_size: Number of current endpoints
            overlap_ratio: Proportion of stable endpoints (0.0-1.0)

        Returns:
            Confidence score from 0.0 to 1.0

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Confidence calculation deferred. "
            "Future implementation should use weighted sample size and overlap metrics."
        )

    def replay(self, recorded_diff: Dict[str, Any]) -> DiffReport:
        """
        Replay a previously generated diff for analysis.

        Enables replayability without re-computing set differences.

        Args:
            recorded_diff: Serialized DiffReport from to_dict()

        Returns:
            Reconstructed DiffReport

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Diff replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this SitemapDiffer instance.

        Returns:
            Dictionary with comparison statistics
        """
        return {
            "comparison_count": self._comparison_count,
            "safe_mode": self._safe_mode,
        }


def create_sitemap_differ(safe_mode: bool = SAFE_MODE) -> SitemapDiffer:
    """
    Factory function to create SitemapDiffer instance.

    This is the recommended way to create SitemapDiffer objects in production code.

    Args:
        safe_mode: Safety mode flag

    Returns:
        Configured SitemapDiffer instance
    """
    return SitemapDiffer(safe_mode=safe_mode)


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    # Verify Endpoint dataclass
    ep1 = Endpoint(path="/api/v1/users", method="GET", parameters=["id"])
    ep2 = Endpoint(path="api/v1/users")  # Missing leading slash

    assert ep1.to_dict()["path"] == "/api/v1/users"
    assert ep2.path == "/api/v1/users", "Path normalization should add leading /"
    assert ep1.signature == "GET:/api/v1/users"
    print("✓ Endpoint normalization works")

    # Verify EndpointStatus enum
    assert EndpointStatus.DELETED.value == "deleted"
    print("✓ EndpointStatus enum works")

    # Verify SitemapDiffer creation
    differ = create_sitemap_differ()
    assert differ.safe_mode is True
    assert differ.comparison_count == 0
    print("✓ SitemapDiffer factory works")

    # Verify safe mode enforcement
    try:
        differ.compare_sets(
            old_sitemap=[],
            new_sitemap=[],
            target="http://insecure.com",  # Non-HTTPS
        )
        print("✗ Safe mode enforcement failed")
    except ValueError as e:
        if "SAFE_MODE" in str(e):
            print("✓ Safe mode enforcement works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All SitemapDiffer design invariants verified!")
