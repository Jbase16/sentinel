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
from typing import Any, Dict, List, Optional
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

    def _build_signature_map(
        self,
        endpoints: List[Endpoint]
    ) -> Dict[str, Endpoint]:
        """
        Build a map from endpoint signatures to endpoints.

        The signature is "{method}:{path}" which uniquely identifies
        an endpoint for comparison purposes.

        Args:
            endpoints: List of endpoints to map

        Returns:
            Dictionary mapping signatures to endpoints
        """
        return {ep.signature: ep for ep in endpoints}

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

        Performs set-based analysis to categorize endpoints as:
        - Deleted: In old but not in new (zombie candidates)
        - Stable: In both old and new
        - Added: In new but not in old
        - Modified: Same path but different parameters

        Args:
            old_sitemap: Endpoints from historical snapshot
            new_sitemap: Endpoints from current state
            target: Domain being analyzed
            timestamp_past: When old sitemap was captured
            timestamp_present: When new sitemap was captured

        Returns:
            DiffReport with categorized endpoints
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
        logger.info(
            f"[SitemapDiffer] {self.EVENT_DIFF_STARTED}: "
            f"target={target}, old_count={len(old_sitemap)}, new_count={len(new_sitemap)}"
        )

        # Build signature maps for O(1) lookups
        old_map = self._build_signature_map(old_sitemap)
        new_map = self._build_signature_map(new_sitemap)

        old_sigs = set(old_map.keys())
        new_sigs = set(new_map.keys())

        # Set operations for categorization
        deleted_sigs = old_sigs - new_sigs
        added_sigs = new_sigs - old_sigs
        common_sigs = old_sigs & new_sigs

        # Categorize endpoints
        deleted: List[Endpoint] = [old_map[sig] for sig in deleted_sigs]
        added: List[Endpoint] = [new_map[sig] for sig in added_sigs]
        stable: List[Endpoint] = []
        modified: List[Endpoint] = []

        # Check common endpoints for parameter changes
        for sig in common_sigs:
            old_ep = old_map[sig]
            new_ep = new_map[sig]

            if self.detect_parameter_changes(old_ep, new_ep):
                modified.append(new_ep)
            else:
                stable.append(new_ep)

        # Calculate confidence
        overlap_ratio = len(common_sigs) / max(len(old_sigs), 1)
        confidence = self.calculate_confidence(
            len(old_sitemap),
            len(new_sitemap),
            overlap_ratio
        )

        # Build report
        report = DiffReport(
            target=target,
            timestamp_past=timestamp_past or datetime.utcnow(),
            timestamp_present=timestamp_present or datetime.utcnow(),
            deleted=deleted,
            stable=stable,
            added=added,
            modified=modified,
            confidence=confidence,
        )

        logger.info(
            f"[SitemapDiffer] {self.EVENT_DIFF_COMPLETED}: "
            f"deleted={len(deleted)}, stable={len(stable)}, "
            f"added={len(added)}, modified={len(modified)}"
        )

        return report

    def get_deleted_paths(
        self,
        old_sitemap: List[Endpoint],
        new_sitemap: List[Endpoint]
    ) -> List[Endpoint]:
        """
        Find endpoints that existed in past but are missing in present.

        These are the "zombie" candidates - endpoints removed from
        documentation but potentially still active.

        Args:
            old_sitemap: Historical endpoints
            new_sitemap: Current endpoints

        Returns:
            List of deleted endpoints, sorted by path
        """
        old_map = self._build_signature_map(old_sitemap)
        new_map = self._build_signature_map(new_sitemap)

        deleted_sigs = set(old_map.keys()) - set(new_map.keys())
        deleted = [old_map[sig] for sig in deleted_sigs]

        # Sort by path for consistent ordering
        return sorted(deleted, key=lambda ep: ep.path)

    def get_stable_paths(
        self,
        old_sitemap: List[Endpoint],
        new_sitemap: List[Endpoint]
    ) -> List[Endpoint]:
        """
        Find endpoints that exist in both past and present.

        These represent stable, maintained API surfaces.

        Args:
            old_sitemap: Historical endpoints
            new_sitemap: Current endpoints

        Returns:
            List of stable endpoints, sorted by path
        """
        old_map = self._build_signature_map(old_sitemap)
        new_map = self._build_signature_map(new_sitemap)

        common_sigs = set(old_map.keys()) & set(new_map.keys())
        stable = [new_map[sig] for sig in common_sigs]

        # Sort by path for consistent ordering
        return sorted(stable, key=lambda ep: ep.path)

    def get_added_paths(
        self,
        old_sitemap: List[Endpoint],
        new_sitemap: List[Endpoint]
    ) -> List[Endpoint]:
        """
        Find endpoints that are new in the present.

        Args:
            old_sitemap: Historical endpoints
            new_sitemap: Current endpoints

        Returns:
            List of added endpoints, sorted by path
        """
        old_map = self._build_signature_map(old_sitemap)
        new_map = self._build_signature_map(new_sitemap)

        added_sigs = set(new_map.keys()) - set(old_map.keys())
        added = [new_map[sig] for sig in added_sigs]

        return sorted(added, key=lambda ep: ep.path)

    def detect_parameter_changes(
        self,
        old_endpoint: Endpoint,
        new_endpoint: Endpoint
    ) -> bool:
        """
        Check if an endpoint's parameters have changed.

        This identifies cases where the path remains the same but
        the interface has evolved (e.g., added required parameters).

        Args:
            old_endpoint: Historical endpoint definition
            new_endpoint: Current endpoint definition

        Returns:
            True if parameters differ significantly
        """
        # Compare parameter lists
        old_params = set(old_endpoint.parameters)
        new_params = set(new_endpoint.parameters)

        # Any difference in parameters counts as a change
        if old_params != new_params:
            return True

        # Check for method changes (if somehow same signature but different method)
        if old_endpoint.method != new_endpoint.method:
            return True

        return False

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

        The formula combines:
        - Sample size factor: log10(min_size + 1) / 3 (scales 0-1 for 1-1000 endpoints)
        - Overlap factor: sqrt(overlap_ratio) (rewards high overlap)
        - Combined: 0.4 * sample_factor + 0.6 * overlap_factor

        Args:
            old_sample_size: Number of historical endpoints
            new_sample_size: Number of current endpoints
            overlap_ratio: Proportion of stable endpoints (0.0-1.0)

        Returns:
            Confidence score from 0.0 to 1.0
        """
        import math

        # Edge case: empty sitemaps
        if old_sample_size == 0 and new_sample_size == 0:
            return 0.0

        if old_sample_size == 0 or new_sample_size == 0:
            # Only one side has data - low confidence
            return 0.2

        # Sample size factor (logarithmic scaling)
        # log10(1001) ≈ 3, so divide by 3 to normalize
        min_size = min(old_sample_size, new_sample_size)
        sample_factor = min(math.log10(min_size + 1) / 3, 1.0)

        # Overlap factor (square root to reward high overlap)
        overlap_factor = math.sqrt(overlap_ratio)

        # Combined score (weighted average)
        confidence = 0.4 * sample_factor + 0.6 * overlap_factor

        # Clamp to [0, 1]
        return max(0.0, min(1.0, confidence))

    def replay(self, recorded_diff: Dict[str, Any]) -> DiffReport:
        """
        Replay a previously generated diff for analysis.

        Enables replayability without re-computing set differences.

        Args:
            recorded_diff: Serialized DiffReport from to_dict()

        Returns:
            Reconstructed DiffReport
        """
        def parse_endpoint(data: Dict[str, Any]) -> Endpoint:
            """Parse endpoint from dict."""
            return Endpoint(
                path=data["path"],
                method=data.get("method", "GET"),
                parameters=data.get("parameters", []),
                first_seen=datetime.fromisoformat(data["first_seen"]) if data.get("first_seen") else None,
                last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
                source=data.get("source", "unknown"),
            )

        return DiffReport(
            target=recorded_diff["target"],
            timestamp_past=datetime.fromisoformat(recorded_diff["timestamp_past"]),
            timestamp_present=datetime.fromisoformat(recorded_diff["timestamp_present"]),
            deleted=[parse_endpoint(ep) for ep in recorded_diff.get("deleted", [])],
            stable=[parse_endpoint(ep) for ep in recorded_diff.get("stable", [])],
            added=[parse_endpoint(ep) for ep in recorded_diff.get("added", [])],
            modified=[parse_endpoint(ep) for ep in recorded_diff.get("modified", [])],
            confidence=recorded_diff.get("confidence", 1.0),
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
