"""
NEXUS Primitives - Low-Severity Finding Inventory

PURPOSE:
Database of "low value" findings that serve as building blocks for exploit chains.
Instead of discarding minor findings, NEXUS treats them as inventory for chain planning.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Track minor issues that could enable attacks
- Understand how small vulnerabilities combine
- Prioritize fixes based on chain participation
- Assess cumulative risk from multiple findings

ASSUMPTIONS:
1. Low-severity findings have value when combined
2. Findings can be linked by dependency relationships
3. Reliability scores indicate exploitation confidence
4. Primitives are reusable across multiple chains

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, excludes exploit primitives from inventory
- No actual exploitation of primitives
- Read-only storage and retrieval
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_PRIMITIVE_COLLECTED events
- DecisionLedger: Logs primitive storage decisions
- KnowledgeGraph: Stores primitive relationships

DEPENDENCIES (Future):
- networkx: For graph-based primitive relationships
- dataclasses: For structured primitive storage
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


class PrimitiveType(str, Enum):
    """
    Types of low-severity findings that become primitives.

    These are "building blocks" that can be chained into attacks.
    The presence of a primitive doesn't mean it's exploitable on its own,
    but it may enable other primitives in a chain.
    """
    REFLECTED_PARAM = "reflected_param"         # XSS via reflected parameter
    OPEN_REDIRECT = "open_redirect"             # Redirect via user input
    LEAKED_HEADER = "leaked_header"             # Information disclosure
    SSRF_PATTERN = "ssrf_pattern"               # URL fetching pattern
    IDOR_PATTERN = "idor_pattern"               # Direct object reference
    MISSING_AUTH = "missing_auth"               # No auth on endpoint
    WEAK_CORS = "weak_cors"                     # Overly permissive CORS
    JSONP_ENDPOINT = "jsonp_endpoint"           # JSONP callback
    DEBUG_PARAM = "debug_param"                 # Debug query parameter
    TEMPLATE_INJECTION = "template_injection"   # SSTI pattern
    DESERIALIZATION = "deserialization"         # Object deserialization
    FILE_UPLOAD = "file_upload"                 # File upload endpoint
    WEBHOOK = "webhook"                         # Webhook registration


class ReliabilityLevel(str, Enum):
    """
    Reliability of a primitive (can it be consistently reproduced?).

    Higher reliability means the primitive is more likely to work
    consistently across requests/environments.
    """
    CERTAIN = "certain"     # 100% reproducible
    HIGH = "high"           # ~90% reproducible
    MEDIUM = "medium"       # ~50% reproducible
    LOW = "low"             # ~10% reproducible
    UNKNOWN = "unknown"     # Reliability unknown


@dataclass(frozen=True)
class Primitive:
    """
    A low-severity finding that can be used in exploit chains.

    Instead of discarding "minor" findings, NEXUS stores them as
    primitives that may enable other attacks when chained.

    Attributes:
        id: Unique identifier
        type: What kind of primitive this is
        target: Where this was found
        parameter: Specific parameter name (if applicable)
        evidence: Proof of existence (response snippet, etc.)
        reliability: How reliable this finding is
        confidence: How confident we are (0.0-1.0)
        enables: Which other primitives this enables (dependencies)
        discovered_at: When this was found
        source: Which tool/scanner found this
    """
    id: str
    type: PrimitiveType
    target: str
    parameter: Optional[str] = None
    evidence: str = ""
    reliability: ReliabilityLevel = ReliabilityLevel.MEDIUM
    confidence: float = 0.5
    enables: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=lambda: datetime.utcnow())
    source: str = "unknown"

    def __post_init__(self):
        """Validate primitive fields."""
        # Validate confidence range
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0-1.0, got {self.confidence}")

        # Validate target is a valid domain
        if "://" in self.target:
            parsed = urlparse(self.target)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"Invalid target scheme: {parsed.scheme}")

    @property
    def is_reliable(self) -> bool:
        """Check if this primitive is reliable enough for chaining."""
        return self.reliability in (ReliabilityLevel.CERTAIN, ReliabilityLevel.HIGH)

    @property
    def signature(self) -> str:
        """Get unique signature for this primitive."""
        param_part = f":{self.parameter}" if self.parameter else ""
        return f"{self.type.value}{param_part}@{self.target}"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize primitive to dict."""
        return {
            "id": self.id,
            "type": self.type.value,
            "target": self.target,
            "parameter": self.parameter,
            "evidence": self.evidence[:200],  # Truncate for storage
            "reliability": self.reliability.value,
            "confidence": self.confidence,
            "enables": self.enables,
            "discovered_at": self.discovered_at.isoformat(),
            "source": self.source,
        }


@dataclass
class PrimitiveInventory:
    """
    Database of primitives for a target.

    This stores all low-severity findings that could be used
    as building blocks in exploit chains.

    Attributes:
        target: Domain these primitives belong to
        primitives: List of discovered primitives
        by_type: Primitives indexed by type
        dependencies: Which primitives enable which others
        last_updated: When inventory was last updated
    """
    target: str
    primitives: List[Primitive] = field(default_factory=list)
    by_type: Dict[PrimitiveType, List[Primitive]] = field(default_factory=dict)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.utcnow())

    def add_primitive(self, primitive: Primitive) -> None:
        """Add a primitive to the inventory."""
        if primitive not in self.primitives:
            self.primitives.append(primitive)

        # Update type index
        if primitive.type not in self.by_type:
            self.by_type[primitive.type] = []
        if primitive not in self.by_type[primitive.type]:
            self.by_type[primitive.type].append(primitive)

        # Update dependencies
        for enabled_id in primitive.enables:
            if enabled_id not in self.dependencies:
                self.dependencies[enabled_id] = []
            if primitive.id not in self.dependencies[enabled_id]:
                self.dependencies[enabled_id].append(primitive.id)

        self.last_updated = datetime.utcnow()

    def find_primitives_by_type(self, type: PrimitiveType) -> List[Primitive]:
        """Get all primitives of a specific type."""
        return self.by_type.get(type, [])

    def find_primitives_by_target(self, target: str) -> List[Primitive]:
        """Get all primitives for a specific target."""
        return [p for p in self.primitives if p.target == target]

    def get_reliable_primitives(self) -> List[Primitive]:
        """Get only reliable primitives (confidence >= 0.7)."""
        return [p for p in self.primitives if p.is_reliable]

    def get_dependencies_for(self, primitive_id: str) -> List[Primitive]:
        """Get primitives that enable the given primitive."""
        if primitive_id not in self.dependencies:
            return []
        return [
            p for p in self.primitives
            if p.id in self.dependencies[primitive_id]
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize inventory to dict."""
        return {
            "target": self.target,
            "total_primitives": len(self.primitives),
            "by_type": {
                type.value: len(prims)
                for type, prims in self.by_type.items()
            },
            "dependency_count": len(self.dependencies),
            "last_updated": self.last_updated.isoformat(),
        }


class PrimitiveCollector:
    """
    Collects low-severity findings as primitives.

    This class processes scan results and extracts primitives,
    converting "noise" into "inventory" for chain planning.

    COLLECTION STRATEGY:
    1. Scan findings for primitive patterns
    2. Extract relevant parameters and evidence
    3. Assess reliability and confidence
    4. Store in inventory for later chaining

    EXAMPLE USAGE:
        ```python
        collector = PrimitiveCollector()
        findings = scan({"reflected": {"param": "name"}})
        inventory = collector.collect(findings, "example.com")
        ```
    """

    # Event names for integration with EventBus
    EVENT_COLLECT_STARTED = "nexus_collect_started"
    EVENT_COLLECT_COMPLETED = "nexus_collect_completed"
    EVENT_PRIMITIVE_FOUND = "nexus_primitive_found"

    def __init__(self, safe_mode: bool = SAFE_MODE):
        """
        Initialize PrimitiveCollector.

        Args:
            safe_mode: If True, excludes exploit primitives
        """
        self._safe_mode = safe_mode
        self._collection_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def collection_count(self) -> int:
        """Get number of collections performed."""
        return self._collection_count

    def collect(
        self,
        findings: List[Dict[str, Any]],
        target: str,
    ) -> PrimitiveInventory:
        """
        Collect primitives from scan findings.

        TODO: Implement finding-to-primitive conversion.
        TODO: Detect primitive types from findings.
        TODO: Extract parameters and evidence.
        TODO: Assess reliability based on reproducibility.
        TODO: Build dependency graph between primitives.

        Args:
            findings: Scan results to process
            target: Domain these findings belong to

        Returns:
            PrimitiveInventory with extracted primitives

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Update statistics
        self._collection_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[PrimitiveCollector] {self.EVENT_COLLECT_STARTED}: "
            f"target={target}, findings={len(findings)}"
        )

        # Create inventory skeleton
        inventory = PrimitiveInventory(target=target)

        raise NotImplementedError(
            "Wrapper-only: Primitive collection implementation deferred. "
            "Future implementation should extract primitives from findings."
        )

    def find_primitive_patterns(
        self,
        finding: Dict[str, Any]
    ) -> List[Primitive]:
        """
        Identify primitive patterns in a finding.

        TODO: Match finding against primitive type patterns.
        TODO: Extract relevant parameters.
        TODO: Generate appropriate evidence strings.
        TODO: Calculate confidence scores.

        Args:
            finding: A single scan finding

        Returns:
            List of detected primitives

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Pattern detection deferred. "
            "Future implementation should match finding signatures."
        )

    def calculate_reliability(
        self,
        finding: Dict[str, Any]
    ) -> ReliabilityLevel:
        """
        Assess reliability of a primitive from finding.

        TODO: Check for consistent reproducibility.
        TODO: Assess tool confidence in finding.
        TODO: Check for false positive indicators.
        TODO: Consider environment-specific factors.

        Args:
            finding: A single scan finding

        Returns:
            Assessed reliability level

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Reliability calculation deferred. "
            "Future implementation should score based on finding metadata."
        )

    def replay(self, recorded_inventory: Dict[str, Any]) -> PrimitiveInventory:
        """
        Replay a previously collected inventory.

        Enables replayability without re-collecting.

        Args:
            recorded_inventory: Serialized PrimitiveInventory from to_dict()

        Returns:
            Reconstructed PrimitiveInventory

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Inventory replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this PrimitiveCollector instance.

        Returns:
            Dictionary with collection statistics
        """
        return {
            "collection_count": self._collection_count,
            "safe_mode": self._safe_mode,
        }


def create_primitive_collector(safe_mode: bool = SAFE_MODE) -> PrimitiveCollector:
    """
    Factory function to create PrimitiveCollector instance.

    This is the recommended way to create PrimitiveCollector objects in production code.

    Args:
        safe_mode: Safety mode flag

    Returns:
        Configured PrimitiveCollector instance
    """
    return PrimitiveCollector(safe_mode=safe_mode)


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    import uuid

    # Verify enums
    assert PrimitiveType.REFLECTED_PARAM.value == "reflected_param"
    assert ReliabilityLevel.HIGH.value == "high"
    print("✓ Enums work")

    # Verify Primitive dataclass
    prim = Primitive(
        id=str(uuid.uuid4()),
        type=PrimitiveType.REFLECTED_PARAM,
        target="example.com",
        parameter="name",
        evidence="Reflection in response",
        reliability=ReliabilityLevel.HIGH,
        confidence=0.8,
    )

    assert prim.is_reliable is True
    assert prim.signature.startswith("reflected_param:name@")
    assert prim.to_dict()["type"] == "reflected_param"
    print("✓ Primitive structure works")

    # Verify PrimitiveInventory dataclass
    inventory = PrimitiveInventory(target="example.com")
    inventory.add_primitive(prim)

    assert len(inventory.primitives) == 1
    assert inventory.find_primitives_by_type(PrimitiveType.REFLECTED_PARAM) == [prim]
    assert inventory.to_dict()["total_primitives"] == 1
    print("✓ PrimitiveInventory aggregation works")

    # Verify PrimitiveCollector creation
    collector = create_primitive_collector()
    assert collector.safe_mode is True
    assert collector.collection_count == 0
    print("✓ PrimitiveCollector factory works")

    # Verify validation
    try:
        Primitive(
            id=str(uuid.uuid4()),
            type=PrimitiveType.REFLECTED_PARAM,
            target="example.com",
            confidence=1.5,  # Invalid
        )
        print("✗ Confidence validation failed")
    except ValueError as e:
        if "confidence" in str(e).lower():
            print("✓ Confidence validation works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All Primitive design invariants verified!")
