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

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
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
        seen_signatures: Set[str] = set()

        # Extract primitive candidates from each finding.
        for finding in findings:
            try:
                candidates = self.find_primitive_patterns(finding)
            except Exception as exc:
                logger.debug("[PrimitiveCollector] pattern extraction failed: %s", exc)
                continue

            for primitive in candidates:
                if self._safe_mode and primitive.type in _safe_mode_blocked_types():
                    logger.debug(
                        "[PrimitiveCollector] SAFE_MODE skipped primitive type=%s id=%s",
                        primitive.type.value,
                        primitive.id,
                    )
                    continue

                # Ensure primitive target is set to the collection target when missing.
                if not primitive.target:
                    object.__setattr__(primitive, "target", target)

                if primitive.signature in seen_signatures:
                    continue
                seen_signatures.add(primitive.signature)
                inventory.add_primitive(primitive)

                logger.debug(
                    "[PrimitiveCollector] %s: id=%s type=%s target=%s",
                    self.EVENT_PRIMITIVE_FOUND,
                    primitive.id,
                    primitive.type.value,
                    primitive.target,
                )

        self._link_dependencies(inventory)

        logger.debug(
            f"[PrimitiveCollector] {self.EVENT_COLLECT_COMPLETED}: "
            f"target={target}, primitives={len(inventory.primitives)}"
        )
        return inventory

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
        primitive_types = self._infer_primitive_types(finding)
        if not primitive_types:
            return []

        normalized_target = _normalize_target(
            str(finding.get("target") or "")
        ) or "unknown"
        reliability = self.calculate_reliability(finding)
        confidence = self._confidence_for_finding(finding, reliability)
        parameter = self._extract_parameter(finding)
        source = str(finding.get("tool", "unknown"))
        evidence = (
            str(finding.get("proof") or "")
            or str(finding.get("message") or "")
            or str(finding.get("value") or "")
            or str(finding.get("description") or "")
        )[:500]

        primitives: List[Primitive] = []
        finding_id = str(finding.get("id", "unknown"))
        for primitive_type in primitive_types:
            primitive_id = self._primitive_id(
                finding_id=finding_id,
                primitive_type=primitive_type,
                target=normalized_target,
                parameter=parameter,
            )
            primitives.append(
                Primitive(
                    id=primitive_id,
                    type=primitive_type,
                    target=normalized_target,
                    parameter=parameter,
                    evidence=evidence,
                    reliability=reliability,
                    confidence=confidence,
                    enables=[],
                    source=source,
                )
            )
        return primitives

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
        confirmation = str(finding.get("confirmation_level", "")).strip().lower()
        if confirmation == "confirmed":
            return ReliabilityLevel.CERTAIN
        if confirmation == "probable":
            return ReliabilityLevel.HIGH
        if confirmation == "hypothesized":
            return ReliabilityLevel.MEDIUM

        metadata = finding.get("metadata")
        if isinstance(metadata, dict):
            if metadata.get("verified") is True or metadata.get("reproducible") is True:
                return ReliabilityLevel.CERTAIN
            if metadata.get("false_positive") is True:
                return ReliabilityLevel.LOW

        severity = str(finding.get("severity", "info")).strip().lower()
        if severity in {"critical", "high"}:
            return ReliabilityLevel.HIGH
        if severity == "medium":
            return ReliabilityLevel.MEDIUM
        if severity in {"low", "info"}:
            return ReliabilityLevel.LOW
        return ReliabilityLevel.UNKNOWN

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
        target = str(recorded_inventory.get("target", "unknown"))
        inventory = PrimitiveInventory(target=target)

        raw_primitives = recorded_inventory.get("primitives", [])
        if isinstance(raw_primitives, list):
            for item in raw_primitives:
                if not isinstance(item, dict):
                    continue
                primitive_type = _safe_enum(PrimitiveType, item.get("type"), PrimitiveType.LEAKED_HEADER)
                reliability = _safe_enum(ReliabilityLevel, item.get("reliability"), ReliabilityLevel.UNKNOWN)
                enables = item.get("enables") if isinstance(item.get("enables"), list) else []
                discovered_at = _safe_datetime(item.get("discovered_at"))
                try:
                    primitive = Primitive(
                        id=str(item.get("id", "")),
                        type=primitive_type,
                        target=str(item.get("target", target)),
                        parameter=item.get("parameter"),
                        evidence=str(item.get("evidence", "")),
                        reliability=reliability,
                        confidence=float(item.get("confidence", 0.5)),
                        enables=[str(v) for v in enables],
                        discovered_at=discovered_at or datetime.utcnow(),
                        source=str(item.get("source", "unknown")),
                    )
                    inventory.add_primitive(primitive)
                except Exception as exc:
                    logger.debug("[PrimitiveCollector] replay skipped primitive: %s", exc)

        parsed_last_updated = _safe_datetime(recorded_inventory.get("last_updated"))
        if parsed_last_updated is not None:
            inventory.last_updated = parsed_last_updated
        return inventory

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

    @staticmethod
    def _primitive_id(
        finding_id: str,
        primitive_type: PrimitiveType,
        target: str,
        parameter: Optional[str],
    ) -> str:
        digest = hashlib.sha256(
            f"{finding_id}|{primitive_type.value}|{target}|{parameter or ''}".encode("utf-8")
        ).hexdigest()[:16]
        return f"prim_{digest}"

    @staticmethod
    def _extract_parameter(finding: Dict[str, Any]) -> Optional[str]:
        metadata = finding.get("metadata")
        if isinstance(metadata, dict):
            for key in ("param", "parameter", "field", "name"):
                value = metadata.get(key)
                if value:
                    return str(value)

        haystack = " ".join(
            str(finding.get(key, ""))
            for key in ("message", "proof", "value", "description")
        )
        # Prefer explicit query parameter references.
        match = re.search(r"[?&]([a-zA-Z0-9_\-]{1,64})=", haystack)
        if match:
            return match.group(1)
        # Fallback for natural language mentions, e.g. "parameter user_id".
        match = re.search(r"(?:parameter|param)\s+([a-zA-Z0-9_\-]{1,64})", haystack, flags=re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _confidence_for_finding(
        finding: Dict[str, Any],
        reliability: ReliabilityLevel,
    ) -> float:
        # Start with reliability-derived baseline.
        baseline = {
            ReliabilityLevel.CERTAIN: 0.95,
            ReliabilityLevel.HIGH: 0.85,
            ReliabilityLevel.MEDIUM: 0.65,
            ReliabilityLevel.LOW: 0.40,
            ReliabilityLevel.UNKNOWN: 0.50,
        }[reliability]

        severity = str(finding.get("severity", "info")).strip().lower()
        if severity == "critical":
            baseline += 0.03
        elif severity == "high":
            baseline += 0.02
        elif severity in {"low", "info"}:
            baseline -= 0.05

        return max(0.05, min(1.0, round(baseline, 3)))

    @staticmethod
    def _infer_primitive_types(finding: Dict[str, Any]) -> List[PrimitiveType]:
        finding_type = str(finding.get("type", "")).strip().lower()
        tags_raw = finding.get("tags", [])
        if isinstance(tags_raw, str):
            tags = {tags_raw.strip().lower()}
        elif isinstance(tags_raw, list):
            tags = {str(tag).strip().lower() for tag in tags_raw if str(tag).strip()}
        else:
            tags = set()
        blob = " ".join(
            str(finding.get(k, ""))
            for k in ("title", "type", "message", "proof", "value", "description")
        ).lower()
        blob = f"{blob} {' '.join(tags)} {finding_type}".strip()

        primitive_types: List[PrimitiveType] = []

        def _match(terms: Tuple[str, ...]) -> bool:
            return any(term in blob for term in terms)

        if _match(("reflected", "xss", "echoed parameter")):
            primitive_types.append(PrimitiveType.REFLECTED_PARAM)
        if _match(("open redirect", "redirect parameter", "unvalidated redirect")):
            primitive_types.append(PrimitiveType.OPEN_REDIRECT)
        if _match(("header leak", "leaked header", "x-powered-by", "server header")):
            primitive_types.append(PrimitiveType.LEAKED_HEADER)
        if _match(("ssrf", "server-side request forgery", "metadata service")):
            primitive_types.append(PrimitiveType.SSRF_PATTERN)
        if _match(("idor", "insecure direct object", "object reference")):
            primitive_types.append(PrimitiveType.IDOR_PATTERN)
        if _match(("missing auth", "no auth", "unauthenticated", "auth bypass")):
            primitive_types.append(PrimitiveType.MISSING_AUTH)
        if _match(("cors", "access-control-allow-origin")) and (
            "*" in blob or "credentials" in blob or "wildcard" in blob
        ):
            primitive_types.append(PrimitiveType.WEAK_CORS)
        if _match(("jsonp", "callback=")):
            primitive_types.append(PrimitiveType.JSONP_ENDPOINT)
        if _match(("debug=true", "debug endpoint", "debug parameter", "verbose mode")):
            primitive_types.append(PrimitiveType.DEBUG_PARAM)
        if _match(("template injection", "ssti", "jinja", "twig")):
            primitive_types.append(PrimitiveType.TEMPLATE_INJECTION)
        if _match(("deserialization", "insecure deserialize", "objectinputstream")):
            primitive_types.append(PrimitiveType.DESERIALIZATION)
        if _match(("file upload", "multipart/form-data", "upload endpoint")):
            primitive_types.append(PrimitiveType.FILE_UPLOAD)
        if _match(("webhook", "callback url", "outbound hook")):
            primitive_types.append(PrimitiveType.WEBHOOK)

        # Conservative fallback: no confident primitive classification.
        deduped: List[PrimitiveType] = []
        seen: Set[PrimitiveType] = set()
        for primitive_type in primitive_types:
            if primitive_type not in seen:
                seen.add(primitive_type)
                deduped.append(primitive_type)
        return deduped

    @staticmethod
    def _link_dependencies(inventory: PrimitiveInventory) -> None:
        """
        Populate primitive.enables and inventory.dependencies deterministically.
        """
        enablement = _primitive_enablement_map()
        by_type: Dict[PrimitiveType, List[Primitive]] = {}
        for primitive in inventory.primitives:
            by_type.setdefault(primitive.type, []).append(primitive)

        for primitive in inventory.primitives:
            allowed_types = enablement.get(primitive.type, set())
            enabled_ids: List[str] = []
            for target_type in allowed_types:
                for candidate in by_type.get(target_type, []):
                    if candidate.id != primitive.id:
                        enabled_ids.append(candidate.id)
            primitive.enables[:] = sorted(set(enabled_ids))

        inventory.dependencies.clear()
        for primitive in inventory.primitives:
            for enabled_id in primitive.enables:
                inventory.dependencies.setdefault(enabled_id, [])
                if primitive.id not in inventory.dependencies[enabled_id]:
                    inventory.dependencies[enabled_id].append(primitive.id)
        inventory.last_updated = datetime.utcnow()


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


def _primitive_enablement_map() -> Dict[PrimitiveType, Set[PrimitiveType]]:
    """
    Lightweight enablement mapping aligned with NEXUS Phase chaining rules.
    """
    return {
        PrimitiveType.MISSING_AUTH: {
            PrimitiveType.IDOR_PATTERN,
            PrimitiveType.SSRF_PATTERN,
            PrimitiveType.FILE_UPLOAD,
        },
        PrimitiveType.IDOR_PATTERN: {
            PrimitiveType.LEAKED_HEADER,
            PrimitiveType.REFLECTED_PARAM,
        },
        PrimitiveType.REFLECTED_PARAM: {
            PrimitiveType.OPEN_REDIRECT,
            PrimitiveType.JSONP_ENDPOINT,
        },
        PrimitiveType.SSRF_PATTERN: {
            PrimitiveType.WEBHOOK,
            PrimitiveType.OPEN_REDIRECT,
        },
        PrimitiveType.FILE_UPLOAD: {
            PrimitiveType.TEMPLATE_INJECTION,
            PrimitiveType.DESERIALIZATION,
        },
        PrimitiveType.WEAK_CORS: {
            PrimitiveType.JSONP_ENDPOINT,
            PrimitiveType.REFLECTED_PARAM,
        },
    }


def _safe_mode_blocked_types() -> Set[PrimitiveType]:
    """
    Primitive categories excluded while collector runs in SAFE_MODE.
    """
    return {
        PrimitiveType.TEMPLATE_INJECTION,
        PrimitiveType.DESERIALIZATION,
    }


def _normalize_target(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        return raw.split("/", 1)[0].lower()
    parsed = urlparse(raw)
    host = parsed.netloc or parsed.path
    return host.lower().strip("/")


def _targets_match(expected: str, observed: str) -> bool:
    if not expected:
        return bool(observed)
    if not observed:
        return False
    if expected == observed:
        return True
    return expected in observed or observed in expected


def _safe_enum(enum_cls, raw_value: Any, default):
    try:
        if raw_value is None:
            return default
        return enum_cls(str(raw_value))
    except Exception:
        return default


def _safe_datetime(raw_value: Any) -> Optional[datetime]:
    if not raw_value:
        return None
    try:
        return datetime.fromisoformat(str(raw_value))
    except Exception:
        return None


async def _load_findings_for_target(target: str, max_findings: int = 1000) -> List[Dict[str, Any]]:
    """
    Load findings for a target from active sessions, then DB fallback.
    """
    normalized_target = _normalize_target(target)
    results: List[Dict[str, Any]] = []

    # 1) Prefer active in-memory scan sessions.
    try:
        from core.server.state import get_state

        state = get_state()
        for session in list(state.session_manager.values()):
            session_target = _normalize_target(str(getattr(session, "target", "")))
            if not _targets_match(normalized_target, session_target):
                continue
            findings_store = getattr(session, "findings", None)
            if findings_store is None:
                continue
            session_findings = findings_store.get_all()
            if isinstance(session_findings, list):
                results.extend(session_findings)
    except Exception as exc:
        logger.debug("[collect_primitives] session lookup failed: %s", exc)

    if results:
        return results[:max_findings]

    # 2) Fall back to persisted DB sessions.
    try:
        from core.data.db import Database

        db = Database.instance()
        await db.init()

        # Prefer the most recent session for the same target.
        session_rows = await db.fetch_all(
            "SELECT id, target FROM sessions ORDER BY start_time DESC LIMIT 100"
        )

        selected_session_id: Optional[str] = None
        for row in session_rows:
            session_id = str(row[0]) if len(row) > 0 else ""
            session_target = _normalize_target(str(row[1]) if len(row) > 1 else "")
            if _targets_match(normalized_target, session_target):
                selected_session_id = session_id
                break

        if selected_session_id:
            db_findings = await db.get_findings(selected_session_id)
        else:
            db_findings = await db.get_findings()

        if normalized_target:
            db_findings = [
                finding for finding in db_findings
                if _targets_match(normalized_target, _normalize_target(str(finding.get("target", ""))))
            ]

        results.extend(db_findings[:max_findings])
    except Exception as exc:
        logger.warning("[collect_primitives] DB fallback failed for target %s: %s", target, exc)

    return results[:max_findings]


async def collect_primitives(
    target: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    safe_mode: bool = SAFE_MODE,
    max_findings: int = 1000,
) -> List[Primitive]:
    """
    Collect primitives for a target (async helper used by OMEGA/NEXUS phase).
    """
    source_findings = findings if findings is not None else await _load_findings_for_target(target, max_findings)
    collector = PrimitiveCollector(safe_mode=safe_mode)
    inventory = collector.collect(source_findings, target=target)
    return inventory.primitives


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
