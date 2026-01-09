# core/contracts/events.contract.py
"""
EVENT CONTRACT: Formal Grammar for SentinelForge Events

This module defines the authoritative contract between the Python backend
and Swift frontend. All event emission MUST go through contract validation.

DESIGN PRINCIPLES:
1. Events are immutable observations, not commands
2. Every event type has explicit required/optional fields
3. Causal relationships are enforced (can't complete what wasn't started)
4. Contract violations fail loudly in dev, log in prod

USAGE:
    from core.contracts.events import EventContract, validate_event

    # On emit:
    EventContract.validate(event_type, payload)  # Raises ContractViolation

    # For introspection:
    EventContract.get_schema("scan_started")
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Event Type Taxonomy
# ============================================================================

class EventType(str, Enum):
    """
    Canonical event types. Swift must mirror this exactly.

    Naming convention: {domain}_{action}
    - Domain: scan, tool, finding, graph, log, decision
    - Action: started, completed, created, emitted, etc.
    """
    # Scan Lifecycle
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_PHASE_CHANGED = "scan_phase_changed"

    # Tool Execution
    TOOL_STARTED = "tool_started"
    TOOL_COMPLETED = "tool_completed"

    # Findings
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    FINDING_INVALIDATED = "finding_invalidated"
    FINDING_SUPPRESSED = "finding_suppressed"

    # Reasoning (Narrator/Strategos)
    DECISION_MADE = "decision_made"
    NARRATIVE_EMITTED = "narrative_emitted"

    # Logging
    LOG = "log"

    # Graph Mutations
    NODE_ADDED = "node_added"
    NODE_UPDATED = "node_updated"
    NODE_REMOVED = "node_removed"
    EDGE_ADDED = "edge_added"

    # CRONUS - Temporal Mining
    CRONUS_QUERY_STARTED = "cronus_query_started"
    CRONUS_QUERY_COMPLETED = "cronus_query_completed"
    CRONUS_QUERY_FAILED = "cronus_query_failed"
    CRONUS_SNAPSHOT_FOUND = "cronus_snapshot_found"
    CRONUS_DIFF_STARTED = "cronus_diff_started"
    CRONUS_DIFF_COMPLETED = "cronus_diff_completed"
    CRONUS_HUNT_STARTED = "cronus_hunt_started"
    CRONUS_HUNT_COMPLETED = "cronus_hunt_completed"
    CRONUS_ZOMBIE_CONFIRMED = "cronus_zombie_confirmed"
    CRONUS_ZOMBIE_DENIED = "cronus_zombie_denied"

    # MIMIC - Source Reconstruction
    MIMIC_DOWNLOAD_STARTED = "mimic_download_started"
    MIMIC_DOWNLOAD_COMPLETED = "mimic_download_completed"
    MIMIC_DOWNLOAD_FAILED = "mimic_download_failed"
    MIMIC_ASSET_DOWNLOADED = "mimic_asset_downloaded"
    MIMIC_PARSE_STARTED = "mimic_parse_started"
    MIMIC_PARSE_COMPLETED = "mimic_parse_completed"
    MIMIC_ROUTE_FOUND = "mimic_route_found"
    MIMIC_SECRET_FOUND = "mimic_secret_found"
    MIMIC_ANALYSIS_STARTED = "mimic_analysis_started"
    MIMIC_ANALYSIS_COMPLETED = "mimic_analysis_completed"
    MIMIC_HIDDEN_ROUTE_FOUND = "mimic_hidden_route_found"

    # NEXUS - Logic Chaining
    NEXUS_COLLECT_STARTED = "nexus_collect_started"
    NEXUS_COLLECT_COMPLETED = "nexus_collect_completed"
    NEXUS_PRIMITIVE_FOUND = "nexus_primitive_found"
    NEXUS_SOLVE_STARTED = "nexus_solve_started"
    NEXUS_SOLVE_COMPLETED = "nexus_solve_completed"
    NEXUS_CHAIN_FOUND = "nexus_chain_found"
    NEXUS_NO_PATH = "nexus_no_path"
    NEXUS_CHAIN_STARTED = "nexus_chain_started"
    NEXUS_CHAIN_COMPLETED = "nexus_chain_completed"
    NEXUS_CHAIN_ABORTED = "nexus_chain_aborted"
    NEXUS_STEP_STARTED = "nexus_step_started"
    NEXUS_STEP_COMPLETED = "nexus_step_completed"

    # NEXUS - Hypothesis Engine (Apex Hardening)
    NEXUS_HYPOTHESIS_FORMED = "nexus_hypothesis_formed"
    NEXUS_HYPOTHESIS_UPDATED = "nexus_hypothesis_updated"
    NEXUS_HYPOTHESIS_REFUTED = "nexus_hypothesis_refuted"
    NEXUS_INSIGHT_FORMED = "nexus_insight_formed"

    # OMEGA - Integration
    OMEGA_RUN_STARTED = "omega_run_started"
    OMEGA_RUN_COMPLETED = "omega_run_completed"
    OMEGA_PHASE_STARTED = "omega_phase_started"
    OMEGA_PHASE_COMPLETED = "omega_phase_completed"


# ============================================================================
# Field Specification
# ============================================================================

@dataclass(frozen=True)
class FieldSpec:
    """
    Specification for a single field in an event payload.
    """
    name: str
    type: type  # Python type (str, int, float, list, dict)
    required: bool = True
    validator: Optional[Callable[[Any], bool]] = None
    description: str = ""

    def validate(self, value: Any) -> bool:
        """Check if value satisfies this field spec."""
        if value is None:
            return not self.required

        # Type check (allow subclasses)
        if not isinstance(value, self.type):
            # Special case: int is valid for float fields
            if self.type is float and isinstance(value, (int, float)):
                pass
            else:
                return False

        # Custom validator
        if self.validator and not self.validator(value):
            return False

        return True


# ============================================================================
# Event Schema Registry
# ============================================================================

class EventSchema:
    """
    Schema for a single event type.
    Defines required fields, optional fields, and causal preconditions.
    """

    def __init__(
        self,
        event_type: EventType,
        fields: List[FieldSpec],
        preconditions: Optional[List[EventType]] = None,
        description: str = ""
    ):
        self.event_type = event_type
        self.fields = {f.name: f for f in fields}
        self.required_fields = {f.name for f in fields if f.required}
        self.preconditions = preconditions or []
        self.description = description

    def validate_payload(self, payload: Dict[str, Any]) -> List[str]:
        """
        Validate a payload against this schema.
        Returns list of violation messages (empty = valid).
        """
        violations: List[str] = []

        # Check required fields
        for field_name in self.required_fields:
            if field_name not in payload:
                violations.append(f"Missing required field: {field_name}")

        # Validate each provided field
        for key, value in payload.items():
            if key in self.fields:
                if not self.fields[key].validate(value):
                    violations.append(
                        f"Invalid value for '{key}': expected {self.fields[key].type.__name__}, "
                        f"got {type(value).__name__}"
                    )

        return violations


# ============================================================================
# Causal Tracker
# ============================================================================

class CausalTracker:
    """
    Tracks causal relationships to enforce event ordering rules.

    Rule: tool_completed for tool X requires prior tool_started for tool X
    Rule: scan_completed requires prior scan_started
    """

    def __init__(self):
        self._started_tools: Set[str] = set()
        self._active_scan: Optional[str] = None  # session_id

    def on_event(self, event_type: EventType, payload: Dict[str, Any]) -> Optional[str]:
        """
        Process event and return violation message if causal rule broken.
        """
        if event_type == EventType.SCAN_STARTED:
            self._active_scan = payload.get("session_id")
            self._started_tools.clear()
            return None

        if event_type == EventType.TOOL_STARTED:
            tool = payload.get("tool")
            if tool:
                self._started_tools.add(tool)
            return None

        if event_type == EventType.TOOL_COMPLETED:
            tool = payload.get("tool")
            if tool and tool not in self._started_tools:
                return f"Causal violation: tool_completed for '{tool}' without prior tool_started"
            return None

        if event_type == EventType.SCAN_COMPLETED:
            if self._active_scan is None:
                return "Causal violation: scan_completed without prior scan_started"
            self._active_scan = None
            return None

        return None

    def reset(self):
        """Reset state (for testing or new scan session)."""
        self._started_tools.clear()
        self._active_scan = None


# ============================================================================
# Contract Violation
# ============================================================================

class ContractViolation(Exception):
    """Raised when event emission violates the contract."""

    def __init__(self, event_type: str, violations: List[str]):
        self.event_type = event_type
        self.violations = violations
        super().__init__(f"Contract violation for '{event_type}': {'; '.join(violations)}")


# ============================================================================
# The Event Contract (Singleton)
# ============================================================================

class EventContract:
    """
    The authoritative event contract.

    All event emission in the backend SHOULD go through validate().
    In development, violations raise exceptions.
    In production, violations are logged but not fatal.
    """

    _instance: Optional["EventContract"] = None
    _schemas: Dict[EventType, EventSchema] = {}
    _causal_tracker: CausalTracker = CausalTracker()
    _strict_mode: bool = True  # Raise on violation (set False in prod)

    @classmethod
    def _init_schemas(cls):
        """Initialize schema registry with all event definitions."""
        if cls._schemas:
            return  # Already initialized

        # ----------------------------------------------------------------
        # SCAN LIFECYCLE
        # ----------------------------------------------------------------
        cls._schemas[EventType.SCAN_STARTED] = EventSchema(
            event_type=EventType.SCAN_STARTED,
            description="A scan has begun. All subsequent events belong to this scan.",
            fields=[
                FieldSpec("target", str, required=True, description="Scan target URL/IP"),
                FieldSpec("session_id", str, required=True, description="Unique scan session"),
                FieldSpec("allowed_tools", list, required=True, description="Tools to run"),
            ]
        )

        cls._schemas[EventType.SCAN_COMPLETED] = EventSchema(
            event_type=EventType.SCAN_COMPLETED,
            description="Scan finished successfully.",
            preconditions=[EventType.SCAN_STARTED],
            fields=[
                FieldSpec("status", str, required=True),
                FieldSpec("findings_count", int, required=True),
                FieldSpec("duration_seconds", float, required=False),
            ]
        )

        cls._schemas[EventType.SCAN_FAILED] = EventSchema(
            event_type=EventType.SCAN_FAILED,
            description="Scan terminated with error.",
            preconditions=[EventType.SCAN_STARTED],
            fields=[
                FieldSpec("error", str, required=True),
                FieldSpec("phase", str, required=False),
            ]
        )

        cls._schemas[EventType.SCAN_PHASE_CHANGED] = EventSchema(
            event_type=EventType.SCAN_PHASE_CHANGED,
            description="Scan transitioned to new phase.",
            preconditions=[EventType.SCAN_STARTED],
            fields=[
                FieldSpec("phase", str, required=True),
                FieldSpec("previous_phase", str, required=False),
            ]
        )

        # ----------------------------------------------------------------
        # TOOL EXECUTION
        # ----------------------------------------------------------------
        cls._schemas[EventType.TOOL_STARTED] = EventSchema(
            event_type=EventType.TOOL_STARTED,
            description="A security tool has been invoked.",
            preconditions=[EventType.SCAN_STARTED],
            fields=[
                FieldSpec("tool", str, required=True),
                FieldSpec("target", str, required=True),
                FieldSpec("args", list, required=False),
            ]
        )

        cls._schemas[EventType.TOOL_COMPLETED] = EventSchema(
            event_type=EventType.TOOL_COMPLETED,
            description="A security tool has finished execution.",
            preconditions=[EventType.TOOL_STARTED],
            fields=[
                FieldSpec("tool", str, required=True),
                FieldSpec("exit_code", int, required=True),
                FieldSpec("findings_count", int, required=True),
            ]
        )

        # ----------------------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------------------
        cls._schemas[EventType.FINDING_CREATED] = EventSchema(
            event_type=EventType.FINDING_CREATED,
            description="A new security finding was discovered.",
            fields=[
                FieldSpec("finding_id", str, required=True),
                FieldSpec("tool", str, required=True),
                FieldSpec("severity", str, required=True),
                FieldSpec("title", str, required=True),
                FieldSpec("target", str, required=False),
            ]
        )

        cls._schemas[EventType.FINDING_UPDATED] = EventSchema(
            event_type=EventType.FINDING_UPDATED,
            description="A finding was modified (e.g. confidence change).",
            fields=[
                FieldSpec("finding_id", str, required=True),
                FieldSpec("changes", dict, required=True),
            ]
        )

        cls._schemas[EventType.FINDING_INVALIDATED] = EventSchema(
            event_type=EventType.FINDING_INVALIDATED,
            description="A finding was proven false.",
            fields=[
                FieldSpec("finding_id", str, required=True),
                FieldSpec("reason", str, required=True),
            ]
        )

        cls._schemas[EventType.FINDING_SUPPRESSED] = EventSchema(
            event_type=EventType.FINDING_SUPPRESSED,
            description="A finding was hidden by policy/user.",
            fields=[
                FieldSpec("finding_id", str, required=True),
                FieldSpec("reason", str, required=True),
            ]
        )

        # ----------------------------------------------------------------
        # REASONING
        # ----------------------------------------------------------------
        cls._schemas[EventType.DECISION_MADE] = EventSchema(
            event_type=EventType.DECISION_MADE,
            description="Strategos made a strategic decision.",
            fields=[
                FieldSpec("intent", str, required=True),
                FieldSpec("reason", str, required=True),
                FieldSpec("context", dict, required=False),
                FieldSpec("source", str, required=False),
            ]
        )

        cls._schemas[EventType.NARRATIVE_EMITTED] = EventSchema(
            event_type=EventType.NARRATIVE_EMITTED,
            description="Human-readable explanation of system behavior.",
            fields=[
                FieldSpec("narrative", str, required=True),
                FieldSpec("decision_id", str, required=False),
                FieldSpec("decision_type", str, required=False),
            ]
        )

        # ----------------------------------------------------------------
        # LOGGING
        # ----------------------------------------------------------------
        cls._schemas[EventType.LOG] = EventSchema(
            event_type=EventType.LOG,
            description="System log message.",
            fields=[
                FieldSpec("message", str, required=True),
                FieldSpec("level", str, required=False),
            ]
        )

        # ----------------------------------------------------------------
        # GRAPH MUTATIONS (FIX: missing schemas)
        # ----------------------------------------------------------------
        cls._schemas[EventType.NODE_ADDED] = EventSchema(
            event_type=EventType.NODE_ADDED,
            description="Node added to knowledge graph.",
            fields=[
                FieldSpec("node_id", str, required=True),
                FieldSpec("node_type", str, required=True),
                FieldSpec("label", str, required=False),
            ]
        )

        cls._schemas[EventType.NODE_UPDATED] = EventSchema(
            event_type=EventType.NODE_UPDATED,
            description="Node updated in knowledge graph.",
            fields=[
                FieldSpec("node_id", str, required=True),
                FieldSpec("changes", dict, required=True, description="Changed fields/values"),
            ]
        )

        cls._schemas[EventType.NODE_REMOVED] = EventSchema(
            event_type=EventType.NODE_REMOVED,
            description="Node removed from knowledge graph.",
            fields=[
                FieldSpec("node_id", str, required=True),
                FieldSpec("reason", str, required=False),
            ]
        )

        cls._schemas[EventType.EDGE_ADDED] = EventSchema(
            event_type=EventType.EDGE_ADDED,
            description="Edge added to knowledge graph.",
            fields=[
                FieldSpec("source", str, required=True),
                FieldSpec("target", str, required=True),
                FieldSpec("edge_type", str, required=True),
                FieldSpec("label", str, required=False),
                FieldSpec("weight", float, required=False),
            ]
        )

        # ----------------------------------------------------------------
        # CRONUS - Temporal Mining
        # ----------------------------------------------------------------
        cls._schemas[EventType.CRONUS_QUERY_STARTED] = EventSchema(
            event_type=EventType.CRONUS_QUERY_STARTED,
            description="TimeMachine archive query started.",
            fields=[
                FieldSpec("target", str, required=True, description="Domain being queried"),
                FieldSpec("sources", list, required=True, description="Archive sources to query"),
                FieldSpec("timestamp_start", str, required=False, description="Start of time range"),
                FieldSpec("timestamp_end", str, required=False, description="End of time range"),
            ]
        )

        cls._schemas[EventType.CRONUS_QUERY_COMPLETED] = EventSchema(
            event_type=EventType.CRONUS_QUERY_COMPLETED,
            description="TimeMachine archive query completed.",
            preconditions=[EventType.CRONUS_QUERY_STARTED],
            fields=[
                FieldSpec("target", str, required=True),
                FieldSpec("snapshots_found", int, required=True, description="Number of snapshots found"),
                FieldSpec("duration_ms", int, required=False),
            ]
        )

        cls._schemas[EventType.CRONUS_QUERY_FAILED] = EventSchema(
            event_type=EventType.CRONUS_QUERY_FAILED,
            description="TimeMachine archive query failed.",
            preconditions=[EventType.CRONUS_QUERY_STARTED],
            fields=[
                FieldSpec("target", str, required=True),
                FieldSpec("error", str, required=True),
                FieldSpec("source", str, required=False, description="Which archive source failed"),
            ]
        )

        cls._schemas[EventType.CRONUS_SNAPSHOT_FOUND] = EventSchema(
            event_type=EventType.CRONUS_SNAPSHOT_FOUND,
            description="Historical snapshot discovered.",
            fields=[
                FieldSpec("url", str, required=True, description="Original URL of snapshot"),
                FieldSpec("timestamp", str, required=True, description="When snapshot was captured"),
                FieldSpec("source", str, required=True, description="Archive source (wayback_machine, etc)"),
                FieldSpec("status_code", int, required=False),
            ]
        )

        cls._schemas[EventType.CRONUS_DIFF_STARTED] = EventSchema(
            event_type=EventType.CRONUS_DIFF_STARTED,
            description="Sitemap comparison started.",
            fields=[
                FieldSpec("target", str, required=True),
                FieldSpec("old_count", int, required=True, description="Historical endpoint count"),
                FieldSpec("new_count", int, required=True, description="Current endpoint count"),
            ]
        )

        cls._schemas[EventType.CRONUS_DIFF_COMPLETED] = EventSchema(
            event_type=EventType.CRONUS_DIFF_COMPLETED,
            description="Sitemap comparison completed.",
            preconditions=[EventType.CRONUS_DIFF_STARTED],
            fields=[
                FieldSpec("target", str, required=True),
                FieldSpec("deleted_count", int, required=True, description="Zombie candidates"),
                FieldSpec("stable_count", int, required=True),
                FieldSpec("added_count", int, required=True),
                FieldSpec("modified_count", int, required=True),
                FieldSpec("confidence", float, required=False),
            ]
        )

        cls._schemas[EventType.CRONUS_HUNT_STARTED] = EventSchema(
            event_type=EventType.CRONUS_HUNT_STARTED,
            description="Zombie endpoint hunting started.",
            fields=[
                FieldSpec("target", str, required=True),
                FieldSpec("candidate_count", int, required=True, description="Endpoints to probe"),
            ]
        )

        cls._schemas[EventType.CRONUS_HUNT_COMPLETED] = EventSchema(
            event_type=EventType.CRONUS_HUNT_COMPLETED,
            description="Zombie endpoint hunting completed.",
            preconditions=[EventType.CRONUS_HUNT_STARTED],
            fields=[
                FieldSpec("target", str, required=True),
                FieldSpec("confirmed", int, required=True, description="Active zombie count"),
                FieldSpec("denied", int, required=True, description="Auth-blocked count"),
                FieldSpec("dead", int, required=True, description="Properly removed count"),
                FieldSpec("duration_ms", int, required=False),
            ]
        )

        cls._schemas[EventType.CRONUS_ZOMBIE_CONFIRMED] = EventSchema(
            event_type=EventType.CRONUS_ZOMBIE_CONFIRMED,
            description="Zombie endpoint confirmed active.",
            fields=[
                FieldSpec("path", str, required=True, description="Endpoint path"),
                FieldSpec("method", str, required=False, description="HTTP method"),
                FieldSpec("status_code", int, required=True, description="HTTP response code"),
                FieldSpec("confidence", float, required=False),
            ]
        )

        cls._schemas[EventType.CRONUS_ZOMBIE_DENIED] = EventSchema(
            event_type=EventType.CRONUS_ZOMBIE_DENIED,
            description="Zombie endpoint exists but requires authentication.",
            fields=[
                FieldSpec("path", str, required=True),
                FieldSpec("method", str, required=False),
                FieldSpec("status_code", int, required=True, description="401 or 403"),
            ]
        )

        # ----------------------------------------------------------------
        # NEXUS - Hypothesis Engine
        # ----------------------------------------------------------------
        cls._schemas[EventType.NEXUS_HYPOTHESIS_FORMED] = EventSchema(
            event_type=EventType.NEXUS_HYPOTHESIS_FORMED,
            description="Nexus hypothesized a path/chain exists.",
            fields=[
                FieldSpec("hypothesis_id", str, required=True, description="Deterministic hash of inputs + logic"),
                FieldSpec("constituent_finding_ids", list, required=True, description="Sorted list of Finding IDs"),
                FieldSpec("rule_id", str, required=True, description="Logic rule identifier"),
                FieldSpec("rule_version", str, required=True, description="Logic rule version"),
                FieldSpec("confidence", float, required=True, description="0.0 to 1.0"),
                FieldSpec("explanation", str, required=False, description="Human readable description"),
            ]
        )

        cls._schemas[EventType.NEXUS_HYPOTHESIS_UPDATED] = EventSchema(
            event_type=EventType.NEXUS_HYPOTHESIS_UPDATED,
            description="Nexus changed confidence/structure because inputs changed.",
            fields=[
                FieldSpec("hypothesis_id", str, required=True),
                FieldSpec("previous_confidence", float, required=False),
                FieldSpec("new_confidence", float, required=True),
                FieldSpec("reason", str, required=True),
            ]
        )

        cls._schemas[EventType.NEXUS_HYPOTHESIS_REFUTED] = EventSchema(
            event_type=EventType.NEXUS_HYPOTHESIS_REFUTED,
            description="A planned validation attempt failed in a way that weakens the hypothesis.",
            fields=[
                FieldSpec("hypothesis_id", str, required=True),
                FieldSpec("refuting_evidence_id", str, required=False),
                FieldSpec("reason", str, required=True),
                FieldSpec("constituent_finding_ids", list, required=True, description="Finding IDs invalidated by this refutation"),
            ]
        )

        cls._schemas[EventType.NEXUS_INSIGHT_FORMED] = EventSchema(
            event_type=EventType.NEXUS_INSIGHT_FORMED,
            description="Nexus minted a human-facing insight derived from hypotheses/findings.",
            fields=[
                FieldSpec("insight_id", str, required=True),
                FieldSpec("title", str, required=True),
                FieldSpec("description", str, required=True),
                FieldSpec("severity", str, required=True),
                FieldSpec("hypothesis_ids", list, required=True),
            ]
        )

    @classmethod
    def validate(cls, event_type: EventType, payload: Dict[str, Any]) -> None:
        """
        Validate an event against the contract.

        Raises ContractViolation in strict mode.
        Logs warning in non-strict mode.
        """
        cls._init_schemas()

        violations: List[str] = []

        # Schema validation
        schema = cls._schemas.get(event_type)
        if schema:
            violations.extend(schema.validate_payload(payload))
        else:
            violations.append(f"Unknown event type: {event_type}")

        # Causal validation
        causal_violation = cls._causal_tracker.on_event(event_type, payload)
        if causal_violation:
            violations.append(causal_violation)

        if violations:
            if cls._strict_mode:
                raise ContractViolation(event_type.value, violations)
            else:
                logger.warning("[EventContract] Violations for %s: %s", event_type.value, violations)

    @classmethod
    def get_schema(cls, event_type: EventType) -> Optional[EventSchema]:
        """Get schema for introspection."""
        cls._init_schemas()
        return cls._schemas.get(event_type)

    @classmethod
    def all_event_types(cls) -> List[EventType]:
        """Get all defined event types."""
        return list(EventType)

    @classmethod
    def set_strict_mode(cls, strict: bool) -> None:
        """Enable/disable strict validation (exceptions vs warnings)."""
        cls._strict_mode = strict

    @classmethod
    def reset_causal_state(cls) -> None:
        """Reset causal tracker (for testing)."""
        cls._causal_tracker.reset()

    @classmethod
    def export_swift_enum(cls) -> str:
        """
        Generate Swift enum code from the contract.

        Ensures Swift stays in sync with Python.
        """
        lines = [
            "/// AUTO-GENERATED from events.contract.py",
            "/// Do not edit manually - run `python -m core.contracts.events --swift`",
            "",
            "public enum GraphEventType: String, CaseIterable, Codable {",
        ]

        for event_type in EventType:
            swift_case = event_type.name.lower()
            parts = swift_case.split("_")
            camel_case = parts[0] + "".join(p.capitalize() for p in parts[1:])
            lines.append(f"    case {camel_case} = \"{event_type.value}\"")

        lines.append("")
        lines.append("    case unknown = \"unknown\"")
        lines.append("}")

        return "\n".join(lines)


# ============================================================================
# Module-level convenience functions
# ============================================================================

def validate_event(event_type: EventType, payload: Dict[str, Any]) -> None:
    """Validate event against contract."""
    EventContract.validate(event_type, payload)


def get_event_schema(event_type: EventType) -> Optional[EventSchema]:
    """Get schema for event type."""
    return EventContract.get_schema(event_type)


# ============================================================================
# CLI for code generation
# ============================================================================

if __name__ == "__main__":
    import sys

    if "--swift" in sys.argv:
        print(EventContract.export_swift_enum())
    elif "--validate" in sys.argv:
        print("Running contract self-test...")

        EventContract.reset_causal_state()

        try:
            validate_event(EventType.SCAN_STARTED, {
                "target": "http://example.com",
                "session_id": "test-123",
                "allowed_tools": ["nmap", "httpx"]
            })
            print("✓ SCAN_STARTED validated")

            validate_event(EventType.TOOL_STARTED, {
                "tool": "nmap",
                "target": "http://example.com"
            })
            print("✓ TOOL_STARTED validated")

            validate_event(EventType.TOOL_COMPLETED, {
                "tool": "nmap",
                "exit_code": 0,
                "findings_count": 5
            })
            print("✓ TOOL_COMPLETED validated")

            validate_event(EventType.SCAN_COMPLETED, {
                "status": "success",
                "findings_count": 5
            })
            print("✓ SCAN_COMPLETED validated")

        except ContractViolation as e:
            print(f"✗ Unexpected violation: {e}")
            sys.exit(1)

        EventContract.reset_causal_state()
        try:
            validate_event(EventType.SCAN_STARTED, {
                "target": "http://example.com",
                "session_id": "test-456",
                "allowed_tools": []
            })
            validate_event(EventType.TOOL_COMPLETED, {
                "tool": "unknown_tool",
                "exit_code": 0,
                "findings_count": 0
            })
            print("✗ Should have raised ContractViolation for causal error")
            sys.exit(1)
        except ContractViolation as e:
            print(f"✓ Correctly caught causal violation: {e.violations[0]}")

        print("\n✅ All contract tests passed!")
    else:
        print("Usage:")
        print("  python -m core.contracts.events --swift     # Generate Swift enum")
        print("  python -m core.contracts.events --validate  # Run self-tests")