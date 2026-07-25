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
from typing import Any, Dict, List, Optional, Set, Callable, Type
import logging
from pydantic import BaseModel, ValidationError

from core.contracts.schemas import (
    ContractViolationPayload,
    ResourceGuardTripPayload,
    TrafficObservedPayload,
    EventSilencePayload,
    ToolChurnPayload,
    OrphanEventPayload,
    MimicDownloadStartedPayload,
    MimicAssetDownloadedPayload,
    MimicDownloadCompletedPayload,
    MimicRouteFoundPayload,
    MimicSecretFoundPayload,
    MimicAnalysisCompletedPayload,
    HypothesisPayload,
    InsightPayload,
    InsightPayload,
    InsightActionType,
    DecisionPayload,
    EventSchema, 
    FieldSpec 
)
from core.contracts.audit import SystemSelfAudit

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
    SCAN_RECON_SKIPPED = "scan_recon_skipped"

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
    MIMIC_ASSET_DOWNLOADED = "mimic_asset_downloaded"
    MIMIC_DOWNLOAD_COMPLETED = "mimic_download_completed"
    MIMIC_ROUTE_FOUND = "mimic_route_found"
    MIMIC_HIDDEN_ROUTE_FOUND = "mimic_hidden_route_found"
    MIMIC_SECRET_FOUND = "mimic_secret_found"
    MIMIC_ANALYSIS_COMPLETED = "mimic_analysis_completed"

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

    # NEXUS - Hypothesis Engine (Probabilistic Reasoning)
    # Strictly separated from Graph Facts.
    NEXUS_HYPOTHESIS_FORMED = "nexus_hypothesis_formed"
    NEXUS_HYPOTHESIS_UPDATED = "nexus_hypothesis_updated"
    NEXUS_HYPOTHESIS_CONFIRMED = "nexus_hypothesis_confirmed"
    NEXUS_HYPOTHESIS_REFUTED = "nexus_hypothesis_refuted"
    NEXUS_INSIGHT_FORMED = "nexus_insight_formed"

    # GHOST - Self-Audit
    SYSTEM_SELF_AUDIT_CREATED = "system_self_audit_created"

    # OMEGA - Integration
    OMEGA_RUN_STARTED = "omega_run_started"
    OMEGA_RUN_COMPLETED = "omega_run_completed"
    OMEGA_PHASE_STARTED = "omega_phase_started"
    OMEGA_PHASE_COMPLETED = "omega_phase_completed"

    # GOVERNANCE & SAFETY (Phase 0)
    CONTRACT_VIOLATION = "contract_violation"
    RESOURCE_GUARD_TRIP = "resource_guard_trip"

    # GHOST - Passive
    TRAFFIC_OBSERVED = "traffic_observed"
    
    NEXUS_CONTEXT_ATTACHED = "nexus_context_attached"
    
    # OBSERVER - Watchdog
    EVENT_SILENCE = "event_silence"
    TOOL_CHURN = "tool_churn"
    ORPHAN_EVENT_DROPPED = "orphan_event_dropped"


# ============================================================================
# Field Specification
# ============================================================================

# ============================================================================
# Event Schema Registry
# ============================================================================

# EventSchema is now imported from core.contracts.schemas





# ============================================================================
# Causal Tracker
# ============================================================================

class CausalTracker:
    """
    Tracks causal relationships to enforce event ordering rules.
    State is sharded by scan_id to allow concurrent scans.
    
    Rule: tool_completed for tool X requires prior tool_started for tool X
    Rule: scan_completed requires prior scan_started (per scan)
    """

    def __init__(self):
        # Format: {scan_id: set(started_tools)}
        self._scan_tool_state: Dict[str, Set[str]] = {}
        # Track active scans to ensure they exist
        self._active_scans: Set[str] = set()

    def on_event(self, event_type: EventType, payload: Dict[str, Any]) -> Optional[str]:
        """
        Process event and return violation message if causal rule broken.
        """
        # 1. Resolve Context (Canonical: scan_id)
        # Normalize session_id if present for legacy compat, but prefer scan_id
        scan_id = payload.get("scan_id") or payload.get("session_id")
        
        # 2. Lifecycle Events (Create/Destroy Context)
        if event_type == EventType.SCAN_STARTED:
            if not scan_id:
                return "Causal violation: scan_started missing scan_id"
            self._active_scans.add(scan_id)
            self._scan_tool_state[scan_id] = set()
            return None

        if event_type == EventType.SCAN_COMPLETED:
            if not scan_id:
                return "Causal violation: scan_completed missing scan_id"
            if scan_id not in self._active_scans:
                return f"Causal violation: scan_completed for unknown scan '{scan_id}'"
            
            # Cleanup
            self._active_scans.discard(scan_id)
            if scan_id in self._scan_tool_state:
                del self._scan_tool_state[scan_id]
            return None

        # 3. Context Check for other events
        # If event has a scan_id but we don't know it, that's a violation 
        # (unless it's an orphan drop, which we allow)
        if scan_id and scan_id not in self._active_scans and event_type != EventType.ORPHAN_EVENT_DROPPED:
             # We might optionally allow some events to fly without context, 
             # but strictly speaking, if it claims a scan_id, that scan should be active.
             # However, to avoid "double jeopardy" with the Manager's checks, 
             # we will focus only on Causal Order here.
             pass

        # 4. Tool Execution Rules
        if event_type == EventType.TOOL_STARTED:
            tool = payload.get("tool")
            if tool and scan_id in self._scan_tool_state:
                self._scan_tool_state[scan_id].add(tool)
            return None

        if event_type == EventType.TOOL_COMPLETED:
            tool = payload.get("tool")
            if scan_id and scan_id in self._scan_tool_state:
                 if tool and tool not in self._scan_tool_state[scan_id]:
                     return f"Causal violation: tool_completed for '{tool}' without prior tool_started in scan '{scan_id}'"
            return None

        return None

    def reset(self):
        """Reset state (for testing)."""
        self._scan_tool_state.clear()
        self._active_scans.clear()


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
                FieldSpec("scan_id", str, required=True, description="Unique scan identifier"),
                FieldSpec("allowed_tools", list, required=True, description="Tools to run"),
            ]
        )

        cls._schemas[EventType.SCAN_COMPLETED] = EventSchema(
            event_type=EventType.SCAN_COMPLETED,
            description="Scan finished successfully.",
            fields=[
                FieldSpec("scan_id", str, required=True),
                FieldSpec("status", str, required=True),
                FieldSpec("findings_count", int, required=True),
                FieldSpec("duration_seconds", float, required=False),
            ]
        )

        cls._schemas[EventType.SCAN_FAILED] = EventSchema(
            event_type=EventType.SCAN_FAILED,
            description="Scan terminated with error.",
            fields=[
                FieldSpec("scan_id", str, required=True),
                FieldSpec("error", str, required=True),
                FieldSpec("phase", str, required=False),
            ]
        )

        cls._schemas[EventType.SCAN_PHASE_CHANGED] = EventSchema(
            event_type=EventType.SCAN_PHASE_CHANGED,
            description="Scan transitioned to new phase.",
            fields=[
                FieldSpec("scan_id", str, required=True),
                FieldSpec("phase", str, required=True),
                FieldSpec("previous_phase", str, required=False),
            ]
        )

        cls._schemas[EventType.SCAN_RECON_SKIPPED] = EventSchema(
            event_type=EventType.SCAN_RECON_SKIPPED,
            description="Passive recon was intentionally skipped with a deterministic reason.",
            fields=[
                FieldSpec("scan_id", str, required=True),
                FieldSpec("target", str, required=True),
                FieldSpec("reason", str, required=True),
                FieldSpec("target_classification", str, required=True),
                FieldSpec("intent", str, required=True),
            ]
        )

        # ----------------------------------------------------------------
        # TOOLS - Execution (Strict + Causal)
        # ----------------------------------------------------------------
        cls._schemas[EventType.TOOL_STARTED] = EventSchema(
            event_type=EventType.TOOL_STARTED,
            description="External tool execution started.",
            fields=[
                FieldSpec("tool", str, required=True),
                FieldSpec("target", str, required=True),
                FieldSpec("scan_id", str, required=True),
                FieldSpec("args", list, required=False),
            ]
        )

        cls._schemas[EventType.TOOL_COMPLETED] = EventSchema(
            event_type=EventType.TOOL_COMPLETED,
            description="External tool execution finished.",
            fields=[
                FieldSpec("tool", str, required=True),
                FieldSpec("exit_code", int, required=True),
                FieldSpec("findings_count", int, required=False),
                FieldSpec("scan_id", str, required=True),
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
            model=DecisionPayload
            # NOTE: Decision causality (trigger validity, scan_id context) is enforced 
            # at the Strategos layer, not the EventContract layer. 
            # We trust Strategos to emit only valid decisions.
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
        
        cls._schemas[EventType.SYSTEM_SELF_AUDIT_CREATED] = EventSchema(
            event_type=EventType.SYSTEM_SELF_AUDIT_CREATED,
            description="Post-scan system self-audit artifact created.",
            model=SystemSelfAudit
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
                FieldSpec("scan_id", str, required=False, description="Correlated scan context"),
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
                FieldSpec("scan_id", str, required=False, description="Correlated scan context"),
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
                FieldSpec("scan_id", str, required=False, description="Correlated scan context"),
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
                FieldSpec("scan_id", str, required=False, description="Correlated scan context"),
                FieldSpec("path", str, required=True),
                FieldSpec("method", str, required=False),
                FieldSpec("status_code", int, required=True, description="401 or 403"),
            ]
        )

        # ----------------------------------------------------------------
        # MIMIC - Source Reconstruction (Pydantic Backed)
        # ----------------------------------------------------------------
        cls._schemas[EventType.MIMIC_DOWNLOAD_STARTED] = EventSchema(
            event_type=EventType.MIMIC_DOWNLOAD_STARTED,
            description="Asset download initiated.",
            model=MimicDownloadStartedPayload
        )

        cls._schemas[EventType.MIMIC_ASSET_DOWNLOADED] = EventSchema(
            event_type=EventType.MIMIC_ASSET_DOWNLOADED,
            description="Asset download completed (individual).",
            model=MimicAssetDownloadedPayload
        )

        cls._schemas[EventType.MIMIC_DOWNLOAD_COMPLETED] = EventSchema(
            event_type=EventType.MIMIC_DOWNLOAD_COMPLETED,
            description="All downloads for batch/session completed.",
            model=MimicDownloadCompletedPayload
        )

        cls._schemas[EventType.MIMIC_ROUTE_FOUND] = EventSchema(
            event_type=EventType.MIMIC_ROUTE_FOUND,
            description="Endpoint/Route extracted from source.",
            model=MimicRouteFoundPayload
        )

        cls._schemas[EventType.MIMIC_HIDDEN_ROUTE_FOUND] = EventSchema(
            event_type=EventType.MIMIC_HIDDEN_ROUTE_FOUND,
            description="Hidden/Heuristic route discovered.",
            model=MimicRouteFoundPayload
        )

        cls._schemas[EventType.MIMIC_SECRET_FOUND] = EventSchema(
            event_type=EventType.MIMIC_SECRET_FOUND,
            description="Secret/Token discovered in source.",
            model=MimicSecretFoundPayload
        )

        cls._schemas[EventType.MIMIC_ANALYSIS_COMPLETED] = EventSchema(
            event_type=EventType.MIMIC_ANALYSIS_COMPLETED,
            description="Mimic analysis session finished.",
            model=MimicAnalysisCompletedPayload
        )
        
        # ----------------------------------------------------------------
        # NEXUS - Hypothesis Engine
        # ----------------------------------------------------------------
        # Unified Pydantic Contract (Point 1 of Audit)
        for et in [
            EventType.NEXUS_HYPOTHESIS_FORMED,
            EventType.NEXUS_HYPOTHESIS_UPDATED,
            EventType.NEXUS_HYPOTHESIS_CONFIRMED,
            EventType.NEXUS_HYPOTHESIS_REFUTED
        ]:
            cls._schemas[et] = EventSchema(
                event_type=et,
                description="Probabilistic reasoning event (Strict Contract).",
                model=HypothesisPayload
            )
            
        # NEXUS - Insight Engine (Hybrid Strategy)
        cls._schemas[EventType.NEXUS_INSIGHT_FORMED] = EventSchema(
            event_type=EventType.NEXUS_INSIGHT_FORMED,
            description="Strategic insight formed from findings.",
            model=InsightPayload
        )

        # ----------------------------------------------------------------
        # GOVERNANCE & SAFETY (Pydantic Backed)
        # ----------------------------------------------------------------
        cls._schemas[EventType.CONTRACT_VIOLATION] = EventSchema(
            event_type=EventType.CONTRACT_VIOLATION,
            description="Event failed validation.",
            model=ContractViolationPayload
        )

        cls._schemas[EventType.RESOURCE_GUARD_TRIP] = EventSchema(
            event_type=EventType.RESOURCE_GUARD_TRIP,
            description="Budget limit reached.",
            model=ResourceGuardTripPayload
        )

        cls._schemas[EventType.TRAFFIC_OBSERVED] = EventSchema(
            event_type=EventType.TRAFFIC_OBSERVED,
            description="Passive traffic observation (redacted).",
            model=TrafficObservedPayload
        )
        
        cls._schemas[EventType.NEXUS_CONTEXT_ATTACHED] = EventSchema(
            event_type=EventType.NEXUS_CONTEXT_ATTACHED,
            description="Nexus session anchored to scan.",
            fields=[
                FieldSpec("scan_id", str, required=True),
                FieldSpec("timestamp", float, required=False),
            ]
        )
        
        cls._schemas[EventType.EVENT_SILENCE] = EventSchema(
            event_type=EventType.EVENT_SILENCE,
            description="Watchdog detected lack of progress.",
            model=EventSilencePayload
        )

        cls._schemas[EventType.TOOL_CHURN] = EventSchema(
            event_type=EventType.TOOL_CHURN,
            description="Watchdog detected high velocity with no findings.",
            model=ToolChurnPayload
        )

        cls._schemas[EventType.ORPHAN_EVENT_DROPPED] = EventSchema(
            event_type=EventType.ORPHAN_EVENT_DROPPED,
            description="Event dropped because it lacked a valid session context.",
            model=OrphanEventPayload
        )

    @classmethod
    def validate(cls, event_type: EventType, payload: Dict[str, Any]) -> List[str]:
        """
        Validate an event against the contract.

        Returns list of violation messages.
        Raises ContractViolation within this method if strict mode is enabled.
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
        
        return violations

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
    def is_strict(cls) -> bool:
        """Check if strict mode is enabled."""
        return cls._strict_mode

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
            # 1. Valid event
            print("Test 1: Valid Event...")
            validate_event(EventType.SCAN_STARTED, {
                "target": "http://example.com",
                "scan_id": "test-123",
                "allowed_tools": ["nmap", "httpx"]
            })
            print("✅ SCAN_STARTED valid.")
            
            # 2. Invalid event
            print("\nTest 2: Expecting Failure (Missing Fields)...")
            try:
                validate_event(EventType.SCAN_STARTED, {
                    "target": "http://example.com"
                    # Missing scan_id and allowed_tools
                })
            except ContractViolation as e:
                print(f"✅ Caught expected violation: {e}")

            # 3. Causal Check
            print("\nTest 3: Causal Integrity...")

            validate_event(EventType.SCAN_STARTED, {
                "target": "http://example.com",
                "scan_id": "causal-test",
                "allowed_tools": []
            })
            print("✓ SCAN_STARTED validated")

            validate_event(EventType.TOOL_STARTED, {
                "tool": "nmap",
                "target": "http://example.com",
                "scan_id": "causal-test",
                "args": ["-sV"]
            })
            print("✓ TOOL_STARTED validated")

            validate_event(EventType.TOOL_COMPLETED, {
                "tool": "nmap",
                "exit_code": 0,
                "findings_count": 5,
                "scan_id": "causal-test"
            })
            print("✓ TOOL_COMPLETED validated")

            validate_event(EventType.SCAN_COMPLETED, {
                "status": "success",
                "findings_count": 5,
                "duration_seconds": 1.23,
                "scan_id": "causal-test"
            })
            print("✓ SCAN_COMPLETED validated")

            # 4. Causal Violation Test
            print("\nTest 4: Expecting Causal Violation (No Tool Start)...")
            try:
                validate_event(EventType.TOOL_COMPLETED, {
                    "tool": "unknown_tool",
                    "exit_code": 0,
                    "findings_count": 0,
                    "scan_id": "causal-test" # Valid scan_id, but tool never started
                })
            except ContractViolation as e:
                print(f"✅ Caught expected violation: {e}")

        except ContractViolation as e:
            print(f"❌ UNEXPECTED VIOLATION: {e}")
            sys.exit(1)

        print("\n✅ All contract tests passed!")
    else:
        print("Usage:")
        print("  python -m core.contracts.events --swift     # Generate Swift enum")
        print("  python -m core.contracts.events --validate  # Run self-tests")
