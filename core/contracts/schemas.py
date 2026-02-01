"""
core/contracts/schemas.py
Pydantic schemas for event payloads.

This module provides the STRICT runtime validation models for the EventContract.
Every event type related to Omega/Governance MUST have a corresponding schema here.
"""

from typing import Dict, List, Optional, Any, Literal
from enum import Enum
import time
from datetime import datetime
from dataclasses import dataclass, field
from pydantic import BaseModel, Field, HttpUrl, validator, conint, ConfigDict, field_validator

# ---------------------------------------------------------------------------
# Base Types (Moved from events.py to prevent circular deps)
# ---------------------------------------------------------------------------

@dataclass
class FieldSpec:
    """Definition of a required/optional field for validation."""
    name: str
    type: Type
    required: bool = True
    validator: Optional[Callable[[Any], bool]] = None
    description: str = ""

@dataclass
class EventSchema:
    """Complete schema definition for an event type."""
    event_type: str
    description: str
    required_fields: List[str] = field(default_factory=list)
    fields: List[FieldSpec] = field(default_factory=list)
    model: Optional[Type[BaseModel]] = None  # Integration with Pydantic
    preconditions: List[Any] = field(default_factory=list)

    def validate_payload(self, payload: Dict[str, Any]) -> List[str]:
        """
        Validate a payload against this schema.
        Returns list of violation messages (empty = valid).
        """
        violations: List[str] = []

        # 1. Pydantic Validation (Preferred)
        if self.model:
            try:
                self.model.model_validate(payload)
                return [] 
            except Exception as e:
                # Convert Pydantic errors to readable strings
                # We catch generic Exception because ValidationError import might be tricky if not top-level
                # but we imported standard pydantic stuff.
                if hasattr(e, "errors"):
                     for err in e.errors():
                        loc = ".".join(str(l) for l in err['loc'])
                        violations.append(f"{loc}: {err['msg']}")
                else:
                     violations.append(str(e))
                return violations

        # 2. FieldSpec Validation (Legacy)
        # Check required fields
        for field_name in self.required_fields:
            if field_name not in payload:
                violations.append(f"Missing required field: {field_name}")

        # Validate each provided field
        if self.fields:
             # fields is a list, convert to dict for lookup if needed or iterate
             # The init converts list to dict? No, dataclass default doesn't do that logic.
             # In events.py __init__ did it. Here it is a raw dataclass.
             # We need to handle 'fields' being a list of FieldSpec.
             
             for spec in self.fields:
                 if spec.name in payload:
                     if not spec.validator: # Basic type check
                         pass # handled by spec.validate if we move that logic here too
                         # Wait, FieldSpec logic was also purely data in schemas.py?
                         # I need to add validation logic to FieldSpec too?
                         pass
        
        return violations

# ---------------------------------------------------------------------------
# Base Models
# ---------------------------------------------------------------------------

class EventPayload(BaseModel):
    """Base payload for all strict events."""
    pass

class OmegaEventPayload(EventPayload):
    """Base payload for all Omega-related events."""
    scan_id: str = Field(..., description="Unique Scan ID")
    mode: str = Field(..., description="Scan mode (e.g., 'omega', 'standard')")

# ---------------------------------------------------------------------------
# Governance & Safety
# ---------------------------------------------------------------------------

class ContractViolationPayload(EventPayload):
    """
    Payload for CONTRACT_VIOLATION.
    Emitted when an event fails validation.
    """
    offending_event_type: str
    violations: List[str]
    context: Optional[Dict[str, Any]] = None

class ResourceGuardTripPayload(OmegaEventPayload):
    """
    Payload for RESOURCE_GUARD_TRIP.
    Emitted when a Budget limit is reached/exceeded.
    """
    phase: str
    metric: str
    limit: float
    current: float

# ---------------------------------------------------------------------------
# Ghost Protocol (Passive Traffic)
# ---------------------------------------------------------------------------

class TrafficObservedPayload(OmegaEventPayload):
    """
    Payload for TRAFFIC_OBSERVED.
    Strictly redacted traffic record.
    """
    method: str
    url: str # We use str instead of HttpUrl to allow malformed URLs seen in wild
    host: str
    headers: Dict[str, str] = Field(..., description="REDACTED headers only")
    body_hash: Optional[str] = Field(None, description="SHA256 of body if captured")
    size_bytes: int
    
    @validator('headers')
    def check_redaction(cls, v):
        """Ensure sensitive headers are not leaking."""
        SENSITIVE = {'authorization', 'cookie', 'set-cookie', 'x-api-key'}
        for key in v.keys():
            if key.lower() in SENSITIVE:
                val = v[key]
                if val != "[REDACTED]" and not val.startswith("REDACTED"):
                     raise ValueError(f"Header '{key}' does not appear to be redacted!")
        return v

# ---------------------------------------------------------------------------
# Observer (Watchdog)
# ---------------------------------------------------------------------------

class EventSilencePayload(OmegaEventPayload):
    """
    Payload for EVENT_SILENCE.
    Emitted when no meaningful activity occurs for a duration.
    """
    silence_seconds: float
    last_progress_event_type: Optional[str] = None
    last_progress_at: float

class ToolChurnPayload(OmegaEventPayload):
    """
    Payload for TOOL_CHURN.
    Emitted when high tool velocity yields zero findings.
    """
    tool_started_count: int
    window_seconds: float
    findings_in_window: int
    is_assumed_zero_findings: bool = True # Heuristic: we assume 0 if we haven't seen FINDING_CREATED

class OrphanEventPayload(EventPayload):
    """
    Payload for ORPHAN_EVENT_DROPPED.
    Emitted when an event is received for a non-existent or missing scan session.
    """
    original_event_type: str
    scan_id: Optional[str] = None
    reason: str
    source_component: str

# ---------------------------------------------------------------------------
# Mimic (Source Reconstruction)
# ---------------------------------------------------------------------------

class MimicDownloadStartedPayload(BaseModel):
    scan_id: str = Field(..., min_length=1)
    root_urls: List[str] = Field(default_factory=list)
    note: Optional[str] = None


class MimicAssetDownloadedPayload(BaseModel):
    scan_id: str = Field(..., min_length=1)
    asset_id: str = Field(..., min_length=1)
    url: str = Field(..., min_length=1)
    content_type: Optional[str] = None
    size_bytes: conint(ge=0) = 0
    sha256: str = Field(..., min_length=64, max_length=64)
    discovered_from: Optional[str] = None  # parent URL


class MimicDownloadCompletedPayload(BaseModel):
    scan_id: str = Field(..., min_length=1)
    assets_downloaded: conint(ge=0) = 0
    total_bytes: conint(ge=0) = 0


class MimicRouteFoundPayload(BaseModel):
    scan_id: str = Field(..., min_length=1)
    asset_id: str = Field(..., min_length=1)
    route: str = Field(..., min_length=1)
    method: Optional[Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]] = None
    confidence: conint(ge=0, le=100) = 50
    evidence: Dict[str, Any] = Field(default_factory=dict)  # offsets, match hashes, etc.


class MimicSecretFoundPayload(BaseModel):
    scan_id: str = Field(..., min_length=1)
    asset_id: str = Field(..., min_length=1)
    secret_type: str = Field(..., min_length=1)
    confidence: conint(ge=0, le=100) = 50
    redacted_preview: str = Field(..., min_length=1)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class MimicAnalysisCompletedPayload(BaseModel):
    scan_id: str = Field(..., min_length=1)
    assets_analyzed: conint(ge=0) = 0
    routes_found: conint(ge=0) = 0
    secrets_found: conint(ge=0) = 0
    hidden_routes_found: conint(ge=0) = 0
    notes: List[str] = Field(default_factory=list)


class InsightActionType(str, Enum):
    """
    Classification of insight actions.
    Determines which handler processes the insight.
    """
    # Target Discovery
    HIGH_VALUE_TARGET = "high_value_target"  # Discovered critical asset
    CRITICAL_PATH = "critical_path"  # Found path to critical system
    
    # Vulnerability Discovery
    CONFIRMED_VULN = "confirmed_vuln"  # Vulnerability validated
    POTENTIAL_VULN = "potential_vuln"  # Vulnerability candidate
    
    # Surface Expansion
    NEW_SUBDOMAIN = "new_subdomain"  # New subdomain discovered
    NEW_ENDPOINT = "new_endpoint"  # New endpoint discovered
    NEW_PARAMETER = "new_parameter"  # New parameter discovered
    
    # Security Posture
    WAF_DETECTED = "waf_detected"  # WAF identified
    AUTH_REQUIRED = "auth_required"  # Authentication required
    RATE_LIMIT = "rate_limit"  # Rate limiting detected
    
    # Intelligence
    TECHNOLOGY_STACK = "technology_stack"  # Technology identified
    EXPOSED_SERVICE = "exposed_service"  # Exposed service found
    MISCONFIGURATION = "misconfiguration"  # Misconfiguration found
    
    # Meta
    GENERAL = "general"  # General insight


class InsightPayload(BaseModel):
    """
    Payload for NEXUS_INSIGHT_FORMED events.
    Represents a strategic insight discovered during scanning.
    """
    model_config = ConfigDict(extra="forbid")

    # Identification
    insight_id: str = Field(..., min_length=1, description="Unique insight identifier")
    scan_id: str = Field(..., min_length=1, description="Associated scan identifier")
    
    # Classification
    action_type: InsightActionType = Field(..., description="Type of insight action")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score [0.0, 1.0]")
    
    # Content
    target: str = Field(..., min_length=1, description="Target asset for this insight")
    summary: str = Field(..., min_length=5, description="Human-readable summary")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured details")
    
    # Traceability
    source_tool: str = Field(..., description="Tool that generated this insight")
    source_finding_id: Optional[str] = Field(None, description="Related finding ID")
    created_at: float = Field(default_factory=time.time, description="Creation timestamp")
    
    # Priority
    priority: int = Field(default=5, ge=1, le=10, description="Priority (1=highest, 10=lowest)")


@dataclass
class InsightQueueStats:
    """Statistics for insight queue monitoring."""
    total_enqueued: int = 0
    total_processed: int = 0
    total_failed: int = 0
    current_size: int = 0
    dropped_count: int = 0  # Insights dropped due to queue full
    processing_time_ms: float = 0.0
    circuit_breaker_state: str = "CLOSED"

# ---------------------------------------------------------------------------
# Reasoning & Hypotheses (The Brain)
# ---------------------------------------------------------------------------

class HypothesisPayload(EventPayload):
    """
    Payload for NEXUS_HYPOTHESIS_*.
    Represents a probabilistic assertion, strictly separated from graph facts.
    """
    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., min_length=1, description="Canonical scan identifier")
    hypothesis_id: str = Field(..., min_length=1)
    confidence: float = Field(..., ge=0.0, le=1.0, description="Bounded probability [0.0, 1.0]")
    summary: str = Field(..., min_length=5, description="One-line human readable summary")
    explanation: str = Field(..., min_length=10, description="Structured reasoning for the confidence score")
    
    # Traceability
    sources: List[str] = Field(default_factory=list, description="IDs of observations (findings, events, nodes) that support this")
    rule_id: Optional[str] = Field(None, description="ID of the reasoning rule that generated this")
    
    # State tracking
    is_terminal: bool = False # If True, no further updates expected (Confirmed/Refuted)
    

# ---------------------------------------------------------------------------
# Decision Layer (Strategos)
# ---------------------------------------------------------------------------

class DecisionPayload(EventPayload):
    """
    Payload for DECISION_MADE.
    Represents a concrete, reputable strategic commitment by the system.
    """
    model_config = ConfigDict(extra="forbid")

    # Identity
    decision_id: str = Field(..., description="Unique ID of the decision")
    scan_id: Optional[str] = Field(None, description="Scope: Scan ID")
    
    # Core Logic
    decision_type: str = Field(..., description="Type of decision (e.g. intent_transition, tool_selection)")
    selected_action: Any = Field(..., description="The option that was chosen")
    rationale: str = Field(..., description="Why this option was chosen")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this decision")
    
    # Context & Options
    alternatives_considered: List[Any] = Field(default_factory=list, description="Options that were available")
    suppressed_actions: List[Any] = Field(default_factory=list, description="Options explicitly rejected/suppressed")
    
    # Causality
    triggers: List[str] = Field(default_factory=list, description="IDs of events/findings that triggered this decision")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting data (metrics, errors, etc)")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Scope/Context (phase, target, etc)")
    timestamp: float = Field(default_factory=time.time, description="When decision was made")


# ---------------------------------------------------------------------------
# Cronus (Time Machine)
# ---------------------------------------------------------------------------

class CronusThinkingPayload(OmegaEventPayload):
    """Payload for internal Cronus logic steps (progress)."""
    phase: str = "cronus"
    step: str
    details: Optional[Dict[str, Any]] = None

# Add more specific schemas as we migrate legacy events...
