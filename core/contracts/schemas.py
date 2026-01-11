"""
core/contracts/schemas.py
Pydantic schemas for event payloads.

This module provides the STRICT runtime validation models for the EventContract.
Every event type related to Omega/Governance MUST have a corresponding schema here.
"""

from typing import Dict, List, Optional, Any, Literal
from pydantic import BaseModel, Field, HttpUrl, validator, conint, ConfigDict, field_validator

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

class OrphanEventPayload(OmegaEventPayload):
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

# ---------------------------------------------------------------------------
# Reasoning & Hypotheses (The Brain)
# ---------------------------------------------------------------------------

class HypothesisPayload(EventPayload):
    """
    Payload for NEXUS_HYPOTHESIS_*.
    Represents a probabilistic assertion, strictly separated from graph facts.
    """
    model_config = ConfigDict(extra="forbid")

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
# Cronus (Time Machine)
# ---------------------------------------------------------------------------

class CronusThinkingPayload(OmegaEventPayload):
    """Payload for internal Cronus logic steps (progress)."""
    phase: str = "cronus"
    step: str
    details: Optional[Dict[str, Any]] = None

# Add more specific schemas as we migrate legacy events...
