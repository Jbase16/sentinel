"""
core/contracts/schemas.py
Pydantic schemas for event payloads.

This module provides the STRICT runtime validation models for the EventContract.
Every event type related to Omega/Governance MUST have a corresponding schema here.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, HttpUrl, validator

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

# ---------------------------------------------------------------------------
# Cronus (Time Machine)
# ---------------------------------------------------------------------------

class CronusThinkingPayload(OmegaEventPayload):
    """Payload for internal Cronus logic steps (progress)."""
    phase: str = "cronus"
    step: str
    details: Optional[Dict[str, Any]] = None

# Add more specific schemas as we migrate legacy events...
