from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, HttpUrl

from .enums import (
    DeltaSeverity,
    SurfaceSource,
    VulnerabilityClass,
    WebAuthMode,
    WebMethod,
)
from .ids import (
    FindingId,
    MissionId,
    PrincipalId,
    RequestId,
    ScanId,
    SessionId,
)
from .models import DeltaVector, EndpointCandidate, EvidenceBundle, HttpExchange, ParamSpec


class EventType(str):
    WEB_SURFACE_DISCOVERED = "WEB_SURFACE_DISCOVERED"
    WEB_ENDPOINT_REGISTERED = "WEB_ENDPOINT_REGISTERED"
    WEB_AUTH_SUCCESS = "WEB_AUTH_SUCCESS"
    WEB_MUTATION_ATTEMPT = "WEB_MUTATION_ATTEMPT"
    WEB_DELTA_DETECTED = "WEB_DELTA_DETECTED"
    WEB_FINDING_CONFIRMED = "WEB_FINDING_CONFIRMED"
    WEB_EVIDENCE_BUNDLE_CREATED = "WEB_EVIDENCE_BUNDLE_CREATED"


class EventEnvelope(BaseModel):
    """
    Canonical event envelope. Every event is (envelope + payload).

    IMPORTANT: The Agent must not invent envelope fields.
    """
    event_type: str = Field(min_length=3, max_length=128)
    occurred_at: datetime = Field(default_factory=lambda: datetime.utcnow())

    mission_id: MissionId
    scan_id: ScanId
    session_id: SessionId

    # Optional correlation
    principal_id: Optional[PrincipalId] = None
    request_id: Optional[RequestId] = None
    finding_id: Optional[FindingId] = None

    # Free-form tags with bounded size
    tags: List[str] = Field(default_factory=list, max_length=64)

    # Payload as structured object, stored separately in typed models below
    payload: Dict[str, Any] = Field(default_factory=dict)


# ---- Typed payloads (the real contract) ----

class WebSurfaceDiscoveredPayload(BaseModel):
    source: SurfaceSource
    discovered_urls: List[HttpUrl] = Field(default_factory=list)
    discovered_assets: List[HttpUrl] = Field(default_factory=list)
    discovered_forms: List[HttpUrl] = Field(default_factory=list)
    depth: int = Field(ge=0, le=20)
    page_count: int = Field(ge=0, le=20000)


class WebEndpointRegisteredPayload(BaseModel):
    source: SurfaceSource
    endpoints: List[EndpointCandidate] = Field(default_factory=list)
    js_asset: Optional[HttpUrl] = None


class WebAuthSuccessPayload(BaseModel):
    auth_mode: WebAuthMode
    principal_id: PrincipalId
    login_url: HttpUrl
    success_signal: str = Field(min_length=1, max_length=256, description="e.g. cookie name, redirect, DOM marker")
    session_fingerprint: str = Field(min_length=8, max_length=256, description="non-secret hash of session state")


class WebMutationAttemptPayload(BaseModel):
    vuln_class: VulnerabilityClass
    target_url: HttpUrl
    method: WebMethod
    param: Optional[ParamSpec] = None
    mutation_label: str = Field(min_length=1, max_length=128, description="e.g. canary_reflect, sqli_error_1, idor_pid_swap")
    baseline_request_id: Optional[RequestId] = None
    mutated_request_id: Optional[RequestId] = None
    budget_index: int = Field(ge=0, le=10_000_000)


class WebDeltaDetectedPayload(BaseModel):
    vuln_class: VulnerabilityClass
    target_url: HttpUrl
    baseline: Optional[Dict[str, Any]] = None  # BaselineSignature serialized
    delta: DeltaVector
    severity: DeltaSeverity = DeltaSeverity.INFO
    notes: List[str] = Field(default_factory=list)


class WebFindingConfirmedPayload(BaseModel):
    finding_id: FindingId
    vuln_class: VulnerabilityClass
    title: str = Field(min_length=3, max_length=256)
    confidence: float = Field(ge=0.0, le=1.0)
    target_url: HttpUrl
    evidence_ready: bool = True


class WebEvidenceBundleCreatedPayload(BaseModel):
    bundle: EvidenceBundle


# ---- Discriminated union helpers (optional use) ----

EventPayload = Union[
    WebSurfaceDiscoveredPayload,
    WebEndpointRegisteredPayload,
    WebAuthSuccessPayload,
    WebMutationAttemptPayload,
    WebDeltaDetectedPayload,
    WebFindingConfirmedPayload,
    WebEvidenceBundleCreatedPayload,
]
