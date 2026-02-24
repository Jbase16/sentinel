from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator
from typing import Literal

from .enums import (
    DeltaSeverity,
    ParamLocation,
    SurfaceSource,
    VulnerabilityClass,
    WebAuthMode,
    WebMethod,
)
from .ids import (
    ArtifactId,
    FindingId,
    MissionId,
    PrincipalId,
    RequestId,
    ScanId,
    SessionId,
)


class WebMission(BaseModel):
    mission_id: MissionId
    scan_id: ScanId
    session_id: SessionId

    origin: HttpUrl
    allowed_origins: List[str] = Field(
        default_factory=list,
        max_length=100,
        description="Hostnames/origins allowed for this mission; origin host must be included.",
    )

    max_depth: int = Field(ge=0, le=20, default=4)
    max_pages: int = Field(ge=1, le=20000, default=500)

    exploit_ceiling: int = Field(ge=0, le=200000, default=1000)
    oob_allowed: bool = False
    destructive_methods_allowed: bool = False

    auth_mode: WebAuthMode = WebAuthMode.NONE
    principal_count: int = Field(ge=1, le=10, default=1)

    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())

    @field_validator("allowed_origins")
    @classmethod
    def validate_allowed_origins(cls, v: List[str]) -> List[str]:
        # Keep this simple and deterministic; normalization happens elsewhere.
        return [x.strip() for x in v if x.strip()]


class EndpointCandidate(BaseModel):
    url: HttpUrl
    method: WebMethod = WebMethod.GET
    source: SurfaceSource
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    requires_auth: bool = False

    tags: List[str] = Field(default_factory=list, max_length=64)


class ParamSpec(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    location: ParamLocation
    example_value: Optional[str] = Field(default=None, max_length=2048)
    type_guess: Optional[str] = Field(default=None, max_length=64)
    reflection_hint: bool = False


class BaselineSignature(BaseModel):
    status_code: int = Field(ge=100, le=599)
    body_hash: str = Field(min_length=8, max_length=256)
    normalized_hash: str = Field(min_length=8, max_length=256)
    dom_hash: Optional[str] = Field(default=None, min_length=8, max_length=256)
    json_shape_hash: Optional[str] = Field(default=None, min_length=8, max_length=256)

    # Simple timing profile (ms). Keep deterministic + bounded.
    ttfb_ms: Optional[int] = Field(default=None, ge=0, le=600000)
    total_ms: Optional[int] = Field(default=None, ge=0, le=600000)


class DeltaVector(BaseModel):
    status_delta: Optional[int] = Field(default=None, description="mutated_status - baseline_status")
    body_length_delta: Optional[int] = None
    structural_delta: float = Field(ge=0.0, le=1.0, default=0.0, description="0..1 distance")
    timing_delta_ms: Optional[int] = None

    severity: DeltaSeverity = DeltaSeverity.INFO
    notes: List[str] = Field(default_factory=list, max_length=100)


class HttpExchange(BaseModel):
    """
    Redacted snapshot of a single request/response exchange.
    Avoid raw secrets by contract: redaction must be done before storing here.
    """
    request_id: RequestId
    url: HttpUrl
    method: WebMethod

    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body_b64: Optional[str] = Field(default=None, max_length=10_000_000, description="Base64-encoded body, redacted as needed")

    response_status: int = Field(ge=100, le=599)
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_b64: Optional[str] = Field(default=None, max_length=10_000_000, description="Base64-encoded body, redacted as needed")

    captured_at: datetime = Field(default_factory=lambda: datetime.utcnow())


class ArtifactRef(BaseModel):
    artifact_id: ArtifactId
    kind: str = Field(min_length=1, max_length=64, description="e.g. har, screenshot, log, pcaps, html")
    path: str = Field(min_length=1, max_length=1024, description="Repo-local or absolute path")
    sha256: Optional[str] = Field(default=None, min_length=16, max_length=128)


class EvidenceBundle(BaseModel):
    """
    Evidence contract: REQUIRED for confirmed findings.
    """
    version: Literal["1.0"] = "1.0"

    finding_id: FindingId
    mission_id: MissionId
    scan_id: ScanId
    session_id: SessionId

    vuln_class: VulnerabilityClass
    title: str = Field(min_length=3, max_length=256)
    summary: str = Field(min_length=1, max_length=8192)

    principal_id: PrincipalId
    affected_principals: List[PrincipalId] = Field(default_factory=list, max_length=100)

    request_sequence: List[HttpExchange] = Field(default_factory=list, max_length=100)
    baseline: Optional[BaselineSignature] = None
    delta: Optional[DeltaVector] = None

    artifacts: List[ArtifactRef] = Field(default_factory=list, max_length=100)
    replay_script_path: Optional[str] = Field(default=None, max_length=1024)

    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())

    @field_validator("affected_principals")
    @classmethod
    def uniq_principals(cls, v: List[PrincipalId]) -> List[PrincipalId]:
        seen = set()
        out = []
        for pid in v:
            s = str(pid)
            if s not in seen:
                out.append(pid)
                seen.add(s)
        return out


class FindingRecord(BaseModel):
    """
    Minimal normalized finding record suitable for piping into existing FindingsStore.
    """
    finding_id: FindingId
    vuln_class: VulnerabilityClass
    title: str = Field(min_length=3, max_length=256)
    confidence: float = Field(ge=0.0, le=1.0)
    confirmed: bool = False

    target_url: HttpUrl
    endpoint: Optional[EndpointCandidate] = None

    evidence_bundle_id: Optional[str] = Field(default=None, description="Optional pointer if stored separately")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())
