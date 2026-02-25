from __future__ import annotations

from typing import Dict, Any

from pydantic import BaseModel

from .events import (
    EventEnvelope,
    WebAuthEstablishedPayload,
    WebDeltaDetectedPayload,
    WebEndpointRegisteredPayload,
    WebEvidenceBundleCreatedPayload,
    WebFindingConfirmedPayload,
    WebMutationAttemptPayload,
    WebSurfaceDiscoveredPayload,
)
from .models import EvidenceBundle


def pydantic_schema(model: type[BaseModel]) -> Dict[str, Any]:
    """
    Returns a JSON Schema dict from Pydantic (v2).
    Used to keep runtime-validated contracts in lockstep with docs/schemas.
    """
    return model.model_json_schema()


def all_contract_schemas() -> Dict[str, Dict[str, Any]]:
    """
    Canonical mapping of schema-name -> JSON schema dict.
    """
    return {
        "EventEnvelope": pydantic_schema(EventEnvelope),
        "WEB_SURFACE_DISCOVERED": pydantic_schema(WebSurfaceDiscoveredPayload),
        "WEB_ENDPOINT_REGISTERED": pydantic_schema(WebEndpointRegisteredPayload),
        "WEB_AUTH_ESTABLISHED": pydantic_schema(WebAuthEstablishedPayload),
        "WEB_MUTATION_ATTEMPT": pydantic_schema(WebMutationAttemptPayload),
        "WEB_DELTA_DETECTED": pydantic_schema(WebDeltaDetectedPayload),
        "WEB_FINDING_CONFIRMED": pydantic_schema(WebFindingConfirmedPayload),
        "WEB_EVIDENCE_BUNDLE_CREATED": pydantic_schema(WebEvidenceBundleCreatedPayload),
        "EvidenceBundle": pydantic_schema(EvidenceBundle),
    }
