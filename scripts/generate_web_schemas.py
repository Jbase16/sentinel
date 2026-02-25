#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Type

from pydantic import BaseModel

# ---- IMPORT YOUR CONTRACT MODELS HERE ----
from core.web.contracts.models import (
    EvidenceBundle,
)
from core.web.contracts.events import (
    EventEnvelope,
    WebAuthEstablishedPayload,
    WebDeltaDetectedPayload,
    WebEndpointRegisteredPayload,
    WebEvidenceBundleCreatedPayload,
    WebFindingConfirmedPayload,
    WebMutationAttemptPayload,
    WebSurfaceDiscoveredPayload,
)

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_ROOT = ROOT / "docs" / "schemas" / "web"
EVENTS_ROOT = SCHEMA_ROOT / "events"


def write_schema(model: Type[BaseModel], output_path: Path) -> None:
    schema = model.model_json_schema()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(schema, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    write_schema(EventEnvelope, SCHEMA_ROOT / "event-envelope.schema.json")
    write_schema(EvidenceBundle, SCHEMA_ROOT / "evidence" / "EvidenceBundle.schema.json")

    write_schema(WebAuthEstablishedPayload, EVENTS_ROOT / "WEB_AUTH_ESTABLISHED.schema.json")
    write_schema(WebDeltaDetectedPayload, EVENTS_ROOT / "WEB_DELTA_DETECTED.schema.json")
    write_schema(WebEndpointRegisteredPayload, EVENTS_ROOT / "WEB_ENDPOINT_REGISTERED.schema.json")
    write_schema(WebEvidenceBundleCreatedPayload, EVENTS_ROOT / "WEB_EVIDENCE_BUNDLE_CREATED.schema.json")
    write_schema(WebFindingConfirmedPayload, EVENTS_ROOT / "WEB_FINDING_CONFIRMED.schema.json")
    write_schema(WebMutationAttemptPayload, EVENTS_ROOT / "WEB_MUTATION_ATTEMPT.schema.json")
    write_schema(WebSurfaceDiscoveredPayload, EVENTS_ROOT / "WEB_SURFACE_DISCOVERED.schema.json")

    print("Web schemas generated successfully.")


if __name__ == "__main__":
    main()
