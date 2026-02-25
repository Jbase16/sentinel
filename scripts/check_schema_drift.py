#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Type

from pydantic import BaseModel

# ---- SAME IMPORTS AS GENERATOR ----
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


def normalize_schema(model: Type[BaseModel]) -> str:
    schema = model.model_json_schema()
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def compare(model: Type[BaseModel], path: Path) -> bool:
    if not path.exists():
        print(f"[DRIFT] Missing schema file: {path}")
        return False

    expected = normalize_schema(model)
    actual = path.read_text(encoding="utf-8")

    if expected != actual:
        print(f"[DRIFT] Schema mismatch: {path}")
        return False

    return True


def main() -> None:
    ok = True

    ok &= compare(EventEnvelope, SCHEMA_ROOT / "event-envelope.schema.json")
    ok &= compare(EvidenceBundle, SCHEMA_ROOT / "evidence" / "EvidenceBundle.schema.json")

    ok &= compare(WebAuthEstablishedPayload, EVENTS_ROOT / "WEB_AUTH_ESTABLISHED.schema.json")
    ok &= compare(WebDeltaDetectedPayload, EVENTS_ROOT / "WEB_DELTA_DETECTED.schema.json")
    ok &= compare(WebEndpointRegisteredPayload, EVENTS_ROOT / "WEB_ENDPOINT_REGISTERED.schema.json")
    ok &= compare(WebEvidenceBundleCreatedPayload, EVENTS_ROOT / "WEB_EVIDENCE_BUNDLE_CREATED.schema.json")
    ok &= compare(WebFindingConfirmedPayload, EVENTS_ROOT / "WEB_FINDING_CONFIRMED.schema.json")
    ok &= compare(WebMutationAttemptPayload, EVENTS_ROOT / "WEB_MUTATION_ATTEMPT.schema.json")
    ok &= compare(WebSurfaceDiscoveredPayload, EVENTS_ROOT / "WEB_SURFACE_DISCOVERED.schema.json")

    if not ok:
        print("\nSchema drift detected. Run `make schemas` and commit changes.")
        sys.exit(1)

    print("Schema drift check passed.")


if __name__ == "__main__":
    main()
