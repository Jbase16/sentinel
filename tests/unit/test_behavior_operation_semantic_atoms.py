from __future__ import annotations

import json

from core.behavior.compiler import (
    OperationOutcome,
    operation_atoms_from_records,
    operation_contracts_from_records,
)
from core.behavior.normalize import stable_hash
from core.behavior.semantic_catalog import SemanticSourceKind, TargetSemanticCatalogBuilder


ORIGIN = "https://api.example.test"
TARGET_REF = stable_hash("security_obligation_target", ORIGIN)


def _mixed_outcome_records() -> tuple[dict[str, object], ...]:
    common = {
        "persona_id": "alice",
        "tenant_id": "tenant-red",
        "method": "POST",
        "url": f"{ORIGIN}/api/users",
        "request_body": json.dumps({"name": "controlled"}),
    }
    return (
        {
            **common,
            "id": "create-user-success",
            "response_status": 201,
            "response_body": json.dumps({"userId": "user_7fa9f13a2b4c5d6e"}),
        },
        {
            **common,
            "id": "create-user-denied",
            "response_status": 403,
            "response_body": json.dumps(
                {"errorId": "error_4a5b6c7d8e9f0123", "status": "forbidden"}
            ),
        },
    )


def test_mixed_outcomes_keep_outputs_on_exact_source_instance() -> None:
    records = _mixed_outcome_records()
    families, instances = operation_atoms_from_records(records)

    assert len(families) == 1
    assert len(instances) == 2
    by_outcome = {item.outcome: item for item in instances}
    success = by_outcome[OperationOutcome.SUCCESS]
    denied = by_outcome[OperationOutcome.CLIENT_ERROR]
    assert {item.name for item in success.outputs} >= {"user_id"}
    assert "error_id" not in {item.name for item in success.outputs}
    assert "error_id" in {item.name for item in denied.outputs}
    assert "user_id" not in {item.name for item in denied.outputs}
    assert success.source_ref != denied.source_ref

    projected = operation_contracts_from_records(records)
    assert len(projected) == 1
    assert projected[0].observed_success
    assert {item.name for item in projected[0].produces} >= {"user_id"}
    assert "error_id" not in {item.name for item in projected[0].produces}
    assert projected[0].source_refs == (success.source_ref,)

    catalog = TargetSemanticCatalogBuilder().build(
        records,
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
    )
    produced_slots = [item for item in catalog.slots if item.direction == "produces"]
    assert "error_id" not in {item.capability.name for item in produced_slots}
    user_slot = next(item for item in produced_slots if item.capability.name == "user_id")

    success_ref = stable_hash("source_ref", "create-user-success")
    denied_ref = stable_hash("source_ref", "create-user-denied")
    success_sources = {
        item.source_id for item in catalog.sources if item.evidence_ref == success_ref
    }
    denied_sources = {
        item.source_id for item in catalog.sources if item.evidence_ref == denied_ref
    }
    assert set(user_slot.source_ids) <= success_sources
    assert set(user_slot.source_ids).isdisjoint(denied_sources)
    assert not any(
        item.kind is SemanticSourceKind.SERVER_IDENTIFIER
        and item.evidence_ref == denied_ref
        for item in catalog.sources
    )
