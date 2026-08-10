"""Unified target-semantic catalog tests; all inputs are already acquired."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.semantic_catalog as semantic_module

from core.behavior.affordances import ClientArtifact, LatentAffordanceMiner
from core.behavior.interactions import InteractionIntentMiner
from core.behavior.normalize import stable_hash
from core.behavior.semantic_catalog import (
    EpistemicStatus,
    SemanticCatalogLimits,
    SemanticProtocol,
    SemanticRelationKind,
    SemanticSlotKind,
    SemanticSourceKind,
    TargetSemanticCatalogBuilder,
)


ORIGIN = "https://api.example.test"
TARGET_REF = stable_hash("security_obligation_target", ORIGIN)
DOCUMENT_ID = "doc_7fa9f13a2b4c5d6e"
JOB_ID = "job_4a5b6c7d8e9f0123"


def _export_record(*, persona: str = "alice", record_id: str = "start-export"):
    return {
        "id": record_id,
        "persona_id": persona,
        "method": "POST",
        "url": f"{ORIGIN}/api/documents/{DOCUMENT_ID}/export",
        "request_body": "{}",
        "response_status": 202,
        "response_body": json.dumps({"jobId": JOB_ID}),
    }


def _graphql_record(operation_name: str, *, record_id: str):
    return {
        "id": record_id,
        "persona_id": "alice",
        "method": "POST",
        "url": f"{ORIGIN}/graphql",
        "request_body": json.dumps(
            {
                "operationName": operation_name,
                "variables": {"accountId": "acct_7fa9f13a2b4c5d6e"},
            }
        ),
        "response_status": 200,
        "response_body": json.dumps({"data": {"ok": True}}),
    }


def _control(index: int, **overrides):
    value = {
        "tag": "button",
        "role": "button",
        "input_type": "",
        "form_method": "none",
        "destination": "none",
        "destination_ref": "",
        "locator": [
            {"tag": "html", "sibling_index": 1},
            {"tag": "body", "sibling_index": 1},
            {"tag": "button", "sibling_index": index},
        ],
        "locator_truncated": False,
        "visible": True,
        "disabled": False,
        "content_editable": False,
        "aria_expanded": False,
        "aria_haspopup": False,
        "sensitive_form": False,
        "download": False,
        "scripted_handler": False,
        "submitter": False,
    }
    value.update(overrides)
    return value


def _artifacts():
    return (
        ClientArtifact(
            f"{ORIGIN}/assets/app.js",
            "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);",
        ),
        ClientArtifact(
            f"{ORIGIN}/assets/app.js.map",
            json.dumps(
                {
                    "version": 3,
                    "sourcesContent": [
                        "const get = jobId => fetch(`/api/download-jobs/${jobId}`);"
                    ],
                }
            ),
            kind="source_map",
        ),
        ClientArtifact(
            f"{ORIGIN}/openapi.json",
            json.dumps(
                {
                    "openapi": "3.1.0",
                    "paths": {
                        "/api/reports/{jobId}": {
                            "get": {"responses": {"200": {}}}
                        }
                    },
                }
            ),
            kind="openapi",
        ),
    )


def _catalog_inputs():
    records = (
        _export_record(),
        _graphql_record("TransferAccount", record_id="graphql-transfer"),
    )
    artifacts = _artifacts()
    affordances = LatentAffordanceMiner().mine(
        records,
        artifacts,
        target_origin=ORIGIN,
    )
    controls = (
        _control(
            1,
            tag="input",
            role="textbox",
            input_type="text",
        ),
        _control(2, form_method="post", submitter=True),
    )
    interactions = InteractionIntentMiner().mine(
        controls,
        target_origin=ORIGIN,
        world_id="alice",
        page_url=f"{ORIGIN}/account/transfer",
    )
    return records, artifacts, affordances, interactions


def test_catalog_unifies_supported_sources_with_epistemic_provenance():
    records, artifacts, affordances, interactions = _catalog_inputs()

    catalog = TargetSemanticCatalogBuilder().build(
        records,
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
        artifacts=artifacts,
        affordances=affordances,
        interactions=interactions,
    )
    reordered = TargetSemanticCatalogBuilder().build(
        tuple(reversed(records)),
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
        artifacts=tuple(reversed(artifacts)),
        affordances=affordances,
        interactions=interactions,
    )

    assert catalog == reordered
    assert catalog.executable is False
    assert catalog.status in {"ready", "partial"}
    assert {
        SemanticSourceKind.REST_EXCHANGE,
        SemanticSourceKind.GRAPHQL_EXCHANGE,
        SemanticSourceKind.JAVASCRIPT,
        SemanticSourceKind.SOURCE_MAP,
        SemanticSourceKind.OPENAPI,
        SemanticSourceKind.HTML_FORM,
        SemanticSourceKind.CLIENT_VALIDATION,
        SemanticSourceKind.SERVER_IDENTIFIER,
    } <= {item.kind for item in catalog.sources}
    assert {
        SemanticProtocol.REST,
        SemanticProtocol.GRAPHQL,
        SemanticProtocol.ARTIFACT_ROUTE,
        SemanticProtocol.HTML_FORM,
    } <= {item.protocol for item in catalog.operations}
    source_statuses = {
        item.kind: item.epistemic_status for item in catalog.sources
    }
    assert source_statuses[SemanticSourceKind.REST_EXCHANGE] is EpistemicStatus.OBSERVED
    assert source_statuses[SemanticSourceKind.OPENAPI] is EpistemicStatus.SPECIFIED
    assert source_statuses[SemanticSourceKind.JAVASCRIPT] is EpistemicStatus.PUBLISHED
    assert catalog.planner_operations()


def test_server_ids_downstream_inputs_and_resource_relations_are_typed():
    records, artifacts, affordances, interactions = _catalog_inputs()
    catalog = TargetSemanticCatalogBuilder().build(
        records,
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
        artifacts=artifacts,
        affordances=affordances,
        interactions=interactions,
    )

    job_slots = [item for item in catalog.slots if item.capability.name == "job_id"]
    assert any(
        item.direction == "produces"
        and item.slot_kind is SemanticSlotKind.RESOURCE_ID
        and item.server_issued
        for item in job_slots
    )
    assert any(
        item.direction == "requires"
        and item.slot_kind is SemanticSlotKind.RESOURCE_ID
        for item in job_slots
    )
    assert any(item.name == "job" for item in catalog.resources)
    assert {
        SemanticRelationKind.OPERATION_REQUIRES,
        SemanticRelationKind.OPERATION_PRODUCES,
    } <= {item.kind for item in catalog.relations}


def test_parent_owner_tenant_role_and_lifecycle_context_are_explicit():
    record = {
        "id": "create-child-document",
        "persona_id": "alice",
        "tenant_id": "tenant-controlled-a",
        "method": "POST",
        "url": f"{ORIGIN}/api/documents",
        "request_body": json.dumps(
            {
                "parentId": "folder_7fa9f13a2b4c5d6e",
                "ownerId": "user_7fa9f13a2b4c5d6e",
                "organizationId": "org_7fa9f13a2b4c5d6e",
                "role": "editor",
            }
        ),
        "response_status": 201,
        "response_body": json.dumps(
            {
                "documentId": DOCUMENT_ID,
                "status": "draft",
            }
        ),
    }

    catalog = TargetSemanticCatalogBuilder().build(
        (record,),
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
    )

    slot_kinds = {item.slot_kind for item in catalog.slots}
    assert {
        SemanticSlotKind.RESOURCE_ID,
        SemanticSlotKind.PARENT_ID,
        SemanticSlotKind.OWNER_ID,
        SemanticSlotKind.TENANT_ID,
        SemanticSlotKind.ROLE,
        SemanticSlotKind.LIFECYCLE_STATE,
    } <= slot_kinds
    relation_kinds = {item.kind for item in catalog.relations}
    assert {
        SemanticRelationKind.PARENT,
        SemanticRelationKind.OWNERSHIP,
        SemanticRelationKind.TENANT,
        SemanticRelationKind.ROLE,
    } <= relation_kinds


def test_equivalent_operations_deduplicate_without_merging_worlds_or_tenants():
    base = {
        "id": "account-read",
        "method": "GET",
        "url": f"{ORIGIN}/api/accounts/acct_7fa9f13a2b4c5d6e",
        "response_status": 200,
        "response_body": json.dumps({"accountId": "acct_7fa9f13a2b4c5d6e"}),
    }
    alice_a = {**base, "persona_id": "alice", "tenant_id": "tenant-a"}
    alice_a_duplicate = dict(alice_a)
    alice_b = {
        **base,
        "id": "account-read-b",
        "persona_id": "alice",
        "tenant_id": "tenant-b",
    }
    bob_a = {
        **base,
        "id": "account-read-peer",
        "persona_id": "bob",
        "tenant_id": "tenant-a",
    }

    catalog = TargetSemanticCatalogBuilder().build(
        (alice_a_duplicate, alice_b, alice_a),
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=(bob_a,),
        peer_world_id="bob",
    )

    matching = [
        item for item in catalog.operations if item.protocol is SemanticProtocol.REST
    ]
    assert len(matching) == 3
    assert len({item.operation_ref for item in matching}) == 3
    assert len({(item.world_ref, item.tenant_ref) for item in matching}) == 3


def test_graphql_action_collisions_and_artifact_version_conflicts_are_explicit():
    artifacts = (
        ClientArtifact(f"{ORIGIN}/openapi.json", '{"openapi":"3.0.0","paths":{}}', kind="openapi"),
        ClientArtifact(f"{ORIGIN}/openapi.json", '{"openapi":"3.1.0","paths":{}}', kind="openapi"),
    )
    catalog = TargetSemanticCatalogBuilder().build(
        (
            _graphql_record("TransferAccount", record_id="first"),
            _graphql_record("DeleteAccount", record_id="second"),
        ),
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
        artifacts=artifacts,
    )

    codes = {item.code: item.count for item in catalog.deficits}
    assert codes["ambiguous_action_semantics"] == 1
    assert codes["conflicting_artifact_versions"] == 1
    graphql = [
        item for item in catalog.operations if item.protocol is SemanticProtocol.GRAPHQL
    ]
    assert {item.label for item in graphql} == {
        "graphql.delete.account",
        "graphql.transfer.account",
    }
    assert len({item.action_id for item in graphql}) == 1


def test_unnamed_graphql_exchange_remains_graphql_and_explicitly_unresolved():
    record = {
        "id": "persisted-operation",
        "persona_id": "alice",
        "method": "POST",
        "url": f"{ORIGIN}/graphql",
        "request_body": json.dumps(
            {"extensions": {"persistedQuery": {"sha256Hash": "a" * 64}}}
        ),
        "response_status": 200,
        "response_body": json.dumps({"data": {"ok": True}}),
    }

    catalog = TargetSemanticCatalogBuilder().build(
        (record,),
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
    )

    assert catalog.operations[0].protocol is SemanticProtocol.GRAPHQL
    assert catalog.operations[0].label == "graphql.operation.unresolved"
    assert "graphql_operation_semantics_unresolved" in {
        item.code for item in catalog.deficits
    }


def test_truncation_and_redacted_semantic_gaps_are_visible_and_deterministic():
    secret = "customerzone"
    records = (
        {
            "id": "one",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/{secret}/export",
            "response_status": 200,
            "response_body": "{}",
        },
        {
            "id": "two",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/{secret}/download",
            "response_status": 200,
            "response_body": "{}",
        },
    )
    builder = TargetSemanticCatalogBuilder(
        SemanticCatalogLimits(max_records_per_world=1)
    )

    first = builder.build(
        records,
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
    )
    second = builder.build(
        tuple(reversed(records)),
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
    )

    assert first == second
    codes = {item.code for item in first.deficits}
    assert "record_limit_truncated" in codes
    assert "redacted_path_semantics" in codes
    assert first.diagnostics.dropped_records == 1
    assert secret not in json.dumps(first.to_dict(), sort_keys=True)


def test_catalog_projection_preserves_graphql_semantics_for_payout_planning():
    catalog = TargetSemanticCatalogBuilder().build(
        (_graphql_record("ExportInvoice", record_id="export-invoice"),),
        target_ref=TARGET_REF,
        target_origin=ORIGIN,
        world_id="alice",
    )

    projected = catalog.planner_operations()
    assert len(projected) == 1
    assert projected[0].label == "graphql.export.invoice"
    assert projected[0].operation_id.startswith("action:")


def test_catalog_has_no_transport_or_package_level_execution_surface():
    source = Path(semantic_module.__file__).read_text(encoding="utf-8")
    imports = {
        node.names[0].name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
    }
    imported_from = {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    }

    assert not {"httpx", "requests", "socket", "urllib.request"} & (
        imports | imported_from
    )
    assert "PolicyExecutor" not in source
    assert "ProofBudget" not in source
    assert "ProvenanceSink" not in source
    assert not hasattr(behavior_package, "TargetSemanticCatalogBuilder")


def test_catalog_rejects_cross_target_semantic_evidence():
    records, artifacts, affordances, interactions = _catalog_inputs()

    with pytest.raises(ValueError, match="affordance target"):
        TargetSemanticCatalogBuilder().build(
            records,
            target_ref=stable_hash(
                "security_obligation_target",
                "https://other.example.test",
            ),
            target_origin="https://other.example.test",
            world_id="alice",
            artifacts=artifacts,
            affordances=affordances,
            interactions=interactions,
        )
