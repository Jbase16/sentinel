"""Passive latent-affordance mining tests; no target transport exists."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import core.behavior as behavior_package
import core.behavior.affordances as affordance_module

from core.behavior.affordances import (
    ClientArtifact,
    LatentAffordanceLimits,
    LatentAffordanceMiner,
)

ORIGIN = "https://api.example.test"
DOCUMENT_ID = "doc_7fa9f13a2b4c5d6e"
JOB_ID = "job_4a5b6c7d8e9f0123"


def _export_record(*, record_id="start-export", job_id=JOB_ID, persona="alice"):
    return {
        "id": record_id,
        "persona_id": persona,
        "method": "POST",
        "url": f"{ORIGIN}/api/documents/{DOCUMENT_ID}/export",
        "request_body": "{}",
        "response_status": 202,
        "response_body": json.dumps({"jobId": job_id}),
    }


def test_js_template_links_produced_capability_to_unobserved_read_route():
    artifact = ClientArtifact(
        f"{ORIGIN}/assets/app.js",
        "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);",
    )

    result = LatentAffordanceMiner().mine(
        (_export_record(),),
        (artifact,),
        target_origin=ORIGIN,
    )

    assert result.status == "ready"
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.capability.name == "job_id"
    assert candidate.consumer_method == "GET"
    assert candidate.consumer_path_template == "/api/export-jobs/{jobId}"
    assert candidate.consumer_parameter_location == "path"
    assert candidate.risk_class == "read"
    assert candidate.executable is False
    assert candidate.to_dict()["requires_active_confirmation"] is True


def test_openapi_generic_id_is_matched_by_its_resource_parent():
    record = {
        "id": "create-document",
        "persona_id": "alice",
        "method": "POST",
        "url": f"{ORIGIN}/api/documents",
        "request_body": '{"title":"controlled"}',
        "response_status": 201,
        "response_body": json.dumps({"documentId": DOCUMENT_ID}),
    }
    artifact = ClientArtifact(
        f"{ORIGIN}/openapi.json",
        json.dumps(
            {
                "openapi": "3.1.0",
                "paths": {
                    "/api/documents/{id}/history": {"get": {"responses": {"200": {}}}}
                },
            }
        ),
        kind="openapi",
    )

    result = LatentAffordanceMiner().mine(
        (record,),
        (artifact,),
        target_origin=ORIGIN,
    )

    assert len(result.candidates) == 1
    assert result.candidates[0].capability.name == "document_id"
    assert result.candidates[0].consumer_path_template.endswith("/{id}/history")
    assert result.candidates[0].evidence_kinds == ("openapi_path",)


def test_already_observed_operation_is_not_reported_as_latent():
    records = (
        _export_record(),
        {
            "id": "poll-export",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/export-jobs/{JOB_ID}",
            "response_status": 200,
            "response_body": '{"status":"complete"}',
        },
    )
    artifact = ClientArtifact(
        f"{ORIGIN}/assets/app.js",
        "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);",
    )

    result = LatentAffordanceMiner().mine(records, (artifact,), target_origin=ORIGIN)

    assert result.status == "no_latent_affordances"
    assert result.candidates == ()
    assert result.diagnostics.observed_routes_rejected == 1


def test_ambiguous_same_world_producers_fail_closed():
    records = (
        _export_record(),
        _export_record(record_id="start-export-again", job_id="job_aaaaaaaaaaaaaaaa"),
    )
    artifact = ClientArtifact(
        f"{ORIGIN}/assets/app.js",
        "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);",
    )

    result = LatentAffordanceMiner().mine(records, (artifact,), target_origin=ORIGIN)

    assert result.candidates == ()
    assert result.diagnostics.ambiguous_producer_groups == 1


def test_cross_origin_and_multi_parameter_routes_fail_closed():
    artifact = ClientArtifact(
        f"{ORIGIN}/assets/app.js",
        "\n".join(
            (
                "fetch(`https://outside.example/jobs/${jobId}`);",
                "fetch(`/api/tenants/${tenantId}/jobs/${jobId}`);",
            )
        ),
    )

    result = LatentAffordanceMiner().mine(
        (_export_record(),),
        (artifact,),
        target_origin=ORIGIN,
    )

    assert result.candidates == ()
    assert result.diagnostics.routes_extracted == 0


def test_source_map_content_and_duplicate_artifact_evidence_are_aggregated():
    source = "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);"
    artifacts = (
        ClientArtifact(
            f"{ORIGIN}/assets/app.js.map",
            json.dumps({"version": 3, "sourcesContent": [source]}),
            kind="source_map",
        ),
        ClientArtifact(f"{ORIGIN}/assets/chunk.js", source),
    )

    result = LatentAffordanceMiner().mine(
        (_export_record(),),
        artifacts,
        target_origin=ORIGIN,
    )
    single_evidence = LatentAffordanceMiner().mine(
        (_export_record(),),
        (artifacts[1],),
        target_origin=ORIGIN,
    )

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert len(candidate.artifact_refs) == 2
    assert candidate.evidence_kinds == ("client_string", "source_map_string")
    assert candidate.affordance_id == single_evidence.candidates[0].affordance_id
    assert candidate.evidence_digest != single_evidence.candidates[0].evidence_digest


def test_query_token_handoff_is_redacted_and_marked_sensitive():
    record = {
        **_export_record(),
        "response_body": json.dumps({"downloadToken": "secret_download_4a5b6c7d8e9f"}),
    }
    artifact = ClientArtifact(
        f"{ORIGIN}/assets/app.js",
        "const load = downloadToken => "
        "axios.get(`/api/downloads?token=${downloadToken}`);",
    )

    result = LatentAffordanceMiner().mine(
        (record,),
        (artifact,),
        target_origin=ORIGIN,
    )

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.capability.name == "download_token"
    assert candidate.consumer_parameter_location == "query"
    assert candidate.consumer_parameter_pointer == "/query/token"
    assert candidate.sensitive is True
    assert "secret_download" not in json.dumps(result.to_dict())


def test_result_is_deterministic_and_does_not_serialize_raw_evidence():
    artifact = ClientArtifact(
        f"{ORIGIN}/assets/private-app.js",
        "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);",
    )
    first = LatentAffordanceMiner().mine(
        (_export_record(),), (artifact,), target_origin=ORIGIN
    )
    second = LatentAffordanceMiner().mine(
        (_export_record(),), (artifact,), target_origin=ORIGIN
    )

    assert first.to_dict() == second.to_dict()
    serialized = json.dumps(first.to_dict(), sort_keys=True)
    for raw_value in (ORIGIN, DOCUMENT_ID, JOB_ID, "private-app.js", "alice"):
        assert raw_value not in serialized


def test_artifact_bounds_are_honest_and_do_not_change_candidate_identity():
    source = "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);"
    miner = LatentAffordanceMiner(
        LatentAffordanceLimits(max_artifacts=1, max_artifact_bytes=128)
    )
    result = miner.mine(
        (_export_record(),),
        (
            ClientArtifact("first.js", source),
            ClientArtifact("second.js", source),
        ),
        target_origin=ORIGIN,
    )

    assert len(result.candidates) == 1
    assert result.diagnostics.artifacts == 1
    assert result.diagnostics.dropped_artifacts == 1


def test_affordance_module_has_no_transport_or_async_execution_surface():
    tree = ast.parse(Path(affordance_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert not hasattr(behavior_package, "LatentAffordanceMiner")
