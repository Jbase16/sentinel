"""Passive security-obligation graph tests; no execution is available."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import core.behavior as behavior_package
import core.behavior.obligations as obligation_module

from core.behavior.affordances import ClientArtifact, LatentAffordanceMiner
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.obligations import (
    OPEN,
    UPHELD,
    SecurityObligationGraphBuilder,
    SecurityObligationLimits,
)
from core.behavior.proposals import compile_authorization_proposals

ORIGIN = "https://api.example.test"
NOTE_ID = "note_7fa9f13a2b4c5d6e"
JOB_ID = "job_4a5b6c7d8e9f0123"
ALICE_DOCUMENT_ID = "doc_alice_7fa9f13a2b4c"
BOB_DOCUMENT_ID = "doc_bob_4a5b6c7d8e9f0"


def _lifecycle():
    records = (
        {
            "id": "create-note",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/notes",
            "request_body": '{"title":"controlled"}',
            "response_status": 201,
            "response_body": json.dumps({"noteId": NOTE_ID}),
        },
        {
            "id": "read-note",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
            "response_status": 200,
            "response_body": '{"title":"controlled"}',
        },
        {
            "id": "cleanup-note",
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        },
    )
    return LifecycleContractMiner().mine(records)


def _proposals():
    source = (
        {
            "id": "bob-document",
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{BOB_DOCUMENT_ID}",
            "response_status": 200,
        },
    )
    peer = (
        {
            "id": "alice-document",
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{ALICE_DOCUMENT_ID}",
            "response_status": 200,
        },
    )
    return compile_authorization_proposals(
        source,
        peer,
        source_world="bob",
        peer_world="alice",
    )


def _affordances():
    records = (
        {
            "id": "start-export",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/documents/{ALICE_DOCUMENT_ID}/export",
            "request_body": "{}",
            "response_status": 202,
            "response_body": json.dumps({"jobId": JOB_ID}),
        },
    )
    artifacts = (
        ClientArtifact(
            f"{ORIGIN}/assets/app.js",
            "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);",
        ),
    )
    return LatentAffordanceMiner().mine(records, artifacts, target_origin=ORIGIN)


def _graph(*, limits=None):
    return SecurityObligationGraphBuilder(limits).build(
        target_origin=ORIGIN,
        lifecycle=_lifecycle(),
        proposals=_proposals(),
        affordances=_affordances(),
    )


def test_graph_derives_controls_questions_and_hidden_surface_dependencies():
    graph = _graph()
    by_kind = {item.kind: item for item in graph.obligations}

    assert graph.status == "ready"
    assert len(graph.obligations) == 5
    assert by_kind["owned_control"].status == UPHELD
    assert by_kind["owned_control"].requires_execution is False
    assert by_kind["ownership_boundary"].status == OPEN
    assert by_kind["authorization_counterexample"].status == OPEN
    assert by_kind["latent_operation_confirmation"].status == OPEN
    assert by_kind["capability_confinement"].status == OPEN
    assert by_kind["capability_confinement"].prerequisite_ids == (
        by_kind["latent_operation_confirmation"].obligation_id,
    )
    assert by_kind["ownership_boundary"].prerequisite_ids == (
        by_kind["owned_control"].obligation_id,
    )


def test_graph_is_deterministic_and_strictly_redacted():
    first = _graph()
    second = _graph()

    assert first.to_dict() == second.to_dict()
    serialized = json.dumps(first.to_dict(), sort_keys=True)
    for raw_value in (
        ORIGIN,
        NOTE_ID,
        JOB_ID,
        ALICE_DOCUMENT_ID,
        BOB_DOCUMENT_ID,
        "alice",
        "bob",
        "app.js",
    ):
        assert raw_value not in serialized


def test_empty_evidence_builds_empty_graph_without_claiming_coverage():
    graph = SecurityObligationGraphBuilder().build(target_origin=ORIGIN)

    assert graph.status == "empty"
    assert graph.obligations == ()
    assert all(value == 0 for value in graph.diagnostics.to_dict().values())


def test_hard_bound_drops_questions_instead_of_emitting_partial_dependencies():
    graph = _graph(limits=SecurityObligationLimits(max_obligations=1))

    assert len(graph.obligations) == 1
    assert graph.obligations[0].kind == "owned_control"
    assert graph.obligations[0].prerequisite_ids == ()
    assert graph.diagnostics.dropped_obligations == 3
    assert graph.diagnostics.dropped_dependencies == 0


def test_affordance_target_mismatch_is_rejected():
    try:
        SecurityObligationGraphBuilder().build(
            target_origin="https://different.example.test",
            affordances=_affordances(),
        )
    except ValueError as exc:
        assert str(exc) == "affordance target does not match obligation target"
    else:
        raise AssertionError("expected mismatched target to be rejected")


def test_obligation_module_has_no_transport_or_async_execution_surface():
    tree = ast.parse(Path(obligation_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert not hasattr(behavior_package, "SecurityObligationGraphBuilder")
