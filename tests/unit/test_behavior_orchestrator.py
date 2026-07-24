"""Closed-loop behavioral shadow orchestration tests; target I/O is forbidden."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import core.behavior as behavior_package
import core.behavior.orchestrator as orchestrator_module

from core.behavior.active import CONTROLLED_WORKFLOW
from core.behavior.affordances import ClientArtifact
from core.behavior.closure import BLOCKED, CONDITIONALLY_CLOSED, ObligationDisposition
from core.behavior.obligations import OPEN, UPHELD
from core.behavior.orchestrator import (
    BehavioralShadowOrchestrator,
    OwnedExperimentShadowContext,
    ShadowOrchestratorConfig,
)
from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
from core.behavior.normalize import stable_hash
from core.behavior.state_machine import (
    StateMachineLegalityLimits,
    StateMachineLegalityMiner,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://api.example.test"
NOTE_ID = "note_7fa9f13a2b4c5d6e"
SOURCE_DOCUMENT_ID = "doc_source_7fa9f13a2b4c"
PEER_DOCUMENT_ID = "doc_peer_4a5b6c7d8e9f0"
JOB_ID = "job_4a5b6c7d8e9f0123"


def _source_records():
    return (
        {
            "id": "create-note",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/notes",
            "request_body": '{"title":"controlled marker"}',
            "response_status": 201,
            "response_body": json.dumps({"noteId": NOTE_ID}),
        },
        {
            "id": "read-note",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
            "response_status": 200,
            "response_body": '{"title":"controlled marker"}',
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
        {
            "id": "source-document",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{SOURCE_DOCUMENT_ID}",
            "response_status": 200,
            "response_body": '{"owner":"alice-private"}',
        },
        {
            "id": "start-export",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/documents/{SOURCE_DOCUMENT_ID}/export",
            "request_body": "{}",
            "response_status": 202,
            "response_body": json.dumps({"jobId": JOB_ID}),
        },
    )


def _peer_records():
    return (
        {
            "id": "peer-document",
            "persona_id": "bob",
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{PEER_DOCUMENT_ID}",
            "response_status": 200,
            "response_body": '{"owner":"bob-private"}',
        },
    )


def _artifacts():
    return (
        ClientArtifact(
            f"{ORIGIN}/assets/app.js",
            "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);",
        ),
    )


def _authorization(*, compiled: bool = True):
    workflows = [CONTROLLED_WORKFLOW]
    if compiled:
        workflows.append(CONTROLLED_SEQUENCE_WORKFLOW)
    envelope = AuthorizationEnvelope(
        envelope_id="shadow-orchestrator-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized shadow orchestration test",
        disclosure_attestation=True,
        allowed_workflows=workflows,
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def _context(*, compiled: bool = True):
    calls = []

    async def forbidden_transport(method, url, body=None, **kwargs):
        calls.append((method, url, body, kwargs))
        raise AssertionError("shadow orchestrator must never invoke transport")

    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=3,
            max_requests_per_endpoint=3,
            max_creates=1,
            allow_real_user_data_access=False,
        ),
        ownership_registry=OwnershipRegistry(),
    )
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    executor = PolicyExecutor(forbidden_transport, policy, provenance=provenance)
    return (
        OwnedExperimentShadowContext(
            authorization=_authorization(compiled=compiled),
            actor_persona_id="alice",
            executor=executor,
        ),
        calls,
        executor,
    )


def _run(*, context=True):
    experiment_context = None
    calls = []
    executor = None
    if context:
        experiment_context, calls, executor = _context()
    result = BehavioralShadowOrchestrator().run(
        _source_records(),
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=_peer_records(),
        peer_world_id="bob",
        artifacts=_artifacts(),
        experiment_context=experiment_context,
    )
    return result, calls, executor


def test_orchestrator_builds_and_ranks_one_unified_frontier_without_traffic():
    result, calls, executor = _run()

    assert result.status == OPEN
    assert result.lifecycle.status == "ready"
    assert result.proposals is not None and len(result.proposals.proposals) == 2
    assert result.affordances.status == "ready"
    assert result.experiment_stage.status == "ready"
    assert len(result.experiment_stage.inventory.experiments) == 1
    assert result.closure.open_count == 5
    assert len(result.ranked_frontier) == 5
    assert result.selected is not None
    assert result.selected.kind == "ownership_boundary"
    assert result.selected.resolution_kind == "owned_experiment"
    assert [item.actionable for item in result.ranked_frontier] == [
        True,
        True,
        False,
        False,
        False,
    ]
    assert calls == []
    assert executor.policy.budget.snapshot()["total_requests"] == 0


def test_state_machine_legality_enters_frontier_without_resolution_authority():
    workflow_id = "workflow_7fa9f13a2b4c5d6e"
    export_token = "token_4a5b6c7d8e9f0123"
    records = (
        {
            "id": "create-workflow",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows",
            "response_status": 201,
            "response_body": json.dumps({"workflowId": workflow_id}),
        },
        {
            "id": "approve-workflow",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows/{workflow_id}/approve",
            "response_status": 200,
            "response_body": json.dumps({"exportToken": export_token}),
        },
        {
            "id": "export-workflow",
            "persona_id": "alice",
            "method": "GET",
            "url": (
                f"{ORIGIN}/api/workflows/{workflow_id}/export"
                f"?exportToken={export_token}"
            ),
            "response_status": 200,
            "response_body": "{}",
        },
    )

    result = BehavioralShadowOrchestrator().run(
        records,
        target_origin=ORIGIN,
        world_id="alice",
    )

    assert result.state_machine.status == "ready"
    assert len(result.state_machine.candidates) == 1
    assert result.graph.diagnostics.state_machine_controls == 1
    assert result.graph.diagnostics.state_machine_legalities == 1
    control = next(
        item
        for item in result.graph.obligations
        if item.kind == "state_machine_control"
    )
    legality = next(
        item
        for item in result.graph.obligations
        if item.kind == "state_machine_legality"
    )
    ranked = next(
        item
        for item in result.ranked_frontier
        if item.kind == "state_machine_legality"
    )
    assert control.status == UPHELD
    assert legality.status == OPEN
    assert legality.prerequisite_ids == (control.obligation_id,)
    assert ranked.actionable is False
    assert ranked.resolution_kind == "unavailable"
    assert result.selected is None


def test_state_machine_analysis_truncation_blocks_frontier_closure():
    result = BehavioralShadowOrchestrator(
        state_machine_miner=StateMachineLegalityMiner(
            StateMachineLegalityLimits(max_records=2)
        )
    ).run(
        _source_records(),
        target_origin=ORIGIN,
        world_id="alice",
    )

    assert result.state_machine.status == "blocked"
    assert result.state_machine.blocker == "record_limit_exceeded"
    assert result.graph.diagnostics.incomplete_relations == 1
    assert result.closure.status == BLOCKED
    assert "relation_analysis_incomplete" in result.closure.blockers


def test_orchestrator_is_deterministic_and_strictly_redacted():
    first, _, _ = _run()
    second, _, _ = _run()

    assert first.to_dict() == second.to_dict()
    serialized = json.dumps(first.to_dict(), sort_keys=True)
    for raw in (
        ORIGIN,
        NOTE_ID,
        SOURCE_DOCUMENT_ID,
        PEER_DOCUMENT_ID,
        JOB_ID,
        "alice",
        "bob",
        "controlled marker",
        "app.js",
    ):
        assert raw not in serialized


def test_missing_compiled_authority_blocks_owned_experiment_but_not_frontier():
    context, calls, executor = _context(compiled=False)
    result = BehavioralShadowOrchestrator().run(
        _source_records(),
        target_origin=ORIGIN,
        world_id="alice",
        experiment_context=context,
    )

    boundary = next(
        item for item in result.ranked_frontier if item.kind == "ownership_boundary"
    )
    assert result.status == OPEN
    assert result.experiment_stage.status == "blocked"
    assert result.experiment_stage.blocker == "factory_global_runtime_preflight_denied"
    assert boundary.actionable is False
    assert boundary.resolution_kind == "unavailable"
    assert calls == []
    assert executor.policy.budget.snapshot()["total_requests"] == 0


def test_state_mutation_proposal_stays_visible_without_a_safe_resolution_path():
    source = ({
        "id": "source-document-update",
        "persona_id": "alice",
        "method": "PATCH",
        "url": f"{ORIGIN}/api/documents/{SOURCE_DOCUMENT_ID}",
        "request_body": json.dumps({"documentId": SOURCE_DOCUMENT_ID, "title": "source"}),
        "response_status": 200,
        "response_body": "{}",
    },)
    peer = ({
        "id": "peer-document-update",
        "persona_id": "bob",
        "method": "PATCH",
        "url": f"{ORIGIN}/api/documents/{PEER_DOCUMENT_ID}",
        "request_body": json.dumps({"documentId": PEER_DOCUMENT_ID, "title": "peer"}),
        "response_status": 200,
        "response_body": "{}",
    },)

    result = BehavioralShadowOrchestrator().run(
        source,
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=peer,
        peer_world_id="bob",
    )

    candidate = next(
        item
        for item in result.ranked_frontier
        if item.kind == "authorization_counterexample"
    )
    assert candidate.risk_class == "state_mutation"
    assert candidate.actionable is False
    assert candidate.resolution_kind == "unavailable"


def test_unproven_graphql_read_stays_visible_without_a_safe_resolution_path():
    def record(persona, document_id):
        return {
            "id": f"{persona}-persisted-read",
            "persona_id": persona,
            "method": "POST",
            "url": f"{ORIGIN}/graphql",
            "request_body": json.dumps({
                "operationName": "GetDocument",
                "variables": {"documentId": document_id},
            }),
            "response_status": 200,
            "response_body": "{}",
        }

    result = BehavioralShadowOrchestrator().run(
        (record("alice", SOURCE_DOCUMENT_ID),),
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=(record("bob", PEER_DOCUMENT_ID),),
        peer_world_id="bob",
    )

    candidate = next(
        item
        for item in result.ranked_frontier
        if item.kind == "authorization_counterexample"
    )
    assert candidate.risk_class == "read"
    assert candidate.actionable is False
    assert candidate.resolution_kind == "unavailable"


def test_second_identical_resolved_frontier_is_conditionally_closed():
    first, _, _ = _run(context=False)
    dispositions = tuple(
        ObligationDisposition.create(
            obligation_id=item.obligation_id,
            status=UPHELD,
            evidence_refs=(stable_hash("orchestrator_test_proof", item.obligation_id),),
            reason_code="test_upheld",
        )
        for item in first.graph.obligations
        if item.status == OPEN
    )

    second = BehavioralShadowOrchestrator().run(
        _source_records(),
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=_peer_records(),
        peer_world_id="bob",
        artifacts=_artifacts(),
        dispositions=reversed(dispositions),
        previous_graph=first.graph,
        derivation_round=2,
    )

    assert second.status == CONDITIONALLY_CLOSED
    assert second.closure.fixed_point is True
    assert second.closure.open_count == 0
    assert second.ranked_frontier == ()
    assert second.selected is None


def test_rank_bound_reports_every_unlisted_open_obligation():
    result = BehavioralShadowOrchestrator(
        config=ShadowOrchestratorConfig(max_ranked_obligations=1)
    ).run(
        _source_records(),
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=_peer_records(),
        peer_world_id="bob",
        artifacts=_artifacts(),
    )

    assert result.closure.open_count == 5
    assert len(result.ranked_frontier) == 1
    assert result.ranked_dropped == 4
    assert result.to_dict()["ranked_dropped"] == 4


def test_orchestrator_module_has_no_transport_or_async_execution_surface():
    tree = ast.parse(Path(orchestrator_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert not hasattr(behavior_package, "BehavioralShadowOrchestrator")
