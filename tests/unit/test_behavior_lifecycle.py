"""Evidence-backed owned lifecycle mining tests; no target network is used."""

from __future__ import annotations

import json

import core.behavior as behavior_package

from core.behavior.admission import ControlledAdmissionConfig
from core.behavior.compiler import (
    BackwardExploitCompiler,
    BackwardGoal,
    OperationSafety,
    operation_contracts_from_records,
)
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.lineage import PlanRehydrator
from core.behavior.manifest import ExecutionManifestCompiler
from core.behavior.safety_contracts import (
    is_proven_safe_cleanup_body,
    is_proven_safe_owned_create_body,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://api.example.test"
CAPTURED_ID = "note_7fa9f13a2b4c5d6e"


def _records(
    *,
    create_url=f"{ORIGIN}/api/notes",
    read_url=f"{ORIGIN}/api/notes/{CAPTURED_ID}",
    cleanup_body='{"archived":true}',
    create_persona="alice",
    read_persona="alice",
    cleanup_persona="alice",
):
    return (
        {
            "id": "create-note",
            "persona_id": create_persona,
            "method": "POST",
            "url": create_url,
            "request_body": '{"title":"controlled lifecycle marker"}',
            "response_status": 201,
            "response_body": json.dumps({"noteId": CAPTURED_ID}),
        },
        {
            "id": "read-note",
            "persona_id": read_persona,
            "method": "GET",
            "url": read_url,
            "response_status": 200,
            "response_body": json.dumps({"title": "controlled lifecycle marker"}),
        },
        {
            "id": "cleanup-note",
            "persona_id": cleanup_persona,
            "method": "PATCH",
            "url": f"{ORIGIN}/api/notes/{CAPTURED_ID}",
            "request_body": cleanup_body,
            "response_status": 200,
            "response_body": json.dumps({"archived": True}),
        },
    )


def _authorization():
    envelope = AuthorizationEnvelope(
        envelope_id="lifecycle-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="Authorized lifecycle test",
        disclosure_attestation=True,
        allowed_workflows=["behavioral_compiled_owned_sequence"],
        created_at=1_800_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def _executor(raw_send):
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
    return PolicyExecutor(raw_send, policy, provenance=provenance)


def test_miner_derives_owned_lifecycle_and_enriches_only_proven_operations():
    records = _records()
    observed = {item.label: item for item in operation_contracts_from_records(records)}
    assert observed["POST /api/notes"].safety == OperationSafety.UNKNOWN
    assert observed["PATCH /api/notes/{id}"].safety == OperationSafety.UNKNOWN

    result = LifecycleContractMiner().mine(records)

    assert result.status == "ready"
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    operations = {item.label: item for item in result.ledger.operations}
    create = operations["POST /api/notes"]
    read = operations["GET /api/notes/{id}"]
    cleanup = operations["PATCH /api/notes/{id}"]
    assert candidate.create_operation_id == create.operation_id
    assert candidate.read_operation_ids == (read.operation_id,)
    assert candidate.cleanup_operation_id == cleanup.operation_id
    assert create.safety == OperationSafety.OWNED_REVERSIBLE_WRITE
    assert create.cleanup_operation_id == cleanup.operation_id
    assert create.requires_owned_state is False
    assert read.safety == OperationSafety.READ_ONLY
    assert read.requires_owned_state is True
    assert cleanup.safety == OperationSafety.OWNED_REVERSIBLE_WRITE
    assert cleanup.requires_owned_state is True
    serialized = json.dumps(result.to_dict(), sort_keys=True)
    for raw_value in (
        ORIGIN,
        CAPTURED_ID,
        "controlled lifecycle marker",
        "alice",
    ):
        assert raw_value not in serialized


def test_lifecycle_mining_is_deterministic():
    first = LifecycleContractMiner().mine(_records())
    second = LifecycleContractMiner().mine(_records())

    assert first.to_dict() == second.to_dict()
    assert [item.to_dict() for item in first.ledger.operations] == [
        item.to_dict() for item in second.ledger.operations
    ]


def test_cross_world_values_never_become_owned_lifecycle_evidence():
    result = LifecycleContractMiner().mine(
        _records(read_persona="bob", cleanup_persona="bob")
    )

    assert result.status == "no_proven_lifecycle"
    assert result.candidates == ()
    assert result.ledger.bindings == ()


def test_unsafe_cleanup_body_leaves_write_safety_unknown():
    result = LifecycleContractMiner().mine(
        _records(cleanup_body='{"title":"not cleanup"}')
    )
    operations = {item.label: item for item in result.ledger.operations}

    assert result.status == "no_proven_lifecycle"
    assert result.diagnostics.incomplete_groups == 1
    assert operations["POST /api/notes"].safety == OperationSafety.UNKNOWN
    assert operations["PATCH /api/notes/{id}"].safety == OperationSafety.UNKNOWN


def test_query_only_identifier_flow_is_not_treated_as_owned_path_lineage():
    result = LifecycleContractMiner().mine(
        _records(read_url=f"{ORIGIN}/api/notes?noteId={CAPTURED_ID}")
    )

    assert result.status == "no_proven_lifecycle"
    assert result.candidates == ()


def test_two_safe_cleanup_operations_are_ambiguous_and_neither_is_enriched():
    records = (
        *_records(),
        {
            "id": "cleanup-note-again",
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/notes/{CAPTURED_ID}/deactivate",
            "request_body": '{"active":false}',
            "response_status": 200,
            "response_body": json.dumps({"active": False}),
        },
    )

    result = LifecycleContractMiner().mine(records)

    assert result.status == "no_proven_lifecycle"
    assert result.diagnostics.ambiguous_cleanup_groups == 1
    assert all(
        item.safety != OperationSafety.OWNED_REVERSIBLE_WRITE
        for item in result.ledger.operations
    )


def test_dangerous_create_path_cannot_be_promoted_by_lifecycle_shape():
    result = LifecycleContractMiner().mine(
        _records(create_url=f"{ORIGIN}/api/payments")
    )

    assert result.status == "no_proven_lifecycle"
    assert result.candidates == ()


def test_consequential_create_body_cannot_be_promoted_by_owned_create_hint():
    records = list(_records())
    records[0] = {
        **records[0],
        "request_body": '{"name":"test","role":"admin"}',
    }

    result = LifecycleContractMiner().mine(tuple(records))

    assert result.status == "no_proven_lifecycle"
    assert result.candidates == ()


def test_shared_cleanup_predicate_accepts_only_archival_or_deactivation_state():
    assert is_proven_safe_cleanup_body('{"archived":true}') is True
    assert is_proven_safe_cleanup_body({"active": False}) is True
    assert is_proven_safe_cleanup_body({"status": "inactive"}) is True
    assert is_proven_safe_cleanup_body({"active": True}) is False
    assert is_proven_safe_cleanup_body({"archived": {}}) is False
    assert is_proven_safe_cleanup_body({"title": "changed"}) is False
    assert is_proven_safe_cleanup_body({"status": "paid"}) is False


def test_shared_create_predicate_rejects_privilege_and_nested_external_effects():
    assert is_proven_safe_owned_create_body({"title": "controlled"}) is True
    assert is_proven_safe_owned_create_body(None) is True
    assert is_proven_safe_owned_create_body("unstructured form data") is False
    assert is_proven_safe_owned_create_body({"role": "admin"}) is False
    assert (
        is_proven_safe_owned_create_body(
            {"settings": {"destination": "https://outside.example/hook"}}
        )
        is False
    )


def test_mined_ledger_compiles_through_plan_recipe_and_manifest_without_traffic():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    mined = LifecycleContractMiner().mine(_records())
    candidate = mined.candidates[0]
    terminal_id = candidate.read_operation_ids[0]
    plan = BackwardExploitCompiler(mined.ledger.operations).compile(
        BackwardGoal("mine_owned_note_lifecycle", terminal_id)
    )
    recipe = PlanRehydrator(mined.ledger).build_recipe(plan, world_id="alice")
    executor = _executor(raw)

    bundle = ExecutionManifestCompiler().compile(
        target_origin=ORIGIN,
        authorization=_authorization(),
        actor_persona_id="alice",
        executor=executor,
        ledger=mined.ledger,
        plan=plan,
        recipe=recipe,
        admission_config=ControlledAdmissionConfig(enabled=False),
    )

    assert calls == []
    assert executor.policy.budget.snapshot()["total_requests"] == 0
    assert [item.role for item in bundle.manifest.steps] == [
        "owned_create",
        "owned_read",
        "owned_cleanup",
    ]


def test_lifecycle_miner_is_not_exported_from_passive_behavior_package():
    assert not hasattr(behavior_package, "LifecycleContractMiner")
