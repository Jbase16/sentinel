"""Controlled runtime substitution tests using only in-memory transports."""

from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest

from core.behavior.compiler import (
    BackwardExploitCompiler,
    BackwardGoal,
    OperationSafety,
    operation_contracts_from_records,
)
from core.behavior.lineage import PlanRehydrator, ValueLineageLedger
from core.behavior.runtime import (
    CONTROLLED_SEQUENCE_WORKFLOW,
    ControlledRuntimeSequenceExecutor,
    ControlledSequenceDenied,
    RuntimeStepIntent,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.action_classifier import (
    OWNED_CREATE,
    OWNED_UPDATE_LOW_RISK,
    SAFE_READ,
)
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://api.example.test"
CAPTURED_ID = "note_7fa9f13a2b4c5d6e"
FRESH_ID = "note_91c8a20b3d4e5f6a"


def _records(*, create_body=None):
    return (
        {
            "id": "create-note",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/notes",
            "request_body": create_body or '{"title":"controlled test note"}',
            "response_status": 201,
            "response_body": json.dumps({"noteId": CAPTURED_ID}),
        },
        {
            "id": "read-note",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/notes/{CAPTURED_ID}",
            "response_status": 200,
            "response_body": json.dumps({"title": "controlled"}),
        },
        {
            "id": "cleanup-note",
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/notes/{CAPTURED_ID}",
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": json.dumps({"archived": True}),
        },
    )


def _authorization():
    now = time.time()
    envelope = AuthorizationEnvelope(
        envelope_id="runtime-test-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="Authorized local controlled-sequence test",
        disclosure_attestation=True,
        allowed_workflows=[CONTROLLED_SEQUENCE_WORKFLOW],
        created_at=now,
        expires_at=now + 3_600,
    )
    envelope.sign()
    return envelope


def _enriched_ledger(
    records=None,
    *,
    cleanup_safety=OperationSafety.OWNED_REVERSIBLE_WRITE,
):
    records = records or _records()
    observed = operation_contracts_from_records(records)
    by_label = {item.label: item for item in observed}
    create = by_label["POST /api/notes"]
    read = by_label["GET /api/notes/{id}"]
    cleanup = by_label["PATCH /api/notes/{id}"]
    enriched = (
        replace(
            create,
            safety=OperationSafety.OWNED_REVERSIBLE_WRITE,
            cleanup_operation_id=cleanup.operation_id,
        ),
        replace(read, requires_owned_state=True),
        replace(
            cleanup,
            safety=cleanup_safety,
            requires_owned_state=True,
        ),
    )
    ledger = ValueLineageLedger(records, operation_contracts=enriched)
    operations = {item.label: item for item in ledger.operations}
    plan = BackwardExploitCompiler(ledger.operations).compile(
        BackwardGoal("read_fresh_owned_note", operations["GET /api/notes/{id}"].operation_id)
    )
    recipe = PlanRehydrator(ledger).build_recipe(plan, world_id="alice")
    intents = {
        operations["POST /api/notes"].operation_id: RuntimeStepIntent(
            operations["POST /api/notes"].operation_id,
            OWNED_CREATE,
            "create_owned_test_object",
        ),
        operations["GET /api/notes/{id}"].operation_id: RuntimeStepIntent(
            operations["GET /api/notes/{id}"].operation_id,
            SAFE_READ,
            "none",
        ),
        operations["PATCH /api/notes/{id}"].operation_id: RuntimeStepIntent(
            operations["PATCH /api/notes/{id}"].operation_id,
            OWNED_UPDATE_LOW_RISK,
            "cleanup_owned_test_object",
        ),
    }
    return ledger, recipe, intents


def _runtime(
    raw_send,
    *,
    budget=None,
    records=None,
    cleanup_safety=OperationSafety.OWNED_REVERSIBLE_WRITE,
    authorization=None,
):
    ledger, recipe, intents = _enriched_ledger(
        records,
        cleanup_safety=cleanup_safety,
    )
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=budget
        or ProofBudget(
            max_total_requests=3,
            max_requests_per_endpoint=3,
            max_creates=1,
            allow_real_user_data_access=False,
        ),
        ownership_registry=OwnershipRegistry(),
    )
    sink = ProvenanceSink()
    sink.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    executor = PolicyExecutor(raw_send, policy, provenance=sink)
    runtime = ControlledRuntimeSequenceExecutor(
        target_origin=ORIGIN,
        authorization=authorization or _authorization(),
        actor_persona_id="alice",
        executor=executor,
        ledger=ledger,
        recipe=recipe,
        intents=intents,
    )
    return runtime, executor


@pytest.mark.asyncio
async def test_runtime_substitutes_fresh_id_registers_ownership_and_cleans_up():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url, body, kwargs))
        if method == "POST":
            return 201, {"noteId": FRESH_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        return 200, {"noteId": FRESH_ID, "title": "controlled"}

    runtime, executor = _runtime(raw)
    result = await runtime.execute()

    assert result.status == "completed"
    assert result.main_steps_attempted == result.main_steps_completed == 2
    assert result.cleanup_steps_attempted == result.cleanup_steps_completed == 1
    assert result.runtime_values_bound == 2
    assert result.orphaned_owned_state_possible is False
    assert [(method, url) for method, url, _body, _kwargs in calls] == [
        ("POST", f"{ORIGIN}/api/notes"),
        ("GET", f"{ORIGIN}/api/notes/{FRESH_ID}"),
        ("PATCH", f"{ORIGIN}/api/notes/{FRESH_ID}"),
    ]
    assert calls[-1][2] == '{"archived":true}'
    assert executor.policy.ownership_registry is not None
    assert executor.policy.ownership_registry.is_owned(
        f"{ORIGIN}/api/notes/{FRESH_ID}"
    )
    assert result.budget_snapshot["total_requests"] == 3
    assert result.budget_snapshot["creates"] == 1
    assert result.provenance_root
    serialized = json.dumps(result.to_dict(), sort_keys=True)
    assert FRESH_ID not in serialized
    assert CAPTURED_ID not in serialized


def test_preflight_is_complete_but_sends_no_traffic_or_reserves_budget():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, executor = _runtime(raw)
    sequence_id = runtime.validate_preflight()

    assert sequence_id.startswith("controlled_runtime_sequence:")
    assert calls == []
    assert executor.policy.budget.snapshot()["total_requests"] == 0


@pytest.mark.asyncio
async def test_whole_sequence_budget_failure_occurs_before_first_request():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, _executor = _runtime(
        raw,
        budget=ProofBudget(
            max_total_requests=2,
            max_requests_per_endpoint=3,
            max_creates=1,
            allow_real_user_data_access=False,
        ),
    )

    with pytest.raises(ControlledSequenceDenied, match="budget_reservation_denied"):
        await runtime.execute()
    assert calls == []


@pytest.mark.asyncio
async def test_missing_fresh_create_identifier_aborts_and_flags_possible_orphan():
    calls = []

    async def corrected_raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return 201, {}
        return 200, {}

    runtime, _executor = _runtime(corrected_raw)
    result = await runtime.execute()

    assert result.status == "aborted"
    assert result.main_steps_attempted == 1
    assert result.main_steps_completed == 0
    assert result.cleanup_steps_attempted == 0
    assert result.orphaned_owned_state_possible is True
    assert calls == [("POST", f"{ORIGIN}/api/notes")]
    assert result.error_code == "runtime_response_locator_missing"
    assert _executor.policy.budget._reservations == {}


def test_unsigned_authorization_is_rejected_before_traffic():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    authorization = _authorization()
    authorization.attestation_signature = ""
    runtime, _executor = _runtime(raw, authorization=authorization)

    with pytest.raises(ControlledSequenceDenied, match="authorization_envelope_is_unsigned"):
        runtime.validate_preflight()
    assert calls == []


def test_cleanup_requires_explicit_owned_reversible_safety_contract():
    async def raw(method, url, body=None, **kwargs):
        raise AssertionError("preflight must not send")

    runtime, _executor = _runtime(raw, cleanup_safety=OperationSafety.UNKNOWN)

    with pytest.raises(
        ControlledSequenceDenied,
        match="runtime_cleanup_safety_contract_mismatch",
    ):
        runtime.validate_preflight()


@pytest.mark.asyncio
async def test_cleanup_failure_is_reported_and_never_hidden_as_success():
    async def raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"noteId": FRESH_ID}
        if method == "PATCH":
            return 500, {"error": "cleanup failed"}
        return 200, {"noteId": FRESH_ID}

    runtime, _executor = _runtime(raw)
    result = await runtime.execute()

    assert result.status == "cleanup_failed"
    assert result.main_steps_completed == 2
    assert result.cleanup_steps_attempted == 1
    assert result.cleanup_steps_completed == 0
    assert result.orphaned_owned_state_possible is True
    assert result.error_code == "runtime_cleanup_failed"


def test_external_side_effect_hidden_in_json_is_rejected_during_preflight():
    records = _records(
        create_body='{"title":"test","destination":"https://outside.example/hook"}'
    )

    async def raw(method, url, body=None, **kwargs):
        raise AssertionError("preflight must not send")

    runtime, _executor = _runtime(raw, records=records)

    with pytest.raises(
        ControlledSequenceDenied,
        match="structural_classification_overruled_intent:EXTERNAL_SIDE_EFFECT",
    ):
        runtime.validate_preflight()


@pytest.mark.asyncio
async def test_runtime_executor_is_single_use_even_after_success():
    async def raw(method, url, body=None, **kwargs):
        if method == "POST":
            return 201, {"noteId": FRESH_ID}
        return 200, {}

    runtime, _executor = _runtime(raw)
    await runtime.execute()

    with pytest.raises(ControlledSequenceDenied, match="already_consumed"):
        await runtime.execute()


def test_enrichment_cannot_rewrite_semantic_capability_edges():
    records = _records()
    observed = operation_contracts_from_records(records)
    create = next(item for item in observed if item.label == "POST /api/notes")
    forged = replace(create, produces=())

    with pytest.raises(ValueError, match="may enrich only"):
        ValueLineageLedger(
            records,
            operation_contracts=(forged, *[item for item in observed if item != create]),
        )
