"""Controlled runtime substitution tests using only in-memory transports."""

from __future__ import annotations

import asyncio
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
from core.behavior.admission import (
    COMPILED_ADMISSION_ENV,
    ControlledAdmissionConfig,
    ControlledAdmissionDenied,
    ControlledSequenceAdmission,
)
import core.behavior as behavior_package
from core.behavior.lineage import PlanRehydrator, ValueLineageLedger
from core.behavior.manifest import (
    ExecutionManifestCompiler,
    ExecutionManifestDenied,
)
from core.behavior.receipts import BehavioralReceiptStore
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


def _plan_for_ledger(ledger):
    operations = {item.label: item for item in ledger.operations}
    return BackwardExploitCompiler(ledger.operations).compile(
        BackwardGoal(
            "read_fresh_owned_note",
            operations["GET /api/notes/{id}"].operation_id,
        )
    )


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
    plan = _plan_for_ledger(ledger)
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
async def test_runtime_sequence_seal_rejects_authorization_change_before_traffic():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    authorization = _authorization()
    runtime, _executor = _runtime(raw, authorization=authorization)
    expected_sequence_id = runtime.validate_preflight()
    authorization.authorization_basis = "Different authorized research basis"
    authorization.sign()

    with pytest.raises(ControlledSequenceDenied, match="sequence_identity_changed"):
        await runtime.execute(expected_sequence_id=expected_sequence_id)
    assert calls == []


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


@pytest.mark.asyncio
async def test_compiled_admission_defaults_off_before_receipt_or_traffic(tmp_path):
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, _executor = _runtime(raw)
    admission = ControlledSequenceAdmission(
        runtime,
        config=ControlledAdmissionConfig(enabled=False),
        receipt_store=BehavioralReceiptStore(tmp_path),
    )

    with pytest.raises(ControlledAdmissionDenied, match="admission_is_disabled"):
        await admission.execute()
    assert calls == []
    assert list(tmp_path.iterdir()) == []


def test_compiled_admission_environment_gate_is_exact_and_not_package_exported(
    monkeypatch,
):
    monkeypatch.delenv(COMPILED_ADMISSION_ENV, raising=False)
    assert ControlledAdmissionConfig.from_environment().enabled is False
    monkeypatch.setenv(COMPILED_ADMISSION_ENV, "true")
    assert ControlledAdmissionConfig.from_environment().enabled is True
    monkeypatch.setenv(COMPILED_ADMISSION_ENV, "truthy")
    assert ControlledAdmissionConfig.from_environment().enabled is False
    assert not hasattr(behavior_package, "ControlledSequenceAdmission")


@pytest.mark.asyncio
async def test_admission_revalidates_authorization_before_receipt_or_traffic(tmp_path):
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    authorization = _authorization()
    authorization.attestation_signature = ""
    runtime, _executor = _runtime(raw, authorization=authorization)
    admission = ControlledSequenceAdmission(
        runtime,
        config=ControlledAdmissionConfig(enabled=True),
        receipt_store=BehavioralReceiptStore(tmp_path),
    )

    with pytest.raises(ControlledSequenceDenied, match="authorization_envelope_is_unsigned"):
        await admission.execute()
    assert calls == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_compiled_admission_executes_once_and_reuses_redacted_receipt(tmp_path):
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return 201, {"noteId": FRESH_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        return 200, {"title": "controlled"}

    store = BehavioralReceiptStore(tmp_path)
    authorization = _authorization()
    runtime, _executor = _runtime(raw, authorization=authorization)
    admission = ControlledSequenceAdmission(
        runtime,
        config=ControlledAdmissionConfig(enabled=True),
        receipt_store=store,
    )
    fingerprint = admission.validate_preflight()
    first = await admission.execute()

    duplicate_runtime, _duplicate_executor = _runtime(
        raw,
        authorization=authorization,
    )
    duplicate = await ControlledSequenceAdmission(
        duplicate_runtime,
        config=ControlledAdmissionConfig(enabled=True),
        receipt_store=BehavioralReceiptStore(tmp_path),
    ).execute()

    assert first.status == "completed"
    assert first.reused is False
    assert duplicate.status == "already_executed"
    assert duplicate.reused is True
    assert len(calls) == 3
    assert duplicate.execution == first.execution
    encoded = (tmp_path / f"behavioral-{fingerprint}.json").read_text()
    assert FRESH_ID not in encoded
    assert CAPTURED_ID not in encoded
    assert ORIGIN not in encoded


@pytest.mark.asyncio
async def test_concurrent_compiled_admission_has_one_traffic_owner(tmp_path):
    calls = []
    entered = asyncio.Event()
    release = asyncio.Event()

    async def first_raw(method, url, body=None, **kwargs):
        calls.append(("first", method, url))
        if method == "POST":
            entered.set()
            await release.wait()
            return 201, {"noteId": FRESH_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        return 200, {"title": "controlled"}

    async def second_raw(method, url, body=None, **kwargs):
        calls.append(("second", method, url))
        raise AssertionError("duplicate admission must not send traffic")

    store = BehavioralReceiptStore(tmp_path)
    authorization = _authorization()
    first_runtime, _first_executor = _runtime(
        first_raw,
        authorization=authorization,
    )
    second_runtime, _second_executor = _runtime(
        second_raw,
        authorization=authorization,
    )
    config = ControlledAdmissionConfig(enabled=True)
    first_admission = ControlledSequenceAdmission(
        first_runtime,
        config=config,
        receipt_store=store,
    )
    second_admission = ControlledSequenceAdmission(
        second_runtime,
        config=config,
        receipt_store=BehavioralReceiptStore(tmp_path),
    )

    first_task = asyncio.create_task(first_admission.execute())
    await entered.wait()
    with pytest.raises(ControlledAdmissionDenied, match="already_reserved_or_terminal"):
        await second_admission.execute()
    release.set()
    result = await first_task

    assert result.status == "completed"
    assert [owner for owner, _method, _url in calls] == ["first", "first", "first"]


@pytest.mark.asyncio
async def test_failed_admission_is_terminal_and_cannot_renew_budget(tmp_path):
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    budget = ProofBudget(
        max_total_requests=2,
        max_requests_per_endpoint=3,
        max_creates=1,
        allow_real_user_data_access=False,
    )
    store = BehavioralReceiptStore(tmp_path)
    authorization = _authorization()
    runtime, _executor = _runtime(
        raw,
        budget=budget,
        authorization=authorization,
    )
    admission = ControlledSequenceAdmission(
        runtime,
        config=ControlledAdmissionConfig(enabled=True),
        receipt_store=store,
    )

    with pytest.raises(ControlledSequenceDenied, match="budget_reservation_denied"):
        await admission.execute()
    retry_runtime, _retry_executor = _runtime(
        raw,
        budget=budget,
        authorization=authorization,
    )
    retry = ControlledSequenceAdmission(
        retry_runtime,
        config=ControlledAdmissionConfig(enabled=True),
        receipt_store=BehavioralReceiptStore(tmp_path),
    )
    with pytest.raises(ControlledAdmissionDenied, match="already_reserved_or_terminal"):
        await retry.execute()
    assert calls == []


def _compile_manifest_from_runtime(
    runtime,
    *,
    admission_config=None,
    receipt_store=None,
    plan=None,
    recipe=None,
):
    return ExecutionManifestCompiler().compile(
        target_origin=runtime.target_origin,
        authorization=runtime.authorization,
        actor_persona_id=runtime.actor_persona_id,
        executor=runtime.executor,
        ledger=runtime.ledger,
        plan=plan or _plan_for_ledger(runtime.ledger),
        recipe=recipe or runtime.recipe,
        admission_config=admission_config,
        receipt_store=receipt_store,
    )


def test_manifest_compiler_derives_complete_runtime_without_traffic():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, executor = _runtime(raw)
    bundle = _compile_manifest_from_runtime(runtime)

    assert calls == []
    assert executor.policy.budget.snapshot()["total_requests"] == 0
    assert [item.role for item in bundle.manifest.steps] == [
        "owned_create",
        "owned_read",
        "owned_cleanup",
    ]
    assert bundle.manifest.sequence_id == bundle.runtime.validate_preflight()
    assert bundle.manifest.executable is False
    assert bundle.admission.config.enabled is False
    serialized = json.dumps(bundle.manifest.to_dict(), sort_keys=True)
    for raw_value in (ORIGIN, CAPTURED_ID, FRESH_ID, "alice", "runtime-test-envelope"):
        assert raw_value not in serialized


def test_manifest_compilation_is_deterministic_for_identical_evidence_and_authority():
    async def raw(method, url, body=None, **kwargs):
        return 200, {}

    authorization = _authorization()
    first_runtime, _first_executor = _runtime(raw, authorization=authorization)
    second_runtime, _second_executor = _runtime(raw, authorization=authorization)

    first = _compile_manifest_from_runtime(first_runtime).manifest
    second = _compile_manifest_from_runtime(second_runtime).manifest

    assert first.to_dict() == second.to_dict()


@pytest.mark.asyncio
async def test_manifest_bundle_integrates_with_existing_guarded_admission(tmp_path):
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return 201, {"noteId": FRESH_ID}
        if method == "PATCH":
            return 200, {"archived": True}
        return 200, {"title": "controlled"}

    runtime, _executor = _runtime(raw)
    bundle = _compile_manifest_from_runtime(
        runtime,
        admission_config=ControlledAdmissionConfig(enabled=True),
        receipt_store=BehavioralReceiptStore(tmp_path),
    )
    assert calls == []

    result = await bundle.admission.execute()

    assert result.status == "completed"
    assert [method for method, _url in calls] == ["POST", "GET", "PATCH"]


def test_manifest_rejects_unknown_cleanup_safety_without_traffic():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, _executor = _runtime(raw, cleanup_safety=OperationSafety.UNKNOWN)

    with pytest.raises(ExecutionManifestDenied, match="cleanup_contract_is_unsupported"):
        _compile_manifest_from_runtime(runtime)
    assert calls == []


def test_manifest_rejects_forged_plan_identity_without_traffic():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, _executor = _runtime(raw)
    plan = replace(
        _plan_for_ledger(runtime.ledger),
        plan_id="backward_plan:" + "0" * 64,
    )

    with pytest.raises(ExecutionManifestDenied, match="plan_identity_mismatch"):
        _compile_manifest_from_runtime(runtime, plan=plan)
    assert calls == []


def test_manifest_rejects_removed_analysis_authority_blocker():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, _executor = _runtime(raw)
    original = _plan_for_ledger(runtime.ledger)
    plan = replace(
        original,
        execution_blockers=tuple(
            item
            for item in original.execution_blockers
            if item != "analysis_only_no_execution_authority"
        ),
    )

    with pytest.raises(ExecutionManifestDenied, match="authority_blocker_is_missing"):
        _compile_manifest_from_runtime(runtime, plan=plan)
    assert calls == []


def test_manifest_rejects_stale_capture_recipe_without_traffic():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, _executor = _runtime(raw)
    stale_recipe = replace(
        runtime.recipe,
        capture_digest="lineage_capture:" + "0" * 64,
    )

    with pytest.raises(ExecutionManifestDenied, match="evidence_digest_mismatch"):
        _compile_manifest_from_runtime(runtime, recipe=stale_recipe)
    assert calls == []


def test_manifest_rejects_read_only_plan_without_owned_create():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    runtime, _executor = _runtime(raw)
    operations = {item.label: item for item in runtime.ledger.operations}
    read = operations["GET /api/notes/{id}"]
    plan = BackwardExploitCompiler(runtime.ledger.operations).compile(
        BackwardGoal("read_existing_note", read.operation_id),
        initial_capabilities=read.requires,
    )
    recipe = PlanRehydrator(runtime.ledger).build_recipe(plan, world_id="alice")

    with pytest.raises(
        ExecutionManifestDenied,
        match="requires_one_create_and_owned_read",
    ):
        _compile_manifest_from_runtime(runtime, plan=plan, recipe=recipe)
    assert calls == []


def test_manifest_uses_runtime_preflight_as_final_cleanup_oracle():
    calls = []

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url))
        return 200, {}

    records = list(_records())
    records[2] = {**records[2], "request_body": '{"title":"not cleanup"}'}
    runtime, _executor = _runtime(raw, records=tuple(records))

    with pytest.raises(ExecutionManifestDenied, match="runtime_preflight_denied"):
        _compile_manifest_from_runtime(runtime)
    assert calls == []


def test_manifest_compiler_is_not_exported_from_passive_behavior_package():
    assert not hasattr(behavior_package, "ExecutionManifestCompiler")
