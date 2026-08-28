"""R5D6 real-clock capability-execution receipt boundary tests."""

from __future__ import annotations

import ast
from dataclasses import fields, replace
import inspect
from pathlib import Path
import time

import pytest

import core.behavior.capability_execution_receipt as execution_module
from core.behavior.capability_confinement_freshness import (
    ConfinedPresentationBinding,
    ConfinementPresentation,
    evaluate_confinement,
)
from core.behavior.capability_consumption_ledger import (
    CapabilityConsumptionLedger,
    ConsumptionDecision,
    ConsumptionOutcome,
    evaluate_consumption,
)
from core.behavior.capability_contract import (
    CapabilityDecision,
    CapabilityOutcome,
    CapabilityPresentation,
    CapabilityRevocationState,
    IssuedCapabilityContract,
    classify_presentation,
)
from core.behavior.capability_execution_receipt import (
    CAPABILITY_EXECUTION_RECEIPT_MODE,
    CapabilityExecutionOutcome,
    CapabilityExecutionReceipt,
    RuntimeExecutionDenied,
    evaluate_capability_execution,
)
from core.behavior.capability_runtime_expiry import AdmittedRuntimeContract
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash


ORIGIN = "https://api.example.test"
ADMITTED_AT = 100.0
EXPIRES_AT = 200.0


def _owned_world(suffix: str = "alice") -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", f"r5d6-{suffix}"),
        persona_ref=stable_hash("experiment_persona", f"r5d6-{suffix}"),
        ownership_ref=stable_hash("ownership_proof", f"r5d6-{suffix}"),
    )


def _contract(suffix: str = "alice") -> IssuedCapabilityContract:
    world = _owned_world(suffix)
    assert world.persona_ref is not None
    tenant_ref = stable_hash("owned_tenant", f"r5d6-{suffix}")
    tenant_ownership_ref = stable_hash(
        "ownership_proof",
        f"r5d6-{suffix}-tenant-owned",
    )
    return IssuedCapabilityContract.build(
        world=world,
        world_tenant_ref=tenant_ref,
        world_tenant_ownership_ref=tenant_ownership_ref,
        subject_ref=world.persona_ref,
        resource_ref=stable_hash("capability_resource", f"r5d6-{suffix}"),
        operation_ref=stable_hash("capability_operation", "download"),
        audience_ref=world.persona_ref,
        issuer_ref=stable_hash("capability_issuer", "r5d6-service"),
        tenant_ref=tenant_ref,
        tenant_ownership_ref=tenant_ownership_ref,
        source_evidence_ref=stable_hash("source_evidence", f"r5d6-{suffix}"),
        secret_digest=stable_hash(
            "capability_secret_digest",
            f"r5d6-ephemeral-secret-{suffix}",
        ),
        issued_at_index=10,
        expires_at_index=20,
        max_uses=1,
        revocation_state=CapabilityRevocationState.ACTIVE,
    )


def _capture_records(*, suffix: str):
    object_id = f"r5d6-object-{suffix}"
    token = f"r5d6-token-{suffix}"
    return [
        {
            "method": "POST",
            "url": f"{ORIGIN}/api/exports",
            "request_body": '{"format":"json"}',
            "response_status": 201,
            "response_body": f'{{"id":"{object_id}","token":"{token}"}}',
        },
        {
            "method": "GET",
            "url": f"{ORIGIN}/api/exports/{object_id}",
            "headers": {"authorization": f"Bearer {token}"},
            "response_status": 200,
            "response_body": '{"ready":true}',
        },
    ]


def _presentation(
    contract: IssuedCapabilityContract,
    **overrides,
) -> CapabilityPresentation:
    values = {
        "resource_ref": contract.resource_ref,
        "account_ref": contract.subject_ref,
        "audience_ref": contract.audience_ref,
        "operation_ref": contract.operation_ref,
        "at_index": contract.issued_at_index,
        "use_index": 0,
    }
    values.update(overrides)
    return CapabilityPresentation.build(**values)


def _logical_decision(
    contract: IssuedCapabilityContract,
    outcome: CapabilityOutcome = CapabilityOutcome.VALID,
) -> CapabilityDecision:
    overrides = {}
    if outcome is CapabilityOutcome.WRONG_BINDING:
        overrides["resource_ref"] = stable_hash("capability_resource", "wrong")
    elif outcome is CapabilityOutcome.EXPIRED:
        overrides["at_index"] = contract.expires_at_index
    elif outcome is CapabilityOutcome.ALREADY_USED:
        overrides["use_index"] = contract.max_uses
    decision = classify_presentation(contract, _presentation(contract, **overrides))
    assert decision.outcome is outcome
    return decision


def _binding(contract: IssuedCapabilityContract) -> ConfinedPresentationBinding:
    return ConfinedPresentationBinding.build(
        contract=contract,
        capability_ref=contract.capability_id,
        confined_world=contract._owned_world,
        confined_tenant_ref=contract.tenant_ref,
        confined_tenant_ownership_ref=contract.tenant_ownership_ref,
        target_origin=ORIGIN,
        prior_presentation_records=_capture_records(suffix="prior"),
        current_presentation_records=_capture_records(suffix="bound"),
    )


def _confinement_decision(
    contract: IssuedCapabilityContract,
    binding: ConfinedPresentationBinding,
    *,
    index: int,
):
    presentation = ConfinementPresentation.build(
        presented_world_ref=binding.confined_world_ref,
        presented_tenant_ref=binding.confined_tenant_ref,
        presented_tenant_ownership_ref=binding.confined_tenant_ownership_ref,
        presented_target_origin=ORIGIN,
        current_capture_records=_capture_records(suffix=f"presentation-{index}"),
    )
    return evaluate_confinement(contract, binding, presentation)


def _consumption_decision(
    contract: IssuedCapabilityContract,
    outcome: ConsumptionOutcome = ConsumptionOutcome.FIRST_CONSUMPTION,
) -> ConsumptionDecision:
    valid_decision = _logical_decision(contract)
    binding = _binding(contract)
    first_presentation = _confinement_decision(contract, binding, index=0)
    first = evaluate_consumption(
        contract,
        valid_decision,
        first_presentation,
        CapabilityConsumptionLedger.build(),
    )
    if outcome is ConsumptionOutcome.FIRST_CONSUMPTION:
        return first.decision
    if outcome is ConsumptionOutcome.REPLAYED_PRESENTATION:
        decision = evaluate_consumption(
            contract,
            valid_decision,
            first_presentation,
            first.ledger,
        ).decision
    else:
        decision = evaluate_consumption(
            contract,
            valid_decision,
            _confinement_decision(contract, binding, index=1),
            first.ledger,
        ).decision
    assert decision.outcome is outcome
    return decision


def _admission(contract: IssuedCapabilityContract) -> AdmittedRuntimeContract:
    return AdmittedRuntimeContract.build(
        contract=contract,
        capability_ref=contract.capability_id,
        runtime_ref=stable_hash("admitted_runtime", "r5d6-worker"),
        admitted_at_epoch=ADMITTED_AT,
        expires_at_epoch=EXPIRES_AT,
    )


def _context(
    *,
    suffix: str = "alice",
    logical_outcome: CapabilityOutcome = CapabilityOutcome.VALID,
    consumption_outcome: ConsumptionOutcome = ConsumptionOutcome.FIRST_CONSUMPTION,
):
    contract = _contract(suffix)
    return (
        _logical_decision(contract, logical_outcome),
        _admission(contract),
        _consumption_decision(contract, consumption_outcome),
    )


def _evaluate(
    *,
    suffix: str = "alice",
    logical_outcome: CapabilityOutcome = CapabilityOutcome.VALID,
    consumption_outcome: ConsumptionOutcome = ConsumptionOutcome.FIRST_CONSUMPTION,
    now: float = 150.0,
) -> CapabilityExecutionReceipt:
    logical, admission, consumption = _context(
        suffix=suffix,
        logical_outcome=logical_outcome,
        consumption_outcome=consumption_outcome,
    )
    return evaluate_capability_execution(
        logical,
        admission,
        consumption,
        clock=lambda: now,
    )


@pytest.mark.parametrize(
    "logical_outcome,consumption_outcome,now,expected",
    (
        (
            CapabilityOutcome.WRONG_BINDING,
            ConsumptionOutcome.FIRST_CONSUMPTION,
            EXPIRES_AT + 1.0,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE,
        ),
        (
            CapabilityOutcome.WRONG_BINDING,
            ConsumptionOutcome.REPLAYED_PRESENTATION,
            150.0,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE,
        ),
        (
            CapabilityOutcome.WRONG_BINDING,
            ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED,
            EXPIRES_AT + 1.0,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.FIRST_CONSUMPTION,
            EXPIRES_AT,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.REPLAYED_PRESENTATION,
            EXPIRES_AT,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED,
            EXPIRES_AT,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.FIRST_CONSUMPTION,
            ADMITTED_AT - 1.0,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_NOT_LIVE,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.REPLAYED_PRESENTATION,
            ADMITTED_AT - 1.0,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED,
            ADMITTED_AT - 1.0,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.FIRST_CONSUMPTION,
            ADMITTED_AT,
            CapabilityExecutionOutcome.EXECUTION_COMPLETED,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.REPLAYED_PRESENTATION,
            150.0,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED,
        ),
        (
            CapabilityOutcome.VALID,
            ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED,
            150.0,
            CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED,
        ),
    ),
)
def test_fixed_total_precedence_composes_every_axis_branch(
    logical_outcome,
    consumption_outcome,
    now,
    expected,
):
    receipt = _evaluate(
        logical_outcome=logical_outcome,
        consumption_outcome=consumption_outcome,
        now=now,
    )

    assert receipt.outcome is expected
    assert receipt.observed_epoch == now


def test_evaluator_reads_clock_once_and_delegates_the_same_instant_to_r5d5(monkeypatch):
    logical, admission, consumption = _context()
    clock_reads = []
    liveness_calls = []
    original = execution_module.evaluate_runtime_liveness

    def clock():
        clock_reads.append("read")
        return 150.0

    def evaluate_spy(logical_decision, runtime_admission, *, now):
        liveness_calls.append((logical_decision, runtime_admission, now))
        return original(logical_decision, runtime_admission, now=now)

    monkeypatch.setattr(execution_module, "evaluate_runtime_liveness", evaluate_spy)
    before = consumption.to_dict()

    receipt = evaluate_capability_execution(
        logical,
        admission,
        consumption,
        clock=clock,
    )

    assert clock_reads == ["read"]
    assert liveness_calls == [(logical, admission, 150.0)]
    assert receipt._consumption_decision is consumption
    assert consumption.to_dict() == before


def test_receipt_content_address_and_public_projection_bind_exact_inputs():
    logical, admission, consumption = _context()
    receipt = evaluate_capability_execution(
        logical,
        admission,
        consumption,
        clock=lambda: 150.0,
    )
    value = receipt.to_dict()
    payload = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "schema_version",
            "receipt_id",
            "target_dispatch_authority",
            "execution_effect_authority",
            "finding_promotion_authority",
            "target_cleanup_authority",
        }
    }

    assert value == {
        "schema_version": 1,
        "receipt_id": receipt.receipt_id,
        "capability_ref": logical.capability_id,
        "liveness_ref": receipt._liveness_decision.liveness_id,
        "consumption_ref": consumption.decision_id,
        "observed_epoch": "150.0",
        "outcome": "execution_completed",
        "mode": CAPABILITY_EXECUTION_RECEIPT_MODE,
        "target_dispatch_authority": False,
        "execution_effect_authority": False,
        "finding_promotion_authority": False,
        "target_cleanup_authority": False,
    }
    assert receipt.receipt_id == stable_hash("capability_execution_receipt", payload)
    assert not hasattr(CapabilityExecutionReceipt, "from_dict")


def test_private_live_context_is_not_serialized_compared_or_represented():
    receipt = _evaluate()
    private_names = {"_liveness_decision", "_consumption_decision"}
    field_map = {item.name: item for item in fields(receipt)}

    assert private_names.isdisjoint(receipt.to_dict())
    assert all(field_map[name].compare is False for name in private_names)
    assert all(field_map[name].repr is False for name in private_names)
    assert "_liveness_decision=" not in repr(receipt)
    assert "_consumption_decision=" not in repr(receipt)


def test_receipt_identity_is_instant_specific_and_deterministic():
    logical, admission, consumption = _context()
    first = evaluate_capability_execution(
        logical,
        admission,
        consumption,
        clock=lambda: 150.0,
    )
    repeated = evaluate_capability_execution(
        logical,
        admission,
        consumption,
        clock=lambda: 150.0,
    )
    later = evaluate_capability_execution(
        logical,
        admission,
        consumption,
        clock=lambda: 151.0,
    )

    assert first == repeated
    assert first.receipt_id == repeated.receipt_id
    assert first.receipt_id != later.receipt_id
    assert first.liveness_ref != later.liveness_ref


@pytest.mark.parametrize(
    "reading",
    (0, True, False, float("nan"), float("inf"), float("-inf")),
)
def test_evaluator_denies_non_float_or_non_finite_clock_readings(reading):
    logical, admission, consumption = _context()

    with pytest.raises(
        RuntimeExecutionDenied,
        match="execution_clock_reading_is_invalid",
    ):
        evaluate_capability_execution(
            logical,
            admission,
            consumption,
            clock=lambda: reading,
        )


@pytest.mark.parametrize(
    "epoch",
    (0, True, False, float("nan"), float("inf"), float("-inf")),
)
def test_receipt_builder_denies_non_float_or_non_finite_epochs(epoch):
    receipt = _evaluate()

    with pytest.raises(RuntimeExecutionDenied):
        CapabilityExecutionReceipt.build(
            liveness_decision=receipt._liveness_decision,
            consumption_decision=receipt._consumption_decision,
            observed_epoch=epoch,
            outcome=receipt.outcome,
        )


@pytest.mark.parametrize(
    "position,expected_message",
    (
        ("logical_decision", "execution_logical_decision_is_invalid"),
        ("admission", "execution_admission_is_invalid"),
        ("consumption_decision", "execution_consumption_decision_is_invalid"),
        ("clock", "execution_clock_is_not_callable"),
    ),
)
def test_evaluator_type_checks_every_argument(position, expected_message):
    logical, admission, consumption = _context()
    values = {
        "logical_decision": logical,
        "admission": admission,
        "consumption_decision": consumption,
        "clock": lambda: 150.0,
    }
    values[position] = object()

    with pytest.raises(RuntimeExecutionDenied, match=expected_message):
        evaluate_capability_execution(**values)


def test_evaluator_rejects_subclasses_instead_of_accepting_lookalike_contexts():
    logical, admission, consumption = _context()

    class DerivedLogicalDecision(CapabilityDecision):
        pass

    class DerivedAdmission(AdmittedRuntimeContract):
        pass

    class DerivedConsumptionDecision(ConsumptionDecision):
        pass

    derived = (
        DerivedLogicalDecision(
            **{item.name: getattr(logical, item.name) for item in fields(logical)}
        ),
        DerivedAdmission(
            **{item.name: getattr(admission, item.name) for item in fields(admission)}
        ),
        DerivedConsumptionDecision(
            **{
                item.name: getattr(consumption, item.name)
                for item in fields(consumption)
            }
        ),
    )
    for position, replacement_value in enumerate(derived):
        values = [logical, admission, consumption]
        values[position] = replacement_value
        with pytest.raises(RuntimeExecutionDenied):
            evaluate_capability_execution(*values, clock=lambda: 150.0)


def test_invalid_context_is_denied_before_the_clock_is_read():
    _, admission, consumption = _context()
    clock_reads = []

    def clock():
        clock_reads.append("read")
        return 150.0

    with pytest.raises(RuntimeExecutionDenied):
        evaluate_capability_execution(
            object(),
            admission,
            consumption,
            clock=clock,
        )

    assert clock_reads == []


def test_clock_failure_is_translated_to_a_fail_closed_execution_denial():
    logical, admission, consumption = _context()

    def broken_clock():
        raise OSError("clock unavailable")

    with pytest.raises(RuntimeExecutionDenied, match="execution_clock_read_failed"):
        evaluate_capability_execution(
            logical,
            admission,
            consumption,
            clock=broken_clock,
        )


@pytest.mark.parametrize("mismatched_position", (0, 1, 2))
def test_evaluator_denies_each_cross_capability_substitution(mismatched_position):
    first = list(_context(suffix="alice"))
    other = _context(suffix="bob")
    first[mismatched_position] = other[mismatched_position]

    with pytest.raises(RuntimeExecutionDenied, match="execution_capability_mismatch"):
        evaluate_capability_execution(*first, clock=lambda: 150.0)


def test_invalid_clock_reading_precedes_cross_capability_denial():
    logical, admission, _ = _context(suffix="alice")
    _, _, other_consumption = _context(suffix="bob")

    with pytest.raises(
        RuntimeExecutionDenied,
        match="execution_clock_reading_is_invalid",
    ):
        evaluate_capability_execution(
            logical,
            admission,
            other_consumption,
            clock=lambda: 150,
        )


@pytest.mark.parametrize(
    "field_name",
    (
        "target_dispatch_authority",
        "execution_effect_authority",
        "finding_promotion_authority",
        "target_cleanup_authority",
    ),
)
@pytest.mark.parametrize("enabled_value", (True, 0, None))
def test_receipt_builder_requires_every_authority_to_be_exactly_false(
    field_name,
    enabled_value,
):
    receipt = _evaluate()
    values = {
        "liveness_decision": receipt._liveness_decision,
        "consumption_decision": receipt._consumption_decision,
        "observed_epoch": receipt.observed_epoch,
        "outcome": receipt.outcome,
        field_name: enabled_value,
    }

    with pytest.raises(
        RuntimeExecutionDenied,
        match="execution_receipt_passive_boundary_violation",
    ):
        CapabilityExecutionReceipt.build(**values)


def test_receipt_builder_rejects_wrong_mode_and_inconsistent_outcome():
    receipt = _evaluate()
    common = {
        "liveness_decision": receipt._liveness_decision,
        "consumption_decision": receipt._consumption_decision,
        "observed_epoch": receipt.observed_epoch,
    }

    with pytest.raises(
        RuntimeExecutionDenied, match="execution_receipt_mode_is_invalid"
    ):
        CapabilityExecutionReceipt.build(
            **common,
            outcome=receipt.outcome,
            mode="behavioral_capability_execution_receipt_v2",
        )
    with pytest.raises(
        RuntimeExecutionDenied,
        match="execution_receipt_outcome_is_inconsistent",
    ):
        CapabilityExecutionReceipt.build(
            **common,
            outcome=CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
        )


def test_receipt_builder_rejects_an_epoch_different_from_r5d5_decision():
    receipt = _evaluate()

    with pytest.raises(
        RuntimeExecutionDenied,
        match="execution_capability_context_is_inconsistent",
    ):
        CapabilityExecutionReceipt.build(
            liveness_decision=receipt._liveness_decision,
            consumption_decision=receipt._consumption_decision,
            observed_epoch=151.0,
            outcome=receipt.outcome,
        )


@pytest.mark.parametrize("position", ("liveness_decision", "consumption_decision"))
def test_receipt_builder_type_checks_both_private_contexts(position):
    receipt = _evaluate()
    values = {
        "liveness_decision": receipt._liveness_decision,
        "consumption_decision": receipt._consumption_decision,
        "observed_epoch": receipt.observed_epoch,
        "outcome": receipt.outcome,
    }
    values[position] = object()

    with pytest.raises(RuntimeExecutionDenied):
        CapabilityExecutionReceipt.build(**values)


def test_post_init_rejects_forged_id_and_hash_consistent_semantic_outcome():
    receipt = _evaluate()

    with pytest.raises(ValueError, match="capability execution receipt is invalid"):
        replace(
            receipt,
            receipt_id=stable_hash("capability_execution_receipt", "forged"),
        )

    forged_outcome = CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED
    forged_payload = {
        key: value
        for key, value in receipt.to_dict().items()
        if key
        not in {
            "schema_version",
            "receipt_id",
            "outcome",
            "target_dispatch_authority",
            "execution_effect_authority",
            "finding_promotion_authority",
            "target_cleanup_authority",
        }
    }
    forged_payload["outcome"] = forged_outcome.value
    with pytest.raises(ValueError, match="capability execution receipt is invalid"):
        replace(
            receipt,
            outcome=forged_outcome,
            receipt_id=stable_hash("capability_execution_receipt", forged_payload),
        )


@pytest.mark.parametrize(
    "field_name,prefix",
    (
        ("capability_ref", "issued_capability_contract"),
        ("liveness_ref", "runtime_liveness_decision"),
        ("consumption_ref", "capability_consumption_decision"),
    ),
)
def test_post_init_rejects_hash_consistent_public_reference_substitution(
    field_name,
    prefix,
):
    receipt = _evaluate()
    replacement_ref = stable_hash(prefix, "other")
    payload = {
        key: value
        for key, value in receipt.to_dict().items()
        if key
        not in {
            "schema_version",
            "receipt_id",
            "target_dispatch_authority",
            "execution_effect_authority",
            "finding_promotion_authority",
            "target_cleanup_authority",
        }
    }
    payload[field_name] = replacement_ref

    with pytest.raises(ValueError, match="capability execution receipt is invalid"):
        replace(
            receipt,
            **{
                field_name: replacement_ref,
                "receipt_id": stable_hash("capability_execution_receipt", payload),
            },
        )


def test_post_init_rejects_private_liveness_or_consumption_substitution():
    receipt = _evaluate(suffix="alice")
    other = _evaluate(suffix="bob")

    with pytest.raises(ValueError, match="capability execution receipt is invalid"):
        replace(receipt, _liveness_decision=other._liveness_decision)
    with pytest.raises(ValueError, match="capability execution receipt is invalid"):
        replace(receipt, _consumption_decision=other._consumption_decision)


def test_post_init_rejects_enabled_authority_even_when_hash_is_unchanged():
    receipt = _evaluate()

    with pytest.raises(ValueError, match="capability execution receipt is invalid"):
        replace(receipt, execution_effect_authority=True)


def test_default_clock_and_ast_prove_one_real_clock_seam_and_no_io_imports():
    source_path = Path(execution_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_from = {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    forbidden = {
        "asyncio",
        "capability_consumption_store",
        "httpx",
        "json",
        "os",
        "pathlib",
        "receipts",
        "requests",
        "socket",
        "subprocess",
    }
    assert not forbidden & (imports | imported_from)
    assert imports == {"math", "time"}
    assert imported_from == {
        "__future__",
        "capability_consumption_ledger",
        "capability_contract",
        "capability_runtime_expiry",
        "dataclasses",
        "enum",
        "normalize",
        "typing",
    }

    function = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "evaluate_capability_execution"
    )
    assert [argument.arg for argument in function.args.kwonlyargs] == ["clock"]
    default = function.args.kw_defaults[0]
    assert isinstance(default, ast.Attribute)
    assert isinstance(default.value, ast.Name)
    assert (default.value.id, default.attr) == ("time", "time")
    assert [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "time"
    ] == [default]
    assert (
        len(
            [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "clock"
            ]
        )
        == 1
    )
    assert (
        inspect.signature(evaluate_capability_execution).parameters["clock"].default
        is time.time
    )


def test_execution_receipt_module_is_not_imported_by_any_other_core_module():
    source_path = Path(execution_module.__file__)
    repository_root = Path(__file__).resolve().parents[2]
    production_consumers = [
        path
        for path in (repository_root / "core").rglob("*.py")
        if path != source_path
        and "capability_execution_receipt" in path.read_text(encoding="utf-8")
    ]

    assert production_consumers == []
    assert CAPABILITY_EXECUTION_RECEIPT_MODE == (
        "behavioral_capability_execution_receipt_v1"
    )
