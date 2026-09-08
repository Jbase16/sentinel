"""Pure admitted-runtime wall-clock expiry tests."""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

import core.behavior.capability_runtime_expiry as runtime_module
from core.behavior.capability_contract import (
    CapabilityDecision,
    CapabilityOutcome,
    CapabilityPresentation,
    CapabilityRevocationState,
    IssuedCapabilityContract,
    classify_presentation,
)
from core.behavior.capability_runtime_expiry import (
    CAPABILITY_RUNTIME_EXPIRY_MODE,
    AdmittedRuntimeContract,
    RuntimeLivenessDenied,
    RuntimeLivenessOutcome,
    evaluate_runtime_liveness,
)
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash
from tests.import_contract import find_module_consumers


ADMITTED_AT = 100.0
EXPIRES_AT = 200.0


def _owned_world(suffix: str = "alice") -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", f"runtime-expiry-{suffix}"),
        persona_ref=stable_hash("experiment_persona", f"runtime-expiry-{suffix}"),
        ownership_ref=stable_hash("ownership_proof", f"runtime-expiry-{suffix}"),
    )


def _contract(
    *,
    suffix: str = "alice",
    revocation_state: CapabilityRevocationState = CapabilityRevocationState.ACTIVE,
) -> IssuedCapabilityContract:
    world = _owned_world(suffix)
    assert world.persona_ref is not None
    tenant_ref = stable_hash("owned_tenant", f"runtime-expiry-{suffix}")
    tenant_ownership_ref = stable_hash(
        "ownership_proof",
        f"runtime-expiry-{suffix}-tenant-owned",
    )
    return IssuedCapabilityContract.build(
        world=world,
        world_tenant_ref=tenant_ref,
        world_tenant_ownership_ref=tenant_ownership_ref,
        subject_ref=world.persona_ref,
        resource_ref=stable_hash("capability_resource", f"runtime-expiry-{suffix}"),
        operation_ref=stable_hash("capability_operation", "download"),
        audience_ref=world.persona_ref,
        issuer_ref=stable_hash("capability_issuer", "runtime-expiry-service"),
        tenant_ref=tenant_ref,
        tenant_ownership_ref=tenant_ownership_ref,
        source_evidence_ref=stable_hash(
            "source_evidence",
            f"runtime-expiry-{suffix}",
        ),
        secret_digest=stable_hash(
            "capability_secret_digest",
            f"runtime-expiry-secret-{suffix}",
        ),
        issued_at_index=10,
        expires_at_index=20,
        max_uses=1,
        revocation_state=revocation_state,
    )


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


def _logical_context(
    outcome: CapabilityOutcome = CapabilityOutcome.VALID,
) -> tuple[IssuedCapabilityContract, CapabilityDecision]:
    contract = _contract(
        suffix=outcome.value,
        revocation_state=(
            CapabilityRevocationState.REVOKED
            if outcome is CapabilityOutcome.REVOKED
            else CapabilityRevocationState.ACTIVE
        ),
    )
    overrides = {}
    if outcome is CapabilityOutcome.WRONG_BINDING:
        overrides["resource_ref"] = stable_hash("capability_resource", "wrong")
    elif outcome is CapabilityOutcome.EXPIRED:
        overrides["at_index"] = contract.expires_at_index
    elif outcome is CapabilityOutcome.ALREADY_USED:
        overrides["use_index"] = contract.max_uses
    decision = classify_presentation(contract, _presentation(contract, **overrides))
    assert decision.outcome is outcome
    return contract, decision


def _admission(
    contract: IssuedCapabilityContract,
    **overrides,
) -> AdmittedRuntimeContract:
    values = {
        "contract": contract,
        "capability_ref": contract.capability_id,
        "runtime_ref": stable_hash("admitted_runtime", "runtime-expiry-worker"),
        "admitted_at_epoch": ADMITTED_AT,
        "expires_at_epoch": EXPIRES_AT,
    }
    values.update(overrides)
    return AdmittedRuntimeContract.build(**values)


@pytest.mark.parametrize(
    "admitted_at,expires_at",
    (
        (1.1, 2.2),
        (1_900_000_000.5, 1_900_000_060.5),
    ),
)
def test_admission_round_trip_is_equal_and_rehashes_exact_float_epochs(
    admitted_at,
    expires_at,
):
    contract = _contract()
    admission = _admission(
        contract,
        admitted_at_epoch=admitted_at,
        expires_at_epoch=expires_at,
    )
    serialized = admission.to_dict()
    reloaded = AdmittedRuntimeContract.from_dict(
        json.loads(json.dumps(serialized, sort_keys=True)),
        contract=contract,
    )

    assert serialized["admitted_at_epoch"] == repr(admitted_at)
    assert serialized["expires_at_epoch"] == repr(expires_at)
    assert reloaded == admission
    assert reloaded.admission_id == admission.admission_id
    assert reloaded.to_dict() == serialized
    assert reloaded._contract is contract
    assert "_contract=" not in repr(admission)
    assert admission.admission_id == stable_hash(
        "admitted_runtime_capability",
        {
            key: value
            for key, value in serialized.items()
            if key
            not in {
                "schema_version",
                "admission_id",
                "target_dispatch_authority",
                "execution_receipt_authority",
                "real_clock_read_authority",
            }
        },
    )


@pytest.mark.parametrize(
    "overrides",
    (
        {"capability_ref": stable_hash("wrong_capability", "value")},
        {"runtime_ref": stable_hash("wrong_runtime", "value")},
    ),
)
def test_admission_rejects_bad_reference_prefixes(overrides):
    with pytest.raises(ValueError, match="reference is invalid"):
        _admission(_contract(), **overrides)


def test_admission_rejects_a_different_well_formed_capability_reference():
    contract = _contract(suffix="alice")
    other = _contract(suffix="bob")

    with pytest.raises(
        RuntimeLivenessDenied,
        match="runtime_admission_contract_reference_mismatch",
    ):
        _admission(contract, capability_ref=other.capability_id)


@pytest.mark.parametrize("field", ("admitted_at_epoch", "expires_at_epoch"))
@pytest.mark.parametrize(
    "value",
    (0, True, False, float("nan"), float("inf"), float("-inf")),
)
def test_admission_rejects_non_float_or_non_finite_epochs(field, value):
    with pytest.raises(ValueError, match="finite float"):
        _admission(_contract(), **{field: value})


@pytest.mark.parametrize("expires_at", (ADMITTED_AT, ADMITTED_AT - 0.1))
def test_admission_rejects_equal_or_backward_windows(expires_at):
    with pytest.raises(ValueError, match="window is invalid"):
        _admission(_contract(), expires_at_epoch=expires_at)


def test_admission_rejects_wrong_mode():
    with pytest.raises(ValueError, match="mode is invalid"):
        _admission(_contract(), mode="behavioral_capability_runtime_expiry_v2")


@pytest.mark.parametrize(
    "field",
    (
        "target_dispatch_authority",
        "execution_receipt_authority",
        "real_clock_read_authority",
    ),
)
def test_admission_rejects_every_enabled_authority(field):
    with pytest.raises(
        RuntimeLivenessDenied,
        match="runtime_admission_passive_boundary_violation",
    ):
        _admission(_contract(), **{field: True})


@pytest.mark.parametrize(
    "mutation",
    (
        "forged_admission_id",
        "mutated_epoch",
        "mutated_ref",
        "extra_field",
        "missing_field",
        "noncanonical_float",
    ),
)
def test_admission_from_dict_rejects_tampering_and_noncanonical_data(mutation):
    contract = _contract()
    value = deepcopy(_admission(contract).to_dict())

    if mutation == "forged_admission_id":
        value["admission_id"] = stable_hash(
            "admitted_runtime_capability",
            "forged",
        )
    elif mutation == "mutated_epoch":
        value["expires_at_epoch"] = repr(EXPIRES_AT + 1.0)
    elif mutation == "mutated_ref":
        value["runtime_ref"] = stable_hash("admitted_runtime", "mutated")
    elif mutation == "extra_field":
        value["unexpected"] = False
    elif mutation == "missing_field":
        value.pop("runtime_ref")
    else:
        value["admitted_at_epoch"] = "100.00"

    with pytest.raises(
        RuntimeLivenessDenied,
        match="runtime_admission_serialization_invalid",
    ):
        AdmittedRuntimeContract.from_dict(value, contract=contract)


@pytest.mark.parametrize(
    "encoded",
    (ADMITTED_AT, "1e2", "+100.0", " 100.0"),
)
def test_admission_from_dict_requires_string_repr_float_encoding(encoded):
    contract = _contract()
    value = _admission(contract).to_dict()
    value["admitted_at_epoch"] = encoded

    with pytest.raises(
        RuntimeLivenessDenied,
        match="runtime_admission_serialization_invalid",
    ):
        AdmittedRuntimeContract.from_dict(value, contract=contract)


def test_admission_post_init_rejects_forged_identity():
    admission = _admission(_contract())

    with pytest.raises(ValueError, match="admitted runtime contract is invalid"):
        replace(
            admission,
            admission_id=stable_hash("admitted_runtime_capability", "forged"),
        )


@pytest.mark.parametrize(
    "now,expected",
    (
        (ADMITTED_AT - 0.1, RuntimeLivenessOutcome.NOT_YET_LIVE),
        (ADMITTED_AT, RuntimeLivenessOutcome.ADMITTED_LIVE),
        (150.0, RuntimeLivenessOutcome.ADMITTED_LIVE),
        (EXPIRES_AT, RuntimeLivenessOutcome.EXPIRED_AT_RUNTIME),
        (EXPIRES_AT + 0.1, RuntimeLivenessOutcome.EXPIRED_AT_RUNTIME),
    ),
)
def test_valid_logical_decision_uses_left_closed_right_open_runtime_window(
    now,
    expected,
):
    contract, logical_decision = _logical_context()
    decision = evaluate_runtime_liveness(
        logical_decision,
        _admission(contract),
        now=now,
    )

    assert decision.outcome is expected
    assert decision.observed_epoch == now
    assert decision.to_dict()["observed_epoch"] == repr(now)


@pytest.mark.parametrize(
    "logical_outcome",
    (
        CapabilityOutcome.WRONG_BINDING,
        CapabilityOutcome.EXPIRED,
        CapabilityOutcome.REVOKED,
        CapabilityOutcome.ALREADY_USED,
    ),
)
@pytest.mark.parametrize(
    "now",
    (
        ADMITTED_AT - 1.0,
        ADMITTED_AT,
        150.0,
        EXPIRES_AT,
        EXPIRES_AT + 1.0,
    ),
)
def test_logical_inadmissibility_dominates_every_runtime_instant(
    logical_outcome,
    now,
):
    contract, logical_decision = _logical_context(logical_outcome)

    decision = evaluate_runtime_liveness(
        logical_decision,
        _admission(contract),
        now=now,
    )

    assert decision.outcome is RuntimeLivenessOutcome.LOGICALLY_INADMISSIBLE
    assert decision.logical_decision_ref == logical_decision.decision_id


def test_evaluator_rejects_cross_capability_admission_before_time_classification():
    first_contract, _ = _logical_context()
    _, other_decision = _logical_context(CapabilityOutcome.ALREADY_USED)

    with pytest.raises(
        RuntimeLivenessDenied,
        match="runtime_admission_capability_mismatch",
    ):
        evaluate_runtime_liveness(
            other_decision,
            _admission(first_contract),
            now=EXPIRES_AT + 1.0,
        )


@pytest.mark.parametrize(
    "now",
    (0, True, False, float("nan"), float("inf"), float("-inf")),
)
def test_evaluator_denies_invalid_clock_readings(now):
    contract, logical_decision = _logical_context()

    with pytest.raises(
        RuntimeLivenessDenied,
        match="runtime_clock_reading_is_invalid",
    ):
        evaluate_runtime_liveness(
            logical_decision,
            _admission(contract),
            now=now,
        )


@pytest.mark.parametrize("position", ("logical_decision", "admission"))
def test_evaluator_type_checks_both_contract_arguments(position):
    contract, logical_decision = _logical_context()
    values = {
        "logical_decision": logical_decision,
        "admission": _admission(contract),
        "now": ADMITTED_AT,
    }
    values[position] = object()

    with pytest.raises(TypeError):
        evaluate_runtime_liveness(**values)


def test_liveness_identity_is_instant_specific_and_deterministic():
    contract, logical_decision = _logical_context()
    admission = _admission(contract)

    first = evaluate_runtime_liveness(logical_decision, admission, now=150.0)
    repeated = evaluate_runtime_liveness(logical_decision, admission, now=150.0)
    later = evaluate_runtime_liveness(logical_decision, admission, now=151.0)

    assert first == repeated
    assert first.liveness_id == repeated.liveness_id
    assert first.liveness_id != later.liveness_id
    assert first.to_dict()["logical_decision_ref"] == logical_decision.decision_id
    assert first.to_dict()["admission_ref"] == admission.admission_id


def test_liveness_post_init_rejects_forged_identity_and_semantic_outcome():
    contract, logical_decision = _logical_context()
    decision = evaluate_runtime_liveness(
        logical_decision,
        _admission(contract),
        now=150.0,
    )

    with pytest.raises(ValueError, match="runtime liveness decision is invalid"):
        replace(
            decision,
            liveness_id=stable_hash("runtime_liveness_decision", "forged"),
        )
    with pytest.raises(ValueError, match="runtime liveness decision is invalid"):
        replace(
            decision,
            outcome=RuntimeLivenessOutcome.EXPIRED_AT_RUNTIME,
            liveness_id=stable_hash(
                "runtime_liveness_decision",
                {
                    **{
                        key: value
                        for key, value in decision.to_dict().items()
                        if key not in {"schema_version", "liveness_id", "outcome"}
                    },
                    "outcome": RuntimeLivenessOutcome.EXPIRED_AT_RUNTIME.value,
                },
            ),
        )


def test_runtime_expiry_module_has_no_io_clock_store_or_production_wiring():
    source_path = Path(runtime_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_modules = {
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
    assert not {
        "asyncio",
        "capability_consumption_store",
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "time",
    } & (imported_modules | imported_from)

    repository_root = Path(__file__).resolve().parents[2]
    production_consumers = find_module_consumers(
        (repository_root / "core").rglob("*.py"),
        "core.behavior.capability_runtime_expiry",
        repository_root=repository_root,
        exclude=(source_path,),
    )
    assert set(production_consumers) == {
        source_path.with_name("capability_effect_one_click.py"),
        source_path.with_name("capability_execution_receipt.py"),
    }
    assert CAPABILITY_RUNTIME_EXPIRY_MODE == ("behavioral_capability_runtime_expiry_v1")
