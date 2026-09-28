"""Focused positive/negative proof of the passive R5E1 aggregate-limit shape."""

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import ProofTopology
from core.behavior import workflow_invariant_contract as module
from core.behavior.workflow_invariant_contract import (
    MAX_RESOURCE_VALUE,
    WorkflowInvariantContract,
    WorkflowInvariantOutcome,
    WorkflowInvariantPredicate,
    WorkflowOperation,
    WorkflowOwnedFixture,
    WorkflowPrecondition,
    WorkflowState,
    classify_sequence,
    evaluate_invariant,
)


def owned_world(suffix="alice"):
    return ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", suffix),
        persona_ref=stable_hash("experiment_persona", suffix),
        ownership_ref=stable_hash("ownership_proof", suffix),
    )


def contract(*, secure=False, amounts=(6, 6), budget=4, initial=None, suffix="alice"):
    world = owned_world(suffix)
    operations = tuple(
        WorkflowOperation(
            operation_ref=stable_hash(
                "workflow_operation", {"workflow": suffix, "index": index}
            ),
            index=index,
            account_ref=world.persona_ref,
            amount=amount,
            precondition=(
                WorkflowPrecondition.PER_OPERATION_AND_AGGREGATE_CAP
                if secure
                else WorkflowPrecondition.PER_OPERATION_CAP
            ),
        )
        for index, amount in enumerate(amounts)
    )
    return WorkflowInvariantContract.build(
        workflow_ref=stable_hash("workflow", suffix),
        account_ref=world.persona_ref,
        tenant_ref=stable_hash("owned_tenant", suffix),
        tenant_ownership_ref=stable_hash("ownership_proof", {"tenant": suffix}),
        initial_state=initial or WorkflowState(0, 10, 6),
        operations=operations,
        max_operations=budget,
    )


def fixture(**values):
    declared = contract(**values)
    return WorkflowOwnedFixture(
        contract=declared,
        world=owned_world(values.get("suffix", "alice")),
        world_tenant_ref=declared.tenant_ref,
        world_tenant_ownership_ref=declared.tenant_ownership_ref,
    )


@pytest.mark.parametrize(
    "secure,expected,consumed,applied",
    [
        (False, WorkflowInvariantOutcome.INVARIANT_VIOLATED, 12, 2),
        (True, WorkflowInvariantOutcome.OPERATION_REFUSED, 6, 1),
    ],
)
def test_aggregate_limit_twins(secure, expected, consumed, applied):
    declared = contract(secure=secure)
    before = declared.to_dict()
    result = classify_sequence(declared, declared.initial_state, declared.operations)
    assert result.outcome is expected
    assert result.terminal_state.consumed == consumed
    assert len(result.applied_operation_refs) == applied
    assert evaluate_invariant(declared.invariant, result.terminal_state) is secure
    assert declared.to_dict() == before
    assert (
        classify_sequence(declared, declared.initial_state, declared.operations)
        == result
    )


@pytest.mark.parametrize("secure", [False, True])
def test_boundary_holds_and_every_step_is_present(secure):
    declared = contract(secure=secure, amounts=(4, 6))
    result = classify_sequence(declared, declared.initial_state, declared.operations)
    assert result.outcome is WorkflowInvariantOutcome.INVARIANT_HELD
    assert result.terminal_state.consumed == 10
    assert result.applied_operation_refs == tuple(
        op.operation_ref for op in declared.operations
    )


def test_oracle_has_no_transition_dependency(monkeypatch):
    monkeypatch.setattr(
        module, "transition_state", lambda *_: pytest.fail("transition was called")
    )
    assert (
        evaluate_invariant(
            WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT, WorkflowState(12, 10, 6)
        )
        is False
    )


def test_contract_identity_roundtrip_and_immutability():
    declared = contract()
    payload = declared.to_dict()
    identity_payload = {
        key: value
        for key, value in payload.items()
        if key not in {"schema_version", "contract_id"}
    }
    assert declared.contract_id == stable_hash(
        "workflow_invariant_contract", identity_payload
    )
    assert (
        WorkflowInvariantContract.from_dict(json.loads(json.dumps(payload))) == declared
    )
    with pytest.raises(FrozenInstanceError):
        declared.initial_state.consumed = 100


@pytest.mark.parametrize(
    "field,value",
    [
        ("consumed", -1),
        ("consumed", True),
        ("declared_limit", -1),
        ("per_op_cap", 0),
        ("per_op_cap", 1.5),
        ("consumed", MAX_RESOURCE_VALUE + 1),
    ],
)
def test_malformed_numeric_state_is_rejected(field, value):
    with pytest.raises(ValueError):
        replace(WorkflowState(0, 10, 6), **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("amount", -1),
        ("amount", True),
        ("operation_ref", "raw-operation"),
        ("index", -1),
        ("single_application", 1),
        ("precondition", "per_operation_cap"),
    ],
)
def test_malformed_operation_is_rejected(field, value):
    with pytest.raises(ValueError):
        replace(contract().operations[0], **{field: value})


@pytest.mark.parametrize(
    "mutation",
    [
        "forged",
        "empty_id",
        "reorder",
        "duplicate",
        "cross_account",
        "bad_budget",
        "initial_violation",
        "mutable_operations",
    ],
)
def test_contract_substitution_fails_closed(mutation):
    declared = contract()
    values = {
        "forged": {"contract_id": stable_hash("workflow_invariant_contract", "forged")},
        "empty_id": {"contract_id": ""},
        "reorder": {"operations": declared.operations[::-1]},
        "duplicate": {"operations": (declared.operations[0], declared.operations[0])},
        "cross_account": {"account_ref": owned_world("bob").persona_ref},
        "bad_budget": {"max_operations": True},
        "initial_violation": {"initial_state": WorkflowState(11, 10, 6)},
        "mutable_operations": {"operations": list(declared.operations)},
    }
    with pytest.raises(ValueError):
        replace(declared, **values[mutation])


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_step",
        "reordered",
        "negative",
        "forged_address",
        "wrong_initial",
        "wrong_type",
    ],
)
def test_classifier_returns_redacted_malformed_for_invalid_input(mutation):
    declared = contract()
    initial, operations = declared.initial_state, declared.operations
    if mutation == "missing_step":
        operations = operations[:1]
    elif mutation == "reordered":
        operations = operations[::-1]
    elif mutation == "negative":
        object.__setattr__(operations[0], "amount", -1)
    elif mutation == "forged_address":
        object.__setattr__(declared, "contract_id", "raw-untrusted-value")
    elif mutation == "wrong_initial":
        initial = WorkflowState(1, 10, 6)
    else:
        declared = object()
    result = classify_sequence(declared, initial, operations)
    assert result.outcome is WorkflowInvariantOutcome.MALFORMED
    assert result.terminal_state is None and result.applied_operation_refs == ()
    assert "raw-untrusted-value" not in json.dumps(result.to_dict())


@pytest.mark.parametrize(
    "mutation",
    [
        "non_owned",
        "role",
        "cross_account",
        "cross_tenant",
        "cross_ownership",
        "wrong_topology",
        "forged_world",
    ],
)
def test_fixture_rejects_non_owned_or_mismatched_sdk_shape(mutation):
    owned = fixture()
    if mutation == "non_owned":
        world = ExperimentWorldBinding.build(
            slot="actor",
            kind=ExperimentWorldKind.FRESH_ANONYMOUS,
            world_ref=stable_hash("world", "anonymous"),
            fresh=True,
        )
        values = {"world": world}
    elif mutation == "role":
        values = {
            "world": ExperimentWorldBinding.build(
                slot="actor",
                kind=ExperimentWorldKind.OWNED_ACCOUNT,
                world_ref=owned.world.world_ref,
                persona_ref=owned.world.persona_ref,
                ownership_ref=owned.world.ownership_ref,
                role_ref=stable_hash("role", "admin"),
            )
        }
    elif mutation == "cross_account":
        values = {"world": owned_world("bob")}
    elif mutation == "cross_tenant":
        values = {"world_tenant_ref": stable_hash("owned_tenant", "bob")}
    elif mutation == "cross_ownership":
        values = {"world_tenant_ownership_ref": stable_hash("ownership_proof", "bob")}
    elif mutation == "wrong_topology":
        values = {"topology": ProofTopology.PAIRED_OWNED_ACCOUNTS}
    else:
        object.__setattr__(
            owned.world, "binding_id", stable_hash("experiment_world_binding", "forged")
        )
        values = {}
    with pytest.raises(ValueError):
        replace(owned, **values)


def test_fixture_has_only_passive_disposable_authority():
    value = fixture().to_dict()
    assert value["disposable"] is True and value["reversible"] is True
    assert value["target_requests_sent"] == 0
    for field in (
        "cleanup_required",
        "residue_created",
        "orphan_risk",
        "budget_reserved",
        "backend_dispatch_authority",
        "finding_authority",
        "executable",
    ):
        assert value[field] is False


@pytest.mark.parametrize(
    "amounts,budget,reason",
    [((7,), 4, "precondition_refused"), ((6, 6), 1, "sequence_budget_exhausted")],
)
def test_refusal_does_not_apply_the_refused_operation(amounts, budget, reason):
    declared = contract(amounts=amounts, budget=budget)
    result = classify_sequence(declared, declared.initial_state, declared.operations)
    assert result.outcome is WorkflowInvariantOutcome.OPERATION_REFUSED
    assert result.reason_code == reason
    assert result.terminal_state.consumed in {0, 6}
