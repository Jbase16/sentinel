"""R5F1 logical race, serial baseline, owned fixture and fail-closed contract proofs."""

from dataclasses import replace
from copy import deepcopy

import pytest

from core.behavior import concurrency_invariant_contract as module
from core.behavior.concurrency_invariant_contract import (
    CommitRefusal,
    ConcurrencyDecision,
    ConcurrencyGuard,
    ConcurrencyGuardMode,
    ConcurrencyInvariantContract,
    ConcurrencyInvariantPredicate,
    ConcurrencyOperation,
    ConcurrencyOutcome,
    ConcurrencyOwnedFixture,
    MicroStep,
    SharedWorkflowState,
    StepKind,
    WorkflowSchedule,
    apply_commit,
    classify_schedule,
    evaluate_invariant,
    is_serializable_safe,
    operation_guard,
    replay_schedule,
    serial_schedules,
)
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash


def case(
    *, secure=False, limit=1, guard=ConcurrencyGuard.PER_OPERATION_AND_AGGREGATE_CAP
):
    actors = tuple(stable_hash("experiment_persona", label) for label in ("a", "b"))
    tenant = stable_hash("owned_tenant", "concurrency")
    ownership = stable_hash("ownership_proof", "concurrency")
    operations = tuple(
        ConcurrencyOperation(
            stable_hash("concurrency_operation", label),
            actor,
            0,
            1,
            ConcurrencyGuardMode.COMMIT_TIME_CAS
            if secure
            else ConcurrencyGuardMode.OBSERVE_TIME_ONLY,
            guard,
        )
        for label, actor in zip(("a", "b"), actors)
    )
    contract = ConcurrencyInvariantContract.build(
        resource_ref=stable_hash("owned_resource", "shared-cap"),
        tenant_ref=tenant,
        tenant_ownership_ref=ownership,
        initial_state=SharedWorkflowState(0, limit, 1),
        operations=operations,
        max_actors=2,
    )
    worlds = tuple(
        ExperimentWorldBinding.build(
            slot=f"actor_{label}",
            kind=ExperimentWorldKind.OWNED_ACCOUNT,
            world_ref=stable_hash("world", label),
            persona_ref=actor,
            ownership_ref=ownership,
        )
        for label, actor in zip(("a", "b"), actors)
    )
    fixture = ConcurrencyOwnedFixture(contract, worlds, tenant, ownership)
    schedule = WorkflowSchedule(
        contract,
        (
            MicroStep(actors[0], operations[0].operation_ref, StepKind.OBSERVE),
            MicroStep(actors[1], operations[1].operation_ref, StepKind.OBSERVE),
            MicroStep(actors[0], operations[0].operation_ref, StepKind.COMMIT),
            MicroStep(actors[1], operations[1].operation_ref, StepKind.COMMIT),
        ),
    )
    return fixture, schedule


def test_three_twins_and_serial_baseline():
    vulnerable, schedule = case()
    contract = vulnerable.contract
    decisions = tuple(
        replay_schedule(contract, contract.initial_state, serial)
        for serial in serial_schedules(contract)
    )
    assert len(decisions) == 2
    assert all(decision.terminal_state.consumed == 1 for decision in decisions)
    assert all(
        decision.outcome is ConcurrencyOutcome.OPERATION_REFUSED
        for decision in decisions
    )
    assert is_serializable_safe(contract) is True
    raced = classify_schedule(contract, contract.initial_state, schedule)
    assert raced.outcome is ConcurrencyOutcome.INVARIANT_VIOLATED
    assert raced.race_confirmed is True
    assert raced.terminal_state.consumed == 2 and raced.terminal_state.version == 2
    secure, secure_schedule = case(secure=True)
    blocked = classify_schedule(
        secure.contract, secure.contract.initial_state, secure_schedule
    )
    assert blocked.outcome is ConcurrencyOutcome.OPERATION_REFUSED
    assert blocked.reason_code == CommitRefusal.CAS_VERSION.value
    assert blocked.terminal_state.consumed == 1 and blocked.race_confirmed is False
    boundary, boundary_schedule = case(limit=2)
    held = classify_schedule(
        boundary.contract, boundary.contract.initial_state, boundary_schedule
    )
    assert held.outcome is ConcurrencyOutcome.INVARIANT_HELD
    assert held.terminal_state.consumed == 2 and held.race_confirmed is False


def test_serial_unsafe_guard_is_not_called_a_race():
    fixture, schedule = case(guard=ConcurrencyGuard.PER_OPERATION_CAP)
    contract = fixture.contract
    assert is_serializable_safe(contract) is False
    assert all(
        replay_schedule(contract, contract.initial_state, serial).outcome
        is ConcurrencyOutcome.INVARIANT_VIOLATED
        for serial in serial_schedules(contract)
    )
    decision = replay_schedule(contract, contract.initial_state, schedule)
    assert decision.outcome is ConcurrencyOutcome.INVARIANT_VIOLATED
    assert decision.race_confirmed is False


def test_terminal_oracle_is_structurally_independent(monkeypatch):
    state = SharedWorkflowState(2, 1, 1)
    monkeypatch.setattr(
        module, "operation_guard", lambda *_: (_ for _ in ()).throw(AssertionError())
    )
    monkeypatch.setattr(
        module, "apply_commit", lambda *_: (_ for _ in ()).throw(AssertionError())
    )
    assert (
        evaluate_invariant(ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT, state)
        is False
    )
    assert (
        evaluate_invariant(
            ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT,
            replace(state, consumed=1),
        )
        is True
    )


def test_replay_is_deterministic_and_commit_carries_observation():
    fixture, schedule = case()
    contract = fixture.contract
    decisions = [
        replay_schedule(contract, contract.initial_state, schedule) for _ in range(3)
    ]
    assert decisions[0] == decisions[1] == decisions[2]
    assert len({decision.decision_id for decision in decisions}) == 1
    operation = contract.operations[0]
    assert operation_guard(contract.initial_state, operation) is True
    assert apply_commit(contract.initial_state, operation, (0, True)).version == 1
    assert (
        apply_commit(contract.initial_state, operation, (0, False))
        is CommitRefusal.OBSERVE_GUARD
    )


def test_valid_schedule_engine_error_is_not_mislabeled_malformed(monkeypatch):
    fixture, schedule = case()

    def broken_guard(*_args):
        raise ValueError("internal replay error")

    monkeypatch.setattr(module, "operation_guard", broken_guard)
    with pytest.raises(ValueError, match="internal replay error"):
        classify_schedule(fixture.contract, fixture.contract.initial_state, schedule)


def test_schedule_admissibility_and_malformed_classifier_carry_no_untrusted_data():
    fixture, schedule = case()
    steps = schedule.steps
    with pytest.raises(ValueError, match="program order"):
        WorkflowSchedule(fixture.contract, (steps[2], steps[1], steps[0], steps[3]))
    with pytest.raises(ValueError, match="program order"):
        WorkflowSchedule(fixture.contract, (steps[0], steps[0], steps[2], steps[3]))
    with pytest.raises(ValueError, match="length"):
        WorkflowSchedule(fixture.contract, steps[:-1])
    forged = deepcopy(schedule)
    object.__setattr__(forged, "steps", (steps[2], steps[1], steps[0], steps[3]))
    decision = classify_schedule(
        fixture.contract, fixture.contract.initial_state, forged
    )
    assert decision.outcome is ConcurrencyOutcome.MALFORMED
    assert decision.contract is decision.schedule is decision.terminal_state is None
    assert decision.applied_operation_refs == () and decision.race_confirmed is False


def test_actor_program_order_with_two_operations_each():
    fixture, _ = case()
    first_a, first_b = fixture.contract.operations
    second_a = replace(
        first_a, operation_ref=stable_hash("concurrency_operation", "a2"), op_index=1
    )
    contract = ConcurrencyInvariantContract.build(
        resource_ref=fixture.contract.resource_ref,
        tenant_ref=fixture.contract.tenant_ref,
        tenant_ownership_ref=fixture.contract.tenant_ownership_ref,
        initial_state=fixture.contract.initial_state,
        operations=(first_a, second_a, first_b),
        max_actors=2,
    )
    steps = (
        MicroStep(first_a.actor_ref, first_a.operation_ref, StepKind.OBSERVE),
        MicroStep(first_a.actor_ref, second_a.operation_ref, StepKind.OBSERVE),
        MicroStep(first_a.actor_ref, first_a.operation_ref, StepKind.COMMIT),
        MicroStep(first_a.actor_ref, second_a.operation_ref, StepKind.COMMIT),
        MicroStep(first_b.actor_ref, first_b.operation_ref, StepKind.OBSERVE),
        MicroStep(first_b.actor_ref, first_b.operation_ref, StepKind.COMMIT),
    )
    with pytest.raises(ValueError, match="program order"):
        WorkflowSchedule(contract, steps)


def test_round_trips_and_tamper_refusal():
    fixture, schedule = case()
    contract = fixture.contract
    decision = classify_schedule(contract, contract.initial_state, schedule)
    for value, cls in (
        (contract.initial_state, SharedWorkflowState),
        (contract.operations[0], ConcurrencyOperation),
        (contract, ConcurrencyInvariantContract),
        (schedule.steps[0], MicroStep),
        (schedule, WorkflowSchedule),
        (fixture, ConcurrencyOwnedFixture),
        (decision, ConcurrencyDecision),
    ):
        assert cls.from_dict(value.to_dict()) == value
    tampered = deepcopy(schedule.to_dict())
    tampered["executable"] = True
    with pytest.raises(ValueError):
        WorkflowSchedule.from_dict(tampered)
    tampered = deepcopy(schedule.to_dict())
    tampered["schedule_id"] = stable_hash("concurrency_workflow_schedule", "wrong")
    with pytest.raises(ValueError):
        WorkflowSchedule.from_dict(tampered)
    tampered = deepcopy(decision.to_dict())
    tampered["race_confirmed"] = False
    with pytest.raises(ValueError):
        ConcurrencyDecision.from_dict(tampered)
    tampered = deepcopy(decision.to_dict())
    tampered["promotion_authority"] = True
    with pytest.raises(ValueError):
        ConcurrencyDecision.from_dict(tampered)
