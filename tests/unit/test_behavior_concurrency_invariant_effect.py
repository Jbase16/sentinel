"""R5F6 hermetic schedule twins, independent observation and unwired proof."""

import ast
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path

import pytest

from core.behavior import concurrency_invariant_contract as contract_module
from core.behavior import concurrency_invariant_effect as module
from core.behavior import concurrency_invariant_ledger as ledger_module
from core.behavior.concurrency_invariant_binding import ConcurrencyInvariantBinding
from core.behavior.concurrency_invariant_contract import (
    MAX_RESOURCE_VALUE,
    MAX_CONCURRENCY_OPERATIONS,
    MAX_SCHEDULE_STEPS,
    ConcurrencyGuard,
    ConcurrencyGuardMode,
    ConcurrencyInvariantContract,
    ConcurrencyInvariantPredicate,
    ConcurrencyOwnedFixture,
    ConcurrencyOutcome,
    MicroStep,
    SharedWorkflowState,
    StepKind,
    WorkflowSchedule,
    classify_schedule,
)
from core.behavior.concurrency_invariant_effect import (
    ConcurrencyEffectCorrespondence,
    ConcurrencyEffectEvidence,
    ConcurrencyEffectOutcome,
    ConcurrencyEffectResult,
    ConcurrencyObservedResponse,
    ConcurrencyObservedState,
    ConcurrencyObservedStatus,
    check_effect_correspondence,
    observed_effect_oracle,
    run_concurrency_effect,
)
from core.behavior.concurrency_invariant_ledger import evaluate_schedule
from core.behavior.normalize import stable_hash
from core.contracts.architecture_ids import IdentifierRegistry, default_registry_path
from tests.import_contract import find_module_consumers
from tests.unit.test_behavior_concurrency_invariant_binding import binding
from tests.unit.test_behavior_concurrency_invariant_contract import case

REPOSITORY = Path(__file__).resolve().parents[2]
FORBIDDEN = {
    "threading",
    "asyncio",
    "multiprocessing",
    "concurrent",
    "queue",
    "socket",
    "ssl",
    "http",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
    "subprocess",
    "signal",
    "time",
    "datetime",
    "random",
    "secrets",
    "os",
}


class FakeOwnedSharedWorld:
    """Independent cooperative resource enforcer; calls no F1/F3 replay helper."""

    def __init__(
        self,
        initial,
        *,
        transform=None,
        fail_at=None,
        extra_per_accept=0,
        force_guard_mode=None,
        observe_return=None,
    ):
        self.consumed = initial.consumed
        self.declared_limit = initial.declared_limit
        self.per_op_cap = initial.per_op_cap
        self.version = initial.version
        self.snapshots = {}
        self.calls = []
        self.returned = []
        self.transform = transform
        self.fail_at = fail_at
        self.extra_per_accept = extra_per_accept
        self.force_guard_mode = force_guard_mode
        self.observe_return = observe_return

    def step(self, bound, micro_step, operation):
        self.calls.append(micro_step)
        if len(self.calls) == self.fail_at:
            raise RuntimeError("untrusted transport detail must not escape")
        if micro_step.step_kind is StepKind.OBSERVE:
            guard_passed = operation.amount <= self.per_op_cap and (
                operation.guard is ConcurrencyGuard.PER_OPERATION_CAP
                or self.consumed + operation.amount <= self.declared_limit
            )
            self.snapshots[operation.operation_ref] = (self.version, guard_passed)
            return self.observe_return
        observed_version, guard_passed = self.snapshots.pop(operation.operation_ref)
        guard_mode = self.force_guard_mode or operation.guard_mode
        accepted = guard_passed
        if guard_mode is ConcurrencyGuardMode.COMMIT_TIME_CAS:
            accepted = (
                accepted
                and self.version == observed_version
                and self.consumed + operation.amount <= self.declared_limit
            )
        accepted = (
            accepted
            and self.consumed + operation.amount <= MAX_RESOURCE_VALUE
            and self.version < MAX_RESOURCE_VALUE
        )
        if accepted:
            self.consumed += operation.amount + self.extra_per_accept
            self.version += 1
        response = ConcurrencyObservedResponse(
            binding_ref=bound.binding_id,
            operation_ref=operation.operation_ref,
            operation_id=operation.operation_id,
            index=len(self.calls) - 1,
            status=(
                ConcurrencyObservedStatus.ACCEPTED
                if accepted
                else ConcurrencyObservedStatus.REFUSED
            ),
            state=ConcurrencyObservedState(self.consumed, self.declared_limit),
        )
        self.returned.append(response)
        return self.transform(response) if self.transform else response


def _bind_fixture(fixture):
    template, _ = binding()
    contract = fixture.contract
    capture = replace(
        template.capture,
        contract_ref=contract.contract_id,
        world_binding_refs=tuple(world.binding_id for world in fixture.worlds),
        actor_refs=tuple(world.persona_ref for world in fixture.worlds),
        resource_ref=contract.resource_ref,
        tenant_ref=contract.tenant_ref,
        tenant_ownership_ref=contract.tenant_ownership_ref,
        operation_ids=tuple(op.operation_id for op in contract.operations),
        source_evidence_refs=tuple(
            stable_hash("source_evidence", index)
            for index in range(len(contract.operations))
        ),
    )
    return ConcurrencyInvariantBinding.build(fixture=fixture, capture=capture)


def _fixture_with(base, *, initial_state=None, operations=None):
    original = base.contract
    contract = ConcurrencyInvariantContract.build(
        resource_ref=original.resource_ref,
        tenant_ref=original.tenant_ref,
        tenant_ownership_ref=original.tenant_ownership_ref,
        initial_state=initial_state or original.initial_state,
        operations=operations or original.operations,
        max_actors=original.max_actors,
    )
    return ConcurrencyOwnedFixture(
        contract, base.worlds, base.world_tenant_ref, base.world_tenant_ownership_ref
    )


def execute(*, secure=False, limit=1, guard=None, **target_options):
    if guard is None:
        bound, schedule = binding(secure=secure, limit=limit)
    else:
        fixture, schedule = case(secure=secure, limit=limit, guard=guard)
        bound = _bind_fixture(fixture)
    target = FakeOwnedSharedWorld(
        bound.fixture.contract.initial_state, **target_options
    )
    result = run_concurrency_effect(bound, bound.capture, schedule, target, at_index=10)
    return bound, schedule, target, result


def assert_invalid(result, attempts):
    assert result.correspondence is ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
    assert result.evidence is None
    assert result.transport_attempts == attempts


@pytest.mark.parametrize(
    "secure,limit,consumed,oracle,outcome,race,statuses",
    [
        (
            False,
            1,
            2,
            ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION,
            ConcurrencyOutcome.INVARIANT_VIOLATED,
            True,
            (ConcurrencyObservedStatus.ACCEPTED, ConcurrencyObservedStatus.ACCEPTED),
        ),
        (
            True,
            1,
            1,
            ConcurrencyEffectOutcome.EFFECT_ABSENT,
            ConcurrencyOutcome.OPERATION_REFUSED,
            False,
            (ConcurrencyObservedStatus.ACCEPTED, ConcurrencyObservedStatus.REFUSED),
        ),
        (
            False,
            2,
            2,
            ConcurrencyEffectOutcome.EFFECT_ABSENT,
            ConcurrencyOutcome.INVARIANT_HELD,
            False,
            (ConcurrencyObservedStatus.ACCEPTED, ConcurrencyObservedStatus.ACCEPTED),
        ),
    ],
)
def test_canonical_twins_and_boundary(
    secure, limit, consumed, oracle, outcome, race, statuses
):
    bound, schedule, target, result = execute(secure=secure, limit=limit)
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    evidence = result.evidence
    assert type(evidence) is ConcurrencyEffectEvidence
    assert evidence.model == evaluate_schedule(
        bound, bound.capture, schedule, at_index=10
    )
    assert evidence.model.decision.outcome is outcome
    assert evidence.model.decision.race_confirmed is race
    assert evidence.oracle_outcome is oracle
    assert evidence.observed_terminal_state.consumed == consumed == target.consumed
    assert type(evidence.observed_terminal_state) is ConcurrencyObservedState
    assert evidence.observed_terminal_state is evidence.responses[-1].state
    assert (
        evidence.observed_terminal_state is not evidence.model.decision.terminal_state
    )
    assert tuple(response.status for response in evidence.responses) == statuses
    assert tuple(response.index for response in evidence.responses) == (2, 3)
    assert target.calls == list(schedule.steps)
    assert result.transport_attempts == evidence.transport_attempts == 4
    payload = evidence.to_dict()
    assert payload["race_confirmed"] is race
    assert payload["hermetic_fake_target_only"] is True
    for key in (
        "real_concurrency_effect_observed",
        "finding_authority",
        "promotion_authority",
        "executable",
    ):
        assert payload[key] is False
    assert payload["target_requests_sent"] == 0
    assert evidence.evidence_id == stable_hash(
        "concurrency_effect_evidence", evidence._payload()
    )


def test_serially_unsafe_guard_has_effect_but_no_race_fact():
    _, _, target, result = execute(guard=ConcurrencyGuard.PER_OPERATION_CAP)
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert target.consumed == 2
    assert (
        result.evidence.oracle_outcome
        is ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION
    )
    assert (
        result.evidence.model.decision.outcome is ConcurrencyOutcome.INVARIANT_VIOLATED
    )
    assert result.evidence.model.decision.race_confirmed is False
    assert result.evidence.to_dict()["race_confirmed"] is False


@pytest.mark.parametrize("secure", [False, True])
def test_target_enforcement_discriminates_model_twins(secure):
    opposite = (
        ConcurrencyGuardMode.OBSERVE_TIME_ONLY
        if secure
        else ConcurrencyGuardMode.COMMIT_TIME_CAS
    )
    _, _, target, result = execute(secure=secure, force_guard_mode=opposite)
    assert_invalid(result, 4)
    assert target.consumed == (2 if secure else 1)


@pytest.mark.parametrize("secure,reported", [(False, 0), (True, 2)])
def test_divergent_observation_fails_correspondence_both_ways(secure, reported):
    def contradict(response):
        return replace(response, state=ConcurrencyObservedState(reported, 1))

    bound, schedule, target, result = execute(secure=secure, transform=contradict)
    model = evaluate_schedule(bound, bound.capture, schedule, at_index=10).decision
    observed = observed_effect_oracle(
        bound.fixture.contract.invariant, ConcurrencyObservedState(reported, 1)
    )
    assert (
        check_effect_correspondence(model, observed)
        is ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
    )
    assert_invalid(result, 4)
    assert len(target.calls) == 4


def test_observed_terminal_is_never_replaced_with_modeled_terminal():
    _, _, target, result = execute(extra_per_accept=1)
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert result.evidence.observed_terminal_state.consumed == target.consumed == 4
    assert result.evidence.model.decision.terminal_state.consumed == 2
    assert (
        result.evidence.oracle_outcome
        is ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION
    )


@pytest.mark.parametrize("consumed", [0, 1, 2])
def test_oracle_has_no_model_classifier_guard_replay_or_baseline_dependency(
    monkeypatch, consumed
):
    def fail(*_, **__):
        pytest.fail("observed oracle consulted the model channel")

    for owner, names in (
        (
            contract_module,
            (
                "classify_schedule",
                "replay_schedule",
                "operation_guard",
                "apply_commit",
                "serial_schedules",
                "is_serializable_safe",
                "evaluate_invariant",
            ),
        ),
        (ledger_module, ("append_step", "evaluate_schedule", "replay_schedule")),
        (module, ("append_step", "evaluate_schedule")),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, fail)
    verdict = observed_effect_oracle(
        ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT,
        ConcurrencyObservedState(consumed, 1),
    )
    assert verdict is (
        ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION
        if consumed > 1
        else ConcurrencyEffectOutcome.EFFECT_ABSENT
    )


@pytest.mark.parametrize(
    "predicate,state",
    [
        ("consumed_within_declared_limit", ConcurrencyObservedState(2, 1)),
        (None, ConcurrencyObservedState(2, 1)),
        (
            ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT,
            SharedWorkflowState(2, 1, 1),
        ),
        (ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT, {"consumed": 2}),
        (ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT, None),
    ],
)
def test_oracle_refuses_model_state_and_untyped_inputs(predicate, state):
    assert (
        observed_effect_oracle(predicate, state) is ConcurrencyEffectOutcome.MALFORMED
    )


def test_oracle_revalidates_forged_live_observed_state():
    state = ConcurrencyObservedState(2, 1)
    object.__setattr__(state, "consumed", True)
    assert (
        observed_effect_oracle(
            ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT, state
        )
        is ConcurrencyEffectOutcome.MALFORMED
    )


@pytest.mark.parametrize("field", ["consumed", "declared_limit"])
@pytest.mark.parametrize("invalid", [-1, True, 1.0, "1", None, MAX_RESOURCE_VALUE + 1])
def test_observed_numeric_fields_are_exact_bounded_integers(field, invalid):
    with pytest.raises(ValueError, match="observed_state_invalid"):
        ConcurrencyObservedState(
            **{**{"consumed": 1, "declared_limit": 1}, field: invalid}
        )


def test_observed_records_roundtrip_addresses_snapshot_and_immutability():
    _, _, target, result = execute()
    evidence = result.evidence
    response = evidence.responses[0]
    assert response is not target.returned[0]
    assert response.state is not target.returned[0].state
    assert (
        ConcurrencyObservedState.from_dict(
            json.loads(json.dumps(response.state.to_dict()))
        )
        == response.state
    )
    assert (
        ConcurrencyObservedResponse.from_dict(
            json.loads(json.dumps(response.to_dict()))
        )
        == response
    )
    assert (
        ConcurrencyEffectEvidence.from_dict(json.loads(json.dumps(evidence.to_dict())))
        == evidence
    )
    assert response.response_id == stable_hash(
        "concurrency_observed_response", response._payload()
    )
    with pytest.raises(FrozenInstanceError):
        response.state.consumed = 0
    with pytest.raises(FrozenInstanceError):
        response.status = ConcurrencyObservedStatus.REFUSED


def test_later_transport_step_cannot_mutate_an_earlier_snapshot():
    bound, schedule = binding()
    target = FakeOwnedSharedWorld(bound.fixture.contract.initial_state)

    def mutate_first_on_last(response):
        if len(target.returned) == 2:
            object.__setattr__(target.returned[0].state, "consumed", 7)
        return response

    target.transform = mutate_first_on_last
    result = run_concurrency_effect(bound, bound.capture, schedule, target, at_index=10)
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert target.returned[0].state.consumed == 7
    assert result.evidence.responses[0].state.consumed == 1


@pytest.mark.parametrize(
    "mutation", ["state_id", "response_id", "state", "status", "schema", "extra"]
)
def test_serialized_observations_refuse_tampering(mutation):
    _, _, _, result = execute()
    value = result.evidence.responses[0].to_dict()
    if mutation == "state_id":
        value["state"]["state_id"] = stable_hash("concurrency_observed_state", "wrong")
    elif mutation == "response_id":
        value["response_id"] = stable_hash("concurrency_observed_response", "wrong")
    elif mutation == "state":
        value["state"]["consumed"] = 0
    elif mutation == "status":
        value["status"] = "refused"
    elif mutation == "schema":
        value["schema_version"] = True
    else:
        value["finding_authority"] = True
    with pytest.raises(ValueError):
        ConcurrencyObservedResponse.from_dict(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("hermetic_fake_target_only", False),
        ("real_concurrency_effect_observed", True),
        ("target_requests_sent", 1),
        ("target_requests_sent", False),
        ("finding_authority", True),
        ("promotion_authority", True),
        ("executable", True),
        ("race_confirmed", False),
    ],
)
def test_evidence_flags_refuse_serialized_tampering(field, value):
    _, _, _, result = execute()
    payload = result.evidence.to_dict()
    payload[field] = value
    with pytest.raises(ValueError):
        ConcurrencyEffectEvidence.from_dict(payload)


@pytest.mark.parametrize(
    "mutation",
    [
        "untyped",
        "none",
        "binding",
        "operation_ref",
        "operation_id",
        "index",
        "limit",
        "status",
        "state_type",
        "forged_numeric",
    ],
)
def test_invalid_observation_stops_before_next_micro_step(mutation):
    def corrupt(response):
        if mutation == "untyped":
            return response.to_dict()
        if mutation == "none":
            return None
        if mutation == "forged_numeric":
            object.__setattr__(response.state, "consumed", True)
            return response
        changes = {
            "binding": {
                "binding_ref": stable_hash("concurrency_invariant_binding", "other")
            },
            "operation_ref": {
                "operation_ref": stable_hash("concurrency_operation", "other")
            },
            "operation_id": {
                "operation_id": stable_hash("concurrency_operation_contract", "other")
            },
            "index": {"index": 3},
            "limit": {"state": ConcurrencyObservedState(1, 2)},
            "status": {"status": "accepted"},
            "state_type": {"state": SharedWorkflowState(1, 1, 1)},
        }
        for field, value in changes[mutation].items():
            object.__setattr__(response, field, value)
        return response

    _, _, target, result = execute(transform=corrupt)
    assert_invalid(result, 3)
    assert len(target.calls) == 3


def test_observe_must_not_return_a_commit_response():
    _, _, target, result = execute(observe_return="unexpected")
    assert_invalid(result, 1)
    assert len(target.calls) == 1


def test_refusal_cannot_claim_resource_mutation():
    def mutate_on_refusal(response):
        if response.status is ConcurrencyObservedStatus.REFUSED:
            return replace(response, state=ConcurrencyObservedState(2, 1))
        return response

    _, _, target, result = execute(secure=True, transform=mutate_on_refusal)
    assert_invalid(result, 4)
    assert target.consumed == 1


@pytest.mark.parametrize("fail_at", [1, 3, 4])
def test_transport_exceptions_count_without_retry_or_evidence(fail_at):
    _, _, target, result = execute(fail_at=fail_at)
    assert_invalid(result, fail_at)
    assert len(target.calls) == fail_at


def test_partial_prefix_cannot_mint_positive_effect_evidence():
    _, _, target, result = execute(fail_at=4)
    assert_invalid(result, 4)
    assert target.consumed == 1


def test_observe_guard_refusal_is_reported_at_commit():
    base, _ = case()
    operations = tuple(replace(op, amount=2) for op in base.contract.operations)
    fixture = _fixture_with(base, operations=operations)
    bound = _bind_fixture(fixture)
    actors = tuple(op.actor_ref for op in operations)
    schedule = WorkflowSchedule(
        fixture.contract,
        tuple(
            MicroStep(actor, operation.operation_ref, kind)
            for kind in (StepKind.OBSERVE, StepKind.COMMIT)
            for actor, operation in zip(actors, operations)
        ),
    )
    target = FakeOwnedSharedWorld(fixture.contract.initial_state)
    result = run_concurrency_effect(bound, bound.capture, schedule, target, at_index=10)
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert result.transport_attempts == 4
    assert target.consumed == 0
    assert all(
        response.status is ConcurrencyObservedStatus.REFUSED
        for response in result.evidence.responses
    )
    assert (
        result.evidence.model.decision.outcome is ConcurrencyOutcome.OPERATION_REFUSED
    )


def test_resource_overflow_refusal_is_observed_without_violation():
    base, original_schedule = case(
        limit=MAX_RESOURCE_VALUE, guard=ConcurrencyGuard.PER_OPERATION_CAP
    )
    fixture = _fixture_with(
        base,
        initial_state=SharedWorkflowState(MAX_RESOURCE_VALUE, MAX_RESOURCE_VALUE, 1),
    )
    bound = _bind_fixture(fixture)
    schedule = WorkflowSchedule(fixture.contract, original_schedule.steps)
    target = FakeOwnedSharedWorld(fixture.contract.initial_state)
    result = run_concurrency_effect(bound, bound.capture, schedule, target, at_index=10)
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert result.transport_attempts == 4
    assert (
        result.evidence.model.decision.outcome is ConcurrencyOutcome.OPERATION_REFUSED
    )
    assert result.evidence.oracle_outcome is ConcurrencyEffectOutcome.EFFECT_ABSENT
    assert result.evidence.observed_terminal_state.consumed == MAX_RESOURCE_VALUE
    assert all(
        response.status is ConcurrencyObservedStatus.REFUSED
        for response in result.evidence.responses
    )


def test_maximum_schedule_is_ordered_and_attempt_bounded():
    base, _ = case(limit=MAX_CONCURRENCY_OPERATIONS)
    operations = tuple(
        replace(
            original,
            operation_ref=stable_hash(
                "concurrency_operation", f"{actor_index}-{index}"
            ),
            op_index=index,
        )
        for actor_index, original in enumerate(base.contract.operations)
        for index in range(MAX_CONCURRENCY_OPERATIONS // 2)
    )
    fixture = _fixture_with(base, operations=operations)
    bound = _bind_fixture(fixture)
    schedule = WorkflowSchedule(
        fixture.contract,
        tuple(
            MicroStep(operation.actor_ref, operation.operation_ref, kind)
            for operation in operations
            for kind in (StepKind.OBSERVE, StepKind.COMMIT)
        ),
    )
    target = FakeOwnedSharedWorld(fixture.contract.initial_state)
    result = run_concurrency_effect(bound, bound.capture, schedule, target, at_index=10)
    assert result.correspondence is ConcurrencyEffectCorrespondence.COHERENT
    assert result.transport_attempts == len(target.calls) == MAX_SCHEDULE_STEPS
    assert target.calls == list(schedule.steps)
    assert result.evidence.model.decision.outcome is ConcurrencyOutcome.INVARIANT_HELD
    assert (
        result.evidence.observed_terminal_state.consumed == MAX_CONCURRENCY_OPERATIONS
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "binding_type",
        "forged_binding",
        "capture_type",
        "capture_changed",
        "stale",
        "index_type",
        "transport",
        "schedule_type",
        "schedule_changed",
        "program_order",
    ],
)
def test_invalid_admission_stops_before_transport(mutation):
    bound, schedule = binding()
    current, index = bound.capture, 10
    target = FakeOwnedSharedWorld(bound.fixture.contract.initial_state)
    transport = target
    if mutation == "binding_type":
        bound = bound.to_dict()
    elif mutation == "forged_binding":
        object.__setattr__(
            bound, "binding_id", stable_hash("concurrency_invariant_binding", "forged")
        )
    elif mutation == "capture_type":
        current = None
    elif mutation == "capture_changed":
        current = replace(
            current,
            capture_generation_ref=stable_hash(
                "concurrency_capture_generation", "other"
            ),
        )
    elif mutation == "stale":
        index = 20
    elif mutation == "index_type":
        index = True
    elif mutation == "transport":
        transport = object()
    elif mutation == "schedule_type":
        schedule = schedule.to_dict()
    elif mutation == "schedule_changed":
        other, schedule = binding(secure=True)
        assert other.fixture.contract != bound.fixture.contract
    else:
        object.__setattr__(schedule, "steps", schedule.steps[::-1])
    result = run_concurrency_effect(bound, current, schedule, transport, at_index=index)
    assert_invalid(result, 0)
    assert target.calls == []


@pytest.mark.parametrize("gate", ["evaluate_schedule", "append_step"])
def test_runner_uses_f3_admission_before_transport(monkeypatch, gate):
    def deny(*_, **__):
        raise ValueError("injected F3 admission refusal")

    monkeypatch.setattr(module, gate, deny)
    _, _, target, result = execute()
    assert_invalid(result, 0)
    assert target.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        "attempts",
        "responses_type",
        "missing",
        "duplicate",
        "order",
        "cross_model",
        "forged_result",
    ],
)
def test_coherent_evidence_revalidates_order_model_and_attempt_accounting(mutation):
    _, _, _, result = execute()
    evidence = result.evidence
    changes = {
        "attempts": {"transport_attempts": True},
        "responses_type": {"responses": list(evidence.responses)},
        "missing": {"responses": evidence.responses[:1]},
        "duplicate": {"responses": (evidence.responses[0],) * 2},
        "order": {"responses": evidence.responses[::-1]},
    }
    if mutation == "cross_model":
        other, schedule = binding(secure=True)
        changes[mutation] = {
            "model": evaluate_schedule(other, other.capture, schedule, at_index=10)
        }
    elif mutation == "forged_result":
        object.__setattr__(evidence, "transport_attempts", 1)
        with pytest.raises(ValueError):
            ConcurrencyEffectResult(4, evidence)
        return
    with pytest.raises(ValueError):
        replace(evidence, **changes[mutation])


@pytest.mark.parametrize(
    "input_kind",
    [
        "untyped_model",
        "untyped_observed",
        "malformed_model",
        "malformed_observed",
        "forged_model",
    ],
)
def test_correspondence_refuses_malformed_or_forged_inputs(input_kind):
    bound, schedule = binding()
    model = evaluate_schedule(bound, bound.capture, schedule, at_index=10).decision
    observed = ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION
    if input_kind == "untyped_model":
        model = model.to_dict()
    elif input_kind == "untyped_observed":
        observed = observed.value
    elif input_kind == "malformed_model":
        model = classify_schedule(None, None, None)
    elif input_kind == "malformed_observed":
        observed = ConcurrencyEffectOutcome.MALFORMED
    else:
        object.__setattr__(model.terminal_state, "consumed", True)
    assert (
        check_effect_correspondence(model, observed)
        is ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
    )


def _imports(tree):
    names = set()
    relatives = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            (relatives if node.level else names).add(root)
    return names, relatives


def test_effect_is_unwired_and_has_only_allowed_imports():
    path = Path(module.__file__)
    names, relatives = _imports(ast.parse(path.read_text()))
    assert not names & FORBIDDEN
    assert names <= {"__future__", "dataclasses", "enum", "typing"}
    assert relatives <= {
        "concurrency_invariant_contract",
        "concurrency_invariant_binding",
        "concurrency_invariant_ledger",
        "normalize",
    }
    allowed = {
        REPOSITORY / "core/behavior" / f"concurrency_invariant_{suffix}.py"
        for suffix in (
            "contract",
            "binding",
            "ledger",
            "store",
            "evidence",
            "effect",
            "effect_transport",
        )
    }
    consumers = find_module_consumers(
        (REPOSITORY / "core").rglob("*.py"),
        "core.behavior.concurrency_invariant_effect",
        repository_root=REPOSITORY,
        exclude=allowed,
    )
    assert consumers == ()


@pytest.mark.parametrize(
    "stem", ["unrelated_consumer", "concurrency_invariant_effect_extra"]
)
def test_consumer_audit_rejects_injected_import(monkeypatch, stem):
    added = REPOSITORY / "core/behavior" / f"{stem}.py"
    original_rglob, original_read = Path.rglob, Path.read_text

    def with_consumer(path, pattern):
        yield from original_rglob(path, pattern)
        if path == REPOSITORY / "core":
            yield added

    def read(path, *args, **kwargs):
        if path == added:
            return "from core.behavior import concurrency_invariant_effect\n"
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", with_consumer)
    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_effect_is_unwired_and_has_only_allowed_imports()


@pytest.mark.parametrize("forbidden", sorted(FORBIDDEN))
def test_effect_import_audit_rejects_each_forbidden_surface(monkeypatch, forbidden):
    path = Path(module.__file__)
    original_read = Path.read_text

    def read(candidate, *args, **kwargs):
        source = original_read(candidate, *args, **kwargs)
        return source + f"\nimport {forbidden}\n" if candidate == path else source

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_effect_is_unwired_and_has_only_allowed_imports()


def test_registry_contains_the_exact_additive_slice_record():
    path = default_registry_path(REPOSITORY)
    registry = IdentifierRegistry.load(path)
    assert "R5F6" in registry.canonical_ids
    records = json.loads(path.read_text())["canonical_ids"]
    index = next(i for i, record in enumerate(records) if record["id"] == "R5F6")
    assert records[index - 1]["id"] == "R5F5"
    assert records[index + 1]["id"] == "R5F7"
    assert records[index] == {
        "id": "R5F6",
        "kind": "slice",
        "description": "Independent concurrency-invariant effect-occurrence oracle over injected hermetic transport",
    }
