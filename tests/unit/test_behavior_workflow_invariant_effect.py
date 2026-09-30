"""R5E6 hermetic twins, independent observation, correspondence and admission proof."""

import ast
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path

import pytest

from core.behavior import workflow_invariant_contract as contract_module
from core.behavior import workflow_invariant_effect as module
from core.behavior import workflow_invariant_ledger as ledger_module
from core.behavior.normalize import stable_hash
from core.behavior.workflow_invariant_contract import (
    MAX_RESOURCE_VALUE,
    WorkflowInvariantOutcome,
    WorkflowInvariantPredicate,
    WorkflowState,
    classify_sequence,
)
from core.behavior.workflow_invariant_effect import (
    WorkflowEffectCorrespondence,
    WorkflowEffectEvidence,
    WorkflowEffectOutcome,
    WorkflowEffectResult,
    WorkflowObservedResponse,
    WorkflowObservedState,
    WorkflowObservedStatus,
    check_effect_correspondence,
    observed_effect_oracle,
    run_workflow_effect,
)
from core.behavior.workflow_invariant_ledger import evaluate_sequence
from core.contracts.architecture_ids import IdentifierRegistry, default_registry_path
from tests.unit.test_behavior_workflow_invariant_binding import binding
from tests.unit.test_behavior_workflow_invariant_evidence import (
    test_all_five_layers_are_unwired_and_have_no_target_imports as spine_import_audit,
)


class FakeOwnedTarget:
    """Only transport implementation: independent in-process resource enforcement."""

    def __init__(
        self,
        initial,
        *,
        aggregate_cap=False,
        transform=None,
        fail_at=None,
        extra_per_accept=0,
    ):
        self.consumed = initial.consumed
        self.declared_limit = initial.declared_limit
        self.per_op_cap = initial.per_op_cap
        self.aggregate_cap = aggregate_cap
        self.transform = transform
        self.fail_at = fail_at
        self.extra_per_accept = extra_per_accept
        self.calls = []
        self.returned = []

    def attempt_operation(self, bound, operation):
        self.calls.append(operation.operation_ref)
        if len(self.calls) == self.fail_at:
            raise RuntimeError("untrusted transport detail must not escape")
        # No model evaluator, precondition enum, twin label or modeled state reads.
        accepted = (
            operation.amount <= self.per_op_cap
            and self.consumed + operation.amount <= MAX_RESOURCE_VALUE
            and (
                not self.aggregate_cap
                or self.consumed + operation.amount <= self.declared_limit
            )
        )
        if accepted:
            self.consumed += operation.amount + self.extra_per_accept
        response = WorkflowObservedResponse(
            binding_ref=bound.binding_id,
            operation_ref=operation.operation_ref,
            operation_id=operation.operation_id,
            index=operation.index,
            status=(
                WorkflowObservedStatus.ACCEPTED
                if accepted
                else WorkflowObservedStatus.REFUSED
            ),
            state=WorkflowObservedState(self.consumed, self.declared_limit),
        )
        self.returned.append(response)
        return self.transform(response) if self.transform else response


def execute(*, secure=False, amounts=(6, 6), budget=4, initial=None, **target_options):
    bound = binding(secure=secure, amounts=amounts, budget=budget, initial=initial)
    target = FakeOwnedTarget(
        bound.fixture.contract.initial_state,
        aggregate_cap=secure,
        **target_options,
    )
    result = run_workflow_effect(bound, bound.capture, target, at_index=10)
    return bound, target, result


def assert_invalid(result, attempts):
    assert result.correspondence is WorkflowEffectCorrespondence.INVALID_EVIDENCE
    assert result.correspondence.value == "invalid_evidence"
    assert result.evidence is None
    assert result.transport_attempts == attempts


@pytest.mark.parametrize(
    "secure,amounts,consumed,oracle,model,statuses",
    [
        (
            False,
            (6, 6),
            12,
            WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION,
            WorkflowInvariantOutcome.INVARIANT_VIOLATED,
            (WorkflowObservedStatus.ACCEPTED, WorkflowObservedStatus.ACCEPTED),
        ),
        (
            True,
            (6, 6),
            6,
            WorkflowEffectOutcome.EFFECT_ABSENT,
            WorkflowInvariantOutcome.OPERATION_REFUSED,
            (WorkflowObservedStatus.ACCEPTED, WorkflowObservedStatus.REFUSED),
        ),
        (
            True,
            (4, 6),
            10,
            WorkflowEffectOutcome.EFFECT_ABSENT,
            WorkflowInvariantOutcome.INVARIANT_HELD,
            (WorkflowObservedStatus.ACCEPTED, WorkflowObservedStatus.ACCEPTED),
        ),
    ],
)
def test_canonical_twins_and_secure_boundary(
    secure, amounts, consumed, oracle, model, statuses
):
    bound, target, result = execute(secure=secure, amounts=amounts)
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    evidence = result.evidence
    assert type(evidence) is WorkflowEffectEvidence
    assert evidence.model.decision.outcome is model
    assert evidence.model == evaluate_sequence(bound, bound.capture, at_index=10)
    assert evidence.oracle_outcome is oracle
    assert evidence.observed_terminal_state.consumed == consumed == target.consumed
    assert type(evidence.observed_terminal_state) is WorkflowObservedState
    assert evidence.observed_terminal_state is evidence.responses[-1].state
    assert (
        evidence.observed_terminal_state is not evidence.model.decision.terminal_state
    )
    assert tuple(response.status for response in evidence.responses) == statuses
    assert tuple(response.index for response in evidence.responses) == (0, 1)
    assert target.calls == [
        op.operation_ref for op in bound.fixture.contract.operations
    ]
    assert len(set(target.calls)) == len(target.calls)
    assert result.transport_attempts == evidence.transport_attempts == len(target.calls)
    assert result.transport_attempts <= bound.fixture.contract.max_operations
    payload = evidence.to_dict()
    assert payload["hermetic_fake_target_only"] is True
    for key in (
        "real_workflow_effect_observed",
        "finding_authority",
        "promotion_authority",
        "executable",
    ):
        assert payload[key] is False
    assert payload["target_requests_sent"] == 0
    assert evidence.evidence_id == stable_hash(
        "workflow_effect_evidence", evidence._payload()
    )


@pytest.mark.parametrize("secure,reported_consumed", [(False, 0), (True, 12)])
def test_divergent_observation_fails_correspondence_in_both_directions(
    secure, reported_consumed
):
    def contradict(response):
        return replace(response, state=WorkflowObservedState(reported_consumed, 10))

    bound, target, result = execute(secure=secure, transform=contradict)
    model = evaluate_sequence(bound, bound.capture, at_index=10).decision
    observed = observed_effect_oracle(
        bound.fixture.contract.invariant, WorkflowObservedState(reported_consumed, 10)
    )
    assert (
        check_effect_correspondence(model, observed)
        is WorkflowEffectCorrespondence.INVALID_EVIDENCE
    )
    assert_invalid(result, 2)
    assert len(target.calls) == 2


@pytest.mark.parametrize("secure", [False, True])
def test_actual_target_enforcement_discriminates_twins(secure):
    bound = binding(secure=secure)
    target = FakeOwnedTarget(
        bound.fixture.contract.initial_state, aggregate_cap=not secure
    )
    result = run_workflow_effect(bound, bound.capture, target, at_index=10)
    assert_invalid(result, 2)
    assert target.consumed == (12 if secure else 6)


def test_observed_terminal_is_never_replaced_with_modeled_terminal():
    _, target, result = execute(extra_per_accept=1)
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    assert result.evidence.observed_terminal_state.consumed == target.consumed == 14
    assert result.evidence.model.decision.terminal_state.consumed == 12
    assert (
        result.evidence.oracle_outcome
        is WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION
    )


@pytest.mark.parametrize("consumed", [0, 10, 12])
def test_oracle_has_no_model_classifier_guard_or_transition_dependency(
    monkeypatch, consumed
):
    def fail(*_, **__):
        pytest.fail("the observed oracle consulted the model channel")

    for owner, names in (
        (
            contract_module,
            (
                "classify_sequence",
                "evaluate_invariant",
                "operation_precondition",
                "transition_state",
            ),
        ),
        (
            ledger_module,
            (
                "classify_sequence",
                "operation_precondition",
                "transition_state",
                "evaluate_operation",
            ),
        ),
        (module, ("classify_sequence", "evaluate_operation")),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, fail)
    observed = WorkflowObservedState(consumed, 10)
    verdict = observed_effect_oracle(
        WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT, observed
    )
    assert verdict is (
        WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION
        if consumed > 10
        else WorkflowEffectOutcome.EFFECT_ABSENT
    )


@pytest.mark.parametrize(
    "predicate,state",
    [
        ("consumed_within_declared_limit", WorkflowObservedState(12, 10)),
        (None, WorkflowObservedState(12, 10)),
        (WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT, WorkflowState(12, 10, 6)),
        (
            WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT,
            {"consumed": 12, "declared_limit": 10},
        ),
        (WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT, None),
    ],
)
def test_oracle_refuses_model_state_and_untyped_inputs(predicate, state):
    assert observed_effect_oracle(predicate, state) is WorkflowEffectOutcome.MALFORMED


def test_oracle_revalidates_a_forged_live_observed_value():
    state = WorkflowObservedState(12, 10)
    object.__setattr__(state, "consumed", True)
    assert (
        observed_effect_oracle(WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT, state)
        is WorkflowEffectOutcome.MALFORMED
    )


@pytest.mark.parametrize("field", ["consumed", "declared_limit"])
@pytest.mark.parametrize("invalid", [-1, True, 1.0, "1", None, MAX_RESOURCE_VALUE + 1])
def test_observed_numeric_fields_are_exact_bounded_integers(field, invalid):
    with pytest.raises(ValueError, match="observed_state_invalid"):
        WorkflowObservedState(
            **{**{"consumed": 6, "declared_limit": 10}, field: invalid}
        )


def test_observed_records_roundtrip_content_addresses_and_are_immutable():
    _, target, result = execute()
    response = result.evidence.responses[0]
    assert response is not target.returned[0]
    assert response.state is not target.returned[0].state
    assert (
        WorkflowObservedState.from_dict(
            json.loads(json.dumps(response.state.to_dict()))
        )
        == response.state
    )
    assert (
        WorkflowObservedResponse.from_dict(json.loads(json.dumps(response.to_dict())))
        == response
    )
    assert response.response_id == stable_hash(
        "workflow_observed_response", response._payload()
    )
    with pytest.raises(FrozenInstanceError):
        response.state.consumed = 0
    with pytest.raises(FrozenInstanceError):
        response.status = WorkflowObservedStatus.REFUSED


@pytest.mark.parametrize(
    "mutation", ["state_id", "response_id", "state", "status", "schema", "extra"]
)
def test_serialized_observations_refuse_tampering(mutation):
    _, _, result = execute()
    value = result.evidence.responses[0].to_dict()
    if mutation == "state_id":
        value["state"]["state_id"] = stable_hash("workflow_observed_state", "forged")
    elif mutation == "response_id":
        value["response_id"] = stable_hash("workflow_observed_response", "forged")
    elif mutation == "state":
        value["state"]["consumed"] = 0
    elif mutation == "status":
        value["status"] = "refused"
    elif mutation == "schema":
        value["schema_version"] = True
    else:
        value["finding_authority"] = True
    with pytest.raises(ValueError):
        WorkflowObservedResponse.from_dict(value)


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
def test_invalid_observations_stop_before_another_attempt(mutation):
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
                "binding_ref": stable_hash("workflow_invariant_binding", "other")
            },
            "operation_ref": {
                "operation_ref": stable_hash("workflow_operation", "other")
            },
            "operation_id": {
                "operation_id": stable_hash("workflow_operation_contract", "other")
            },
            "index": {"index": 1},
            "limit": {"state": WorkflowObservedState(6, 100)},
            "status": {"status": "accepted"},
            "state_type": {"state": WorkflowState(6, 10, 6)},
        }
        for field, value in changes[mutation].items():
            object.__setattr__(response, field, value)
        return response

    _, target, result = execute(transform=corrupt)
    assert_invalid(result, 1)
    assert len(target.calls) == 1


def test_refusal_cannot_claim_a_resource_mutation():
    def mutate_on_refusal(response):
        if response.status is WorkflowObservedStatus.REFUSED:
            return replace(response, state=WorkflowObservedState(7, 10))
        return response

    _, target, result = execute(secure=True, transform=mutate_on_refusal)
    assert_invalid(result, 2)
    assert target.consumed == 6


@pytest.mark.parametrize("fail_at", [1, 2])
def test_transport_exceptions_are_counted_without_retry_or_evidence(fail_at):
    _, target, result = execute(fail_at=fail_at)
    assert_invalid(result, fail_at)
    assert len(target.calls) == fail_at


@pytest.mark.parametrize("secure", [False, True])
def test_admission_stops_before_transport_when_allowance_is_exhausted(secure):
    bound, target, result = execute(secure=secure, budget=1)
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    assert result.transport_attempts == len(target.calls) == 1
    assert result.evidence.model.decision.reason_code == "sequence_budget_exhausted"
    assert result.evidence.observed_terminal_state.consumed == 6
    assert result.evidence.oracle_outcome is WorkflowEffectOutcome.EFFECT_ABSENT
    assert target.calls == [bound.fixture.contract.operations[0].operation_ref]


def test_incomplete_budget_prefix_cannot_mint_positive_effect_evidence():
    _, target, result = execute(amounts=(6, 6, 6), budget=2)
    assert_invalid(result, 2)
    assert target.consumed == 12


def test_guard_refusal_counts_as_an_attempt_and_stops_the_sequence():
    _, target, result = execute(amounts=(7, 6))
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    assert result.transport_attempts == len(target.calls) == 1
    assert result.evidence.model.decision.reason_code == "precondition_refused"
    assert result.evidence.observed_terminal_state.consumed == 0


def test_resource_overflow_refusal_is_observed_without_minting_a_violation():
    _, target, result = execute(
        initial=WorkflowState(MAX_RESOURCE_VALUE, MAX_RESOURCE_VALUE, 6)
    )
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    assert result.transport_attempts == 1
    assert result.evidence.model.decision.reason_code == "resource_value_exhausted"
    assert (
        result.evidence.observed_terminal_state.consumed
        == target.consumed
        == MAX_RESOURCE_VALUE
    )


def test_maximum_declared_sequence_is_ordered_and_bounded():
    bound, target, result = execute(secure=True, amounts=(0,) * 64, budget=64)
    assert result.correspondence is WorkflowEffectCorrespondence.COHERENT
    assert result.transport_attempts == len(target.calls) == 64
    assert target.calls == [
        operation.operation_ref for operation in bound.fixture.contract.operations
    ]
    assert result.evidence.observed_terminal_state.consumed == 0


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
    ],
)
def test_invalid_admission_contexts_fail_before_transport(mutation):
    bound = binding()
    current, index = bound.capture, 10
    target = FakeOwnedTarget(bound.fixture.contract.initial_state)
    transport = target
    if mutation == "binding_type":
        bound = bound.to_dict()
    elif mutation == "forged_binding":
        object.__setattr__(
            bound, "binding_id", stable_hash("workflow_invariant_binding", "forged")
        )
    elif mutation == "capture_type":
        current = None
    elif mutation == "capture_changed":
        current = replace(
            current,
            capture_generation_ref=stable_hash("workflow_capture_generation", "other"),
        )
    elif mutation == "stale":
        index = 20
    elif mutation == "index_type":
        index = True
    else:
        transport = object()
    result = run_workflow_effect(bound, current, transport, at_index=index)
    assert_invalid(result, 0)
    assert target.calls == []


def test_runner_uses_e3_evaluate_operation_before_transport(monkeypatch):
    def deny(*_, **__):
        raise ValueError("injected E3 admission refusal")

    monkeypatch.setattr(module, "evaluate_operation", deny)
    _, target, result = execute()
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
    _, _, result = execute()
    evidence = result.evidence
    changes = {
        "attempts": {"transport_attempts": True},
        "responses_type": {"responses": list(evidence.responses)},
        "missing": {"responses": evidence.responses[:1], "transport_attempts": 1},
        "duplicate": {"responses": (evidence.responses[0],) * 2},
        "order": {"responses": evidence.responses[::-1]},
    }
    if mutation == "cross_model":
        other = binding(secure=True)
        changes[mutation] = {
            "model": evaluate_sequence(other, other.capture, at_index=10)
        }
    elif mutation == "forged_result":
        object.__setattr__(evidence, "transport_attempts", 1)
        with pytest.raises(ValueError):
            WorkflowEffectResult(2, evidence)
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
def test_correspondence_cannot_accept_malformed_or_forged_inputs(input_kind):
    bound = binding()
    model = evaluate_sequence(bound, bound.capture, at_index=10).decision
    observed = WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION
    if input_kind == "untyped_model":
        model = model.to_dict()
    elif input_kind == "untyped_observed":
        observed = observed.value
    elif input_kind == "malformed_model":
        model = classify_sequence(None, None, None)
    elif input_kind == "malformed_observed":
        observed = WorkflowEffectOutcome.MALFORMED
    else:
        object.__setattr__(model.terminal_state, "consumed", True)
    assert (
        check_effect_correspondence(model, observed)
        is WorkflowEffectCorrespondence.INVALID_EVIDENCE
    )


def _import_references(tree):
    references = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            references.update((node.module or "").split("."))
            references.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            references.update(
                part for alias in node.names for part in alias.name.split(".")
            )
    return references


def test_effect_is_unwired_and_has_no_production_or_transport_imports():
    repository = Path(__file__).resolve().parents[2]
    forbidden = {
        "httpx",
        "requests",
        "socket",
        "asyncio",
        "subprocess",
        "time",
        "foundry",
        "submission_candidate",
        "capability_effect_promotion",
    }
    effect_path = repository / "core/behavior/workflow_invariant_effect.py"
    assert not _import_references(ast.parse(effect_path.read_text())) & forbidden
    family = {
        f"workflow_invariant_{suffix}"
        for suffix in ("contract", "binding", "ledger", "store", "evidence", "effect")
    }
    family.add("workflow_invariant_effect_transport")
    consumers = []
    for path in (repository / "core").rglob("*.py"):
        if path.stem in family:
            continue
        if "workflow_invariant_effect" in _import_references(
            ast.parse(path.read_text())
        ):
            consumers.append(str(path))
    assert consumers == []


@pytest.mark.parametrize(
    "stem", ["unrelated_consumer", "workflow_invariant_effect_extra"]
)
@pytest.mark.parametrize(
    "audit,imported",
    [
        (spine_import_audit, "workflow_invariant_contract"),
        (
            test_effect_is_unwired_and_has_no_production_or_transport_imports,
            "workflow_invariant_effect",
        ),
    ],
)
def test_import_audits_reject_every_other_consumer(monkeypatch, stem, audit, imported):
    repository = Path(__file__).resolve().parents[2]
    added = repository / "core/behavior" / f"{stem}.py"
    original_rglob, original_read = Path.rglob, Path.read_text

    def with_consumer(path, pattern):
        yield from original_rglob(path, pattern)
        if path == repository / "core":
            yield added

    def read(path, *args, **kwargs):
        if path == added:
            return f"from core.behavior import {imported}\n"
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", with_consumer)
    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        audit()


@pytest.mark.parametrize(
    "forbidden",
    [
        "httpx",
        "requests",
        "socket",
        "asyncio",
        "subprocess",
        "time",
        "foundry",
        "submission_candidate",
        "capability_effect_promotion",
    ],
)
def test_effect_import_audit_rejects_each_forbidden_surface(monkeypatch, forbidden):
    effect_path = Path(module.__file__)
    original_read = Path.read_text

    def read(path, *args, **kwargs):
        text = original_read(path, *args, **kwargs)
        return text + f"\nimport {forbidden}\n" if path == effect_path else text

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_effect_is_unwired_and_has_no_production_or_transport_imports()


def test_registry_contains_the_exact_additive_slice_record():
    repository = Path(__file__).resolve().parents[2]
    path = default_registry_path(repository)
    registry = IdentifierRegistry.load(path)
    assert "R5E6" in registry.canonical_ids
    records = json.loads(path.read_text())["canonical_ids"]
    assert [record for record in records if record["id"] == "R5E6"] == [
        {
            "id": "R5E6",
            "kind": "slice",
            "description": "Independent workflow-invariant effect-occurrence oracle over injected hermetic transport",
        }
    ]
