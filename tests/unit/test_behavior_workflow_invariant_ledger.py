"""Focused R5E3 sequentiality, replay, budget and terminal-state proof."""

from dataclasses import replace
import json

import pytest

from core.behavior.normalize import stable_hash
from core.behavior.workflow_invariant_contract import WorkflowInvariantOutcome
from core.behavior.workflow_invariant_binding import (
    WorkflowBindingDenied,
    WorkflowInvariantBinding,
)
from core.behavior.workflow_invariant_ledger import (
    WorkflowLedgerDenied,
    WorkflowSequenceResult,
    WorkflowTransitionLedger,
    WorkflowTransitionOutcome,
    evaluate_operation,
    evaluate_sequence,
)
from tests.unit.test_behavior_workflow_invariant_binding import ORIGIN, binding


def apply(bound, ledger, index=0, at_index=10):
    return evaluate_operation(
        bound,
        bound.capture,
        bound.fixture.contract.operations[index],
        ledger,
        at_index=at_index,
    )


@pytest.mark.parametrize(
    "secure,outcome,count,consumed",
    [
        (False, WorkflowInvariantOutcome.INVARIANT_VIOLATED, 2, 12),
        (True, WorkflowInvariantOutcome.OPERATION_REFUSED, 1, 6),
    ],
)
def test_sequence_semantics_twins(secure, outcome, count, consumed):
    bound = binding(secure=secure)
    genesis = WorkflowTransitionLedger(bound)
    result = evaluate_sequence(bound, bound.capture, at_index=10, ledger=genesis)
    assert result.decision.outcome is outcome
    assert len(result.ledger.entries) == count
    assert result.ledger.terminal_state.consumed == consumed
    assert genesis.entries == ()


def test_first_application_is_immutable_and_replay_returns_exact_input():
    bound = binding()
    genesis = WorkflowTransitionLedger(bound)
    first = apply(bound, genesis)
    replay = apply(bound, first.ledger)
    assert first.outcome is WorkflowTransitionOutcome.FIRST_APPLICATION
    assert first.ledger is not genesis and genesis.entries == ()
    assert replay.outcome is WorkflowTransitionOutcome.REPLAY_REFUSED
    assert replay.ledger is first.ledger


def test_budget_is_whole_sequence_and_replay_precedes_exhaustion():
    bound = binding(budget=1)
    first = apply(bound, WorkflowTransitionLedger(bound))
    exhausted = apply(bound, first.ledger, index=1)
    replay = apply(bound, first.ledger)
    assert exhausted.outcome is WorkflowTransitionOutcome.BUDGET_EXHAUSTED
    assert replay.outcome is WorkflowTransitionOutcome.REPLAY_REFUSED
    assert exhausted.ledger is replay.ledger is first.ledger
    result = evaluate_sequence(bound, bound.capture, at_index=10)
    assert result.decision.reason_code == "sequence_budget_exhausted"


def test_secure_refusal_returns_same_ledger():
    bound = binding(secure=True)
    first = apply(bound, WorkflowTransitionLedger(bound))
    refused = apply(bound, first.ledger, index=1)
    assert refused.outcome is WorkflowTransitionOutcome.OPERATION_REFUSED
    assert refused.ledger is first.ledger


def test_out_of_order_refused_instead_of_becoming_family_b():
    bound = binding()
    with pytest.raises(WorkflowLedgerDenied, match="order"):
        apply(bound, WorkflowTransitionLedger(bound), index=1)


def test_resume_sequence_preserves_applied_prefix():
    bound = binding()
    prefix = apply(bound, WorkflowTransitionLedger(bound)).ledger
    result = evaluate_sequence(bound, bound.capture, at_index=11, ledger=prefix)
    assert result.ledger.entries[0] is prefix.entries[0]
    assert len(result.ledger.entries) == 2


def test_ledger_roundtrip_recomputes_transition_semantics():
    bound = binding()
    ledger = evaluate_sequence(bound, bound.capture, at_index=10).ledger
    assert (
        WorkflowTransitionLedger.from_dict(json.loads(json.dumps(ledger.to_dict())))
        == ledger
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "ledger_address",
        "entry_address",
        "state",
        "index",
        "duplicate",
        "operation",
        "authority",
    ],
)
def test_forged_serialized_ledger_is_refused(mutation):
    bound = binding()
    value = evaluate_sequence(bound, bound.capture, at_index=10).ledger.to_dict()
    if mutation == "ledger_address":
        value["ledger_id"] = stable_hash("workflow_transition_ledger", "forged")
    elif mutation == "entry_address":
        value["entries"][0]["entry_id"] = stable_hash(
            "workflow_transition_entry", "forged"
        )
    elif mutation == "state":
        value["entries"][0]["after_state"]["consumed"] = 5
    elif mutation == "index":
        value["entries"][0]["index"] = True
    elif mutation == "duplicate":
        value["entries"][1] = value["entries"][0]
    elif mutation == "operation":
        value["entries"][0]["operation_ref"] = stable_hash(
            "workflow_operation", "other"
        )
    else:
        value["executable"] = True
    with pytest.raises(ValueError):
        WorkflowTransitionLedger.from_dict(value)


def test_rehashed_false_transition_still_fails_closed():
    bound = binding()
    ledger = evaluate_sequence(bound, bound.capture, at_index=10).ledger
    wrong_state = replace(ledger.entries[0].after_state, consumed=5)
    wrong_entry = replace(ledger.entries[0], after_state=wrong_state)
    with pytest.raises(WorkflowLedgerDenied, match="transition"):
        WorkflowTransitionLedger(bound, (wrong_entry,))


@pytest.mark.parametrize(
    "mutation", ["stale", "other_binding", "forged_operation", "changed_capture"]
)
def test_context_failures_precede_application(mutation):
    bound = binding()
    ledger = WorkflowTransitionLedger(bound)
    operation = bound.fixture.contract.operations[0]
    current_capture, index = bound.capture, 10
    if mutation == "stale":
        index = 20
    elif mutation == "other_binding":
        bound = binding(suffix="bob")
        current_capture = bound.capture
        operation = bound.fixture.contract.operations[0]
    elif mutation == "forged_operation":
        operation = replace(operation, amount=5)
    else:
        current_capture = replace(
            current_capture,
            capture_generation_ref=stable_hash(
                "workflow_capture_generation", "changed"
            ),
        )
    with pytest.raises((WorkflowBindingDenied, WorkflowLedgerDenied)):
        evaluate_operation(bound, current_capture, operation, ledger, at_index=index)
    assert ledger.entries == ()


def test_recapture_does_not_reset_or_rebind_an_applied_ledger():
    bound = binding()
    ledger = apply(bound, WorkflowTransitionLedger(bound)).ledger
    changed = replace(
        bound.capture,
        capture_generation_ref=stable_hash("workflow_capture_generation", "new"),
    )
    renewed = WorkflowInvariantBinding.build(
        fixture=bound.fixture, capture=changed, target_origin=ORIGIN
    )
    with pytest.raises(WorkflowLedgerDenied, match="context"):
        evaluate_sequence(renewed, changed, at_index=11, ledger=ledger)


def test_partial_ledger_cannot_claim_a_completed_counterexample():
    bound = binding()
    complete = evaluate_sequence(bound, bound.capture, at_index=10)
    prefix = apply(bound, WorkflowTransitionLedger(bound)).ledger
    with pytest.raises(WorkflowLedgerDenied, match="terminal"):
        WorkflowSequenceResult(prefix, 10, complete.decision)
