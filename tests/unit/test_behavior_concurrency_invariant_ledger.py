"""R5F3 immutable micro-step prefixes, program order and single-engine replay."""

from copy import deepcopy

import pytest

from core.behavior.concurrency_invariant_contract import ConcurrencyOutcome
from core.behavior.concurrency_invariant_ledger import (
    ConcurrencyLedgerDenied,
    ConcurrencyScheduleLedger,
    ConcurrencyScheduleResult,
    append_step,
    evaluate_schedule,
)
from tests.unit.test_behavior_concurrency_invariant_binding import binding


def test_append_each_step_and_complete_race_result():
    bound, schedule = binding()
    ledger = ConcurrencyScheduleLedger(bound)
    snapshots = [ledger]
    for step in schedule.steps:
        ledger = append_step(bound, bound.capture, ledger, step, at_index=10)
        snapshots.append(ledger)
    assert snapshots[0].steps == ()
    assert all(len(value.steps) == index for index, value in enumerate(snapshots))
    result = ConcurrencyScheduleResult(
        ledger,
        10,
        evaluate_schedule(
            bound, bound.capture, schedule, at_index=10, ledger=ledger
        ).decision,
    )
    assert result.decision.outcome is ConcurrencyOutcome.INVARIANT_VIOLATED
    assert result.decision.race_confirmed is True
    assert ConcurrencyScheduleResult.from_dict(result.to_dict()) == result
    assert ConcurrencyScheduleLedger.from_dict(ledger.to_dict()) == ledger


def test_resume_exact_prefix_and_reject_replay_or_out_of_order_step():
    bound, schedule = binding()
    first = append_step(
        bound,
        bound.capture,
        ConcurrencyScheduleLedger(bound),
        schedule.steps[0],
        at_index=10,
    )
    resumed = evaluate_schedule(
        bound, bound.capture, schedule, at_index=10, ledger=first
    )
    fresh = evaluate_schedule(bound, bound.capture, schedule, at_index=10)
    assert resumed == fresh
    with pytest.raises(ConcurrencyLedgerDenied, match="program_order"):
        append_step(bound, bound.capture, first, schedule.steps[0], at_index=10)
    with pytest.raises(ConcurrencyLedgerDenied, match="program_order"):
        append_step(
            bound,
            bound.capture,
            ConcurrencyScheduleLedger(bound),
            schedule.steps[2],
            at_index=10,
        )
    with pytest.raises(ConcurrencyLedgerDenied, match="prefix"):
        evaluate_schedule(
            bound,
            bound.capture,
            schedule,
            at_index=10,
            ledger=ConcurrencyScheduleLedger(bound, (schedule.steps[1],)),
        )


def test_ledger_result_tamper_refusal():
    bound, schedule = binding()
    result = evaluate_schedule(bound, bound.capture, schedule, at_index=10)
    value = deepcopy(result.ledger.to_dict())
    value["backend_dispatch_authority"] = True
    with pytest.raises(ConcurrencyLedgerDenied):
        ConcurrencyScheduleLedger.from_dict(value)
    value = deepcopy(result.to_dict())
    value["result_id"] = result.ledger.ledger_id
    with pytest.raises(ConcurrencyLedgerDenied):
        ConcurrencyScheduleResult.from_dict(value)
    value = deepcopy(result.to_dict())
    value["decision"]["race_confirmed"] = False
    with pytest.raises(ValueError):
        ConcurrencyScheduleResult.from_dict(value)
