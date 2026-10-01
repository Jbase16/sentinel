"""R5F3: passive, unwired immutable micro-step ledger and logical replay.

No production entry point imports this module. It adds no authority of any kind.
The evaluator runs a deterministic offline logical schedule, with no real
concurrency, threads, async execution, or clock. Its result is not independent
evidence of an observed target-side effect. Running-workflow effect proof and
native OCB-S22 are deferred to the active tail.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .concurrency_invariant_binding import (
    ConcurrencyCaptureProvenance,
    ConcurrencyInvariantBinding,
    validate_current_capture,
)
from .concurrency_invariant_contract import (
    MAX_SCHEDULE_STEPS,
    ConcurrencyDecision,
    ConcurrencyOutcome,
    MicroStep,
    StepKind,
    WorkflowSchedule,
    _fields,
    _passive_flags,
    _revalidate,
    replay_schedule,
)
from .normalize import stable_hash

CONCURRENCY_INVARIANT_LEDGER_MODE = "behavioral_concurrency_invariant_ledger_v1"


class ConcurrencyLedgerDenied(ValueError):
    """A micro-step would violate the exact declared actor program order."""


def _expected_actor_steps(
    binding: ConcurrencyInvariantBinding, actor_ref: str
) -> tuple[MicroStep, ...]:
    return tuple(
        MicroStep(actor_ref, op.operation_ref, kind)
        for op in binding.fixture.contract.operations
        if op.actor_ref == actor_ref
        for kind in (StepKind.OBSERVE, StepKind.COMMIT)
    )


@dataclass(frozen=True)
class ConcurrencyScheduleLedger:
    binding: ConcurrencyInvariantBinding
    steps: tuple[MicroStep, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not ConcurrencyInvariantBinding
            or type(self.steps) is not tuple
        ):
            raise ConcurrencyLedgerDenied("concurrency_ledger_types_invalid")
        _revalidate(self.binding)
        if len(self.steps) > min(
            MAX_SCHEDULE_STEPS, 2 * len(self.binding.fixture.contract.operations)
        ):
            raise ConcurrencyLedgerDenied("concurrency_ledger_length_invalid")
        by_actor: dict[str, list[MicroStep]] = {}
        actors = {op.actor_ref for op in self.binding.fixture.contract.operations}
        for step in self.steps:
            if type(step) is not MicroStep:
                raise ConcurrencyLedgerDenied("concurrency_ledger_step_type_invalid")
            _revalidate(step)
            if step.actor_ref not in actors:
                raise ConcurrencyLedgerDenied("concurrency_ledger_unknown_actor")
            by_actor.setdefault(step.actor_ref, []).append(step)
        for actor, actual in by_actor.items():
            expected = _expected_actor_steps(self.binding, actor)
            if tuple(actual) != expected[: len(actual)]:
                raise ConcurrencyLedgerDenied(
                    "concurrency_ledger_program_order_invalid"
                )

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": CONCURRENCY_INVARIANT_LEDGER_MODE,
            "binding": self.binding.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            **_passive_flags(),
        }

    @property
    def ledger_id(self) -> str:
        return stable_hash("concurrency_schedule_ledger", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "ledger_id": self.ledger_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyScheduleLedger:
        value = _fields(
            value, {"ledger_id", "mode", "binding", "steps", *_passive_flags()}
        )
        if type(value["steps"]) is not list:
            raise ConcurrencyLedgerDenied("concurrency_ledger_serialization_invalid")
        result = cls(
            ConcurrencyInvariantBinding.from_dict(value["binding"]),
            tuple(MicroStep.from_dict(step) for step in value["steps"]),
        )
        if value != result.to_dict():
            raise ConcurrencyLedgerDenied(
                "concurrency_ledger_address_or_flags_mismatch"
            )
        return result


def append_step(
    binding: ConcurrencyInvariantBinding,
    current_capture: ConcurrencyCaptureProvenance,
    ledger: ConcurrencyScheduleLedger,
    step: MicroStep,
    *,
    at_index: int,
) -> ConcurrencyScheduleLedger:
    """Return a new prefix only when this is the actor's exact next micro-step."""
    validate_current_capture(binding, current_capture, at_index)
    if type(ledger) is not ConcurrencyScheduleLedger or type(step) is not MicroStep:
        raise ConcurrencyLedgerDenied("concurrency_append_types_invalid")
    _revalidate(ledger)
    _revalidate(step)
    if ledger.binding.binding_id != binding.binding_id:
        raise ConcurrencyLedgerDenied("concurrency_append_binding_mismatch")
    return ConcurrencyScheduleLedger(binding, ledger.steps + (step,))


@dataclass(frozen=True)
class ConcurrencyScheduleResult:
    ledger: ConcurrencyScheduleLedger
    at_index: int
    decision: ConcurrencyDecision

    def __post_init__(self) -> None:
        if (
            type(self.ledger) is not ConcurrencyScheduleLedger
            or type(self.decision) is not ConcurrencyDecision
        ):
            raise ConcurrencyLedgerDenied("concurrency_result_types_invalid")
        _revalidate(self.ledger)
        _revalidate(self.decision)
        binding = self.ledger.binding
        validate_current_capture(binding, binding.capture, self.at_index)
        contract = binding.fixture.contract
        if len(self.ledger.steps) != 2 * len(contract.operations):
            raise ConcurrencyLedgerDenied("concurrency_result_incomplete_schedule")
        schedule = WorkflowSchedule(contract, self.ledger.steps)
        expected = replay_schedule(contract, contract.initial_state, schedule)
        if (
            self.decision != expected
            or self.decision.outcome is ConcurrencyOutcome.MALFORMED
        ):
            raise ConcurrencyLedgerDenied("concurrency_result_decision_mismatch")

    def _payload(self) -> dict[str, Any]:
        return {
            "ledger": self.ledger.to_dict(),
            "at_index": self.at_index,
            "decision": self.decision.to_dict(),
            **_passive_flags(),
        }

    @property
    def result_id(self) -> str:
        return stable_hash("concurrency_schedule_result", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "result_id": self.result_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyScheduleResult:
        value = _fields(
            value, {"result_id", "ledger", "at_index", "decision", *_passive_flags()}
        )
        result = cls(
            ConcurrencyScheduleLedger.from_dict(value["ledger"]),
            value["at_index"],
            ConcurrencyDecision.from_dict(value["decision"]),
        )
        if value != result.to_dict():
            raise ConcurrencyLedgerDenied(
                "concurrency_result_address_or_flags_mismatch"
            )
        return result


def evaluate_schedule(
    binding: ConcurrencyInvariantBinding,
    current_capture: ConcurrencyCaptureProvenance,
    schedule: WorkflowSchedule,
    *,
    at_index: int,
    ledger: ConcurrencyScheduleLedger | None = None,
) -> ConcurrencyScheduleResult:
    """Complete an exact schedule prefix, then reuse F1's sole replay engine."""
    validate_current_capture(binding, current_capture, at_index)
    if type(schedule) is not WorkflowSchedule:
        raise ConcurrencyLedgerDenied("concurrency_schedule_type_invalid")
    _revalidate(schedule)
    contract = binding.fixture.contract
    if schedule.contract != contract:
        raise ConcurrencyLedgerDenied("concurrency_schedule_contract_mismatch")
    current = ConcurrencyScheduleLedger(binding) if ledger is None else ledger
    if type(current) is not ConcurrencyScheduleLedger:
        raise ConcurrencyLedgerDenied("concurrency_ledger_type_invalid")
    _revalidate(current)
    if (
        current.binding.binding_id != binding.binding_id
        or current.steps != schedule.steps[: len(current.steps)]
    ):
        raise ConcurrencyLedgerDenied("concurrency_schedule_prefix_mismatch")
    for step in schedule.steps[len(current.steps) :]:
        current = append_step(
            binding, current_capture, current, step, at_index=at_index
        )
    return ConcurrencyScheduleResult(
        current,
        at_index,
        replay_schedule(contract, contract.initial_state, schedule),
    )
