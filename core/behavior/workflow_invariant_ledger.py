"""R5E3: immutable sequential workflow ledger with pure transition semantics.

The exact contract order is preserved. Fresh owned provenance is required before
replay/budget/guard evaluation; replay precedes budget exhaustion. Refusals return
the same ledger, first applications return a new one. The ledger pins one binding
through the sequence: changing capture cannot reset already-applied operations.

Passive/unwired: no filesystem, clock, persistence, target traffic, transport,
finding or execution authority. No origin/identity/action/budget authority is
added. The fixture is disposable/reversible, cleanup unneeded, orphan-risk false.
The independent terminal predicate is a deterministic outcome evaluator, not
independent evidence of an observed target-side effect.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from .normalize import stable_hash
from .workflow_invariant_binding import (
    WorkflowCaptureProvenance,
    WorkflowInvariantBinding,
    validate_current_capture,
)
from .workflow_invariant_contract import (
    MAX_RESOURCE_VALUE,
    WorkflowInvariantDecision,
    WorkflowOperation,
    WorkflowState,
    _fields,
    _hash_ref,
    _integer,
    classify_sequence,
    operation_precondition,
    transition_state,
)

WORKFLOW_INVARIANT_LEDGER_MODE = "behavioral_workflow_invariant_ledger_v1"


class WorkflowLedgerDenied(ValueError):
    """The request/ledger cannot represent an admitted sequential workflow."""


class WorkflowTransitionOutcome(str, Enum):
    FIRST_APPLICATION = "first_application"
    REPLAY_REFUSED = "replay_refused"
    BUDGET_EXHAUSTED = "budget_exhausted"
    OPERATION_REFUSED = "operation_refused"


@dataclass(frozen=True)
class WorkflowTransitionEntry:
    operation_ref: str
    operation_id: str
    index: int
    before_state: WorkflowState
    after_state: WorkflowState

    def __post_init__(self) -> None:
        if (
            not _hash_ref(self.operation_ref, "workflow_operation")
            or not _hash_ref(self.operation_id, "workflow_operation_contract")
            or not _integer(self.index, 0, 63)
            or type(self.before_state) is not WorkflowState
            or type(self.after_state) is not WorkflowState
        ):
            raise WorkflowLedgerDenied("workflow_transition_entry_invalid")
        replace(self.before_state)
        replace(self.after_state)

    def _payload(self) -> dict[str, Any]:
        return {
            "operation_ref": self.operation_ref,
            "operation_id": self.operation_id,
            "index": self.index,
            "before_state": self.before_state.to_dict(),
            "after_state": self.after_state.to_dict(),
        }

    @property
    def entry_id(self) -> str:
        return stable_hash("workflow_transition_entry", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "entry_id": self.entry_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowTransitionEntry:
        value = _fields(
            value,
            {
                "entry_id",
                "operation_ref",
                "operation_id",
                "index",
                "before_state",
                "after_state",
            },
        )
        entry = cls(
            value["operation_ref"],
            value["operation_id"],
            value["index"],
            WorkflowState.from_dict(value["before_state"]),
            WorkflowState.from_dict(value["after_state"]),
        )
        if value["entry_id"] != entry.entry_id:
            raise WorkflowLedgerDenied("workflow_entry_address_mismatch")
        return entry


@dataclass(frozen=True)
class WorkflowTransitionLedger:
    binding: WorkflowInvariantBinding
    entries: tuple[WorkflowTransitionEntry, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not WorkflowInvariantBinding
            or type(self.entries) is not tuple
        ):
            raise WorkflowLedgerDenied("workflow_ledger_types_invalid")
        replace(self.binding)
        contract = self.binding.fixture.contract
        if len(self.entries) > min(contract.max_operations, len(contract.operations)):
            raise WorkflowLedgerDenied("workflow_ledger_budget_invalid")
        state = contract.initial_state
        for index, entry in enumerate(self.entries):
            if type(entry) is not WorkflowTransitionEntry:
                raise WorkflowLedgerDenied("workflow_ledger_entry_type_invalid")
            replace(entry)
            operation = contract.operations[index]
            if (
                entry.index != index
                or entry.operation_ref != operation.operation_ref
                or entry.operation_id != operation.operation_id
                or entry.before_state != state
                or not operation_precondition(state, operation)
                or entry.after_state != transition_state(state, operation)
            ):
                raise WorkflowLedgerDenied("workflow_ledger_transition_mismatch")
            state = entry.after_state

    @property
    def terminal_state(self) -> WorkflowState:
        return (
            self.entries[-1].after_state
            if self.entries
            else self.binding.fixture.contract.initial_state
        )

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": WORKFLOW_INVARIANT_LEDGER_MODE,
            "binding": self.binding.to_dict(),
            "entries": [entry.to_dict() for entry in self.entries],
            "target_requests_sent": 0,
            "executable": False,
        }

    @property
    def ledger_id(self) -> str:
        return stable_hash("workflow_transition_ledger", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "ledger_id": self.ledger_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowTransitionLedger:
        value = _fields(
            value,
            {
                "ledger_id",
                "mode",
                "binding",
                "entries",
                "target_requests_sent",
                "executable",
            },
        )
        if (
            value["mode"] != WORKFLOW_INVARIANT_LEDGER_MODE
            or type(value["entries"]) is not list
            or type(value["target_requests_sent"]) is not int
            or value["target_requests_sent"] != 0
            or value["executable"] is not False
        ):
            raise WorkflowLedgerDenied("workflow_ledger_serialization_invalid")
        result = cls(
            WorkflowInvariantBinding.from_dict(value["binding"]),
            tuple(
                WorkflowTransitionEntry.from_dict(entry) for entry in value["entries"]
            ),
        )
        if value["ledger_id"] != result.ledger_id:
            raise WorkflowLedgerDenied("workflow_ledger_address_mismatch")
        return result


@dataclass(frozen=True)
class WorkflowTransitionResult:
    outcome: WorkflowTransitionOutcome
    ledger: WorkflowTransitionLedger

    def __post_init__(self) -> None:
        if (
            type(self.outcome) is not WorkflowTransitionOutcome
            or type(self.ledger) is not WorkflowTransitionLedger
        ):
            raise WorkflowLedgerDenied("workflow_transition_result_invalid")
        replace(self.ledger)


def evaluate_operation(
    binding: WorkflowInvariantBinding,
    current_capture: WorkflowCaptureProvenance,
    operation: WorkflowOperation,
    ledger: WorkflowTransitionLedger,
    *,
    at_index: int,
) -> WorkflowTransitionResult:
    validate_current_capture(binding, current_capture, at_index)
    if (
        type(ledger) is not WorkflowTransitionLedger
        or type(operation) is not WorkflowOperation
    ):
        raise WorkflowLedgerDenied("workflow_transition_types_invalid")
    replace(ledger)
    replace(operation)
    contract = binding.fixture.contract
    if (
        ledger.binding.binding_id != binding.binding_id
        or operation.index >= len(contract.operations)
        or operation != contract.operations[operation.index]
    ):
        raise WorkflowLedgerDenied("workflow_sequence_context_mismatch")
    if any(entry.operation_ref == operation.operation_ref for entry in ledger.entries):
        return WorkflowTransitionResult(
            WorkflowTransitionOutcome.REPLAY_REFUSED, ledger
        )
    if operation.index != len(ledger.entries):
        raise WorkflowLedgerDenied("workflow_operation_order_mismatch")
    if len(ledger.entries) >= contract.max_operations:
        return WorkflowTransitionResult(
            WorkflowTransitionOutcome.BUDGET_EXHAUSTED, ledger
        )
    state = ledger.terminal_state
    if (
        not operation_precondition(state, operation)
        or state.consumed + operation.amount > MAX_RESOURCE_VALUE
    ):
        return WorkflowTransitionResult(
            WorkflowTransitionOutcome.OPERATION_REFUSED, ledger
        )
    entry = WorkflowTransitionEntry(
        operation.operation_ref,
        operation.operation_id,
        operation.index,
        state,
        transition_state(state, operation),
    )
    return WorkflowTransitionResult(
        WorkflowTransitionOutcome.FIRST_APPLICATION,
        WorkflowTransitionLedger(binding, ledger.entries + (entry,)),
    )


@dataclass(frozen=True)
class WorkflowSequenceResult:
    ledger: WorkflowTransitionLedger
    at_index: int
    decision: WorkflowInvariantDecision

    def __post_init__(self) -> None:
        if (
            type(self.ledger) is not WorkflowTransitionLedger
            or type(self.decision) is not WorkflowInvariantDecision
        ):
            raise WorkflowLedgerDenied("workflow_sequence_result_invalid")
        replace(self.ledger)
        replace(self.decision)
        binding = self.ledger.binding
        validate_current_capture(binding, binding.capture, self.at_index)
        contract = binding.fixture.contract
        expected = classify_sequence(
            contract, contract.initial_state, contract.operations
        )
        if (
            self.decision != expected
            or self.decision.terminal_state != self.ledger.terminal_state
            or self.decision.applied_operation_refs
            != tuple(entry.operation_ref for entry in self.ledger.entries)
        ):
            raise WorkflowLedgerDenied("workflow_sequence_terminal_mismatch")

    def _payload(self) -> dict[str, Any]:
        return {
            "ledger": self.ledger.to_dict(),
            "at_index": self.at_index,
            "decision": self.decision.to_dict(),
        }

    @property
    def result_id(self) -> str:
        return stable_hash("workflow_sequence_result", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "result_id": self.result_id, **self._payload()}


def evaluate_sequence(
    binding: WorkflowInvariantBinding,
    current_capture: WorkflowCaptureProvenance,
    *,
    at_index: int,
    ledger: WorkflowTransitionLedger | None = None,
) -> WorkflowSequenceResult:
    """Complete/resume the exact ordered sequence using the one transition seam."""
    validate_current_capture(binding, current_capture, at_index)
    current = WorkflowTransitionLedger(binding) if ledger is None else ledger
    if type(current) is not WorkflowTransitionLedger:
        raise WorkflowLedgerDenied("workflow_sequence_ledger_invalid")
    replace(current)
    if current.binding.binding_id != binding.binding_id:
        raise WorkflowLedgerDenied("workflow_sequence_context_mismatch")
    contract = binding.fixture.contract
    for operation in contract.operations[len(current.entries) :]:
        transition = evaluate_operation(
            binding, current_capture, operation, current, at_index=at_index
        )
        current = transition.ledger
        if transition.outcome is not WorkflowTransitionOutcome.FIRST_APPLICATION:
            break
    return WorkflowSequenceResult(
        current,
        at_index,
        classify_sequence(contract, contract.initial_state, contract.operations),
    )
