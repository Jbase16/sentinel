"""R5E6: independent workflow effect oracle over an injected hermetic transport.

Phase 1 proves the oracle mechanism and its structural independence hermetically,
against an in-process fake owned target. It is not yet evidence of an effect
against a real running workflow (that is Phase 2+). No cleanup/teardown authority,
no receipt authority, no finding promotion, no OCB-S21 claim is made or implied.

No concrete transport or production caller is provided. Observations are a separate
input channel from the frozen E1/E3 model; hashes bind records, not target truth.
Attempts count calls into the injected seam, including exceptions, not network
requests. Admission is bounded within one run; production admission, durable replay
prevention and independently authenticated acquisition remain deferred.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .normalize import stable_hash
from .workflow_invariant_binding import (
    WorkflowCaptureProvenance,
    WorkflowInvariantBinding,
    validate_current_capture,
)
from .workflow_invariant_contract import (
    MAX_WORKFLOW_OPERATIONS,
    WorkflowInvariantDecision,
    WorkflowInvariantOutcome,
    WorkflowInvariantPredicate,
    WorkflowOperation,
    _fields,
    _hash_ref,
    _integer,
    _revalidate,
    classify_sequence,
)
from .workflow_invariant_ledger import (
    WorkflowSequenceResult,
    WorkflowTransitionLedger,
    WorkflowTransitionOutcome,
    evaluate_operation,
)

WORKFLOW_INVARIANT_EFFECT_MODE = "workflow_invariant_effect_hermetic_v1"


class WorkflowObservedStatus(str, Enum):
    ACCEPTED = "accepted"
    REFUSED = "refused"


class WorkflowEffectOutcome(str, Enum):
    EFFECT_OBSERVED_VIOLATION = "effect_observed_violation"
    EFFECT_ABSENT = "effect_absent"
    MALFORMED = "malformed"


class WorkflowEffectCorrespondence(str, Enum):
    COHERENT = "coherent"
    INVALID_EVIDENCE = "invalid_evidence"


@dataclass(frozen=True)
class WorkflowObservedState:
    """Transport-reported values; never an E1/E3 modeled WorkflowState."""

    consumed: int
    declared_limit: int

    def __post_init__(self) -> None:
        if not _integer(self.consumed) or not _integer(self.declared_limit):
            raise ValueError("workflow_observed_state_invalid")

    def _payload(self) -> dict[str, Any]:
        return {"consumed": self.consumed, "declared_limit": self.declared_limit}

    @property
    def state_id(self) -> str:
        return stable_hash("workflow_observed_state", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "state_id": self.state_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowObservedState:
        value = _fields(value, {"state_id", "consumed", "declared_limit"})
        result = cls(value["consumed"], value["declared_limit"])
        if value["state_id"] != result.state_id:
            raise ValueError("workflow_observed_state_address_mismatch")
        return result


@dataclass(frozen=True)
class WorkflowObservedResponse:
    binding_ref: str
    operation_ref: str
    operation_id: str
    index: int
    status: WorkflowObservedStatus
    state: WorkflowObservedState

    def __post_init__(self) -> None:
        if (
            not _hash_ref(self.binding_ref, "workflow_invariant_binding")
            or not _hash_ref(self.operation_ref, "workflow_operation")
            or not _hash_ref(self.operation_id, "workflow_operation_contract")
            or not _integer(self.index, 0, MAX_WORKFLOW_OPERATIONS - 1)
            or type(self.status) is not WorkflowObservedStatus
            or type(self.state) is not WorkflowObservedState
        ):
            raise ValueError("workflow_observed_response_invalid")
        _revalidate(self.state)

    def _payload(self) -> dict[str, Any]:
        return {
            "binding_ref": self.binding_ref,
            "operation_ref": self.operation_ref,
            "operation_id": self.operation_id,
            "index": self.index,
            "status": self.status.value,
            "state": self.state.to_dict(),
        }

    @property
    def response_id(self) -> str:
        return stable_hash("workflow_observed_response", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "response_id": self.response_id,
            **self._payload(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowObservedResponse:
        value = _fields(
            value,
            {
                "response_id",
                "binding_ref",
                "operation_ref",
                "operation_id",
                "index",
                "status",
                "state",
            },
        )
        result = cls(
            value["binding_ref"],
            value["operation_ref"],
            value["operation_id"],
            value["index"],
            WorkflowObservedStatus(value["status"]),
            WorkflowObservedState.from_dict(value["state"]),
        )
        if value["response_id"] != result.response_id:
            raise ValueError("workflow_observed_response_address_mismatch")
        return result


class ExecutionTransport(Protocol):
    """Injected hermetic seam: attempt once and report observed post-operation state."""

    def attempt_operation(
        self, binding: WorkflowInvariantBinding, operation: WorkflowOperation
    ) -> WorkflowObservedResponse: ...


def observed_effect_oracle(
    predicate: WorkflowInvariantPredicate, terminal_state: WorkflowObservedState
) -> WorkflowEffectOutcome:
    """Read only the observed channel; no classifier, guard or transition calls."""
    if (
        predicate is not WorkflowInvariantPredicate.CONSUMED_WITHIN_LIMIT
        or type(terminal_state) is not WorkflowObservedState
    ):
        return WorkflowEffectOutcome.MALFORMED
    try:
        _revalidate(terminal_state)
    except (TypeError, ValueError, AttributeError):
        return WorkflowEffectOutcome.MALFORMED
    return (
        WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION
        if terminal_state.consumed > terminal_state.declared_limit
        else WorkflowEffectOutcome.EFFECT_ABSENT
    )


def check_effect_correspondence(
    model: WorkflowInvariantDecision, observed: WorkflowEffectOutcome
) -> WorkflowEffectCorrespondence:
    """Reject malformed inputs and disagreement in either direction."""
    if (
        type(model) is not WorkflowInvariantDecision
        or type(observed) is not WorkflowEffectOutcome
        or observed is WorkflowEffectOutcome.MALFORMED
    ):
        return WorkflowEffectCorrespondence.INVALID_EVIDENCE
    try:
        _revalidate(model)
    except (TypeError, ValueError, AttributeError):
        return WorkflowEffectCorrespondence.INVALID_EVIDENCE
    if model.outcome is WorkflowInvariantOutcome.MALFORMED:
        return WorkflowEffectCorrespondence.INVALID_EVIDENCE
    agrees = (model.outcome is WorkflowInvariantOutcome.INVARIANT_VIOLATED) == (
        observed is WorkflowEffectOutcome.EFFECT_OBSERVED_VIOLATION
    )
    return (
        WorkflowEffectCorrespondence.COHERENT
        if agrees
        else WorkflowEffectCorrespondence.INVALID_EVIDENCE
    )


def _validate_response(
    binding: WorkflowInvariantBinding,
    operation: WorkflowOperation,
    response: WorkflowObservedResponse,
    model_outcome: WorkflowTransitionOutcome,
    observed_before: int,
) -> None:
    if type(response) is not WorkflowObservedResponse:
        raise ValueError("invalid_evidence")
    _revalidate(response)
    if (
        response.binding_ref != binding.binding_id
        or response.operation_ref != operation.operation_ref
        or response.operation_id != operation.operation_id
        or response.index != operation.index
        or response.state.declared_limit
        != binding.fixture.contract.initial_state.declared_limit
        or model_outcome
        not in {
            WorkflowTransitionOutcome.FIRST_APPLICATION,
            WorkflowTransitionOutcome.OPERATION_REFUSED,
        }
        or (response.status is WorkflowObservedStatus.ACCEPTED)
        != (model_outcome is WorkflowTransitionOutcome.FIRST_APPLICATION)
        or (
            response.status is WorkflowObservedStatus.REFUSED
            and response.state.consumed != observed_before
        )
    ):
        raise ValueError("invalid_evidence")


@dataclass(frozen=True)
class WorkflowEffectEvidence:
    """Ephemeral coherent hermetic evidence; no persistence or receipt authority."""

    model: WorkflowSequenceResult
    responses: tuple[WorkflowObservedResponse, ...]
    transport_attempts: int

    def __post_init__(self) -> None:
        if (
            type(self.model) is not WorkflowSequenceResult
            or type(self.responses) is not tuple
            or not self.responses
        ):
            raise ValueError("invalid_evidence")
        _revalidate(self.model)
        binding = self.model.ledger.binding
        contract = binding.fixture.contract
        if (
            not _integer(self.transport_attempts, 1, contract.max_operations)
            or self.transport_attempts != len(self.responses)
            or len(self.responses) > len(contract.operations)
        ):
            raise ValueError("invalid_evidence")
        ledger = WorkflowTransitionLedger(binding)
        observed_before = contract.initial_state.consumed
        for index, response in enumerate(self.responses):
            operation = contract.operations[index]
            transition = evaluate_operation(
                binding,
                binding.capture,
                operation,
                ledger,
                at_index=self.model.at_index,
            )
            _validate_response(
                binding, operation, response, transition.outcome, observed_before
            )
            if (
                response.status is WorkflowObservedStatus.REFUSED
                and index != len(self.responses) - 1
            ):
                raise ValueError("invalid_evidence")
            observed_before = response.state.consumed
            ledger = transition.ledger
        if (
            ledger != self.model.ledger
            or check_effect_correspondence(self.model.decision, self.oracle_outcome)
            is not WorkflowEffectCorrespondence.COHERENT
        ):
            raise ValueError("invalid_evidence")

    @property
    def observed_terminal_state(self) -> WorkflowObservedState:
        return self.responses[-1].state

    @property
    def oracle_outcome(self) -> WorkflowEffectOutcome:
        return observed_effect_oracle(
            self.model.ledger.binding.fixture.contract.invariant,
            self.observed_terminal_state,
        )

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": WORKFLOW_INVARIANT_EFFECT_MODE,
            "model": self.model.to_dict(),
            "responses": [response.to_dict() for response in self.responses],
            "transport_attempts": self.transport_attempts,
            "observed_terminal_state": self.observed_terminal_state.to_dict(),
            "oracle_outcome": self.oracle_outcome.value,
            "correspondence": WorkflowEffectCorrespondence.COHERENT.value,
            "hermetic_fake_target_only": True,
            "real_workflow_effect_observed": False,
            "target_requests_sent": 0,
            "finding_authority": False,
            "promotion_authority": False,
            "executable": False,
        }

    @property
    def evidence_id(self) -> str:
        return stable_hash("workflow_effect_evidence", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "evidence_id": self.evidence_id,
            **self._payload(),
        }


@dataclass(frozen=True)
class WorkflowEffectResult:
    transport_attempts: int
    evidence: WorkflowEffectEvidence | None = None

    def __post_init__(self) -> None:
        if not _integer(self.transport_attempts, 0, MAX_WORKFLOW_OPERATIONS):
            raise ValueError("invalid_evidence")
        if self.evidence is not None:
            if type(self.evidence) is not WorkflowEffectEvidence:
                raise ValueError("invalid_evidence")
            _revalidate(self.evidence)
            if self.transport_attempts != self.evidence.transport_attempts:
                raise ValueError("invalid_evidence")

    @property
    def correspondence(self) -> WorkflowEffectCorrespondence:
        return (
            WorkflowEffectCorrespondence.COHERENT
            if self.evidence is not None
            else WorkflowEffectCorrespondence.INVALID_EVIDENCE
        )


def run_workflow_effect(
    binding: WorkflowInvariantBinding,
    current_capture: WorkflowCaptureProvenance,
    transport: ExecutionTransport,
    *,
    at_index: int,
) -> WorkflowEffectResult:
    """Run once in declared order; no retries, resume, default transport or network I/O."""
    attempts = 0
    try:
        validate_current_capture(binding, current_capture, at_index)
        if not callable(getattr(transport, "attempt_operation", None)):
            raise ValueError("invalid_evidence")
        contract = binding.fixture.contract
        ledger = WorkflowTransitionLedger(binding)
        responses: tuple[WorkflowObservedResponse, ...] = ()
        observed_before = contract.initial_state.consumed
        for operation in contract.operations:
            transition = evaluate_operation(
                binding, current_capture, operation, ledger, at_index=at_index
            )
            if transition.outcome is WorkflowTransitionOutcome.BUDGET_EXHAUSTED:
                break
            if (
                transition.outcome
                not in {
                    WorkflowTransitionOutcome.FIRST_APPLICATION,
                    WorkflowTransitionOutcome.OPERATION_REFUSED,
                }
                or attempts >= contract.max_operations
            ):
                raise ValueError("invalid_evidence")
            attempts += 1
            response = transport.attempt_operation(binding, operation)
            _validate_response(
                binding, operation, response, transition.outcome, observed_before
            )
            # Snapshot the observed record so a later call cannot alter prior data.
            response = WorkflowObservedResponse.from_dict(response.to_dict())
            responses += (response,)
            observed_before = response.state.consumed
            ledger = transition.ledger
            if (
                transition.outcome is WorkflowTransitionOutcome.OPERATION_REFUSED
                or response.status is WorkflowObservedStatus.REFUSED
            ):
                break
        model = WorkflowSequenceResult(
            ledger,
            at_index,
            classify_sequence(contract, contract.initial_state, contract.operations),
        )
        evidence = WorkflowEffectEvidence(model, responses, attempts)
        return WorkflowEffectResult(attempts, evidence)
    except Exception:
        # No raw exception, malformed response or partial prefix mints evidence.
        return WorkflowEffectResult(attempts)
