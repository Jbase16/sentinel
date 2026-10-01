"""R5F6: independent concurrency effect oracle over an injected hermetic transport.

This slice proves the oracle mechanism against an in-process owned fake shared
world. A schedule is walked cooperatively, one logical micro-step at a time;
there is no real concurrency or observed running-target effect. No concrete
transport, production caller, cleanup, receipt, or finding authority ships here.

Observed values are a separate input channel from the frozen F1/F3 model.
Content hashes bind records, not target truth. Attempts count calls into the
injected seam, including exceptions, and never represent network requests.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .concurrency_invariant_binding import (
    ConcurrencyCaptureProvenance,
    ConcurrencyInvariantBinding,
    validate_current_capture,
)
from .concurrency_invariant_contract import (
    MAX_SCHEDULE_STEPS,
    ConcurrencyDecision,
    ConcurrencyInvariantPredicate,
    ConcurrencyOperation,
    ConcurrencyOutcome,
    MicroStep,
    StepKind,
    WorkflowSchedule,
    _fields,
    _hash_ref,
    _integer,
    _revalidate,
)
from .concurrency_invariant_ledger import (
    ConcurrencyScheduleLedger,
    ConcurrencyScheduleResult,
    append_step,
    evaluate_schedule,
)
from .normalize import stable_hash

CONCURRENCY_INVARIANT_EFFECT_MODE = "concurrency_invariant_effect_hermetic_v1"


class ConcurrencyObservedStatus(str, Enum):
    ACCEPTED = "accepted"
    REFUSED = "refused"


class ConcurrencyEffectOutcome(str, Enum):
    EFFECT_OBSERVED_VIOLATION = "effect_observed_violation"
    EFFECT_ABSENT = "effect_absent"
    MALFORMED = "malformed"


class ConcurrencyEffectCorrespondence(str, Enum):
    COHERENT = "coherent"
    INVALID_EVIDENCE = "invalid_evidence"


@dataclass(frozen=True)
class ConcurrencyObservedState:
    """Transport-reported resource values, never a modeled SharedWorkflowState."""

    consumed: int
    declared_limit: int

    def __post_init__(self) -> None:
        if not _integer(self.consumed) or not _integer(self.declared_limit):
            raise ValueError("concurrency_observed_state_invalid")

    def _payload(self) -> dict[str, Any]:
        return {"consumed": self.consumed, "declared_limit": self.declared_limit}

    @property
    def state_id(self) -> str:
        return stable_hash("concurrency_observed_state", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "state_id": self.state_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyObservedState:
        value = _fields(value, {"state_id", "consumed", "declared_limit"})
        result = cls(value["consumed"], value["declared_limit"])
        if value["state_id"] != result.state_id:
            raise ValueError("concurrency_observed_state_address_mismatch")
        return result


@dataclass(frozen=True)
class ConcurrencyObservedResponse:
    """One transport-reported result for a COMMIT at its schedule-step index."""

    binding_ref: str
    operation_ref: str
    operation_id: str
    index: int
    status: ConcurrencyObservedStatus
    state: ConcurrencyObservedState

    def __post_init__(self) -> None:
        if (
            not _hash_ref(self.binding_ref, "concurrency_invariant_binding")
            or not _hash_ref(self.operation_ref, "concurrency_operation")
            or not _hash_ref(self.operation_id, "concurrency_operation_contract")
            or not _integer(self.index, 0, MAX_SCHEDULE_STEPS - 1)
            or type(self.status) is not ConcurrencyObservedStatus
            or type(self.state) is not ConcurrencyObservedState
        ):
            raise ValueError("concurrency_observed_response_invalid")
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
        return stable_hash("concurrency_observed_response", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "response_id": self.response_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyObservedResponse:
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
            ConcurrencyObservedStatus(value["status"]),
            ConcurrencyObservedState.from_dict(value["state"]),
        )
        if value["response_id"] != result.response_id:
            raise ValueError("concurrency_observed_response_address_mismatch")
        return result


class ConcurrencyTransport(Protocol):
    """Injected seam: OBSERVE returns None; COMMIT returns post-step observation."""

    def step(
        self,
        binding: ConcurrencyInvariantBinding,
        micro_step: MicroStep,
        operation: ConcurrencyOperation,
    ) -> ConcurrencyObservedResponse | None: ...


def observed_effect_oracle(
    predicate: ConcurrencyInvariantPredicate,
    terminal_state: ConcurrencyObservedState,
) -> ConcurrencyEffectOutcome:
    """Read only the observed terminal resource values, never model replay."""
    if (
        predicate is not ConcurrencyInvariantPredicate.CONSUMED_WITHIN_LIMIT
        or type(terminal_state) is not ConcurrencyObservedState
    ):
        return ConcurrencyEffectOutcome.MALFORMED
    try:
        _revalidate(terminal_state)
    except (TypeError, ValueError, AttributeError):
        return ConcurrencyEffectOutcome.MALFORMED
    return (
        ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION
        if terminal_state.consumed > terminal_state.declared_limit
        else ConcurrencyEffectOutcome.EFFECT_ABSENT
    )


def check_effect_correspondence(
    model: ConcurrencyDecision, observed: ConcurrencyEffectOutcome
) -> ConcurrencyEffectCorrespondence:
    """Reject malformed inputs and model/observation disagreement either way."""
    if (
        type(model) is not ConcurrencyDecision
        or type(observed) is not ConcurrencyEffectOutcome
        or observed is ConcurrencyEffectOutcome.MALFORMED
    ):
        return ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
    try:
        _revalidate(model)
    except (TypeError, ValueError, AttributeError):
        return ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
    if model.outcome is ConcurrencyOutcome.MALFORMED:
        return ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
    agrees = (model.outcome is ConcurrencyOutcome.INVARIANT_VIOLATED) == (
        observed is ConcurrencyEffectOutcome.EFFECT_OBSERVED_VIOLATION
    )
    return (
        ConcurrencyEffectCorrespondence.COHERENT
        if agrees
        else ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
    )


def _validate_response(
    binding: ConcurrencyInvariantBinding,
    operation: ConcurrencyOperation,
    index: int,
    response: ConcurrencyObservedResponse,
    applied_operation_refs: tuple[str, ...],
    observed_before: int,
) -> None:
    if type(response) is not ConcurrencyObservedResponse:
        raise ValueError("invalid_evidence")
    _revalidate(response)
    accepted = operation.operation_ref in applied_operation_refs
    if (
        response.binding_ref != binding.binding_id
        or response.operation_ref != operation.operation_ref
        or response.operation_id != operation.operation_id
        or response.index != index
        or response.state.declared_limit
        != binding.fixture.contract.initial_state.declared_limit
        or (response.status is ConcurrencyObservedStatus.ACCEPTED) != accepted
        or (
            response.status is ConcurrencyObservedStatus.REFUSED
            and response.state.consumed != observed_before
        )
    ):
        raise ValueError("invalid_evidence")


@dataclass(frozen=True)
class ConcurrencyEffectEvidence:
    """Ephemeral coherent hermetic evidence; no persistence or receipt authority."""

    model: ConcurrencyScheduleResult
    responses: tuple[ConcurrencyObservedResponse, ...]
    transport_attempts: int

    def __post_init__(self) -> None:
        if (
            type(self.model) is not ConcurrencyScheduleResult
            or type(self.responses) is not tuple
        ):
            raise ValueError("invalid_evidence")
        _revalidate(self.model)
        binding = self.model.ledger.binding
        contract = binding.fixture.contract
        schedule = WorkflowSchedule(contract, self.model.ledger.steps)
        expected = evaluate_schedule(
            binding, binding.capture, schedule, at_index=self.model.at_index
        )
        if (
            self.model != expected
            or not _integer(self.transport_attempts, 1, MAX_SCHEDULE_STEPS)
            or self.transport_attempts != len(schedule.steps)
        ):
            raise ValueError("invalid_evidence")
        commits = tuple(
            (index, contract_operation)
            for index, step in enumerate(schedule.steps)
            if step.step_kind is StepKind.COMMIT
            for contract_operation in contract.operations
            if contract_operation.operation_ref == step.operation_ref
        )
        if len(self.responses) != len(commits):
            raise ValueError("invalid_evidence")
        observed_before = contract.initial_state.consumed
        for response, (index, operation) in zip(self.responses, commits):
            _validate_response(
                binding,
                operation,
                index,
                response,
                self.model.decision.applied_operation_refs,
                observed_before,
            )
            observed_before = response.state.consumed
        if (
            check_effect_correspondence(self.model.decision, self.oracle_outcome)
            is not ConcurrencyEffectCorrespondence.COHERENT
        ):
            raise ValueError("invalid_evidence")

    @property
    def observed_terminal_state(self) -> ConcurrencyObservedState:
        return self.responses[-1].state

    @property
    def oracle_outcome(self) -> ConcurrencyEffectOutcome:
        return observed_effect_oracle(
            self.model.ledger.binding.fixture.contract.invariant,
            self.observed_terminal_state,
        )

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": CONCURRENCY_INVARIANT_EFFECT_MODE,
            "model": self.model.to_dict(),
            "responses": [response.to_dict() for response in self.responses],
            "transport_attempts": self.transport_attempts,
            "observed_terminal_state": self.observed_terminal_state.to_dict(),
            "oracle_outcome": self.oracle_outcome.value,
            "correspondence": ConcurrencyEffectCorrespondence.COHERENT.value,
            "race_confirmed": self.model.decision.race_confirmed,
            "hermetic_fake_target_only": True,
            "real_concurrency_effect_observed": False,
            "target_requests_sent": 0,
            "finding_authority": False,
            "promotion_authority": False,
            "executable": False,
        }

    @property
    def evidence_id(self) -> str:
        return stable_hash("concurrency_effect_evidence", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "evidence_id": self.evidence_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyEffectEvidence:
        value = _fields(
            value,
            {
                "evidence_id",
                "mode",
                "model",
                "responses",
                "transport_attempts",
                "observed_terminal_state",
                "oracle_outcome",
                "correspondence",
                "race_confirmed",
                "hermetic_fake_target_only",
                "real_concurrency_effect_observed",
                "target_requests_sent",
                "finding_authority",
                "promotion_authority",
                "executable",
            },
        )
        if type(value["responses"]) is not list:
            raise ValueError("invalid_evidence")
        result = cls(
            ConcurrencyScheduleResult.from_dict(value["model"]),
            tuple(
                ConcurrencyObservedResponse.from_dict(item)
                for item in value["responses"]
            ),
            value["transport_attempts"],
        )
        flags = {
            "race_confirmed": result.model.decision.race_confirmed,
            "hermetic_fake_target_only": True,
            "real_concurrency_effect_observed": False,
            "finding_authority": False,
            "promotion_authority": False,
            "executable": False,
        }
        if (
            any(value[key] is not expected for key, expected in flags.items())
            or type(value["target_requests_sent"]) is not int
            or value["target_requests_sent"] != 0
            or ConcurrencyObservedState.from_dict(value["observed_terminal_state"])
            != result.observed_terminal_state
            or value != result.to_dict()
        ):
            raise ValueError("invalid_evidence")
        return result


@dataclass(frozen=True)
class ConcurrencyEffectResult:
    transport_attempts: int
    evidence: ConcurrencyEffectEvidence | None = None

    def __post_init__(self) -> None:
        if not _integer(self.transport_attempts, 0, MAX_SCHEDULE_STEPS):
            raise ValueError("invalid_evidence")
        if self.evidence is not None:
            if type(self.evidence) is not ConcurrencyEffectEvidence:
                raise ValueError("invalid_evidence")
            _revalidate(self.evidence)
            if self.transport_attempts != self.evidence.transport_attempts:
                raise ValueError("invalid_evidence")

    @property
    def correspondence(self) -> ConcurrencyEffectCorrespondence:
        return (
            ConcurrencyEffectCorrespondence.COHERENT
            if self.evidence is not None
            else ConcurrencyEffectCorrespondence.INVALID_EVIDENCE
        )


def run_concurrency_effect(
    binding: ConcurrencyInvariantBinding,
    current_capture: ConcurrencyCaptureProvenance,
    schedule: WorkflowSchedule,
    transport: ConcurrencyTransport,
    *,
    at_index: int,
) -> ConcurrencyEffectResult:
    """Walk one admitted schedule; no retries, resume, real concurrency, or I/O."""
    attempts = 0
    try:
        validate_current_capture(binding, current_capture, at_index)
        if not callable(getattr(transport, "step", None)):
            raise ValueError("invalid_evidence")
        model = evaluate_schedule(binding, current_capture, schedule, at_index=at_index)
        contract = binding.fixture.contract
        operations = {op.operation_ref: op for op in contract.operations}
        ledger = ConcurrencyScheduleLedger(binding)
        responses: tuple[ConcurrencyObservedResponse, ...] = ()
        observed_before = contract.initial_state.consumed
        for index, micro_step in enumerate(schedule.steps):
            ledger = append_step(
                binding, current_capture, ledger, micro_step, at_index=at_index
            )
            operation = operations[micro_step.operation_ref]
            attempts += 1
            response = transport.step(binding, micro_step, operation)
            if micro_step.step_kind is StepKind.OBSERVE:
                if response is not None:
                    raise ValueError("invalid_evidence")
                continue
            _validate_response(
                binding,
                operation,
                index,
                response,
                model.decision.applied_operation_refs,
                observed_before,
            )
            # Snapshot now so a later micro-step cannot mutate this observation.
            response = ConcurrencyObservedResponse.from_dict(response.to_dict())
            responses += (response,)
            observed_before = response.state.consumed
        if ledger != model.ledger:
            raise ValueError("invalid_evidence")
        evidence = ConcurrencyEffectEvidence(model, responses, attempts)
        return ConcurrencyEffectResult(attempts, evidence)
    except Exception:
        # Raw errors, forged records and partial prefixes never mint evidence.
        return ConcurrencyEffectResult(attempts)
