"""Real-clock composition into a passive capability-execution receipt decision.

R5D6 reads one wall-clock instant, delegates all time classification to R5D5, and
composes that liveness verdict with an already-computed R5D3 consumption verdict.
The result is an ephemeral, content-addressed terminal decision.  It performs no
persistence, target dispatch, effect evaluation, finding promotion, or cleanup and
remains production-unwired.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Callable, Dict

from .capability_consumption_ledger import ConsumptionDecision, ConsumptionOutcome
from .capability_contract import CapabilityDecision, _hash_ref
from .capability_runtime_expiry import (
    AdmittedRuntimeContract,
    RuntimeLivenessDecision,
    RuntimeLivenessOutcome,
    evaluate_runtime_liveness,
)
from .normalize import stable_hash


CAPABILITY_EXECUTION_RECEIPT_MODE = "behavioral_capability_execution_receipt_v1"


class RuntimeExecutionDenied(RuntimeError):
    """The supplied execution context cannot support a terminal receipt decision."""


class CapabilityExecutionOutcome(str, Enum):
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_REFUSED_INADMISSIBLE = "execution_refused_inadmissible"
    EXECUTION_REFUSED_ALREADY_CONSUMED = "execution_refused_already_consumed"
    EXECUTION_REFUSED_EXPIRED = "execution_refused_expired"
    EXECUTION_REFUSED_NOT_LIVE = "execution_refused_not_live"


def _canonical_epoch(value: object) -> str:
    if type(value) is not float or not math.isfinite(value):
        raise ValueError("execution receipt epoch must be a finite float")
    return repr(value)


def _execution_outcome(
    liveness_decision: RuntimeLivenessDecision,
    consumption_decision: ConsumptionDecision,
) -> CapabilityExecutionOutcome:
    if liveness_decision.outcome is RuntimeLivenessOutcome.LOGICALLY_INADMISSIBLE:
        return CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE
    if consumption_decision.outcome in {
        ConsumptionOutcome.REPLAYED_PRESENTATION,
        ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED,
    }:
        return CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED
    if liveness_decision.outcome is RuntimeLivenessOutcome.EXPIRED_AT_RUNTIME:
        return CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED
    if liveness_decision.outcome is RuntimeLivenessOutcome.NOT_YET_LIVE:
        return CapabilityExecutionOutcome.EXECUTION_REFUSED_NOT_LIVE
    if (
        liveness_decision.outcome is RuntimeLivenessOutcome.ADMITTED_LIVE
        and consumption_decision.outcome is ConsumptionOutcome.FIRST_CONSUMPTION
    ):
        return CapabilityExecutionOutcome.EXECUTION_COMPLETED
    raise RuntimeExecutionDenied("execution_decision_combination_is_invalid")


def _receipt_payload(
    *,
    capability_ref: str,
    liveness_ref: str,
    consumption_ref: str,
    observed_epoch: float,
    outcome: CapabilityExecutionOutcome,
    mode: str,
) -> Dict[str, Any]:
    return {
        "capability_ref": capability_ref,
        "liveness_ref": liveness_ref,
        "consumption_ref": consumption_ref,
        "observed_epoch": _canonical_epoch(observed_epoch),
        "outcome": outcome.value,
        "mode": mode,
    }


@dataclass(frozen=True)
class CapabilityExecutionReceipt:
    """An instant-specific terminal decision with no target or persistence authority."""

    receipt_id: str
    capability_ref: str
    liveness_ref: str
    consumption_ref: str
    observed_epoch: float
    outcome: CapabilityExecutionOutcome
    _liveness_decision: RuntimeLivenessDecision = field(repr=False, compare=False)
    _consumption_decision: ConsumptionDecision = field(repr=False, compare=False)
    mode: str = CAPABILITY_EXECUTION_RECEIPT_MODE
    target_dispatch_authority: bool = False
    execution_effect_authority: bool = False
    finding_promotion_authority: bool = False
    target_cleanup_authority: bool = False

    @classmethod
    def build(
        cls,
        *,
        liveness_decision: RuntimeLivenessDecision,
        consumption_decision: ConsumptionDecision,
        observed_epoch: float,
        outcome: CapabilityExecutionOutcome,
        mode: str = CAPABILITY_EXECUTION_RECEIPT_MODE,
        target_dispatch_authority: bool = False,
        execution_effect_authority: bool = False,
        finding_promotion_authority: bool = False,
        target_cleanup_authority: bool = False,
    ) -> "CapabilityExecutionReceipt":
        if type(liveness_decision) is not RuntimeLivenessDecision:
            raise RuntimeExecutionDenied("execution_liveness_decision_is_invalid")
        if type(consumption_decision) is not ConsumptionDecision:
            raise RuntimeExecutionDenied("execution_consumption_decision_is_invalid")
        if type(outcome) is not CapabilityExecutionOutcome:
            raise RuntimeExecutionDenied("execution_outcome_is_invalid")
        try:
            observed_encoding = _canonical_epoch(observed_epoch)
            liveness_encoding = _canonical_epoch(liveness_decision.observed_epoch)
            replace(liveness_decision)
            replace(consumption_decision)
        except (RuntimeError, TypeError, ValueError) as exc:
            raise RuntimeExecutionDenied(
                "execution_decision_context_is_invalid"
            ) from exc
        if mode != CAPABILITY_EXECUTION_RECEIPT_MODE:
            raise RuntimeExecutionDenied("execution_receipt_mode_is_invalid")
        if any(
            flag is not False
            for flag in (
                target_dispatch_authority,
                execution_effect_authority,
                finding_promotion_authority,
                target_cleanup_authority,
            )
        ):
            raise RuntimeExecutionDenied("execution_receipt_passive_boundary_violation")
        if (
            liveness_decision.capability_ref != consumption_decision.capability_ref
            or observed_encoding != liveness_encoding
        ):
            raise RuntimeExecutionDenied("execution_capability_context_is_inconsistent")
        expected_outcome = _execution_outcome(liveness_decision, consumption_decision)
        if outcome is not expected_outcome:
            raise RuntimeExecutionDenied("execution_receipt_outcome_is_inconsistent")

        payload = _receipt_payload(
            capability_ref=liveness_decision.capability_ref,
            liveness_ref=liveness_decision.liveness_id,
            consumption_ref=consumption_decision.decision_id,
            observed_epoch=observed_epoch,
            outcome=outcome,
            mode=mode,
        )
        return cls(
            receipt_id=stable_hash("capability_execution_receipt", payload),
            capability_ref=liveness_decision.capability_ref,
            liveness_ref=liveness_decision.liveness_id,
            consumption_ref=consumption_decision.decision_id,
            observed_epoch=observed_epoch,
            outcome=outcome,
            _liveness_decision=liveness_decision,
            _consumption_decision=consumption_decision,
            mode=mode,
            target_dispatch_authority=target_dispatch_authority,
            execution_effect_authority=execution_effect_authority,
            finding_promotion_authority=finding_promotion_authority,
            target_cleanup_authority=target_cleanup_authority,
        )

    def __post_init__(self) -> None:
        if type(self._liveness_decision) is not RuntimeLivenessDecision:
            raise TypeError("liveness_decision must be a RuntimeLivenessDecision")
        if type(self._consumption_decision) is not ConsumptionDecision:
            raise TypeError("consumption_decision must be a ConsumptionDecision")
        if type(self.outcome) is not CapabilityExecutionOutcome:
            raise TypeError("outcome must be a CapabilityExecutionOutcome")
        try:
            observed_encoding = _canonical_epoch(self.observed_epoch)
            liveness_encoding = _canonical_epoch(self._liveness_decision.observed_epoch)
            replace(self._liveness_decision)
            replace(self._consumption_decision)
            expected_outcome = _execution_outcome(
                self._liveness_decision,
                self._consumption_decision,
            )
            payload = _receipt_payload(
                capability_ref=self.capability_ref,
                liveness_ref=self.liveness_ref,
                consumption_ref=self.consumption_ref,
                observed_epoch=self.observed_epoch,
                outcome=self.outcome,
                mode=self.mode,
            )
        except (RuntimeError, TypeError, ValueError) as exc:
            raise ValueError("capability execution receipt is invalid") from exc

        refs = (
            (self.receipt_id, "capability_execution_receipt"),
            (self.capability_ref, "issued_capability_contract"),
            (self.liveness_ref, "runtime_liveness_decision"),
            (self.consumption_ref, "capability_consumption_decision"),
        )
        if (
            self.receipt_id != stable_hash("capability_execution_receipt", payload)
            or any(not _hash_ref(value, prefix) for value, prefix in refs)
            or self.capability_ref != self._liveness_decision.capability_ref
            or self.capability_ref != self._consumption_decision.capability_ref
            or self.liveness_ref != self._liveness_decision.liveness_id
            or self.consumption_ref != self._consumption_decision.decision_id
            or observed_encoding != liveness_encoding
            or self.outcome is not expected_outcome
            or self.mode != CAPABILITY_EXECUTION_RECEIPT_MODE
            or self.target_dispatch_authority is not False
            or self.execution_effect_authority is not False
            or self.finding_promotion_authority is not False
            or self.target_cleanup_authority is not False
        ):
            raise ValueError("capability execution receipt is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "receipt_id": self.receipt_id,
            **_receipt_payload(
                capability_ref=self.capability_ref,
                liveness_ref=self.liveness_ref,
                consumption_ref=self.consumption_ref,
                observed_epoch=self.observed_epoch,
                outcome=self.outcome,
                mode=self.mode,
            ),
            "target_dispatch_authority": self.target_dispatch_authority,
            "execution_effect_authority": self.execution_effect_authority,
            "finding_promotion_authority": self.finding_promotion_authority,
            "target_cleanup_authority": self.target_cleanup_authority,
        }


def evaluate_capability_execution(
    logical_decision: CapabilityDecision,
    admission: AdmittedRuntimeContract,
    consumption_decision: ConsumptionDecision,
    *,
    clock: Callable[[], object] = time.time,
) -> CapabilityExecutionReceipt:
    """Read one real instant and compose the existing liveness/consumption axes."""

    if type(logical_decision) is not CapabilityDecision:
        raise RuntimeExecutionDenied("execution_logical_decision_is_invalid")
    if type(admission) is not AdmittedRuntimeContract:
        raise RuntimeExecutionDenied("execution_admission_is_invalid")
    if type(consumption_decision) is not ConsumptionDecision:
        raise RuntimeExecutionDenied("execution_consumption_decision_is_invalid")
    if not callable(clock):
        raise RuntimeExecutionDenied("execution_clock_is_not_callable")

    try:
        now = clock()
    except Exception as exc:
        raise RuntimeExecutionDenied("execution_clock_read_failed") from exc
    try:
        _canonical_epoch(now)
    except ValueError as exc:
        raise RuntimeExecutionDenied("execution_clock_reading_is_invalid") from exc
    if not (
        logical_decision.capability_id
        == admission.capability_ref
        == consumption_decision.capability_ref
    ):
        raise RuntimeExecutionDenied("execution_capability_mismatch")

    try:
        liveness_decision = evaluate_runtime_liveness(
            logical_decision,
            admission,
            now=now,
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeExecutionDenied("execution_liveness_evaluation_failed") from exc
    outcome = _execution_outcome(liveness_decision, consumption_decision)
    return CapabilityExecutionReceipt.build(
        liveness_decision=liveness_decision,
        consumption_decision=consumption_decision,
        observed_epoch=now,
        outcome=outcome,
    )


__all__ = [
    "CAPABILITY_EXECUTION_RECEIPT_MODE",
    "CapabilityExecutionOutcome",
    "CapabilityExecutionReceipt",
    "RuntimeExecutionDenied",
    "evaluate_capability_execution",
]
