"""Pure wall-clock expiry under an admitted runtime contract.

A capability is runtime-live iff R5D1 classifies its presentation ``VALID`` and the
admitting runtime's wall-clock window contains the observed instant. R5D5 adds only
the second conjunct; it never re-decides the first. The clock is an injected argument,
so this module is a pure function of ``(logical_decision, admission, now)`` and reads
no real time.

The module performs no persistence, target I/O, backend dispatch, callback
provisioning, execution-receipt transition, effect evaluation, finding construction,
promotion, or cleanup. It is production-unwired and grants no execution authority.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping

from .capability_contract import (
    CapabilityDecision,
    CapabilityOutcome,
    IssuedCapabilityContract,
    _hash_ref,
)
from .normalize import stable_hash


CAPABILITY_RUNTIME_EXPIRY_MODE = "behavioral_capability_runtime_expiry_v1"


class RuntimeLivenessDenied(RuntimeError):
    """A runtime admission or clock reading cannot support a liveness verdict."""


class RuntimeLivenessOutcome(str, Enum):
    ADMITTED_LIVE = "admitted_live"
    EXPIRED_AT_RUNTIME = "expired_at_runtime"
    NOT_YET_LIVE = "not_yet_live"
    LOGICALLY_INADMISSIBLE = "logically_inadmissible"


def _canonical_epoch(value: object) -> str:
    if type(value) is not float or not math.isfinite(value):
        raise ValueError("runtime epoch must be a finite float")
    return repr(value)


def _parse_canonical_epoch(value: object) -> float:
    if not isinstance(value, str):
        raise ValueError("runtime epoch encoding is invalid")
    try:
        parsed = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError("runtime epoch encoding is invalid") from exc
    if _canonical_epoch(parsed) != value:
        raise ValueError("runtime epoch encoding is not canonical")
    return parsed


def _admission_payload(
    *,
    capability_ref: str,
    runtime_ref: str,
    admitted_at_epoch: float,
    expires_at_epoch: float,
    mode: str,
) -> Dict[str, Any]:
    return {
        "capability_ref": capability_ref,
        "runtime_ref": runtime_ref,
        "admitted_at_epoch": _canonical_epoch(admitted_at_epoch),
        "expires_at_epoch": _canonical_epoch(expires_at_epoch),
        "mode": mode,
    }


@dataclass(frozen=True)
class AdmittedRuntimeContract:
    """One runtime's explicit wall-clock window for one issued capability."""

    admission_id: str
    capability_ref: str
    runtime_ref: str
    admitted_at_epoch: float
    expires_at_epoch: float
    _contract: IssuedCapabilityContract = field(repr=False, compare=False)
    mode: str = CAPABILITY_RUNTIME_EXPIRY_MODE
    target_dispatch_authority: bool = False
    execution_receipt_authority: bool = False
    real_clock_read_authority: bool = False

    @classmethod
    def build(
        cls,
        *,
        contract: IssuedCapabilityContract,
        capability_ref: str,
        runtime_ref: str,
        admitted_at_epoch: float,
        expires_at_epoch: float,
        mode: str = CAPABILITY_RUNTIME_EXPIRY_MODE,
        target_dispatch_authority: bool = False,
        execution_receipt_authority: bool = False,
        real_clock_read_authority: bool = False,
    ) -> "AdmittedRuntimeContract":
        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        if not _hash_ref(capability_ref, "issued_capability_contract") or not _hash_ref(
            runtime_ref, "admitted_runtime"
        ):
            raise ValueError("admitted runtime contract reference is invalid")
        if capability_ref != contract.capability_id:
            raise RuntimeLivenessDenied("runtime_admission_contract_reference_mismatch")
        if any(
            flag is not False
            for flag in (
                target_dispatch_authority,
                execution_receipt_authority,
                real_clock_read_authority,
            )
        ):
            raise RuntimeLivenessDenied("runtime_admission_passive_boundary_violation")
        if mode != CAPABILITY_RUNTIME_EXPIRY_MODE:
            raise ValueError("admitted runtime contract mode is invalid")
        _canonical_epoch(admitted_at_epoch)
        _canonical_epoch(expires_at_epoch)
        if expires_at_epoch <= admitted_at_epoch:
            raise ValueError("admitted runtime contract window is invalid")

        payload = _admission_payload(
            capability_ref=capability_ref,
            runtime_ref=runtime_ref,
            admitted_at_epoch=admitted_at_epoch,
            expires_at_epoch=expires_at_epoch,
            mode=mode,
        )
        return cls(
            admission_id=stable_hash("admitted_runtime_capability", payload),
            capability_ref=capability_ref,
            runtime_ref=runtime_ref,
            admitted_at_epoch=admitted_at_epoch,
            expires_at_epoch=expires_at_epoch,
            _contract=contract,
            mode=mode,
            target_dispatch_authority=target_dispatch_authority,
            execution_receipt_authority=execution_receipt_authority,
            real_clock_read_authority=real_clock_read_authority,
        )

    def __post_init__(self) -> None:
        if not isinstance(self._contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        payload = _admission_payload(
            capability_ref=self.capability_ref,
            runtime_ref=self.runtime_ref,
            admitted_at_epoch=self.admitted_at_epoch,
            expires_at_epoch=self.expires_at_epoch,
            mode=self.mode,
        )
        if (
            self.admission_id != stable_hash("admitted_runtime_capability", payload)
            or not _hash_ref(self.admission_id, "admitted_runtime_capability")
            or not _hash_ref(self.capability_ref, "issued_capability_contract")
            or not _hash_ref(self.runtime_ref, "admitted_runtime")
            or self.capability_ref != self._contract.capability_id
            or self.expires_at_epoch <= self.admitted_at_epoch
            or self.mode != CAPABILITY_RUNTIME_EXPIRY_MODE
            or self.target_dispatch_authority is not False
            or self.execution_receipt_authority is not False
            or self.real_clock_read_authority is not False
        ):
            raise ValueError("admitted runtime contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "admission_id": self.admission_id,
            **_admission_payload(
                capability_ref=self.capability_ref,
                runtime_ref=self.runtime_ref,
                admitted_at_epoch=self.admitted_at_epoch,
                expires_at_epoch=self.expires_at_epoch,
                mode=self.mode,
            ),
            "target_dispatch_authority": self.target_dispatch_authority,
            "execution_receipt_authority": self.execution_receipt_authority,
            "real_clock_read_authority": self.real_clock_read_authority,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        contract: IssuedCapabilityContract,
    ) -> "AdmittedRuntimeContract":
        """Reload an admission while retaining its separately supplied live context."""

        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        expected_fields = {
            "schema_version",
            "admission_id",
            "capability_ref",
            "runtime_ref",
            "admitted_at_epoch",
            "expires_at_epoch",
            "mode",
            "target_dispatch_authority",
            "execution_receipt_authority",
            "real_clock_read_authority",
        }
        authority_fields = (
            "target_dispatch_authority",
            "execution_receipt_authority",
            "real_clock_read_authority",
        )
        if (
            not isinstance(value, Mapping)
            or set(value) != expected_fields
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or any(value.get(name) is not False for name in authority_fields)
        ):
            raise RuntimeLivenessDenied("runtime_admission_serialization_invalid")
        try:
            return cls(
                admission_id=value["admission_id"],
                capability_ref=value["capability_ref"],
                runtime_ref=value["runtime_ref"],
                admitted_at_epoch=_parse_canonical_epoch(value["admitted_at_epoch"]),
                expires_at_epoch=_parse_canonical_epoch(value["expires_at_epoch"]),
                _contract=contract,
                mode=value["mode"],
                target_dispatch_authority=value["target_dispatch_authority"],
                execution_receipt_authority=value["execution_receipt_authority"],
                real_clock_read_authority=value["real_clock_read_authority"],
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeLivenessDenied(
                "runtime_admission_serialization_invalid"
            ) from exc


def _runtime_liveness_outcome(
    logical_decision: CapabilityDecision,
    admission: AdmittedRuntimeContract,
    observed_epoch: float,
) -> RuntimeLivenessOutcome:
    if logical_decision.outcome is not CapabilityOutcome.VALID:
        return RuntimeLivenessOutcome.LOGICALLY_INADMISSIBLE
    if observed_epoch >= admission.expires_at_epoch:
        return RuntimeLivenessOutcome.EXPIRED_AT_RUNTIME
    if observed_epoch < admission.admitted_at_epoch:
        return RuntimeLivenessOutcome.NOT_YET_LIVE
    return RuntimeLivenessOutcome.ADMITTED_LIVE


def _liveness_payload(
    *,
    admission_ref: str,
    logical_decision_ref: str,
    capability_ref: str,
    observed_epoch: float,
    outcome: RuntimeLivenessOutcome,
    mode: str,
) -> Dict[str, Any]:
    return {
        "admission_ref": admission_ref,
        "logical_decision_ref": logical_decision_ref,
        "capability_ref": capability_ref,
        "observed_epoch": _canonical_epoch(observed_epoch),
        "outcome": outcome.value,
        "mode": mode,
    }


@dataclass(frozen=True)
class RuntimeLivenessDecision:
    """An instant-specific, content-addressed composition of logic and wall time."""

    liveness_id: str
    admission_ref: str
    logical_decision_ref: str
    capability_ref: str
    observed_epoch: float
    outcome: RuntimeLivenessOutcome
    _logical_decision: CapabilityDecision = field(repr=False, compare=False)
    _admission: AdmittedRuntimeContract = field(repr=False, compare=False)
    mode: str = CAPABILITY_RUNTIME_EXPIRY_MODE

    @classmethod
    def build(
        cls,
        *,
        logical_decision: CapabilityDecision,
        admission: AdmittedRuntimeContract,
        observed_epoch: float,
        outcome: RuntimeLivenessOutcome,
    ) -> "RuntimeLivenessDecision":
        if not isinstance(logical_decision, CapabilityDecision):
            raise TypeError("logical_decision must be a CapabilityDecision")
        if not isinstance(admission, AdmittedRuntimeContract):
            raise TypeError("admission must be an AdmittedRuntimeContract")
        if not isinstance(outcome, RuntimeLivenessOutcome):
            raise TypeError("outcome must be a RuntimeLivenessOutcome")
        _canonical_epoch(observed_epoch)
        if admission.capability_ref != logical_decision.capability_id:
            raise RuntimeLivenessDenied("runtime_admission_capability_mismatch")
        if outcome is not _runtime_liveness_outcome(
            logical_decision,
            admission,
            observed_epoch,
        ):
            raise ValueError("runtime liveness decision outcome is inconsistent")

        payload = _liveness_payload(
            admission_ref=admission.admission_id,
            logical_decision_ref=logical_decision.decision_id,
            capability_ref=logical_decision.capability_id,
            observed_epoch=observed_epoch,
            outcome=outcome,
            mode=CAPABILITY_RUNTIME_EXPIRY_MODE,
        )
        return cls(
            liveness_id=stable_hash("runtime_liveness_decision", payload),
            admission_ref=admission.admission_id,
            logical_decision_ref=logical_decision.decision_id,
            capability_ref=logical_decision.capability_id,
            observed_epoch=observed_epoch,
            outcome=outcome,
            _logical_decision=logical_decision,
            _admission=admission,
        )

    def __post_init__(self) -> None:
        if not isinstance(self._logical_decision, CapabilityDecision):
            raise TypeError("logical_decision must be a CapabilityDecision")
        if not isinstance(self._admission, AdmittedRuntimeContract):
            raise TypeError("admission must be an AdmittedRuntimeContract")
        if not isinstance(self.outcome, RuntimeLivenessOutcome):
            raise TypeError("outcome must be a RuntimeLivenessOutcome")
        payload = _liveness_payload(
            admission_ref=self.admission_ref,
            logical_decision_ref=self.logical_decision_ref,
            capability_ref=self.capability_ref,
            observed_epoch=self.observed_epoch,
            outcome=self.outcome,
            mode=self.mode,
        )
        if (
            self.liveness_id != stable_hash("runtime_liveness_decision", payload)
            or not _hash_ref(self.liveness_id, "runtime_liveness_decision")
            or not _hash_ref(self.admission_ref, "admitted_runtime_capability")
            or not _hash_ref(self.logical_decision_ref, "capability_decision")
            or not _hash_ref(self.capability_ref, "issued_capability_contract")
            or self.admission_ref != self._admission.admission_id
            or self.logical_decision_ref != self._logical_decision.decision_id
            or self.capability_ref != self._admission.capability_ref
            or self.capability_ref != self._logical_decision.capability_id
            or self.outcome
            is not _runtime_liveness_outcome(
                self._logical_decision,
                self._admission,
                self.observed_epoch,
            )
            or self.mode != CAPABILITY_RUNTIME_EXPIRY_MODE
        ):
            raise ValueError("runtime liveness decision is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "liveness_id": self.liveness_id,
            **_liveness_payload(
                admission_ref=self.admission_ref,
                logical_decision_ref=self.logical_decision_ref,
                capability_ref=self.capability_ref,
                observed_epoch=self.observed_epoch,
                outcome=self.outcome,
                mode=self.mode,
            ),
        }


def evaluate_runtime_liveness(
    logical_decision: CapabilityDecision,
    admission: AdmittedRuntimeContract,
    *,
    now: float,
) -> RuntimeLivenessDecision:
    """Compose an existing logical verdict with an injected wall-clock instant."""

    if not isinstance(logical_decision, CapabilityDecision):
        raise TypeError("logical_decision must be a CapabilityDecision")
    if not isinstance(admission, AdmittedRuntimeContract):
        raise TypeError("admission must be an AdmittedRuntimeContract")
    try:
        _canonical_epoch(now)
    except ValueError as exc:
        raise RuntimeLivenessDenied("runtime_clock_reading_is_invalid") from exc
    if admission.capability_ref != logical_decision.capability_id:
        raise RuntimeLivenessDenied("runtime_admission_capability_mismatch")

    outcome = _runtime_liveness_outcome(logical_decision, admission, now)
    return RuntimeLivenessDecision.build(
        logical_decision=logical_decision,
        admission=admission,
        observed_epoch=now,
        outcome=outcome,
    )


__all__ = [
    "CAPABILITY_RUNTIME_EXPIRY_MODE",
    "AdmittedRuntimeContract",
    "RuntimeLivenessDecision",
    "RuntimeLivenessDenied",
    "RuntimeLivenessOutcome",
    "evaluate_runtime_liveness",
]
