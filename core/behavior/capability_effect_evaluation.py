"""Default-off R5D8 capability-effect execution and independent evaluation.

One already-certified R5D6 completion receipt admits a fixed five-observation
experiment through an injected transport.  Every observation is bound to an exact
R5D6 terminal receipt and the owned experiment world retained by the capability.
The module owns no concrete client, reads no clock, has no production caller, and
can emit only a finding candidate.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Protocol, Sequence, Tuple

from .capability_contract import _hash_ref
from .capability_execution_receipt import (
    CapabilityExecutionOutcome,
    CapabilityExecutionReceipt,
)
from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from .normalize import stable_hash


CAPABILITY_EFFECT_EXECUTION_ENV = "SENTINELFORGE_BEHAVIOR_CAPABILITY_EFFECT_EXECUTION"
CAPABILITY_EFFECT_EXECUTION_MODE = "behavioral_capability_effect_execution_v1"

_TRUE = frozenset({"1", "true", "yes", "on"})
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_OBSERVATION_KINDS = (
    "no_capability_baseline",
    "valid_capability_effect_witness",
    "replayed_capability_probe",
    "expired_capability_probe",
    "inadmissible_capability_probe",
)
_EXPECTED_OUTCOMES = {
    "no_capability_baseline": (CapabilityExecutionOutcome.EXECUTION_REFUSED_NOT_LIVE),
    "valid_capability_effect_witness": (CapabilityExecutionOutcome.EXECUTION_COMPLETED),
    "replayed_capability_probe": (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED
    ),
    "expired_capability_probe": (CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED),
    "inadmissible_capability_probe": (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE
    ),
}
_REFUSAL_OUTCOMES = frozenset(
    {
        CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE,
        CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED,
        CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
        CapabilityExecutionOutcome.EXECUTION_REFUSED_NOT_LIVE,
    }
)
_REFUSAL_KINDS = (
    "no_capability_baseline",
    "replayed_capability_probe",
    "expired_capability_probe",
    "inadmissible_capability_probe",
)


def _validated_receipt(
    value: object,
    *,
    expected_outcome: Optional[CapabilityExecutionOutcome] = None,
    capability_ref: Optional[str] = None,
) -> CapabilityExecutionReceipt:
    if type(value) is not CapabilityExecutionReceipt:
        raise TypeError("receipt must be an exact CapabilityExecutionReceipt")
    receipt = replace(value)
    if expected_outcome is not None and receipt.outcome is not expected_outcome:
        raise ValueError("capability effect receipt outcome is invalid")
    if capability_ref is not None and receipt.capability_ref != capability_ref:
        raise ValueError("capability effect receipt capability is invalid")
    return receipt


def _owned_world(receipt: CapabilityExecutionReceipt) -> ExperimentWorldBinding:
    try:
        world = receipt._liveness_decision._admission._contract._owned_world
        if type(world) is not ExperimentWorldBinding:
            raise TypeError("owned world must be an exact ExperimentWorldBinding")
        world = replace(world)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("capability effect owned world is invalid") from exc
    if world.kind is not ExperimentWorldKind.OWNED_ACCOUNT:
        raise ValueError("capability effect owned world is invalid")
    return world


@dataclass(frozen=True)
class CapabilityEffectExecutionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise TypeError("capability effect execution enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "CapabilityEffectExecutionConfig":
        return cls(
            enabled=(
                str(os.environ.get(CAPABILITY_EFFECT_EXECUTION_ENV, "")).strip().lower()
                in _TRUE
            )
        )


@dataclass(frozen=True)
class CapabilityCleanupResult:
    status: str
    target_requests_sent: int
    target_request_may_have_been_sent: bool
    orphaned_owned_state_possible: bool

    def __post_init__(self) -> None:
        verified = (
            self.status == "verified"
            and not self.target_request_may_have_been_sent
            and not self.orphaned_owned_state_possible
        )
        unattempted = (
            self.status == "unattempted"
            and self.target_requests_sent == 0
            and not self.target_request_may_have_been_sent
            and not self.orphaned_owned_state_possible
        )
        uncertain = self.status == "uncertain" and self.orphaned_owned_state_possible
        if (
            self.status not in {"verified", "uncertain", "unattempted"}
            or isinstance(self.target_requests_sent, bool)
            or not isinstance(self.target_requests_sent, int)
            or self.target_requests_sent < 0
            or type(self.target_request_may_have_been_sent) is not bool
            or type(self.orphaned_owned_state_possible) is not bool
            or not (verified or unattempted or uncertain)
        ):
            raise ValueError("capability cleanup result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "target_requests_sent": self.target_requests_sent,
            "target_request_may_have_been_sent": (
                self.target_request_may_have_been_sent
            ),
            "orphaned_owned_state_possible": (self.orphaned_owned_state_possible),
        }


class CapabilityEffectExecutionDenied(RuntimeError):
    """R5D8 was refused or could not establish a clean conclusive result."""

    def __init__(
        self,
        reason: str,
        *,
        category: str,
        target_request_possible: bool = False,
        cleanup: Optional[CapabilityCleanupResult] = None,
        oracle: Optional["CapabilityEffectOracleEvaluation"] = None,
        terminal_receipt: Optional[CapabilityExecutionReceipt] = None,
    ) -> None:
        if not isinstance(reason, str) or _SEMANTIC.fullmatch(reason) is None:
            raise ValueError("capability effect denial reason is invalid")
        if not isinstance(category, str) or _SEMANTIC.fullmatch(category) is None:
            raise ValueError("capability effect denial category is invalid")
        if type(target_request_possible) is not bool:
            raise TypeError("target_request_possible must be boolean")
        if cleanup is not None and type(cleanup) is not CapabilityCleanupResult:
            raise TypeError("cleanup must be a CapabilityCleanupResult")
        evaluation_type = globals().get("CapabilityEffectOracleEvaluation")
        if oracle is not None and (
            evaluation_type is None or type(oracle) is not evaluation_type
        ):
            raise TypeError("oracle must be a CapabilityEffectOracleEvaluation")
        validated_terminal = None
        if terminal_receipt is not None:
            try:
                validated_terminal = _validated_receipt(terminal_receipt)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "capability effect terminal receipt is invalid"
                ) from exc
            if validated_terminal.outcome not in _REFUSAL_OUTCOMES:
                raise ValueError("capability effect terminal receipt is invalid")

        super().__init__(reason)
        self.category = category
        self.target_request_possible = target_request_possible
        self.cleanup = cleanup
        self.oracle = oracle
        self.terminal_receipt = validated_terminal


def _observation_payload(
    *,
    receipt_ref: str,
    capability_ref: str,
    observation_binding_id: str,
    response_ref: str,
    observation_kind: str,
    receipt_outcome: CapabilityExecutionOutcome,
    access_decision: str,
    response_status: int,
    effect_ref: Optional[str],
    protected_effect_observed: bool,
    target_projection_observed: bool,
) -> Dict[str, Any]:
    return {
        "receipt_ref": receipt_ref,
        "capability_ref": capability_ref,
        "observation_binding_id": observation_binding_id,
        "response_ref": response_ref,
        "observation_kind": observation_kind,
        "receipt_outcome": receipt_outcome.value,
        "access_decision": access_decision,
        "response_status": response_status,
        "effect_ref": effect_ref,
        "protected_effect_observed": protected_effect_observed,
        "target_projection_observed": target_projection_observed,
    }


@dataclass(frozen=True)
class CapabilityEffectObservation:
    observation_id: str
    receipt_ref: str
    capability_ref: str
    observation_binding_id: str
    response_ref: str
    observation_kind: str
    receipt_outcome: CapabilityExecutionOutcome
    access_decision: str
    response_status: int
    effect_ref: Optional[str]
    protected_effect_observed: bool
    target_projection_observed: bool
    _terminal_receipt: CapabilityExecutionReceipt = field(
        repr=False,
        compare=False,
    )

    @classmethod
    def build(
        cls,
        *,
        terminal_receipt: CapabilityExecutionReceipt,
        observation_binding: ExperimentWorldBinding,
        response_ref: str,
        observation_kind: str,
        access_decision: str,
        response_status: int,
        effect: Any,
        target_projection_observed: bool,
    ) -> "CapabilityEffectObservation":
        if observation_kind not in _EXPECTED_OUTCOMES:
            raise ValueError("capability effect observation kind is invalid")
        receipt = _validated_receipt(
            terminal_receipt,
            expected_outcome=_EXPECTED_OUTCOMES[observation_kind],
        )
        if type(observation_binding) is not ExperimentWorldBinding:
            raise TypeError("observation binding must be an ExperimentWorldBinding")
        binding = replace(observation_binding)
        effect_ref = (
            stable_hash("capability_protected_effect", effect)
            if effect is not None
            else None
        )
        payload = _observation_payload(
            receipt_ref=receipt.receipt_id,
            capability_ref=receipt.capability_ref,
            observation_binding_id=binding.binding_id,
            response_ref=response_ref,
            observation_kind=observation_kind,
            receipt_outcome=receipt.outcome,
            access_decision=access_decision,
            response_status=response_status,
            effect_ref=effect_ref,
            protected_effect_observed=effect_ref is not None,
            target_projection_observed=target_projection_observed,
        )
        return cls(
            observation_id=stable_hash("capability_effect_observation", payload),
            receipt_ref=receipt.receipt_id,
            capability_ref=receipt.capability_ref,
            observation_binding_id=binding.binding_id,
            response_ref=response_ref,
            observation_kind=observation_kind,
            receipt_outcome=receipt.outcome,
            access_decision=access_decision,
            response_status=response_status,
            effect_ref=effect_ref,
            protected_effect_observed=effect_ref is not None,
            target_projection_observed=target_projection_observed,
            _terminal_receipt=receipt,
        )

    def __post_init__(self) -> None:
        if self.observation_kind not in _EXPECTED_OUTCOMES:
            raise ValueError("capability effect observation is invalid")
        try:
            receipt = _validated_receipt(
                self._terminal_receipt,
                expected_outcome=_EXPECTED_OUTCOMES[self.observation_kind],
                capability_ref=self.capability_ref,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capability effect observation is invalid") from exc
        payload = _observation_payload(
            receipt_ref=self.receipt_ref,
            capability_ref=self.capability_ref,
            observation_binding_id=self.observation_binding_id,
            response_ref=self.response_ref,
            observation_kind=self.observation_kind,
            receipt_outcome=self.receipt_outcome,
            access_decision=self.access_decision,
            response_status=self.response_status,
            effect_ref=self.effect_ref,
            protected_effect_observed=self.protected_effect_observed,
            target_projection_observed=self.target_projection_observed,
        )
        status_valid = (
            not isinstance(self.response_status, bool)
            and isinstance(self.response_status, int)
            and 100 <= self.response_status <= 599
        )
        allowed = (
            self.access_decision == "allowed"
            and status_valid
            and 200 <= self.response_status < 300
        )
        denied = (
            self.access_decision == "denied"
            and status_valid
            and not 200 <= self.response_status < 300
        )
        unknown = self.access_decision == "unknown" and status_valid
        if (
            self.observation_id != stable_hash("capability_effect_observation", payload)
            or not _hash_ref(self.observation_id, "capability_effect_observation")
            or not _hash_ref(self.receipt_ref, "capability_execution_receipt")
            or self.receipt_ref != receipt.receipt_id
            or not _hash_ref(self.capability_ref, "issued_capability_contract")
            or not _hash_ref(
                self.observation_binding_id,
                "experiment_world_binding",
            )
            or not _hash_ref(
                self.response_ref,
                "capability_effect_target_response",
            )
            or type(self.receipt_outcome) is not CapabilityExecutionOutcome
            or self.receipt_outcome is not receipt.outcome
            or not (allowed or denied or unknown)
            or (
                self.effect_ref is not None
                and not _hash_ref(
                    self.effect_ref,
                    "capability_protected_effect",
                )
            )
            or type(self.protected_effect_observed) is not bool
            or self.protected_effect_observed != (self.effect_ref is not None)
            or type(self.target_projection_observed) is not bool
            or (
                self.protected_effect_observed
                and not (allowed and self.target_projection_observed)
            )
            or (denied and self.protected_effect_observed)
            or (
                not self.target_projection_observed
                and (
                    self.access_decision != "unknown" or self.protected_effect_observed
                )
            )
        ):
            raise ValueError("capability effect observation is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "observation_id": self.observation_id,
            **_observation_payload(
                receipt_ref=self.receipt_ref,
                capability_ref=self.capability_ref,
                observation_binding_id=self.observation_binding_id,
                response_ref=self.response_ref,
                observation_kind=self.observation_kind,
                receipt_outcome=self.receipt_outcome,
                access_decision=self.access_decision,
                response_status=self.response_status,
                effect_ref=self.effect_ref,
                protected_effect_observed=self.protected_effect_observed,
                target_projection_observed=self.target_projection_observed,
            ),
        }


class CapabilityEffectOracleVerdict(str, Enum):
    CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT = "confirmed_one_time_authorized_effect"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


def _oracle_components(
    *,
    oracle_id: str,
    observation_binding_id: str,
    observations: Sequence[CapabilityEffectObservation],
) -> Dict[str, Any]:
    values = tuple(observations)
    if tuple(item.observation_kind for item in values) != _OBSERVATION_KINDS:
        raise ValueError("capability effect observation order is invalid")
    if any(item.observation_binding_id != observation_binding_id for item in values):
        raise ValueError("capability effect observation binding changed")
    if len({item.receipt_ref for item in values}) != len(values):
        raise ValueError("capability effect receipt binding is not unique")
    if len({item.capability_ref for item in values}) != 1:
        raise ValueError("capability effect capability binding changed")

    baseline, witness, replay, expired, inadmissible = values

    def refusal_observed(item: CapabilityEffectObservation) -> bool:
        return bool(
            item.target_projection_observed
            and item.access_decision == "denied"
            and not item.protected_effect_observed
        )

    baseline_absent = refusal_observed(baseline)
    replay_absent = refusal_observed(replay)
    expired_absent = refusal_observed(expired)
    inadmissible_absent = refusal_observed(inadmissible)
    refusal_absence = (
        baseline_absent,
        replay_absent,
        expired_absent,
        inadmissible_absent,
    )
    witness_effect = bool(
        witness.target_projection_observed
        and witness.access_decision == "allowed"
        and witness.protected_effect_observed
    )
    observed_effects = tuple(item for item in values if item.protected_effect_observed)
    unauthorized_effect = any(
        item.protected_effect_observed
        for item in (baseline, replay, expired, inadmissible)
    )
    unauthorized_access = any(
        item.target_projection_observed
        and item.access_decision == "allowed"
        and not item.protected_effect_observed
        for item in (baseline, replay, expired, inadmissible)
    )
    witness_absent = bool(
        witness.target_projection_observed
        and witness.access_decision in {"allowed", "denied"}
        and not witness.protected_effect_observed
    )
    duplicated_effect = len(observed_effects) > 1

    uncertainty = set()
    for kind, item in zip(_OBSERVATION_KINDS, values):
        if not item.target_projection_observed or item.access_decision == "unknown":
            uncertainty.add(f"{kind}_evidence_unavailable")
    if not witness_effect and not witness_absent:
        uncertainty.add("authorized_effect_witness_unavailable")
    for kind, absent, item in zip(
        _REFUSAL_KINDS,
        refusal_absence,
        (baseline, replay, expired, inadmissible),
    ):
        if (
            not absent
            and not item.protected_effect_observed
            and item.access_decision != "allowed"
        ):
            uncertainty.add(f"{kind}_refusal_unavailable")

    if (
        unauthorized_effect
        or unauthorized_access
        or witness_absent
        or duplicated_effect
    ):
        verdict = CapabilityEffectOracleVerdict.REFUTED
    elif witness_effect and all(refusal_absence):
        verdict = CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
        uncertainty.clear()
    else:
        verdict = CapabilityEffectOracleVerdict.INCONCLUSIVE

    finding_candidate_ref = (
        stable_hash(
            "capability_effect_finding_candidate",
            {
                "oracle_id": oracle_id,
                "observation_binding_id": observation_binding_id,
                "verdict": verdict.value,
                "observation_refs": [item.observation_id for item in values],
                "authorized_effect_ref": witness.effect_ref,
            },
        )
        if verdict is CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
        else None
    )
    return {
        "oracle_id": oracle_id,
        "observation_binding_id": observation_binding_id,
        "verdict": verdict,
        "observation_refs": tuple(item.observation_id for item in values),
        "uncertainty_reasons": tuple(sorted(uncertainty)),
        "no_capability_effect_absent": baseline_absent,
        "authorized_effect_observed_once": (
            witness_effect and len(observed_effects) == 1
        ),
        "replay_effect_absent": replay_absent,
        "expired_effect_absent": expired_absent,
        "inadmissible_effect_absent": inadmissible_absent,
        "authorized_effect_ref": witness.effect_ref if witness_effect else None,
        "finding_candidate_ref": finding_candidate_ref,
    }


def _oracle_payload(components: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "oracle_id": components["oracle_id"],
        "observation_binding_id": components["observation_binding_id"],
        "verdict": components["verdict"].value,
        "observation_refs": list(components["observation_refs"]),
        "uncertainty_reasons": list(components["uncertainty_reasons"]),
        "no_capability_effect_absent": components["no_capability_effect_absent"],
        "authorized_effect_observed_once": components[
            "authorized_effect_observed_once"
        ],
        "replay_effect_absent": components["replay_effect_absent"],
        "expired_effect_absent": components["expired_effect_absent"],
        "inadmissible_effect_absent": components["inadmissible_effect_absent"],
        "authorized_effect_ref": components["authorized_effect_ref"],
        "finding_candidate_ref": components["finding_candidate_ref"],
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }


@dataclass(frozen=True)
class CapabilityEffectOracleEvaluation:
    evaluation_id: str
    oracle_id: str
    observation_binding_id: str
    verdict: CapabilityEffectOracleVerdict
    observation_refs: Tuple[str, ...]
    uncertainty_reasons: Tuple[str, ...]
    no_capability_effect_absent: bool
    authorized_effect_observed_once: bool
    replay_effect_absent: bool
    expired_effect_absent: bool
    inadmissible_effect_absent: bool
    authorized_effect_ref: Optional[str]
    finding_candidate_ref: Optional[str]
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False

    @classmethod
    def build(
        cls,
        *,
        oracle_id: str,
        observation_binding: ExperimentWorldBinding,
        observations: Sequence[CapabilityEffectObservation],
    ) -> "CapabilityEffectOracleEvaluation":
        if not _hash_ref(oracle_id, "capability_effect_oracle"):
            raise ValueError("capability effect oracle id is invalid")
        if type(observation_binding) is not ExperimentWorldBinding:
            raise TypeError("observation binding must be an ExperimentWorldBinding")
        binding = replace(observation_binding)
        if binding.kind is not ExperimentWorldKind.OWNED_ACCOUNT:
            raise ValueError("capability effect observation binding is not owned")
        values = tuple(observations)
        if any(type(item) is not CapabilityEffectObservation for item in values):
            raise TypeError("capability effect observations are invalid")
        components = _oracle_components(
            oracle_id=oracle_id,
            observation_binding_id=binding.binding_id,
            observations=values,
        )
        return cls(
            evaluation_id=stable_hash(
                "capability_effect_oracle_evaluation",
                _oracle_payload(components),
            ),
            **components,
        )

    def __post_init__(self) -> None:
        components = {
            "oracle_id": self.oracle_id,
            "observation_binding_id": self.observation_binding_id,
            "verdict": self.verdict,
            "observation_refs": self.observation_refs,
            "uncertainty_reasons": self.uncertainty_reasons,
            "no_capability_effect_absent": self.no_capability_effect_absent,
            "authorized_effect_observed_once": (self.authorized_effect_observed_once),
            "replay_effect_absent": self.replay_effect_absent,
            "expired_effect_absent": self.expired_effect_absent,
            "inadmissible_effect_absent": self.inadmissible_effect_absent,
            "authorized_effect_ref": self.authorized_effect_ref,
            "finding_candidate_ref": self.finding_candidate_ref,
        }
        confirmed = (
            self.verdict
            is CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
        )
        if (
            self.evaluation_id
            != stable_hash(
                "capability_effect_oracle_evaluation",
                _oracle_payload(components),
            )
            or not _hash_ref(
                self.evaluation_id,
                "capability_effect_oracle_evaluation",
            )
            or not _hash_ref(self.oracle_id, "capability_effect_oracle")
            or not _hash_ref(
                self.observation_binding_id,
                "experiment_world_binding",
            )
            or type(self.verdict) is not CapabilityEffectOracleVerdict
            or len(self.observation_refs) != len(_OBSERVATION_KINDS)
            or len(set(self.observation_refs)) != len(self.observation_refs)
            or any(
                not _hash_ref(item, "capability_effect_observation")
                for item in self.observation_refs
            )
            or self.uncertainty_reasons != tuple(sorted(set(self.uncertainty_reasons)))
            or any(
                _SEMANTIC.fullmatch(item) is None for item in self.uncertainty_reasons
            )
            or any(
                type(item) is not bool
                for item in (
                    self.no_capability_effect_absent,
                    self.authorized_effect_observed_once,
                    self.replay_effect_absent,
                    self.expired_effect_absent,
                    self.inadmissible_effect_absent,
                    self.adversarial_triage_required,
                    self.promotion_authority,
                    self.finding_authority,
                )
            )
            or (
                self.authorized_effect_ref is not None
                and not _hash_ref(
                    self.authorized_effect_ref,
                    "capability_protected_effect",
                )
            )
            or (
                self.finding_candidate_ref is not None
                and not _hash_ref(
                    self.finding_candidate_ref,
                    "capability_effect_finding_candidate",
                )
            )
            or confirmed != (self.finding_candidate_ref is not None)
            or (
                confirmed
                and not all(
                    (
                        self.no_capability_effect_absent,
                        self.authorized_effect_observed_once,
                        self.replay_effect_absent,
                        self.expired_effect_absent,
                        self.inadmissible_effect_absent,
                    )
                )
            )
            or (confirmed and self.uncertainty_reasons)
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError("capability effect oracle evaluation is invalid")

    def to_dict(self) -> Dict[str, Any]:
        components = {
            "oracle_id": self.oracle_id,
            "observation_binding_id": self.observation_binding_id,
            "verdict": self.verdict,
            "observation_refs": self.observation_refs,
            "uncertainty_reasons": self.uncertainty_reasons,
            "no_capability_effect_absent": self.no_capability_effect_absent,
            "authorized_effect_observed_once": (self.authorized_effect_observed_once),
            "replay_effect_absent": self.replay_effect_absent,
            "expired_effect_absent": self.expired_effect_absent,
            "inadmissible_effect_absent": self.inadmissible_effect_absent,
            "authorized_effect_ref": self.authorized_effect_ref,
            "finding_candidate_ref": self.finding_candidate_ref,
        }
        return {
            "schema_version": 1,
            "evaluation_id": self.evaluation_id,
            **_oracle_payload(components),
        }


class CapabilityEffectTransport(Protocol):
    """Injected operator transport; this module owns no concrete target client."""

    async def dispatch(
        self,
        request: Mapping[str, Any],
    ) -> Tuple[int, Mapping[str, Any]]: ...

    async def cleanup(
        self,
        request: Mapping[str, Any],
    ) -> CapabilityCleanupResult: ...


def _result_payload(
    *,
    receipt_id: str,
    capability_ref: str,
    observation_binding_id: str,
    observations: Sequence[CapabilityEffectObservation],
    oracle: CapabilityEffectOracleEvaluation,
    cleanup: CapabilityCleanupResult,
    execution_enabled: bool,
    execution_effect_authority: bool,
    mode: str,
) -> Dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "capability_ref": capability_ref,
        "observation_binding_id": observation_binding_id,
        "effect_observations": [item.to_dict() for item in observations],
        "observation_refs": [item.observation_id for item in observations],
        "oracle": oracle.to_dict(),
        "oracle_verdict": oracle.verdict.value,
        "finding_candidate_ref": oracle.finding_candidate_ref,
        "cleanup": cleanup.to_dict(),
        "execution_enabled": execution_enabled,
        "execution_effect_authority": execution_effect_authority,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
        "mode": mode,
    }


@dataclass(frozen=True)
class CapabilityEffectExecutionResult:
    result_id: str
    receipt_id: str
    capability_ref: str
    observation_binding_id: str
    effect_observations: Tuple[CapabilityEffectObservation, ...]
    oracle: CapabilityEffectOracleEvaluation
    cleanup: CapabilityCleanupResult
    execution_enabled: bool
    execution_effect_authority: bool
    _receipt: CapabilityExecutionReceipt = field(repr=False, compare=False)
    mode: str = CAPABILITY_EFFECT_EXECUTION_MODE
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False

    @classmethod
    def build(
        cls,
        *,
        receipt: CapabilityExecutionReceipt,
        observation_binding: ExperimentWorldBinding,
        observations: Sequence[CapabilityEffectObservation],
        oracle: CapabilityEffectOracleEvaluation,
        cleanup: CapabilityCleanupResult,
        execution_enabled: bool,
    ) -> "CapabilityEffectExecutionResult":
        validated_receipt = _validated_receipt(
            receipt,
            expected_outcome=CapabilityExecutionOutcome.EXECUTION_COMPLETED,
        )
        if type(observation_binding) is not ExperimentWorldBinding:
            raise TypeError("observation binding must be an ExperimentWorldBinding")
        binding = replace(observation_binding)
        values = tuple(observations)
        authority = bool(
            execution_enabled
            and oracle.verdict
            is CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
            and cleanup.status == "verified"
        )
        payload = _result_payload(
            receipt_id=validated_receipt.receipt_id,
            capability_ref=validated_receipt.capability_ref,
            observation_binding_id=binding.binding_id,
            observations=values,
            oracle=oracle,
            cleanup=cleanup,
            execution_enabled=execution_enabled,
            execution_effect_authority=authority,
            mode=CAPABILITY_EFFECT_EXECUTION_MODE,
        )
        return cls(
            result_id=stable_hash("capability_effect_execution_result", payload),
            receipt_id=validated_receipt.receipt_id,
            capability_ref=validated_receipt.capability_ref,
            observation_binding_id=binding.binding_id,
            effect_observations=values,
            oracle=oracle,
            cleanup=cleanup,
            execution_enabled=execution_enabled,
            execution_effect_authority=authority,
            _receipt=validated_receipt,
        )

    def __post_init__(self) -> None:
        try:
            receipt = _validated_receipt(
                self._receipt,
                expected_outcome=CapabilityExecutionOutcome.EXECUTION_COMPLETED,
                capability_ref=self.capability_ref,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capability effect execution result is invalid") from exc
        payload = _result_payload(
            receipt_id=self.receipt_id,
            capability_ref=self.capability_ref,
            observation_binding_id=self.observation_binding_id,
            observations=self.effect_observations,
            oracle=self.oracle,
            cleanup=self.cleanup,
            execution_enabled=self.execution_enabled,
            execution_effect_authority=self.execution_effect_authority,
            mode=self.mode,
        )
        expected_authority = bool(
            self.execution_enabled
            and self.oracle.verdict
            is CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
            and self.cleanup.status == "verified"
        )
        if (
            self.result_id != stable_hash("capability_effect_execution_result", payload)
            or not _hash_ref(
                self.result_id,
                "capability_effect_execution_result",
            )
            or self.receipt_id != receipt.receipt_id
            or not _hash_ref(self.capability_ref, "issued_capability_contract")
            or not _hash_ref(
                self.observation_binding_id,
                "experiment_world_binding",
            )
            or any(
                type(item) is not CapabilityEffectObservation
                for item in self.effect_observations
            )
            or tuple(item.observation_kind for item in self.effect_observations)
            != _OBSERVATION_KINDS
            or any(
                item.capability_ref != self.capability_ref
                or item.observation_binding_id != self.observation_binding_id
                for item in self.effect_observations
            )
            or type(self.oracle) is not CapabilityEffectOracleEvaluation
            or self.oracle.observation_binding_id != self.observation_binding_id
            or self.oracle.observation_refs
            != tuple(item.observation_id for item in self.effect_observations)
            or self.oracle.verdict is CapabilityEffectOracleVerdict.INCONCLUSIVE
            or type(self.cleanup) is not CapabilityCleanupResult
            or self.cleanup.status != "verified"
            or self.cleanup.target_requests_sent < len(_OBSERVATION_KINDS)
            or type(self.execution_enabled) is not bool
            or not self.execution_enabled
            or type(self.execution_effect_authority) is not bool
            or self.execution_effect_authority != expected_authority
            or self.mode != CAPABILITY_EFFECT_EXECUTION_MODE
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError("capability effect execution result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "result_id": self.result_id,
            **_result_payload(
                receipt_id=self.receipt_id,
                capability_ref=self.capability_ref,
                observation_binding_id=self.observation_binding_id,
                observations=self.effect_observations,
                oracle=self.oracle,
                cleanup=self.cleanup,
                execution_enabled=self.execution_enabled,
                execution_effect_authority=self.execution_effect_authority,
                mode=self.mode,
            ),
        }


def _unattempted_cleanup() -> CapabilityCleanupResult:
    return CapabilityCleanupResult(
        status="unattempted",
        target_requests_sent=0,
        target_request_may_have_been_sent=False,
        orphaned_owned_state_possible=False,
    )


def _uncertain_cleanup(
    *,
    target_requests_sent: int,
    target_request_may_have_been_sent: bool,
) -> CapabilityCleanupResult:
    return CapabilityCleanupResult(
        status="uncertain",
        target_requests_sent=target_requests_sent,
        target_request_may_have_been_sent=target_request_may_have_been_sent,
        orphaned_owned_state_possible=True,
    )


def _refusal_receipt(value: object) -> Optional[CapabilityExecutionReceipt]:
    try:
        receipt = _validated_receipt(value)
    except (TypeError, ValueError):
        return None
    return receipt if receipt.outcome in _REFUSAL_OUTCOMES else None


def _denial_reason(error: BaseException) -> Tuple[str, str]:
    if isinstance(error, CapabilityEffectExecutionDenied):
        return str(error), error.category
    return "capability_effect_execution_failed", "execution"


class CapabilityEffectExperimentExecutor:
    """Consume one R5D6 completion receipt and run one fixed R5D8 matrix."""

    def __init__(
        self,
        receipt: CapabilityExecutionReceipt,
        *,
        transport: CapabilityEffectTransport,
        config: Optional[CapabilityEffectExecutionConfig] = None,
    ) -> None:
        if type(receipt) is not CapabilityExecutionReceipt:
            raise TypeError("receipt must be an exact CapabilityExecutionReceipt")
        if not callable(getattr(transport, "dispatch", None)) or not callable(
            getattr(transport, "cleanup", None)
        ):
            raise TypeError("transport must implement dispatch and cleanup")
        if config is not None and type(config) is not CapabilityEffectExecutionConfig:
            raise TypeError("config must be a CapabilityEffectExecutionConfig")
        self.receipt = receipt
        self.transport = transport
        self.config = config or CapabilityEffectExecutionConfig.from_environment()
        self._lock = asyncio.Lock()
        self._consumed = False

    @staticmethod
    def _request(
        *,
        receipt: CapabilityExecutionReceipt,
        world: ExperimentWorldBinding,
        observation_kind: str,
    ) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": CAPABILITY_EFFECT_EXECUTION_MODE,
            "observation_kind": observation_kind,
            "expected_receipt_outcome": _EXPECTED_OUTCOMES[observation_kind].value,
            "witness_receipt_ref": receipt.receipt_id,
            "capability_ref": receipt.capability_ref,
            "observation_binding_id": world.binding_id,
            "owned_world_ref": world.world_ref,
            "owned_persona_ref": world.persona_ref,
            "ownership_ref": world.ownership_ref,
        }

    @staticmethod
    def _observation(
        *,
        witness_receipt: CapabilityExecutionReceipt,
        world: ExperimentWorldBinding,
        observation_kind: str,
        response_status: object,
        response: object,
    ) -> CapabilityEffectObservation:
        attached = None
        if isinstance(response, Mapping):
            attached = _refusal_receipt(response.get("terminal_receipt"))
        try:
            if (
                isinstance(response_status, bool)
                or not isinstance(response_status, int)
                or not 100 <= response_status <= 599
                or not isinstance(response, Mapping)
                or not {
                    "terminal_receipt",
                    "access_decision",
                    "effect",
                    "target_projection_observed",
                }
                <= set(response)
            ):
                raise ValueError("transport response shape is invalid")
            receipt = _validated_receipt(
                response["terminal_receipt"],
                expected_outcome=_EXPECTED_OUTCOMES[observation_kind],
                capability_ref=witness_receipt.capability_ref,
            )
            if (
                observation_kind == "valid_capability_effect_witness"
                and receipt.receipt_id != witness_receipt.receipt_id
            ):
                raise ValueError("witness receipt identity changed")
            access_decision = response["access_decision"]
            target_projection_observed = response["target_projection_observed"]
            if not isinstance(access_decision, str):
                raise TypeError("access decision is invalid")
            if type(target_projection_observed) is not bool:
                raise TypeError("target projection flag is invalid")
            effect = response["effect"]
            effect_ref = (
                stable_hash("capability_protected_effect", effect)
                if effect is not None
                else None
            )
            response_ref = stable_hash(
                "capability_effect_target_response",
                {
                    "receipt_ref": receipt.receipt_id,
                    "response_status": response_status,
                    "access_decision": access_decision,
                    "effect_ref": effect_ref,
                    "target_projection_observed": target_projection_observed,
                },
            )
            return CapabilityEffectObservation.build(
                terminal_receipt=receipt,
                observation_binding=world,
                response_ref=response_ref,
                observation_kind=observation_kind,
                access_decision=access_decision,
                response_status=response_status,
                effect=effect,
                target_projection_observed=target_projection_observed,
            )
        except (TypeError, ValueError) as exc:
            raise CapabilityEffectExecutionDenied(
                "capability_effect_transport_response_invalid",
                category="transport",
                target_request_possible=True,
                terminal_receipt=attached,
            ) from exc

    async def _cleanup(
        self,
        *,
        receipt: CapabilityExecutionReceipt,
        world: ExperimentWorldBinding,
        observations: Sequence[CapabilityEffectObservation],
        target_requests_sent: int,
        target_request_may_have_been_sent: bool,
    ) -> Tuple[CapabilityCleanupResult, Optional[BaseException]]:
        request = {
            "schema_version": 1,
            "mode": CAPABILITY_EFFECT_EXECUTION_MODE,
            "capability_ref": receipt.capability_ref,
            "witness_receipt_ref": receipt.receipt_id,
            "observation_binding_id": world.binding_id,
            "owned_world_ref": world.world_ref,
            "observation_refs": [item.observation_id for item in observations],
        }
        try:
            cleanup = await self.transport.cleanup(request)
            if type(cleanup) is not CapabilityCleanupResult:
                raise TypeError("cleanup result type is invalid")
            cleanup = replace(cleanup)
            if cleanup.target_requests_sent < target_requests_sent:
                raise ValueError("cleanup request count is invalid")
            return cleanup, None
        except BaseException as exc:
            return (
                _uncertain_cleanup(
                    target_requests_sent=target_requests_sent,
                    target_request_may_have_been_sent=True,
                ),
                exc,
            )

    async def execute(self) -> CapabilityEffectExecutionResult:
        async with self._lock:
            if self._consumed:
                raise CapabilityEffectExecutionDenied(
                    "capability_effect_executor_already_consumed",
                    category="executor",
                    cleanup=_unattempted_cleanup(),
                )
            if not self.config.enabled:
                raise CapabilityEffectExecutionDenied(
                    "capability_effect_execution_is_disabled",
                    category="configuration",
                    cleanup=_unattempted_cleanup(),
                )
            self._consumed = True

            try:
                receipt = _validated_receipt(self.receipt)
            except (TypeError, ValueError) as exc:
                raise CapabilityEffectExecutionDenied(
                    "capability_effect_execution_receipt_invalid",
                    category="receipt",
                    cleanup=_unattempted_cleanup(),
                ) from exc
            if receipt.outcome is not CapabilityExecutionOutcome.EXECUTION_COMPLETED:
                raise CapabilityEffectExecutionDenied(
                    "capability_effect_execution_receipt_not_completed",
                    category="receipt",
                    cleanup=_unattempted_cleanup(),
                    terminal_receipt=(
                        receipt if receipt.outcome in _REFUSAL_OUTCOMES else None
                    ),
                )
            try:
                world = _owned_world(receipt)
            except ValueError as exc:
                raise CapabilityEffectExecutionDenied(
                    "capability_effect_owned_world_invalid",
                    category="authority",
                    cleanup=_unattempted_cleanup(),
                ) from exc

            oracle_id = stable_hash(
                "capability_effect_oracle",
                {
                    "capability_ref": receipt.capability_ref,
                    "observation_binding_id": world.binding_id,
                    "mode": CAPABILITY_EFFECT_EXECUTION_MODE,
                },
            )
            observations = []
            oracle = None
            primary_error: Optional[BaseException] = None
            target_requests_sent = 0
            target_request_may_have_been_sent = False
            try:
                for observation_kind in _OBSERVATION_KINDS:
                    request = self._request(
                        receipt=receipt,
                        world=world,
                        observation_kind=observation_kind,
                    )
                    target_request_may_have_been_sent = True
                    response_status, response = await self.transport.dispatch(request)
                    target_requests_sent += 1
                    target_request_may_have_been_sent = False
                    observations.append(
                        self._observation(
                            witness_receipt=receipt,
                            world=world,
                            observation_kind=observation_kind,
                            response_status=response_status,
                            response=response,
                        )
                    )
                oracle = CapabilityEffectOracleEvaluation.build(
                    oracle_id=oracle_id,
                    observation_binding=world,
                    observations=observations,
                )
            except BaseException as exc:
                primary_error = exc

            cleanup, cleanup_error = await self._cleanup(
                receipt=receipt,
                world=world,
                observations=observations,
                target_requests_sent=target_requests_sent,
                target_request_may_have_been_sent=(target_request_may_have_been_sent),
            )
            if primary_error is None and cleanup_error is not None:
                primary_error = cleanup_error
            target_request_possible = bool(
                target_requests_sent
                or target_request_may_have_been_sent
                or cleanup.target_requests_sent
                or cleanup.target_request_may_have_been_sent
            )
            terminal_receipt = (
                primary_error.terminal_receipt
                if isinstance(primary_error, CapabilityEffectExecutionDenied)
                else None
            )
            if cleanup.status != "verified":
                raise CapabilityEffectExecutionDenied(
                    "capability_effect_cleanup_unverified",
                    category="cleanup",
                    target_request_possible=target_request_possible,
                    cleanup=cleanup,
                    oracle=oracle,
                    terminal_receipt=terminal_receipt,
                ) from primary_error
            if primary_error is not None:
                reason, category = _denial_reason(primary_error)
                raise CapabilityEffectExecutionDenied(
                    reason,
                    category=category,
                    target_request_possible=target_request_possible,
                    cleanup=cleanup,
                    oracle=oracle,
                    terminal_receipt=terminal_receipt,
                ) from primary_error
            if oracle is None:
                raise CapabilityEffectExecutionDenied(
                    "capability_effect_oracle_unavailable",
                    category="oracle",
                    target_request_possible=target_request_possible,
                    cleanup=cleanup,
                )
            if oracle.verdict is CapabilityEffectOracleVerdict.INCONCLUSIVE:
                raise CapabilityEffectExecutionDenied(
                    "capability_effect_oracle_inconclusive",
                    category="oracle",
                    target_request_possible=target_request_possible,
                    cleanup=cleanup,
                    oracle=oracle,
                )
            return CapabilityEffectExecutionResult.build(
                receipt=receipt,
                observation_binding=world,
                observations=observations,
                oracle=oracle,
                cleanup=cleanup,
                execution_enabled=self.config.enabled,
            )


__all__ = [
    "CAPABILITY_EFFECT_EXECUTION_ENV",
    "CAPABILITY_EFFECT_EXECUTION_MODE",
    "CapabilityCleanupResult",
    "CapabilityEffectExecutionConfig",
    "CapabilityEffectExecutionDenied",
    "CapabilityEffectExecutionResult",
    "CapabilityEffectExperimentExecutor",
    "CapabilityEffectObservation",
    "CapabilityEffectOracleEvaluation",
    "CapabilityEffectOracleVerdict",
    "CapabilityEffectTransport",
]
