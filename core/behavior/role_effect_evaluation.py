"""Default-off R5C6 protected-effect execution and independent evaluation.

One fresh R5C4 claim drives the already-bound eight-action role lifecycle. The
five protected-effect actions use their exact retained personas and sessions,
while setup, revocation, and target-side revocation verification reuse the R5C5
lifecycle seam. Response bodies are interpreted only through the R5C6 binding;
durable receipts retain content-addressed evidence, never raw effect values.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.cortex.execution_policy import DENIED_STATUS

from .normalize import stable_hash
from .receipts import ABORTED, COMPLETED, BehavioralExecutionReceipt
from .role_execution_claim import (
    RoleMonotonicityExecutionClaim,
    RoleMonotonicityExecutionClaimDenied,
)
from .role_membership_lifecycle import (
    RoleMembershipCleanupResult,
    RoleMembershipStateObservation,
    RoleSessionResponseText,
    _LifecycleState,
    _cleanup,
    _dispatch,
    _entries,
    _observe_membership,
    _skip_to,
    _validate_runtime_plan,
)
from .role_request_binding import (
    RoleMonotonicityRuntimeContext,
    RoleProtectedEffectObservationBinding,
    RoleRuntimeActionAuthorityBinding,
)


ROLE_PROTECTED_EFFECT_EXECUTION_ENV = (
    "SENTINELFORGE_BEHAVIOR_ROLE_PROTECTED_EFFECT_EXECUTION"
)
ROLE_PROTECTED_EFFECT_EXECUTION_KIND = "role_protected_effect_execution"
ROLE_PROTECTED_EFFECT_EXECUTION_MODE = (
    "behavioral_role_protected_effect_execution_v1"
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_BARE_HASH = re.compile(r"^[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_OBSERVATION_KINDS = (
    "higher_baseline",
    "active_lower_probe",
    "active_effect_witness",
    "revoked_lower_probe",
    "revoked_effect_witness",
)
_ORDINAL_KIND = dict(zip((1, 2, 3, 6, 7), _OBSERVATION_KINDS))
_PROBE_KINDS = frozenset(
    {"higher_baseline", "active_lower_probe", "revoked_lower_probe"}
)


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return bool(
        isinstance(value, str)
        and _HASH_REF.fullmatch(value)
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


class RoleProtectedEffectExecutionDenied(RuntimeError):
    """R5C6 was refused, aborted, or could not establish a conclusive oracle."""

    def __init__(
        self,
        reason: str,
        *,
        category: str = "execution",
        target_request_possible: bool = False,
        cleanup: Optional[RoleMembershipCleanupResult] = None,
        oracle: Optional["RoleProtectedEffectOracleEvaluation"] = None,
        terminal_receipt: Optional[BehavioralExecutionReceipt] = None,
    ) -> None:
        super().__init__(reason)
        self.category = category
        self.target_request_possible = bool(target_request_possible)
        self.cleanup = cleanup
        self.oracle = oracle
        if terminal_receipt is not None and (
            not isinstance(terminal_receipt, BehavioralExecutionReceipt)
            or terminal_receipt.state != ABORTED
        ):
            raise ValueError("role effect terminal receipt is invalid")
        self.terminal_receipt = terminal_receipt


@dataclass(frozen=True)
class RoleProtectedEffectExecutionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("role protected effect execution enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "RoleProtectedEffectExecutionConfig":
        return cls(
            enabled=(
                str(os.environ.get(ROLE_PROTECTED_EFFECT_EXECUTION_ENV, ""))
                .strip()
                .lower()
                in _TRUE
            )
        )


class RoleProtectedEffectOracleVerdict(str, Enum):
    CONFIRMED_ACTIVE_ESCALATION = "confirmed_active_escalation"
    CONFIRMED_REVOCATION_SURVIVAL = "confirmed_revocation_survival"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


def _resolve_pointer(value: Any, pointer: str) -> Any:
    current = value
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and token in current:
            current = current[token]
            continue
        if isinstance(current, list) and token.isdigit():
            index = int(token)
            if index < len(current):
                current = current[index]
                continue
        raise RoleProtectedEffectExecutionDenied(
            "role_protected_effect_observation_pointer_unresolved",
            category="oracle",
            target_request_possible=True,
        )
    return current


def _expected_session(
    *,
    entry: RoleRuntimeActionAuthorityBinding,
    runtime: RoleMonotonicityRuntimeContext,
) -> Tuple[str, str]:
    if entry.session_ref == runtime.higher_session_ref:
        return runtime.higher_persona_id, runtime.higher_session_id
    if entry.session_ref == runtime.active_lower_session_ref:
        return runtime.lower_persona_id, runtime.active_lower_session_id
    if entry.session_ref == runtime.revoked_lower_session_ref:
        return runtime.lower_persona_id, runtime.revoked_lower_session_id
    raise RoleProtectedEffectExecutionDenied(
        "role_protected_effect_runtime_session_is_not_bound",
        category="session",
    )


def _effect_observation_payload(
    *,
    action_binding_id: str,
    observation_binding_id: str,
    session_attestation_ref: str,
    response_ref: str,
    observation_kind: str,
    response_status: int,
    access_decision: str,
    effect_ref: Optional[str],
) -> Dict[str, Any]:
    return {
        "action_binding_id": action_binding_id,
        "observation_binding_id": observation_binding_id,
        "session_attestation_ref": session_attestation_ref,
        "response_ref": response_ref,
        "observation_kind": observation_kind,
        "response_status": response_status,
        "access_decision": access_decision,
        "effect_ref": effect_ref,
        "protected_effect_observed": effect_ref is not None,
        "target_projection_observed": True,
    }


@dataclass(frozen=True)
class RoleProtectedEffectObservation:
    observation_id: str
    action_binding_id: str
    observation_binding_id: str
    session_attestation_ref: str
    response_ref: str
    observation_kind: str
    response_status: int
    access_decision: str
    effect_ref: Optional[str]
    protected_effect_observed: bool
    target_projection_observed: bool = True

    def __post_init__(self) -> None:
        payload = _effect_observation_payload(
            action_binding_id=self.action_binding_id,
            observation_binding_id=self.observation_binding_id,
            session_attestation_ref=self.session_attestation_ref,
            response_ref=self.response_ref,
            observation_kind=self.observation_kind,
            response_status=self.response_status,
            access_decision=self.access_decision,
            effect_ref=self.effect_ref,
        )
        decision_valid = (
            self.access_decision == "allowed"
            and 200 <= self.response_status < 300
            and self.effect_ref is not None
        ) or (
            self.access_decision == "denied"
            and 100 <= self.response_status < 500
            and self.effect_ref is None
        ) or (
            self.access_decision == "witness"
            and 200 <= self.response_status < 300
            and self.effect_ref is not None
        ) or self.access_decision == "unknown"
        if (
            self.observation_id
            != stable_hash("role_protected_effect_observation", payload)
            or not _hash_ref(
                self.observation_id,
                "role_protected_effect_observation",
            )
            or not _hash_ref(
                self.action_binding_id,
                "role_runtime_action_authority",
            )
            or not _hash_ref(
                self.observation_binding_id,
                "role_protected_effect_observation_binding",
            )
            or not _hash_ref(
                self.session_attestation_ref,
                "role_session_transport_attestation",
            )
            or not _hash_ref(
                self.response_ref,
                "role_protected_effect_target_response",
            )
            or self.observation_kind not in _OBSERVATION_KINDS
            or isinstance(self.response_status, bool)
            or not isinstance(self.response_status, int)
            or not 100 <= self.response_status <= 599
            or not decision_valid
            or (
                self.observation_kind in _PROBE_KINDS
                and self.access_decision == "witness"
            )
            or (
                self.observation_kind not in _PROBE_KINDS
                and self.access_decision in {"allowed", "denied"}
            )
            or (
                self.effect_ref is not None
                and not _hash_ref(self.effect_ref, "role_protected_effect")
            )
            or not isinstance(self.protected_effect_observed, bool)
            or self.protected_effect_observed != (self.effect_ref is not None)
            or self.target_projection_observed is not True
        ):
            raise ValueError("role protected effect observation is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            **_effect_observation_payload(
                action_binding_id=self.action_binding_id,
                observation_binding_id=self.observation_binding_id,
                session_attestation_ref=self.session_attestation_ref,
                response_ref=self.response_ref,
                observation_kind=self.observation_kind,
                response_status=self.response_status,
                access_decision=self.access_decision,
                effect_ref=self.effect_ref,
            ),
        }


def _observe_effect(
    *,
    entry: RoleRuntimeActionAuthorityBinding,
    runtime: RoleMonotonicityRuntimeContext,
    response_status: int,
    response: Any,
) -> RoleProtectedEffectObservation:
    ordinal = entry.request_binding.ordinal
    kind = _ORDINAL_KIND.get(ordinal)
    if kind is None:
        raise RoleProtectedEffectExecutionDenied(
            "role_protected_effect_action_is_not_an_oracle_unit",
            category="plan",
        )
    binding = runtime.effect_observation_binding
    action_ids = {
        "higher_baseline": binding.higher_baseline_action_id,
        "active_lower_probe": binding.active_lower_probe_action_id,
        "active_effect_witness": binding.active_effect_witness_action_id,
        "revoked_lower_probe": binding.revoked_lower_probe_action_id,
        "revoked_effect_witness": binding.revoked_effect_witness_action_id,
    }
    if entry.request_binding.action_id != action_ids[kind]:
        raise RoleProtectedEffectExecutionDenied(
            "role_protected_effect_action_binding_mismatch",
            category="plan",
        )
    if (
        response_status == DENIED_STATUS
        or isinstance(response_status, bool)
        or not isinstance(response_status, int)
        or not 100 <= response_status <= 599
        or not isinstance(response, RoleSessionResponseText)
        or response.body_truncated
    ):
        raise RoleProtectedEffectExecutionDenied(
            "role_protected_effect_target_observation_unavailable",
            category="oracle",
            target_request_possible=True,
        )
    persona_id, session_id = _expected_session(entry=entry, runtime=runtime)
    if (
        not hmac.compare_digest(response.persona_id, persona_id)
        or not hmac.compare_digest(response.session_id, session_id)
    ):
        raise RoleProtectedEffectExecutionDenied(
            "role_protected_effect_session_attestation_mismatch",
            category="session",
            target_request_possible=True,
        )
    try:
        decoded = json.loads(str(response))
    except (TypeError, ValueError) as exc:
        raise RoleProtectedEffectExecutionDenied(
            "role_protected_effect_target_observation_is_not_json",
            category="oracle",
            target_request_possible=True,
        ) from exc
    if not isinstance(decoded, Mapping):
        raise RoleProtectedEffectExecutionDenied(
            "role_protected_effect_target_observation_is_not_an_object",
            category="oracle",
            target_request_possible=True,
        )

    if kind in _PROBE_KINDS:
        authorized = _resolve_pointer(decoded, binding.probe_authorized_pointer)
        effect = _resolve_pointer(decoded, binding.probe_effect_pointer)
        if authorized is True and effect is not None and 200 <= response_status < 300:
            decision = "allowed"
        elif authorized is False and effect is None and response_status < 500:
            decision = "denied"
        else:
            decision = "unknown"
    else:
        effect = _resolve_pointer(decoded, binding.witness_effect_pointer)
        decision = (
            "witness"
            if effect is not None and 200 <= response_status < 300
            else "unknown"
        )
    effect_ref = (
        stable_hash("role_protected_effect", effect)
        if effect is not None
        else None
    )
    response_ref = stable_hash(
        "role_protected_effect_target_response",
        {"status": response_status, "body": str(response)},
    )
    session_attestation_ref = stable_hash(
        "role_session_transport_attestation",
        {
            "action_binding_id": entry.binding_id,
            "session_ref": entry.session_ref,
            "response_ref": response_ref,
        },
    )
    payload = _effect_observation_payload(
        action_binding_id=entry.binding_id,
        observation_binding_id=binding.binding_id,
        session_attestation_ref=session_attestation_ref,
        response_ref=response_ref,
        observation_kind=kind,
        response_status=response_status,
        access_decision=decision,
        effect_ref=effect_ref,
    )
    return RoleProtectedEffectObservation(
        observation_id=stable_hash(
            "role_protected_effect_observation",
            payload,
        ),
        action_binding_id=entry.binding_id,
        observation_binding_id=binding.binding_id,
        session_attestation_ref=session_attestation_ref,
        response_ref=response_ref,
        observation_kind=kind,
        response_status=response_status,
        access_decision=decision,
        effect_ref=effect_ref,
        protected_effect_observed=effect_ref is not None,
    )


def _oracle_components(
    *,
    oracle_id: str,
    observation_binding_id: str,
    observations: Sequence[RoleProtectedEffectObservation],
) -> Dict[str, Any]:
    values = tuple(observations)
    if tuple(item.observation_kind for item in values) != _OBSERVATION_KINDS:
        raise ValueError("role protected effect observation order is invalid")
    if any(
        item.observation_binding_id != observation_binding_id for item in values
    ):
        raise ValueError("role protected effect observation binding changed")
    baseline, active_probe, active_witness, revoked_probe, revoked_witness = values
    baseline_valid = bool(
        baseline.access_decision == "allowed" and baseline.effect_ref is not None
    )
    baseline_effect_ref = baseline.effect_ref if baseline_valid else None
    active_witness_valid = bool(
        baseline_effect_ref is not None
        and active_witness.access_decision == "witness"
        and active_witness.effect_ref == baseline_effect_ref
    )
    revoked_witness_valid = bool(
        baseline_effect_ref is not None
        and revoked_witness.access_decision == "witness"
        and revoked_witness.effect_ref == baseline_effect_ref
    )

    def phase_outcome(
        probe: RoleProtectedEffectObservation,
        witness_valid: bool,
    ) -> str:
        if not witness_valid:
            return "unknown"
        if (
            probe.access_decision == "allowed"
            and probe.effect_ref == baseline_effect_ref
        ):
            return "effect"
        if probe.access_decision == "denied" and probe.effect_ref is None:
            return "denied"
        return "unknown"

    active_outcome = phase_outcome(active_probe, active_witness_valid)
    revoked_outcome = phase_outcome(revoked_probe, revoked_witness_valid)
    uncertainty = set()
    if not baseline_valid:
        uncertainty.add("higher_baseline_effect_unavailable")
    if not active_witness_valid:
        uncertainty.add("active_independent_effect_witness_unavailable")
    if not revoked_witness_valid:
        uncertainty.add("revoked_independent_effect_witness_unavailable")
    if active_outcome == "unknown":
        uncertainty.add("active_lower_probe_effect_inconclusive")
    if revoked_outcome == "unknown":
        uncertainty.add("revoked_lower_probe_effect_inconclusive")

    verdict = RoleProtectedEffectOracleVerdict.INCONCLUSIVE
    if not uncertainty:
        if revoked_outcome == "effect":
            verdict = (
                RoleProtectedEffectOracleVerdict.CONFIRMED_REVOCATION_SURVIVAL
            )
        elif active_outcome == "effect":
            verdict = (
                RoleProtectedEffectOracleVerdict.CONFIRMED_ACTIVE_ESCALATION
            )
        else:
            verdict = RoleProtectedEffectOracleVerdict.REFUTED
    active_witness_ref = (
        stable_hash(
            "role_active_effect_witness",
            {
                "oracle_id": oracle_id,
                "observation_binding_id": observation_binding_id,
                "baseline_observation_ref": baseline.observation_id,
                "witness_observation_ref": active_witness.observation_id,
                "effect_ref": baseline_effect_ref,
            },
        )
        if active_witness_valid
        else None
    )
    revoked_witness_ref = (
        stable_hash(
            "role_revoked_effect_witness",
            {
                "oracle_id": oracle_id,
                "observation_binding_id": observation_binding_id,
                "baseline_observation_ref": baseline.observation_id,
                "witness_observation_ref": revoked_witness.observation_id,
                "effect_ref": baseline_effect_ref,
            },
        )
        if revoked_witness_valid
        else None
    )
    confirmed = verdict in {
        RoleProtectedEffectOracleVerdict.CONFIRMED_ACTIVE_ESCALATION,
        RoleProtectedEffectOracleVerdict.CONFIRMED_REVOCATION_SURVIVAL,
    }
    candidate_ref = (
        stable_hash(
            "role_monotonicity_finding_candidate",
            {
                "oracle_id": oracle_id,
                "observation_binding_id": observation_binding_id,
                "verdict": verdict.value,
                "observation_refs": [item.observation_id for item in values],
                "active_effect_witness_ref": active_witness_ref,
                "revoked_effect_witness_ref": revoked_witness_ref,
            },
        )
        if confirmed
        else None
    )
    return {
        "oracle_id": oracle_id,
        "observation_binding_id": observation_binding_id,
        "verdict": verdict,
        "observation_refs": tuple(item.observation_id for item in values),
        "uncertainty_reasons": tuple(sorted(uncertainty)),
        "valid_baseline_observed": baseline_valid,
        "active_independent_witness_observed": active_witness_valid,
        "revoked_independent_witness_observed": revoked_witness_valid,
        "active_reference_effect_observed": active_outcome == "effect",
        "revoked_reference_effect_observed": revoked_outcome == "effect",
        "active_explicit_denial_observed": active_outcome == "denied",
        "revoked_explicit_denial_observed": revoked_outcome == "denied",
        "active_effect_witness_ref": active_witness_ref,
        "revoked_effect_witness_ref": revoked_witness_ref,
        "finding_candidate_ref": candidate_ref,
    }


def _oracle_payload(components: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "oracle_id": components["oracle_id"],
        "observation_binding_id": components["observation_binding_id"],
        "verdict": components["verdict"].value,
        "observation_refs": list(components["observation_refs"]),
        "uncertainty_reasons": list(components["uncertainty_reasons"]),
        "valid_baseline_observed": components["valid_baseline_observed"],
        "active_independent_witness_observed": components[
            "active_independent_witness_observed"
        ],
        "revoked_independent_witness_observed": components[
            "revoked_independent_witness_observed"
        ],
        "active_reference_effect_observed": components[
            "active_reference_effect_observed"
        ],
        "revoked_reference_effect_observed": components[
            "revoked_reference_effect_observed"
        ],
        "active_explicit_denial_observed": components[
            "active_explicit_denial_observed"
        ],
        "revoked_explicit_denial_observed": components[
            "revoked_explicit_denial_observed"
        ],
        "active_effect_witness_ref": components["active_effect_witness_ref"],
        "revoked_effect_witness_ref": components["revoked_effect_witness_ref"],
        "finding_candidate_ref": components["finding_candidate_ref"],
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }


@dataclass(frozen=True)
class RoleProtectedEffectOracleEvaluation:
    evaluation_id: str
    oracle_id: str
    observation_binding_id: str
    verdict: RoleProtectedEffectOracleVerdict
    observation_refs: Tuple[str, ...]
    uncertainty_reasons: Tuple[str, ...]
    valid_baseline_observed: bool
    active_independent_witness_observed: bool
    revoked_independent_witness_observed: bool
    active_reference_effect_observed: bool
    revoked_reference_effect_observed: bool
    active_explicit_denial_observed: bool
    revoked_explicit_denial_observed: bool
    active_effect_witness_ref: Optional[str]
    revoked_effect_witness_ref: Optional[str]
    finding_candidate_ref: Optional[str]
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False

    @classmethod
    def build(
        cls,
        *,
        oracle_id: str,
        observation_binding: RoleProtectedEffectObservationBinding,
        observations: Sequence[RoleProtectedEffectObservation],
    ) -> "RoleProtectedEffectOracleEvaluation":
        if not _hash_ref(oracle_id, "role_monotonicity_oracle"):
            raise ValueError("role protected effect oracle id is invalid")
        if not isinstance(
            observation_binding,
            RoleProtectedEffectObservationBinding,
        ):
            raise TypeError(
                "observation_binding must be a protected effect binding"
            )
        values = tuple(observations)
        if any(
            not isinstance(item, RoleProtectedEffectObservation)
            for item in values
        ):
            raise TypeError("protected effect observations are invalid")
        components = _oracle_components(
            oracle_id=oracle_id,
            observation_binding_id=observation_binding.binding_id,
            observations=values,
        )
        payload = _oracle_payload(components)
        return cls(
            evaluation_id=stable_hash(
                "role_protected_effect_oracle_evaluation",
                payload,
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
            "valid_baseline_observed": self.valid_baseline_observed,
            "active_independent_witness_observed": (
                self.active_independent_witness_observed
            ),
            "revoked_independent_witness_observed": (
                self.revoked_independent_witness_observed
            ),
            "active_reference_effect_observed": (
                self.active_reference_effect_observed
            ),
            "revoked_reference_effect_observed": (
                self.revoked_reference_effect_observed
            ),
            "active_explicit_denial_observed": (
                self.active_explicit_denial_observed
            ),
            "revoked_explicit_denial_observed": (
                self.revoked_explicit_denial_observed
            ),
            "active_effect_witness_ref": self.active_effect_witness_ref,
            "revoked_effect_witness_ref": self.revoked_effect_witness_ref,
            "finding_candidate_ref": self.finding_candidate_ref,
        }
        payload = _oracle_payload(components)
        confirmed = self.verdict in {
            RoleProtectedEffectOracleVerdict.CONFIRMED_ACTIVE_ESCALATION,
            RoleProtectedEffectOracleVerdict.CONFIRMED_REVOCATION_SURVIVAL,
        }
        conclusive = self.verdict is not RoleProtectedEffectOracleVerdict.INCONCLUSIVE
        active_decisive = (
            self.active_reference_effect_observed
            != self.active_explicit_denial_observed
        )
        revoked_decisive = (
            self.revoked_reference_effect_observed
            != self.revoked_explicit_denial_observed
        )
        verdict_consistent = (
            self.verdict
            is RoleProtectedEffectOracleVerdict.CONFIRMED_REVOCATION_SURVIVAL
            and self.revoked_reference_effect_observed
        ) or (
            self.verdict
            is RoleProtectedEffectOracleVerdict.CONFIRMED_ACTIVE_ESCALATION
            and self.active_reference_effect_observed
            and self.revoked_explicit_denial_observed
        ) or (
            self.verdict is RoleProtectedEffectOracleVerdict.REFUTED
            and self.active_explicit_denial_observed
            and self.revoked_explicit_denial_observed
        ) or self.verdict is RoleProtectedEffectOracleVerdict.INCONCLUSIVE
        if (
            self.evaluation_id
            != stable_hash("role_protected_effect_oracle_evaluation", payload)
            or not _hash_ref(
                self.evaluation_id,
                "role_protected_effect_oracle_evaluation",
            )
            or not _hash_ref(self.oracle_id, "role_monotonicity_oracle")
            or not _hash_ref(
                self.observation_binding_id,
                "role_protected_effect_observation_binding",
            )
            or len(self.observation_refs) != 5
            or len(set(self.observation_refs)) != 5
            or any(
                not _hash_ref(item, "role_protected_effect_observation")
                for item in self.observation_refs
            )
            or self.uncertainty_reasons
            != tuple(sorted(set(self.uncertainty_reasons)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.uncertainty_reasons)
            or any(
                not isinstance(item, bool)
                for item in (
                    self.valid_baseline_observed,
                    self.active_independent_witness_observed,
                    self.revoked_independent_witness_observed,
                    self.active_reference_effect_observed,
                    self.revoked_reference_effect_observed,
                    self.active_explicit_denial_observed,
                    self.revoked_explicit_denial_observed,
                )
            )
            or (
                self.verdict is RoleProtectedEffectOracleVerdict.INCONCLUSIVE
            )
            != bool(self.uncertainty_reasons)
            or (
                conclusive
                and not (
                    self.valid_baseline_observed
                    and self.active_independent_witness_observed
                    and self.revoked_independent_witness_observed
                    and active_decisive
                    and revoked_decisive
                )
            )
            or not verdict_consistent
            or (self.active_effect_witness_ref is not None)
            != self.active_independent_witness_observed
            or (self.revoked_effect_witness_ref is not None)
            != self.revoked_independent_witness_observed
            or (
                self.active_effect_witness_ref is not None
                and not _hash_ref(
                    self.active_effect_witness_ref,
                    "role_active_effect_witness",
                )
            )
            or (
                self.revoked_effect_witness_ref is not None
                and not _hash_ref(
                    self.revoked_effect_witness_ref,
                    "role_revoked_effect_witness",
                )
            )
            or (self.finding_candidate_ref is not None) != confirmed
            or (
                self.finding_candidate_ref is not None
                and not _hash_ref(
                    self.finding_candidate_ref,
                    "role_monotonicity_finding_candidate",
                )
            )
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError("role protected effect oracle evaluation is invalid")

    def to_dict(self) -> Dict[str, Any]:
        components = {
            "oracle_id": self.oracle_id,
            "observation_binding_id": self.observation_binding_id,
            "verdict": self.verdict,
            "observation_refs": self.observation_refs,
            "uncertainty_reasons": self.uncertainty_reasons,
            "valid_baseline_observed": self.valid_baseline_observed,
            "active_independent_witness_observed": (
                self.active_independent_witness_observed
            ),
            "revoked_independent_witness_observed": (
                self.revoked_independent_witness_observed
            ),
            "active_reference_effect_observed": (
                self.active_reference_effect_observed
            ),
            "revoked_reference_effect_observed": (
                self.revoked_reference_effect_observed
            ),
            "active_explicit_denial_observed": (
                self.active_explicit_denial_observed
            ),
            "revoked_explicit_denial_observed": (
                self.revoked_explicit_denial_observed
            ),
            "active_effect_witness_ref": self.active_effect_witness_ref,
            "revoked_effect_witness_ref": self.revoked_effect_witness_ref,
            "finding_candidate_ref": self.finding_candidate_ref,
        }
        return {
            "evaluation_id": self.evaluation_id,
            **_oracle_payload(components),
        }


def _completed_outcome(
    *,
    claim_contract_id: str,
    active_observation: RoleMembershipStateObservation,
    revoked_observation: RoleMembershipStateObservation,
    observations: Sequence[RoleProtectedEffectObservation],
    oracle: RoleProtectedEffectOracleEvaluation,
    cleanup: RoleMembershipCleanupResult,
    provenance_root: str,
    target_requests_sent: int,
) -> Dict[str, Any]:
    confirmed = oracle.verdict in {
        RoleProtectedEffectOracleVerdict.CONFIRMED_ACTIVE_ESCALATION,
        RoleProtectedEffectOracleVerdict.CONFIRMED_REVOCATION_SURVIVAL,
    }
    return {
        "kind": ROLE_PROTECTED_EFFECT_EXECUTION_KIND,
        "mode": ROLE_PROTECTED_EFFECT_EXECUTION_MODE,
        "status": oracle.verdict.value,
        "receipt_state": COMPLETED,
        "claim_contract_id": claim_contract_id,
        "oracle_id": oracle.oracle_id,
        "oracle_evaluation_id": oracle.evaluation_id,
        "oracle_verdict": oracle.verdict.value,
        "active_membership_observation_ref": active_observation.observation_id,
        "revoked_membership_observation_ref": revoked_observation.observation_id,
        "effect_observation_refs": [
            item.observation_id for item in observations
        ],
        "active_effect_witness_ref": oracle.active_effect_witness_ref,
        "revoked_effect_witness_ref": oracle.revoked_effect_witness_ref,
        "cleanup_status": cleanup.status,
        "target_requests_sent": target_requests_sent,
        "target_request_may_have_been_sent": (
            cleanup.target_request_may_have_been_sent
        ),
        "orphaned_owned_state_possible": (
            cleanup.orphaned_owned_state_possible
        ),
        "provenance_root": provenance_root,
        "finding_candidate_ref": oracle.finding_candidate_ref,
        "finding_confirmed": confirmed,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }


def _terminal_evidence(
    *,
    claim_contract_id: str,
    oracle_id: str,
    reason: str,
    category: str,
    active_observation: Optional[RoleMembershipStateObservation],
    revoked_observation: Optional[RoleMembershipStateObservation],
    observations: Sequence[RoleProtectedEffectObservation],
    oracle: Optional[RoleProtectedEffectOracleEvaluation],
    cleanup: RoleMembershipCleanupResult,
) -> Dict[str, Any]:
    payload = {
        "kind": "role_protected_effect_execution_terminal",
        "status": (
            "cleaned" if cleanup.status == "verified" else "cleanup_failed"
        ),
        "reason_code": reason,
        "category": category,
        "claim_contract_id": claim_contract_id,
        "oracle_id": oracle_id,
        "oracle_evaluation_id": (
            oracle.evaluation_id if oracle is not None else None
        ),
        "active_membership_observation_ref": (
            active_observation.observation_id
            if active_observation is not None
            else None
        ),
        "revoked_membership_observation_ref": (
            revoked_observation.observation_id
            if revoked_observation is not None
            else None
        ),
        "effect_observation_refs": [
            item.observation_id for item in observations
        ],
        "cleanup": cleanup.to_dict(),
        "target_requests_sent": cleanup.target_requests_sent,
        "target_request_may_have_been_sent": (
            cleanup.target_request_may_have_been_sent
        ),
        "orphaned_owned_state_possible": (
            cleanup.orphaned_owned_state_possible
        ),
        "oracle_verdict": "inconclusive",
        "finding_candidate_ref": None,
        "finding_confirmed": False,
        "promotion_authority": False,
        "finding_authority": False,
        "retry_authority": False,
    }
    return {
        "schema_version": 1,
        "terminal_evidence_ref": stable_hash(
            "role_protected_effect_execution_terminal_evidence",
            payload,
        ),
        **payload,
    }


def _result_payload(
    *,
    receipt_id: str,
    claim_contract_id: str,
    active_observation: RoleMembershipStateObservation,
    revoked_observation: RoleMembershipStateObservation,
    observations: Sequence[RoleProtectedEffectObservation],
    oracle: RoleProtectedEffectOracleEvaluation,
    cleanup: RoleMembershipCleanupResult,
    provenance_root: str,
) -> Dict[str, Any]:
    outcome = _completed_outcome(
        claim_contract_id=claim_contract_id,
        active_observation=active_observation,
        revoked_observation=revoked_observation,
        observations=observations,
        oracle=oracle,
        cleanup=cleanup,
        provenance_root=provenance_root,
        target_requests_sent=cleanup.target_requests_sent,
    )
    return {
        **outcome,
        "receipt_id": receipt_id,
        "active_membership_observation": active_observation.to_dict(),
        "revoked_membership_observation": revoked_observation.to_dict(),
        "effect_observations": [item.to_dict() for item in observations],
        "oracle": oracle.to_dict(),
        "cleanup": cleanup.to_dict(),
    }


@dataclass(frozen=True)
class RoleProtectedEffectExecutionResult:
    result_id: str
    receipt_id: str
    claim_contract_id: str
    active_membership_observation: RoleMembershipStateObservation
    revoked_membership_observation: RoleMembershipStateObservation
    effect_observations: Tuple[RoleProtectedEffectObservation, ...]
    oracle: RoleProtectedEffectOracleEvaluation
    cleanup: RoleMembershipCleanupResult
    provenance_root: str

    def __post_init__(self) -> None:
        payload = _result_payload(
            receipt_id=self.receipt_id,
            claim_contract_id=self.claim_contract_id,
            active_observation=self.active_membership_observation,
            revoked_observation=self.revoked_membership_observation,
            observations=self.effect_observations,
            oracle=self.oracle,
            cleanup=self.cleanup,
            provenance_root=self.provenance_root,
        )
        if (
            self.result_id
            != stable_hash("role_protected_effect_execution_result", payload)
            or not _hash_ref(
                self.result_id,
                "role_protected_effect_execution_result",
            )
            or not isinstance(self.receipt_id, str)
            or not self.receipt_id.startswith("behavioral-")
            or len(self.receipt_id) != len("behavioral-") + 64
            or not _hash_ref(
                self.claim_contract_id,
                "role_monotonicity_execution_claim_contract",
            )
            or tuple(
                item.observation_kind for item in self.effect_observations
            )
            != _OBSERVATION_KINDS
            or self.oracle.observation_refs
            != tuple(item.observation_id for item in self.effect_observations)
            or self.active_membership_observation.state != "active"
            or self.revoked_membership_observation.state != "revoked"
            or self.active_membership_observation.membership_ref
            != self.revoked_membership_observation.membership_ref
            or self.cleanup.status != "verified"
            or self.cleanup.orphaned_owned_state_possible
            or self.cleanup.target_requests_sent != 8
            or _BARE_HASH.fullmatch(self.provenance_root) is None
            or self.oracle.verdict
            is RoleProtectedEffectOracleVerdict.INCONCLUSIVE
        ):
            raise ValueError("role protected effect execution result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "result_id": self.result_id,
            **_result_payload(
                receipt_id=self.receipt_id,
                claim_contract_id=self.claim_contract_id,
                active_observation=self.active_membership_observation,
                revoked_observation=self.revoked_membership_observation,
                observations=self.effect_observations,
                oracle=self.oracle,
                cleanup=self.cleanup,
                provenance_root=self.provenance_root,
            ),
        }

    def execution_response(self) -> Dict[str, Any]:
        return _completed_outcome(
            claim_contract_id=self.claim_contract_id,
            active_observation=self.active_membership_observation,
            revoked_observation=self.revoked_membership_observation,
            observations=self.effect_observations,
            oracle=self.oracle,
            cleanup=self.cleanup,
            provenance_root=self.provenance_root,
            target_requests_sent=self.cleanup.target_requests_sent,
        )


def _reason(error: Optional[BaseException], cleanup) -> Tuple[str, str]:
    if cleanup.status != "verified":
        return "role_protected_effect_cleanup_unverified", "cleanup"
    if error is None:
        return "role_protected_effect_execution_failed", "execution"
    reason = str(error)
    category = getattr(error, "category", "execution")
    if _SEMANTIC.fullmatch(reason) is None:
        reason = "role_protected_effect_execution_failed"
    if _SEMANTIC.fullmatch(str(category or "")) is None:
        category = "execution"
    return reason, str(category)


def _cleanup_snapshot(
    cleanup: RoleMembershipCleanupResult,
    state: _LifecycleState,
) -> RoleMembershipCleanupResult:
    return replace(
        cleanup,
        target_requests_sent=state.target_requests_sent,
        target_request_may_have_been_sent=(
            state.target_request_may_have_been_sent
        ),
    )


def _uncertain_cleanup(state: _LifecycleState) -> RoleMembershipCleanupResult:
    return RoleMembershipCleanupResult(
        status="uncertain",
        revocation_attempted=0,
        revocation_completed=0,
        verification_attempted=0,
        verification_completed=0,
        revoked_observation_ref=None,
        target_requests_sent=state.target_requests_sent,
        target_request_may_have_been_sent=(
            state.target_request_may_have_been_sent
        ),
        orphaned_owned_state_possible=True,
    )


class RoleProtectedEffectExperimentExecutor:
    """Consume one fresh claim and terminalize every R5C6 path exactly once."""

    def __init__(
        self,
        claim: RoleMonotonicityExecutionClaim,
        *,
        config: Optional[RoleProtectedEffectExecutionConfig] = None,
    ) -> None:
        if not isinstance(claim, RoleMonotonicityExecutionClaim):
            raise TypeError("claim must be a RoleMonotonicityExecutionClaim")
        if config is not None and not isinstance(
            config,
            RoleProtectedEffectExecutionConfig,
        ):
            raise TypeError(
                "config must be a RoleProtectedEffectExecutionConfig"
            )
        self.claim = claim
        self.config = config or RoleProtectedEffectExecutionConfig.from_environment()
        self._lock = asyncio.Lock()
        self._consumed = False

    async def execute(self) -> RoleProtectedEffectExecutionResult:
        async with self._lock:
            if self._consumed:
                raise RoleProtectedEffectExecutionDenied(
                    "role_protected_effect_executor_already_consumed",
                    category="claim",
                )
            if not self.config.enabled:
                raise RoleProtectedEffectExecutionDenied(
                    "role_protected_effect_execution_is_disabled",
                    category="configuration",
                )
            self._consumed = True
            try:
                authority = self.claim._begin_effect_evaluation()
            except RoleMonotonicityExecutionClaimDenied as exc:
                raise RoleProtectedEffectExecutionDenied(
                    str(exc),
                    category=exc.category,
                ) from exc

            state = _LifecycleState()
            observations = []
            active_observation = None
            revoked_observation = None
            oracle = None
            primary_error: Optional[BaseException] = None
            cancellation: Optional[asyncio.CancelledError] = None
            plan_valid = False
            cleanup: Optional[RoleMembershipCleanupResult] = None
            try:
                entries = _entries(authority.runtime_plan.request_binding)
                _validate_runtime_plan(authority, entries)
                proof = authority.runtime_plan.proof
                binding = authority.runtime_plan.request_binding
                effect_binding = binding.effect_observation_binding
                if (
                    proof.oracle.oracle_id != binding.oracle_id
                    or proof.oracle.verdict_vocabulary
                    != tuple(item.value for item in RoleProtectedEffectOracleVerdict)
                    or effect_binding
                    != authority.runtime_plan.runtime.effect_observation_binding
                ):
                    raise RoleProtectedEffectExecutionDenied(
                        "role_protected_effect_oracle_contract_mismatch",
                        category="authority",
                    )
                plan_valid = True
                status, response = await _dispatch(authority, entries, state, 0)
                runtime = authority.runtime_plan.runtime
                active_observation = _observe_membership(
                    entry=entries[0],
                    runtime=runtime,
                    response_status=status,
                    response=response,
                    expected_state="active",
                    expected_generation=runtime.active_membership_generation,
                    expected_generation_ref=runtime.active_generation_ref,
                )
                for ordinal in (1, 2, 3):
                    status, response = await _dispatch(
                        authority,
                        entries,
                        state,
                        ordinal,
                    )
                    observations.append(
                        _observe_effect(
                            entry=entries[ordinal],
                            runtime=runtime,
                            response_status=status,
                            response=response,
                        )
                    )
            except asyncio.CancelledError as exc:
                primary_error = exc
                cancellation = exc
            except BaseException as exc:
                primary_error = exc

            if not plan_valid:
                try:
                    authority.abort(
                        reason="role_protected_effect_plan_invalid"
                    )
                except Exception as abort_exc:
                    raise RoleProtectedEffectExecutionDenied(
                        "role_protected_effect_plan_abort_failed",
                        category="receipt",
                    ) from abort_exc
                if cancellation is not None:
                    raise cancellation
                raise RoleProtectedEffectExecutionDenied(
                    "role_protected_effect_runtime_authority_invalid",
                    category="authority",
                    terminal_receipt=authority.terminal_receipt,
                ) from primary_error

            cleanup_task = asyncio.create_task(
                _cleanup(
                    authority,
                    entries,
                    state,
                    release_post_revocation_units=False,
                )
            )
            try:
                cleanup, revoked_observation, cleanup_errors = await asyncio.shield(
                    cleanup_task
                )
            except asyncio.CancelledError as exc:
                cancellation = cancellation or exc
                try:
                    cleanup, revoked_observation, cleanup_errors = await cleanup_task
                except BaseException as cleanup_exc:
                    cleanup = _uncertain_cleanup(state)
                    cleanup_errors = [cleanup_exc]
            except BaseException as cleanup_exc:
                cleanup = _uncertain_cleanup(state)
                cleanup_errors = [cleanup_exc]
            if cleanup_errors and primary_error is None:
                primary_error = cleanup_errors[0]

            if (
                primary_error is None
                and cleanup.status == "verified"
                and active_observation is not None
                and revoked_observation is not None
            ):
                runtime = authority.runtime_plan.runtime
                try:
                    for ordinal in (6, 7):
                        status, response = await _dispatch(
                            authority,
                            entries,
                            state,
                            ordinal,
                        )
                        observations.append(
                            _observe_effect(
                                entry=entries[ordinal],
                                runtime=runtime,
                                response_status=status,
                                response=response,
                            )
                        )
                    oracle = RoleProtectedEffectOracleEvaluation.build(
                        oracle_id=authority.runtime_plan.proof.oracle.oracle_id,
                        observation_binding=(
                            authority.runtime_plan.request_binding.effect_observation_binding
                        ),
                        observations=observations,
                    )
                    if (
                        oracle.verdict
                        is RoleProtectedEffectOracleVerdict.INCONCLUSIVE
                    ):
                        raise RoleProtectedEffectExecutionDenied(
                            "role_protected_effect_oracle_inconclusive",
                            category="oracle",
                        )
                except asyncio.CancelledError as exc:
                    primary_error = exc
                    cancellation = cancellation or exc
                except BaseException as exc:
                    primary_error = exc
            elif primary_error is None:
                primary_error = RoleProtectedEffectExecutionDenied(
                    "role_protected_effect_cleanup_unverified",
                    category="cleanup",
                )

            if state.next_ordinal < 8:
                try:
                    _skip_to(authority, entries, state, 8)
                except BaseException as exc:
                    if primary_error is None:
                        primary_error = exc
            cleanup = _cleanup_snapshot(cleanup, state)

            sink = authority.runtime_plan.executor.provenance
            provenance_root = (
                sink.root()
                if sink is not None and sink.verify() and sink.root()
                else None
            )
            if provenance_root is None and primary_error is None:
                primary_error = RoleProtectedEffectExecutionDenied(
                    "role_protected_effect_provenance_invalid",
                    category="provenance",
                    target_request_possible=True,
                )
            if primary_error is None and (
                active_observation is None
                or revoked_observation is None
                or oracle is None
                or provenance_root is None
                or len(observations) != 5
                or state.target_requests_sent != 8
            ):
                primary_error = RoleProtectedEffectExecutionDenied(
                    "role_protected_effect_terminal_state_invalid",
                    category="execution",
                )

            if primary_error is not None or cleanup.status != "verified":
                reason, category = _reason(primary_error, cleanup)
                terminal_evidence = _terminal_evidence(
                    claim_contract_id=self.claim.contract.contract_id,
                    oracle_id=authority.runtime_plan.proof.oracle.oracle_id,
                    reason=reason,
                    category=category,
                    active_observation=active_observation,
                    revoked_observation=revoked_observation,
                    observations=observations,
                    oracle=oracle,
                    cleanup=cleanup,
                )
                try:
                    authority.abort(
                        reason=reason,
                        terminal_evidence=terminal_evidence,
                    )
                except Exception as exc:
                    raise RoleProtectedEffectExecutionDenied(
                        "role_protected_effect_receipt_abort_failed",
                        category="receipt",
                        target_request_possible=(
                            state.target_requests_sent > 0
                            or state.target_request_may_have_been_sent
                        ),
                        cleanup=cleanup,
                        oracle=oracle,
                    ) from exc
                if cancellation is not None:
                    raise cancellation
                raise RoleProtectedEffectExecutionDenied(
                    reason,
                    category=category,
                    target_request_possible=(
                        state.target_requests_sent > 0
                        or state.target_request_may_have_been_sent
                    ),
                    cleanup=cleanup,
                    oracle=oracle,
                    terminal_receipt=authority.terminal_receipt,
                ) from primary_error

            outcome = _completed_outcome(
                claim_contract_id=self.claim.contract.contract_id,
                active_observation=active_observation,
                revoked_observation=revoked_observation,
                observations=observations,
                oracle=oracle,
                cleanup=cleanup,
                provenance_root=provenance_root,
                target_requests_sent=state.target_requests_sent,
            )
            try:
                receipt = authority.finish(outcome=outcome)
            except RoleMonotonicityExecutionClaimDenied as exc:
                terminal_receipt = None
                if authority.state == "effect_evaluation":
                    reason = "role_protected_effect_receipt_completion_failed"
                    terminal_evidence = _terminal_evidence(
                        claim_contract_id=self.claim.contract.contract_id,
                        oracle_id=authority.runtime_plan.proof.oracle.oracle_id,
                        reason=reason,
                        category="receipt",
                        active_observation=active_observation,
                        revoked_observation=revoked_observation,
                        observations=observations,
                        oracle=None,
                        cleanup=cleanup,
                    )
                    try:
                        authority.abort(
                            reason=reason,
                            terminal_evidence=terminal_evidence,
                        )
                        terminal_receipt = authority.terminal_receipt
                    except Exception:
                        terminal_receipt = None
                raise RoleProtectedEffectExecutionDenied(
                    str(exc),
                    category=exc.category,
                    cleanup=cleanup,
                    oracle=oracle,
                    terminal_receipt=terminal_receipt,
                ) from exc
            payload = _result_payload(
                receipt_id=receipt.receipt_id,
                claim_contract_id=self.claim.contract.contract_id,
                active_observation=active_observation,
                revoked_observation=revoked_observation,
                observations=observations,
                oracle=oracle,
                cleanup=cleanup,
                provenance_root=provenance_root,
            )
            return RoleProtectedEffectExecutionResult(
                result_id=stable_hash(
                    "role_protected_effect_execution_result",
                    payload,
                ),
                receipt_id=receipt.receipt_id,
                claim_contract_id=self.claim.contract.contract_id,
                active_membership_observation=active_observation,
                revoked_membership_observation=revoked_observation,
                effect_observations=tuple(observations),
                oracle=oracle,
                cleanup=cleanup,
                provenance_root=provenance_root,
            )


__all__ = [
    "ROLE_PROTECTED_EFFECT_EXECUTION_ENV",
    "ROLE_PROTECTED_EFFECT_EXECUTION_KIND",
    "ROLE_PROTECTED_EFFECT_EXECUTION_MODE",
    "RoleProtectedEffectExecutionConfig",
    "RoleProtectedEffectExecutionDenied",
    "RoleProtectedEffectExecutionResult",
    "RoleProtectedEffectExperimentExecutor",
    "RoleProtectedEffectObservation",
    "RoleProtectedEffectOracleEvaluation",
    "RoleProtectedEffectOracleVerdict",
]
