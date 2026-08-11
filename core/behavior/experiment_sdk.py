"""Passive generalized experiment manifests for payout-oriented proof backends.

The SDK seals topology, controls, treatment, witnesses, cleanup, budgets, and backend
invariants into one content-addressed contract.  It has no transport, does not reserve
a mutable proof budget, and cannot promote an oracle result into a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Sequence, Tuple

from .normalize import stable_hash
from .omission import MinimizedOmissionExperiment
from .payout_goals import (
    PayoutGoalCandidate,
    ProofTopology,
    SecurityProperty,
    SecurityWitnessGoal,
    WorldRequirement,
)
from .proposals import AuthorizationExperimentProposal
from .replanning import ConstraintReplanResult


PROOF_EXPERIMENT_SDK_MODE = "behavioral_proof_experiment_sdk_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_.:-]{0,191}$")
_VERDICT_VOCABULARY = ("confirmed", "refuted", "inconclusive")
_BASE_EXECUTION_BLOCKERS = frozenset(
    {
        "analysis_only_no_execution_authority",
        "atomic_budget_reservation_required",
        "backend_specific_admission_required",
        "durable_execution_receipt_required",
    }
)


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _semantic(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a bounded semantic value")
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
    normalized = re.sub(r"[^a-z0-9_.:-]+", "_", separated.lower()).strip("_")
    if not normalized or _SEMANTIC.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} must be a bounded semantic value")
    return normalized


def _sorted_refs(values: Sequence[str], *, field_name: str) -> Tuple[str, ...]:
    if any(not isinstance(item, str) for item in values):
        raise ValueError(f"{field_name} must contain content-addressed references")
    refs = tuple(sorted(set(values)))
    if any(not _hash_ref(item) for item in refs):
        raise ValueError(f"{field_name} must contain content-addressed references")
    return refs


def _sorted_semantics(values: Sequence[str], *, field_name: str) -> Tuple[str, ...]:
    if any(not isinstance(item, str) for item in values):
        raise ValueError(f"{field_name} must contain bounded semantic values")
    semantics = tuple(sorted(set(values)))
    if any(_SEMANTIC.fullmatch(item) is None for item in semantics):
        raise ValueError(f"{field_name} must contain bounded semantic values")
    return semantics


class ExperimentWorldKind(str, Enum):
    OWNED_ACCOUNT = "owned_account"
    FRESH_ANONYMOUS = "fresh_anonymous"
    CALLBACK_RECEIVER = "callback_receiver"


def _world_binding_payload(
    *,
    slot: str,
    kind: ExperimentWorldKind,
    world_ref: str,
    persona_ref: Optional[str],
    ownership_ref: Optional[str],
    role_ref: Optional[str],
    lifecycle_ref: Optional[str],
    callback_ref: Optional[str],
    fresh: bool,
) -> Dict[str, Any]:
    return {
        "slot": slot,
        "kind": kind.value,
        "world_ref": world_ref,
        "persona_ref": persona_ref,
        "ownership_ref": ownership_ref,
        "role_ref": role_ref,
        "lifecycle_ref": lifecycle_ref,
        "callback_ref": callback_ref,
        "fresh": fresh,
    }


@dataclass(frozen=True)
class ExperimentWorldBinding:
    binding_id: str
    slot: str
    kind: ExperimentWorldKind
    world_ref: str
    persona_ref: Optional[str] = None
    ownership_ref: Optional[str] = None
    role_ref: Optional[str] = None
    lifecycle_ref: Optional[str] = None
    callback_ref: Optional[str] = None
    fresh: bool = False

    @classmethod
    def build(
        cls,
        *,
        slot: str,
        kind: ExperimentWorldKind,
        world_ref: str,
        persona_ref: Optional[str] = None,
        ownership_ref: Optional[str] = None,
        role_ref: Optional[str] = None,
        lifecycle_ref: Optional[str] = None,
        callback_ref: Optional[str] = None,
        fresh: bool = False,
    ) -> "ExperimentWorldBinding":
        normalized_slot = _semantic(slot, field_name="world slot")
        payload = _world_binding_payload(
            slot=normalized_slot,
            kind=kind,
            world_ref=world_ref,
            persona_ref=persona_ref,
            ownership_ref=ownership_ref,
            role_ref=role_ref,
            lifecycle_ref=lifecycle_ref,
            callback_ref=callback_ref,
            fresh=fresh,
        )
        return cls(
            binding_id=stable_hash("experiment_world_binding", payload),
            slot=normalized_slot,
            kind=kind,
            world_ref=world_ref,
            persona_ref=persona_ref,
            ownership_ref=ownership_ref,
            role_ref=role_ref,
            lifecycle_ref=lifecycle_ref,
            callback_ref=callback_ref,
            fresh=fresh,
        )

    def __post_init__(self) -> None:
        payload = _world_binding_payload(
            slot=self.slot,
            kind=self.kind,
            world_ref=self.world_ref,
            persona_ref=self.persona_ref,
            ownership_ref=self.ownership_ref,
            role_ref=self.role_ref,
            lifecycle_ref=self.lifecycle_ref,
            callback_ref=self.callback_ref,
            fresh=self.fresh,
        )
        optional_refs = (
            self.persona_ref,
            self.ownership_ref,
            self.role_ref,
            self.lifecycle_ref,
            self.callback_ref,
        )
        owned = self.kind is ExperimentWorldKind.OWNED_ACCOUNT
        anonymous = self.kind is ExperimentWorldKind.FRESH_ANONYMOUS
        callback = self.kind is ExperimentWorldKind.CALLBACK_RECEIVER
        shape_valid = (
            (
                owned
                and self.persona_ref is not None
                and self.ownership_ref is not None
                and self.callback_ref is None
                and not self.fresh
            )
            or (anonymous and all(item is None for item in optional_refs) and self.fresh)
            or (
                callback
                and self.callback_ref is not None
                and all(
                    item is None
                    for item in (
                        self.persona_ref,
                        self.ownership_ref,
                        self.role_ref,
                        self.lifecycle_ref,
                    )
                )
                and not self.fresh
            )
        )
        if (
            self.binding_id != stable_hash("experiment_world_binding", payload)
            or _SEMANTIC.fullmatch(self.slot) is None
            or not isinstance(self.kind, ExperimentWorldKind)
            or not _hash_ref(self.world_ref, "world")
            or any(item is not None and not _hash_ref(item) for item in optional_refs)
            or not isinstance(self.fresh, bool)
            or not shape_valid
        ):
            raise ValueError("experiment world binding contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            **_world_binding_payload(
                slot=self.slot,
                kind=self.kind,
                world_ref=self.world_ref,
                persona_ref=self.persona_ref,
                ownership_ref=self.ownership_ref,
                role_ref=self.role_ref,
                lifecycle_ref=self.lifecycle_ref,
                callback_ref=self.callback_ref,
                fresh=self.fresh,
            ),
        }


def _world_manifest_payload(
    *,
    requirement: WorldRequirement,
    bindings: Sequence[ExperimentWorldBinding],
) -> Dict[str, Any]:
    return {
        "requirement": requirement.to_dict(),
        "bindings": [item.to_dict() for item in bindings],
    }


def _validate_world_topology(
    requirement: WorldRequirement,
    bindings: Sequence[ExperimentWorldBinding],
) -> None:
    by_slot = {item.slot: item for item in bindings}
    if len(by_slot) != len(bindings):
        raise ValueError("experiment world slots must be unique")
    topology = requirement.topology
    expected_slots = {
        ProofTopology.ZERO_PERSONA_ANONYMOUS: (),
        ProofTopology.FRESH_ANONYMOUS: ("anonymous",),
        ProofTopology.SINGLE_OWNED_ACCOUNT: ("actor",),
        ProofTopology.PAIRED_OWNED_ACCOUNTS: ("actor", "peer"),
        ProofTopology.OWNED_ROLE_DIFFERENTIAL: ("high_role", "low_role"),
        ProofTopology.CONTROLLED_LIFECYCLE: ("actor",),
        ProofTopology.CALLBACK_RECEIVER: ("callback",),
    }[topology]
    if tuple(sorted(by_slot)) != tuple(sorted(expected_slots)):
        raise ValueError("experiment world slots do not match the proof topology")
    if topology is ProofTopology.ZERO_PERSONA_ANONYMOUS:
        return
    if topology is ProofTopology.FRESH_ANONYMOUS:
        if by_slot["anonymous"].kind is not ExperimentWorldKind.FRESH_ANONYMOUS:
            raise ValueError("fresh-anonymous topology requires one fresh anonymous world")
        return
    if topology is ProofTopology.CALLBACK_RECEIVER:
        if by_slot["callback"].kind is not ExperimentWorldKind.CALLBACK_RECEIVER:
            raise ValueError("callback topology requires one controlled callback world")
        return
    if any(item.kind is not ExperimentWorldKind.OWNED_ACCOUNT for item in bindings):
        raise ValueError("owned topology requires only owned-account worlds")
    if topology is ProofTopology.SINGLE_OWNED_ACCOUNT:
        if by_slot["actor"].role_ref is not None or by_slot["actor"].lifecycle_ref is not None:
            raise ValueError("single-account topology cannot impersonate role or lifecycle topology")
        return
    if topology is ProofTopology.CONTROLLED_LIFECYCLE:
        if by_slot["actor"].lifecycle_ref is None or by_slot["actor"].role_ref is not None:
            raise ValueError("lifecycle topology requires one lifecycle-bound owned world")
        return
    values = tuple(bindings)
    if (
        len({item.world_ref for item in values}) != 2
        or len({item.persona_ref for item in values}) != 2
        or len({item.ownership_ref for item in values}) != 2
    ):
        raise ValueError("two-world topology requires two distinct owned worlds")
    if topology is ProofTopology.PAIRED_OWNED_ACCOUNTS:
        if any(item.role_ref is not None or item.lifecycle_ref is not None for item in values):
            raise ValueError("paired topology cannot impersonate role or lifecycle topology")
        return
    if (
        any(item.role_ref is None or item.lifecycle_ref is not None for item in values)
        or len({item.role_ref for item in values}) != 2
    ):
        raise ValueError("role topology requires two distinct role-bound owned worlds")


@dataclass(frozen=True)
class ExperimentWorldManifest:
    world_manifest_id: str
    requirement: WorldRequirement
    bindings: Tuple[ExperimentWorldBinding, ...]

    @classmethod
    def build(
        cls,
        *,
        requirement: WorldRequirement,
        bindings: Sequence[ExperimentWorldBinding],
    ) -> "ExperimentWorldManifest":
        if not isinstance(requirement, WorldRequirement):
            raise TypeError("requirement must be a WorldRequirement")
        raw_values = tuple(bindings)
        if any(not isinstance(item, ExperimentWorldBinding) for item in raw_values):
            raise TypeError("bindings must contain ExperimentWorldBinding values")
        values = tuple(sorted(raw_values, key=lambda item: item.slot))
        _validate_world_topology(requirement, values)
        payload = _world_manifest_payload(requirement=requirement, bindings=values)
        return cls(
            world_manifest_id=stable_hash("experiment_world_manifest", payload),
            requirement=requirement,
            bindings=values,
        )

    def __post_init__(self) -> None:
        _validate_world_topology(self.requirement, self.bindings)
        payload = _world_manifest_payload(
            requirement=self.requirement,
            bindings=self.bindings,
        )
        if (
            self.world_manifest_id != stable_hash("experiment_world_manifest", payload)
            or self.bindings != tuple(sorted(self.bindings, key=lambda item: item.slot))
        ):
            raise ValueError("experiment world manifest contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "world_manifest_id": self.world_manifest_id,
            **_world_manifest_payload(
                requirement=self.requirement,
                bindings=self.bindings,
            ),
        }


class ExperimentPhase(str, Enum):
    SETUP = "setup"
    CONTROL = "control"
    TREATMENT = "treatment"
    WITNESS = "witness"
    CLEANUP = "cleanup"
    CLEANUP_VERIFICATION = "cleanup_verification"


_PHASE_ORDER = {
    ExperimentPhase.SETUP: 0,
    ExperimentPhase.CONTROL: 1,
    ExperimentPhase.TREATMENT: 2,
    ExperimentPhase.WITNESS: 3,
    ExperimentPhase.CLEANUP: 4,
    ExperimentPhase.CLEANUP_VERIFICATION: 5,
}


class ExperimentActionClass(str, Enum):
    SAFE_READ = "SAFE_READ"
    OWNED_CREATE = "OWNED_CREATE"
    OWNED_UPDATE_LOW_RISK = "OWNED_UPDATE_LOW_RISK"
    AUTHZ_PROBE = "AUTHZ_PROBE"
    PRIVILEGE_MUTATION = "PRIVILEGE_MUTATION"
    CROSS_OBJECT_READ = "CROSS_OBJECT_READ"
    CALLBACK_OBSERVATION = "CALLBACK_OBSERVATION"


class MutationExpectation(str, Enum):
    NONE = "none"
    OWNED_CREATE = "owned_create"
    OWNED_REVERSIBLE = "owned_reversible"
    PRIVILEGE_REVERSIBLE = "privilege_reversible"
    CLEANUP = "cleanup"


_EXPECTED_MUTATION = {
    ExperimentActionClass.SAFE_READ: MutationExpectation.NONE,
    ExperimentActionClass.AUTHZ_PROBE: MutationExpectation.NONE,
    ExperimentActionClass.CROSS_OBJECT_READ: MutationExpectation.NONE,
    ExperimentActionClass.CALLBACK_OBSERVATION: MutationExpectation.NONE,
    ExperimentActionClass.OWNED_CREATE: MutationExpectation.OWNED_CREATE,
    ExperimentActionClass.OWNED_UPDATE_LOW_RISK: MutationExpectation.OWNED_REVERSIBLE,
    ExperimentActionClass.PRIVILEGE_MUTATION: MutationExpectation.PRIVILEGE_REVERSIBLE,
}


def _action_payload(
    *,
    ordinal: int,
    phase: ExperimentPhase,
    operation_id: str,
    world_binding_id: Optional[str],
    action_class: ExperimentActionClass,
    endpoint_ref: str,
    mutation: MutationExpectation,
    evidence_refs: Sequence[str],
) -> Dict[str, Any]:
    return {
        "ordinal": ordinal,
        "phase": phase.value,
        "operation_id": operation_id,
        "world_binding_id": world_binding_id,
        "action_class": action_class.value,
        "endpoint_ref": endpoint_ref,
        "mutation": mutation.value,
        "evidence_refs": list(evidence_refs),
        "request_units": 1,
    }


@dataclass(frozen=True)
class ExperimentAction:
    action_id: str
    ordinal: int
    phase: ExperimentPhase
    operation_id: str
    world_binding_id: Optional[str]
    action_class: ExperimentActionClass
    endpoint_ref: str
    mutation: MutationExpectation
    evidence_refs: Tuple[str, ...]
    request_units: int = 1

    @classmethod
    def build(
        cls,
        *,
        ordinal: int,
        phase: ExperimentPhase,
        operation_id: str,
        world_binding_id: Optional[str],
        action_class: ExperimentActionClass,
        endpoint_ref: str,
        mutation: MutationExpectation,
        evidence_refs: Sequence[str],
    ) -> "ExperimentAction":
        normalized_operation = _semantic(operation_id, field_name="operation_id")
        refs = _sorted_refs(evidence_refs, field_name="action evidence_refs")
        payload = _action_payload(
            ordinal=ordinal,
            phase=phase,
            operation_id=normalized_operation,
            world_binding_id=world_binding_id,
            action_class=action_class,
            endpoint_ref=endpoint_ref,
            mutation=mutation,
            evidence_refs=refs,
        )
        return cls(
            action_id=stable_hash("proof_experiment_action", payload),
            ordinal=ordinal,
            phase=phase,
            operation_id=normalized_operation,
            world_binding_id=world_binding_id,
            action_class=action_class,
            endpoint_ref=endpoint_ref,
            mutation=mutation,
            evidence_refs=refs,
        )

    def __post_init__(self) -> None:
        payload = _action_payload(
            ordinal=self.ordinal,
            phase=self.phase,
            operation_id=self.operation_id,
            world_binding_id=self.world_binding_id,
            action_class=self.action_class,
            endpoint_ref=self.endpoint_ref,
            mutation=self.mutation,
            evidence_refs=self.evidence_refs,
        )
        cleanup = self.phase is ExperimentPhase.CLEANUP
        expected_mutation = (
            MutationExpectation.CLEANUP if cleanup else _EXPECTED_MUTATION[self.action_class]
        )
        if (
            self.action_id != stable_hash("proof_experiment_action", payload)
            or isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or self.ordinal < 0
            or not isinstance(self.phase, ExperimentPhase)
            or _SEMANTIC.fullmatch(self.operation_id) is None
            or (
                self.world_binding_id is not None
                and not _hash_ref(self.world_binding_id, "experiment_world_binding")
            )
            or not isinstance(self.action_class, ExperimentActionClass)
            or not _hash_ref(self.endpoint_ref, "experiment_endpoint")
            or self.mutation is not expected_mutation
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or not self.evidence_refs
            or any(not _hash_ref(item) for item in self.evidence_refs)
            or self.request_units != 1
            or (
                cleanup
                and self.action_class
                not in {
                    ExperimentActionClass.OWNED_UPDATE_LOW_RISK,
                    ExperimentActionClass.PRIVILEGE_MUTATION,
                }
            )
            or (
                self.phase is ExperimentPhase.CLEANUP_VERIFICATION
                and self.action_class is not ExperimentActionClass.SAFE_READ
            )
        ):
            raise ValueError("proof experiment action contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            **_action_payload(
                ordinal=self.ordinal,
                phase=self.phase,
                operation_id=self.operation_id,
                world_binding_id=self.world_binding_id,
                action_class=self.action_class,
                endpoint_ref=self.endpoint_ref,
                mutation=self.mutation,
                evidence_refs=self.evidence_refs,
            ),
        }


class ExperimentControlKind(str, Enum):
    OWNER_BASELINE = "owner_baseline"
    PEER_BASELINE = "peer_baseline"
    NEGATIVE_CONTROL = "negative_control"
    VALID_SEQUENCE_BASELINE = "valid_sequence_baseline"


def _control_payload(
    *,
    kind: ExperimentControlKind,
    action_ids: Sequence[str],
    world_binding_ids: Sequence[str],
) -> Dict[str, Any]:
    return {
        "kind": kind.value,
        "action_ids": list(action_ids),
        "world_binding_ids": list(world_binding_ids),
        "independent": True,
        "finding_authority": False,
    }


@dataclass(frozen=True)
class ExperimentControl:
    control_id: str
    kind: ExperimentControlKind
    action_ids: Tuple[str, ...]
    world_binding_ids: Tuple[str, ...]
    independent: bool = True
    finding_authority: bool = False

    @classmethod
    def build(
        cls,
        *,
        kind: ExperimentControlKind,
        action_ids: Sequence[str],
        world_binding_ids: Sequence[str] = (),
    ) -> "ExperimentControl":
        actions = tuple(sorted(set(action_ids)))
        worlds = tuple(sorted(set(world_binding_ids)))
        payload = _control_payload(
            kind=kind,
            action_ids=actions,
            world_binding_ids=worlds,
        )
        return cls(
            control_id=stable_hash("proof_experiment_control", payload),
            kind=kind,
            action_ids=actions,
            world_binding_ids=worlds,
        )

    def __post_init__(self) -> None:
        payload = _control_payload(
            kind=self.kind,
            action_ids=self.action_ids,
            world_binding_ids=self.world_binding_ids,
        )
        if (
            self.control_id != stable_hash("proof_experiment_control", payload)
            or not isinstance(self.kind, ExperimentControlKind)
            or not self.action_ids
            or self.action_ids != tuple(sorted(set(self.action_ids)))
            or any(not _hash_ref(item, "proof_experiment_action") for item in self.action_ids)
            or self.world_binding_ids != tuple(sorted(set(self.world_binding_ids)))
            or any(
                not _hash_ref(item, "experiment_world_binding")
                for item in self.world_binding_ids
            )
            or not self.independent
            or self.finding_authority
        ):
            raise ValueError("proof experiment control contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            **_control_payload(
                kind=self.kind,
                action_ids=self.action_ids,
                world_binding_ids=self.world_binding_ids,
            ),
        }


def _oracle_payload(
    *,
    goal_id: str,
    security_property: SecurityProperty,
    control_ids: Sequence[str],
    treatment_action_ids: Sequence[str],
    witness_action_ids: Sequence[str],
    comparison_kind: str,
    witness_requirements: Sequence[str],
) -> Dict[str, Any]:
    return {
        "goal_id": goal_id,
        "security_property": security_property.value,
        "control_ids": list(control_ids),
        "treatment_action_ids": list(treatment_action_ids),
        "witness_action_ids": list(witness_action_ids),
        "comparison_kind": comparison_kind,
        "witness_requirements": list(witness_requirements),
        "verdict_vocabulary": list(_VERDICT_VOCABULARY),
        "adversarial_triage_required": True,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class ExperimentOracleContract:
    oracle_id: str
    goal_id: str
    security_property: SecurityProperty
    control_ids: Tuple[str, ...]
    treatment_action_ids: Tuple[str, ...]
    witness_action_ids: Tuple[str, ...]
    comparison_kind: str
    witness_requirements: Tuple[str, ...]
    verdict_vocabulary: Tuple[str, ...] = _VERDICT_VOCABULARY
    adversarial_triage_required: bool = True
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        goal: SecurityWitnessGoal,
        control_ids: Sequence[str],
        treatment_action_ids: Sequence[str],
        witness_action_ids: Sequence[str],
        comparison_kind: str,
    ) -> "ExperimentOracleContract":
        if not isinstance(goal, SecurityWitnessGoal):
            raise TypeError("goal must be a SecurityWitnessGoal")
        controls = tuple(sorted(set(control_ids)))
        treatment = tuple(sorted(set(treatment_action_ids)))
        witnesses = tuple(sorted(set(witness_action_ids)))
        comparison = _semantic(comparison_kind, field_name="comparison_kind")
        payload = _oracle_payload(
            goal_id=goal.goal_id,
            security_property=goal.security_property,
            control_ids=controls,
            treatment_action_ids=treatment,
            witness_action_ids=witnesses,
            comparison_kind=comparison,
            witness_requirements=goal.witness_requirements,
        )
        return cls(
            oracle_id=stable_hash("proof_experiment_oracle", payload),
            goal_id=goal.goal_id,
            security_property=goal.security_property,
            control_ids=controls,
            treatment_action_ids=treatment,
            witness_action_ids=witnesses,
            comparison_kind=comparison,
            witness_requirements=goal.witness_requirements,
        )

    def __post_init__(self) -> None:
        payload = _oracle_payload(
            goal_id=self.goal_id,
            security_property=self.security_property,
            control_ids=self.control_ids,
            treatment_action_ids=self.treatment_action_ids,
            witness_action_ids=self.witness_action_ids,
            comparison_kind=self.comparison_kind,
            witness_requirements=self.witness_requirements,
        )
        ref_groups = (
            (self.control_ids, "proof_experiment_control"),
            (self.treatment_action_ids, "proof_experiment_action"),
            (self.witness_action_ids, "proof_experiment_action"),
        )
        if (
            self.oracle_id != stable_hash("proof_experiment_oracle", payload)
            or not _hash_ref(self.goal_id, "security_witness_goal")
            or not isinstance(self.security_property, SecurityProperty)
            or any(not values for values, _ in ref_groups)
            or any(
                values != tuple(sorted(set(values)))
                or any(not _hash_ref(item, prefix) for item in values)
                for values, prefix in ref_groups
            )
            or _SEMANTIC.fullmatch(self.comparison_kind) is None
            or self.witness_requirements
            != tuple(sorted(set(self.witness_requirements)))
            or not self.witness_requirements
            or any(_SEMANTIC.fullmatch(item) is None for item in self.witness_requirements)
            or self.verdict_vocabulary != _VERDICT_VOCABULARY
            or not self.adversarial_triage_required
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("proof experiment oracle contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "oracle_id": self.oracle_id,
            **_oracle_payload(
                goal_id=self.goal_id,
                security_property=self.security_property,
                control_ids=self.control_ids,
                treatment_action_ids=self.treatment_action_ids,
                witness_action_ids=self.witness_action_ids,
                comparison_kind=self.comparison_kind,
                witness_requirements=self.witness_requirements,
            ),
        }


def _cleanup_binding_payload(
    *,
    mutation_action_id: str,
    cleanup_action_id: str,
    verification_action_id: str,
) -> Dict[str, str]:
    return {
        "mutation_action_id": mutation_action_id,
        "cleanup_action_id": cleanup_action_id,
        "verification_action_id": verification_action_id,
    }


@dataclass(frozen=True)
class CleanupBinding:
    binding_id: str
    mutation_action_id: str
    cleanup_action_id: str
    verification_action_id: str

    @classmethod
    def build(
        cls,
        *,
        mutation_action_id: str,
        cleanup_action_id: str,
        verification_action_id: str,
    ) -> "CleanupBinding":
        payload = _cleanup_binding_payload(
            mutation_action_id=mutation_action_id,
            cleanup_action_id=cleanup_action_id,
            verification_action_id=verification_action_id,
        )
        return cls(
            binding_id=stable_hash("proof_experiment_cleanup_binding", payload),
            mutation_action_id=mutation_action_id,
            cleanup_action_id=cleanup_action_id,
            verification_action_id=verification_action_id,
        )

    def __post_init__(self) -> None:
        payload = _cleanup_binding_payload(
            mutation_action_id=self.mutation_action_id,
            cleanup_action_id=self.cleanup_action_id,
            verification_action_id=self.verification_action_id,
        )
        if (
            self.binding_id != stable_hash("proof_experiment_cleanup_binding", payload)
            or any(
                not _hash_ref(item, "proof_experiment_action")
                for item in (
                    self.mutation_action_id,
                    self.cleanup_action_id,
                    self.verification_action_id,
                )
            )
            or len(
                {
                    self.mutation_action_id,
                    self.cleanup_action_id,
                    self.verification_action_id,
                }
            )
            != 3
        ):
            raise ValueError("proof experiment cleanup binding contract is invalid")

    def to_dict(self) -> Dict[str, str]:
        return {
            "binding_id": self.binding_id,
            **_cleanup_binding_payload(
                mutation_action_id=self.mutation_action_id,
                cleanup_action_id=self.cleanup_action_id,
                verification_action_id=self.verification_action_id,
            ),
        }


def _cleanup_payload(bindings: Sequence[CleanupBinding]) -> Dict[str, Any]:
    return {
        "bindings": [item.to_dict() for item in bindings],
        "required": bool(bindings),
        "stop_on_uncertain_mutation": True,
        "independent_verification_required": True,
        "executable": False,
    }


@dataclass(frozen=True)
class ExperimentCleanupContract:
    cleanup_id: str
    bindings: Tuple[CleanupBinding, ...]
    required: bool
    stop_on_uncertain_mutation: bool = True
    independent_verification_required: bool = True
    executable: bool = False

    @classmethod
    def build(
        cls,
        bindings: Sequence[CleanupBinding] = (),
    ) -> "ExperimentCleanupContract":
        raw_values = tuple(bindings)
        if any(not isinstance(item, CleanupBinding) for item in raw_values):
            raise TypeError("bindings must contain CleanupBinding values")
        values = tuple(sorted(raw_values, key=lambda item: item.mutation_action_id))
        payload = _cleanup_payload(values)
        return cls(
            cleanup_id=stable_hash("proof_experiment_cleanup", payload),
            bindings=values,
            required=bool(values),
        )

    def __post_init__(self) -> None:
        payload = _cleanup_payload(self.bindings)
        if (
            self.cleanup_id != stable_hash("proof_experiment_cleanup", payload)
            or self.bindings
            != tuple(sorted(self.bindings, key=lambda item: item.mutation_action_id))
            or len({item.mutation_action_id for item in self.bindings})
            != len(self.bindings)
            or len({item.cleanup_action_id for item in self.bindings})
            != len(self.bindings)
            or len({item.verification_action_id for item in self.bindings})
            != len(self.bindings)
            or self.required != bool(self.bindings)
            or not self.stop_on_uncertain_mutation
            or not self.independent_verification_required
            or self.executable
        ):
            raise ValueError("proof experiment cleanup contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cleanup_id": self.cleanup_id,
            **_cleanup_payload(self.bindings),
        }


def _budget_claim_payload(action: ExperimentAction) -> Dict[str, Any]:
    return {
        "action_id": action.action_id,
        "ordinal": action.ordinal,
        "action_class": action.action_class.value,
        "endpoint_ref": action.endpoint_ref,
        "request_units": action.request_units,
    }


@dataclass(frozen=True)
class ExperimentBudgetClaim:
    claim_id: str
    action_id: str
    ordinal: int
    action_class: ExperimentActionClass
    endpoint_ref: str
    request_units: int = 1

    @classmethod
    def build(cls, action: ExperimentAction) -> "ExperimentBudgetClaim":
        if not isinstance(action, ExperimentAction):
            raise TypeError("action must be an ExperimentAction")
        payload = _budget_claim_payload(action)
        return cls(
            claim_id=stable_hash("proof_experiment_budget_claim", payload),
            action_id=action.action_id,
            ordinal=action.ordinal,
            action_class=action.action_class,
            endpoint_ref=action.endpoint_ref,
        )

    def __post_init__(self) -> None:
        payload = {
            "action_id": self.action_id,
            "ordinal": self.ordinal,
            "action_class": self.action_class.value,
            "endpoint_ref": self.endpoint_ref,
            "request_units": self.request_units,
        }
        if (
            self.claim_id != stable_hash("proof_experiment_budget_claim", payload)
            or not _hash_ref(self.action_id, "proof_experiment_action")
            or isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or self.ordinal < 0
            or not isinstance(self.action_class, ExperimentActionClass)
            or not _hash_ref(self.endpoint_ref, "experiment_endpoint")
            or self.request_units != 1
        ):
            raise ValueError("proof experiment budget claim contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "action_id": self.action_id,
            "ordinal": self.ordinal,
            "action_class": self.action_class.value,
            "endpoint_ref": self.endpoint_ref,
            "request_units": self.request_units,
        }


def _budget_payload(claims: Sequence[ExperimentBudgetClaim]) -> Dict[str, Any]:
    return {
        "claims": [item.to_dict() for item in claims],
        "total_request_units": sum(item.request_units for item in claims),
        "reservation_scope": "complete_experiment",
        "atomic_reservation_required": True,
        "reserved": False,
        "executable": False,
    }


@dataclass(frozen=True)
class ExperimentBudgetManifest:
    budget_id: str
    claims: Tuple[ExperimentBudgetClaim, ...]
    total_request_units: int
    reservation_scope: str = "complete_experiment"
    atomic_reservation_required: bool = True
    reserved: bool = False
    executable: bool = False

    @classmethod
    def build(cls, actions: Sequence[ExperimentAction]) -> "ExperimentBudgetManifest":
        claims = tuple(ExperimentBudgetClaim.build(item) for item in actions)
        payload = _budget_payload(claims)
        return cls(
            budget_id=stable_hash("proof_experiment_budget", payload),
            claims=claims,
            total_request_units=sum(item.request_units for item in claims),
        )

    def __post_init__(self) -> None:
        payload = _budget_payload(self.claims)
        if (
            self.budget_id != stable_hash("proof_experiment_budget", payload)
            or not self.claims
            or tuple(item.ordinal for item in self.claims)
            != tuple(range(len(self.claims)))
            or len({item.action_id for item in self.claims}) != len(self.claims)
            or self.total_request_units
            != sum(item.request_units for item in self.claims)
            or self.reservation_scope != "complete_experiment"
            or not self.atomic_reservation_required
            or self.reserved
            or self.executable
        ):
            raise ValueError("proof experiment budget manifest contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "budget_id": self.budget_id,
            **_budget_payload(self.claims),
        }


class ExistingBackendKind(str, Enum):
    OBJECT_AUTHORIZATION = "object_authorization"
    PREREQUISITE_OMISSION = "prerequisite_omission"


_BACKEND_GUARDS = {
    ExistingBackendKind.OBJECT_AUTHORIZATION: tuple(
        sorted(
            {
                "adversarial_triage",
                "counterfactual_response",
                "distinct_owned_worlds",
                "durable_receipt",
                "independent_effect_witness",
                "ownership_proof",
                "peer_baseline",
                "policy_scope_provenance",
                "source_baseline",
            }
        )
    ),
    ExistingBackendKind.PREREQUISITE_OMISSION: tuple(
        sorted(
            {
                "adversarial_triage",
                "captured_state_match",
                "cleanup_proof",
                "durable_receipt",
                "exact_success_body_match",
                "non_truncated_baseline",
                "policy_scope_provenance",
                "single_prerequisite_delta",
                "valid_baseline_sequence",
            }
        )
    ),
}


def _backend_payload(
    *,
    backend: ExistingBackendKind,
    source_contract_ref: str,
    source_evidence_refs: Sequence[str],
    required_guards: Sequence[str],
    inherited_execution_blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "backend": backend.value,
        "source_contract_ref": source_contract_ref,
        "source_evidence_refs": list(source_evidence_refs),
        "required_backend_guards": list(required_guards),
        "inherited_execution_blockers": list(inherited_execution_blockers),
        "inherits_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class BackendConformanceContract:
    conformance_id: str
    backend: ExistingBackendKind
    source_contract_ref: str
    source_evidence_refs: Tuple[str, ...]
    required_guards: Tuple[str, ...]
    inherited_execution_blockers: Tuple[str, ...]
    inherits_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _backend_payload(
            backend=self.backend,
            source_contract_ref=self.source_contract_ref,
            source_evidence_refs=self.source_evidence_refs,
            required_guards=self.required_guards,
            inherited_execution_blockers=self.inherited_execution_blockers,
        )
        expected_prefix = {
            ExistingBackendKind.OBJECT_AUTHORIZATION: "authorization_proposal",
            ExistingBackendKind.PREREQUISITE_OMISSION: "omission_experiment",
        }[self.backend]
        if (
            self.conformance_id != stable_hash("backend_conformance", payload)
            or not _hash_ref(self.source_contract_ref, expected_prefix)
            or self.source_evidence_refs
            != tuple(sorted(set(self.source_evidence_refs)))
            or self.source_contract_ref not in self.source_evidence_refs
            or any(not _hash_ref(item) for item in self.source_evidence_refs)
            or self.required_guards != _BACKEND_GUARDS[self.backend]
            or self.inherited_execution_blockers
            != tuple(sorted(set(self.inherited_execution_blockers)))
            or "analysis_only_no_execution_authority"
            not in self.inherited_execution_blockers
            or any(
                _SEMANTIC.fullmatch(item) is None
                for item in self.inherited_execution_blockers
            )
            or self.inherits_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("backend conformance contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conformance_id": self.conformance_id,
            **_backend_payload(
                backend=self.backend,
                source_contract_ref=self.source_contract_ref,
                source_evidence_refs=self.source_evidence_refs,
                required_guards=self.required_guards,
                inherited_execution_blockers=self.inherited_execution_blockers,
            ),
        }


class ExistingBackendAdapter:
    """Describe an existing backend without replacing any of its runtime checks."""

    @staticmethod
    def authorization(
        proposal: AuthorizationExperimentProposal,
    ) -> BackendConformanceContract:
        if not isinstance(proposal, AuthorizationExperimentProposal):
            raise TypeError("proposal must be an AuthorizationExperimentProposal")
        legs = {item.name: item for item in proposal.legs}
        if (
            proposal.property_kind != "object_authorization"
            or proposal.executable
            or not proposal.requires_owned_worlds
            or not proposal.requires_policy_reclassification
            or not proposal.mutations
            or set(legs) != {"peer_baseline", "source_baseline", "counterfactual"}
            or legs["peer_baseline"].identifier_source != "peer_observed_value"
            or legs["source_baseline"].identifier_source != "source_observed_value"
            or legs["counterfactual"].identifier_source != "peer_observed_value"
            or legs["peer_baseline"].actor_world_ref
            == legs["source_baseline"].actor_world_ref
            or legs["counterfactual"].actor_world_ref
            != legs["source_baseline"].actor_world_ref
        ):
            raise ValueError("authorization backend guards are incomplete")
        source_refs = _sorted_refs(
            (proposal.proposal_id, proposal.action_id, proposal.source_ref),
            field_name="authorization backend evidence",
        )
        blockers = tuple(
            sorted(
                {
                    "analysis_only_no_execution_authority",
                    "backend_specific_ownership_proof_required",
                    "backend_specific_policy_reclassification_required",
                }
            )
        )
        payload = _backend_payload(
            backend=ExistingBackendKind.OBJECT_AUTHORIZATION,
            source_contract_ref=proposal.proposal_id,
            source_evidence_refs=source_refs,
            required_guards=_BACKEND_GUARDS[ExistingBackendKind.OBJECT_AUTHORIZATION],
            inherited_execution_blockers=blockers,
        )
        return BackendConformanceContract(
            conformance_id=stable_hash("backend_conformance", payload),
            backend=ExistingBackendKind.OBJECT_AUTHORIZATION,
            source_contract_ref=proposal.proposal_id,
            source_evidence_refs=source_refs,
            required_guards=_BACKEND_GUARDS[ExistingBackendKind.OBJECT_AUTHORIZATION],
            inherited_execution_blockers=blockers,
        )

    @staticmethod
    def omission(
        experiment: MinimizedOmissionExperiment,
    ) -> BackendConformanceContract:
        if not isinstance(experiment, MinimizedOmissionExperiment):
            raise TypeError("experiment must be a MinimizedOmissionExperiment")
        if (
            experiment.executable
            or experiment.finding_authority
            or experiment.oracle.executable
            or experiment.oracle.finding_authority
            or not experiment.oracle.require_success
            or not experiment.oracle.require_non_truncated
            or experiment.oracle.baseline_requirement != "captured_state_match"
            or experiment.oracle.comparison_kind != "exact_success_body_match"
            or not {
                "analysis_only_no_execution_authority",
                "requires_two_fresh_owned_states",
            }
            <= set(experiment.execution_blockers)
        ):
            raise ValueError("omission backend guards are incomplete")
        source_refs = _sorted_refs(
            (
                experiment.experiment_id,
                experiment.oracle.oracle_id,
                experiment.baseline_source_ref,
                experiment.plan_id,
                experiment.recipe_id,
            ),
            field_name="omission backend evidence",
        )
        blockers = tuple(sorted(set(experiment.execution_blockers)))
        payload = _backend_payload(
            backend=ExistingBackendKind.PREREQUISITE_OMISSION,
            source_contract_ref=experiment.experiment_id,
            source_evidence_refs=source_refs,
            required_guards=_BACKEND_GUARDS[ExistingBackendKind.PREREQUISITE_OMISSION],
            inherited_execution_blockers=blockers,
        )
        return BackendConformanceContract(
            conformance_id=stable_hash("backend_conformance", payload),
            backend=ExistingBackendKind.PREREQUISITE_OMISSION,
            source_contract_ref=experiment.experiment_id,
            source_evidence_refs=source_refs,
            required_guards=_BACKEND_GUARDS[ExistingBackendKind.PREREQUISITE_OMISSION],
            inherited_execution_blockers=blockers,
        )


def _manifest_payload(
    *,
    candidate_id: str,
    goal_id: str,
    replan_result_id: str,
    target_ref: str,
    authority_context_ref: str,
    policy_digest: str,
    world_manifest: ExperimentWorldManifest,
    backend: BackendConformanceContract,
    actions: Sequence[ExperimentAction],
    controls: Sequence[ExperimentControl],
    oracle: ExperimentOracleContract,
    cleanup: ExperimentCleanupContract,
    budget: ExperimentBudgetManifest,
    provenance_refs: Sequence[str],
    execution_blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "mode": PROOF_EXPERIMENT_SDK_MODE,
        "candidate_id": candidate_id,
        "goal_id": goal_id,
        "replan_result_id": replan_result_id,
        "target_ref": target_ref,
        "authority_context_ref": authority_context_ref,
        "policy_digest": policy_digest,
        "world_manifest": world_manifest.to_dict(),
        "backend": backend.to_dict(),
        "actions": [item.to_dict() for item in actions],
        "controls": [item.to_dict() for item in controls],
        "oracle": oracle.to_dict(),
        "cleanup": cleanup.to_dict(),
        "budget": budget.to_dict(),
        "provenance_refs": list(provenance_refs),
        "execution_blockers": list(execution_blockers),
        "target_requests_sent": 0,
        "finding_authority": False,
        "executable": False,
    }


def _validate_manifest_relations(
    *,
    world_manifest: ExperimentWorldManifest,
    actions: Sequence[ExperimentAction],
    controls: Sequence[ExperimentControl],
    oracle: ExperimentOracleContract,
    cleanup: ExperimentCleanupContract,
    budget: ExperimentBudgetManifest,
) -> None:
    if tuple(item.ordinal for item in actions) != tuple(range(len(actions))):
        raise ValueError("experiment action ordinals must be contiguous")
    if tuple(_PHASE_ORDER[item.phase] for item in actions) != tuple(
        sorted(_PHASE_ORDER[item.phase] for item in actions)
    ):
        raise ValueError("experiment actions must be phase ordered")
    by_action = {item.action_id: item for item in actions}
    if len(by_action) != len(actions):
        raise ValueError("experiment actions must be unique")
    binding_ids = {item.binding_id for item in world_manifest.bindings}
    if binding_ids:
        if any(item.world_binding_id not in binding_ids for item in actions):
            raise ValueError("experiment action has an unbound world")
    elif any(item.world_binding_id is not None for item in actions):
        raise ValueError("zero-world experiment cannot bind a world")
    control_actions = {
        item.action_id for item in actions if item.phase is ExperimentPhase.CONTROL
    }
    treatment_actions = {
        item.action_id for item in actions if item.phase is ExperimentPhase.TREATMENT
    }
    witness_actions = {
        item.action_id for item in actions if item.phase is ExperimentPhase.WITNESS
    }
    if not control_actions or not treatment_actions or not witness_actions:
        raise ValueError("experiment requires control, treatment, and witness actions")
    by_control = {item.control_id: item for item in controls}
    if len(by_control) != len(controls) or not controls:
        raise ValueError("experiment controls must be present and unique")
    referenced_control_actions = tuple(
        action_id for control in controls for action_id in control.action_ids
    )
    if set(referenced_control_actions) != control_actions:
        raise ValueError("every control action must belong to a declared control")
    if len(referenced_control_actions) != len(set(referenced_control_actions)):
        raise ValueError("every control action must belong to exactly one control")
    if any(
        not set(control.world_binding_ids) <= binding_ids
        or not set(control.action_ids) <= control_actions
        for control in controls
    ):
        raise ValueError("experiment control bindings are invalid")
    for control in controls:
        action_worlds = {
            by_action[action_id].world_binding_id
            for action_id in control.action_ids
            if by_action[action_id].world_binding_id is not None
        }
        if set(control.world_binding_ids) != action_worlds:
            raise ValueError("control worlds must exactly match their control actions")
    if (
        set(oracle.control_ids) != set(by_control)
        or set(oracle.treatment_action_ids) != treatment_actions
        or set(oracle.witness_action_ids) != witness_actions
    ):
        raise ValueError("oracle does not cover the complete experiment comparison")

    mutations = {
        item.action_id
        for item in actions
        if item.mutation
        in {
            MutationExpectation.OWNED_CREATE,
            MutationExpectation.OWNED_REVERSIBLE,
            MutationExpectation.PRIVILEGE_REVERSIBLE,
        }
    }
    cleanup_actions = {
        item.action_id for item in actions if item.phase is ExperimentPhase.CLEANUP
    }
    verification_actions = {
        item.action_id
        for item in actions
        if item.phase is ExperimentPhase.CLEANUP_VERIFICATION
    }
    if mutations:
        if (
            {item.mutation_action_id for item in cleanup.bindings} != mutations
            or {item.cleanup_action_id for item in cleanup.bindings} != cleanup_actions
            or {item.verification_action_id for item in cleanup.bindings}
            != verification_actions
        ):
            raise ValueError("cleanup does not cover every possible mutation")
    elif cleanup.bindings or cleanup_actions or verification_actions:
        raise ValueError("read-only experiment cannot contain mutation cleanup")
    if tuple(item.action_id for item in budget.claims) != tuple(
        item.action_id for item in actions
    ):
        raise ValueError("budget does not reserve the complete action sequence")


@dataclass(frozen=True)
class ProofExperimentManifest:
    manifest_id: str
    candidate_id: str
    goal_id: str
    replan_result_id: str
    target_ref: str
    authority_context_ref: str
    policy_digest: str
    world_manifest: ExperimentWorldManifest
    backend: BackendConformanceContract
    actions: Tuple[ExperimentAction, ...]
    controls: Tuple[ExperimentControl, ...]
    oracle: ExperimentOracleContract
    cleanup: ExperimentCleanupContract
    budget: ExperimentBudgetManifest
    provenance_refs: Tuple[str, ...]
    execution_blockers: Tuple[str, ...]
    mode: str = PROOF_EXPERIMENT_SDK_MODE
    target_requests_sent: int = 0
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        _validate_manifest_relations(
            world_manifest=self.world_manifest,
            actions=self.actions,
            controls=self.controls,
            oracle=self.oracle,
            cleanup=self.cleanup,
            budget=self.budget,
        )
        payload = _manifest_payload(
            candidate_id=self.candidate_id,
            goal_id=self.goal_id,
            replan_result_id=self.replan_result_id,
            target_ref=self.target_ref,
            authority_context_ref=self.authority_context_ref,
            policy_digest=self.policy_digest,
            world_manifest=self.world_manifest,
            backend=self.backend,
            actions=self.actions,
            controls=self.controls,
            oracle=self.oracle,
            cleanup=self.cleanup,
            budget=self.budget,
            provenance_refs=self.provenance_refs,
            execution_blockers=self.execution_blockers,
        )
        if (
            self.mode != PROOF_EXPERIMENT_SDK_MODE
            or self.manifest_id != stable_hash("proof_experiment_manifest", payload)
            or not _hash_ref(self.candidate_id, "payout_goal_candidate")
            or not _hash_ref(self.goal_id, "security_witness_goal")
            or not _hash_ref(self.replan_result_id, "constraint_replan_result")
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(self.authority_context_ref, "experiment_authority_context")
            or not _hash_ref(self.policy_digest, "compiler_policy")
            or self.oracle.goal_id != self.goal_id
            or self.provenance_refs != tuple(sorted(set(self.provenance_refs)))
            or not self.provenance_refs
            or any(not _hash_ref(item) for item in self.provenance_refs)
            or self.execution_blockers
            != tuple(sorted(set(self.execution_blockers)))
            or not _BASE_EXECUTION_BLOCKERS <= set(self.execution_blockers)
            or any(_SEMANTIC.fullmatch(item) is None for item in self.execution_blockers)
            or self.target_requests_sent != 0
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("proof experiment manifest contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "manifest_id": self.manifest_id,
            **_manifest_payload(
                candidate_id=self.candidate_id,
                goal_id=self.goal_id,
                replan_result_id=self.replan_result_id,
                target_ref=self.target_ref,
                authority_context_ref=self.authority_context_ref,
                policy_digest=self.policy_digest,
                world_manifest=self.world_manifest,
                backend=self.backend,
                actions=self.actions,
                controls=self.controls,
                oracle=self.oracle,
                cleanup=self.cleanup,
                budget=self.budget,
                provenance_refs=self.provenance_refs,
                execution_blockers=self.execution_blockers,
            ),
        }


class ProofExperimentCompiler:
    """Seal a payout goal and R3 plan into a non-executable experiment manifest."""

    def compile(
        self,
        *,
        candidate: PayoutGoalCandidate,
        replan: ConstraintReplanResult,
        world_manifest: ExperimentWorldManifest,
        backend: BackendConformanceContract,
        actions: Sequence[ExperimentAction],
        controls: Sequence[ExperimentControl],
        oracle: ExperimentOracleContract,
        cleanup: ExperimentCleanupContract,
        target_ref: str,
        authority_context_ref: str,
        provenance_refs: Sequence[str],
    ) -> ProofExperimentManifest:
        if not isinstance(candidate, PayoutGoalCandidate):
            raise TypeError("candidate must be a PayoutGoalCandidate")
        if not isinstance(replan, ConstraintReplanResult):
            raise TypeError("replan must be a ConstraintReplanResult")
        if (
            not isinstance(world_manifest, ExperimentWorldManifest)
            or not isinstance(backend, BackendConformanceContract)
            or not isinstance(oracle, ExperimentOracleContract)
            or not isinstance(cleanup, ExperimentCleanupContract)
        ):
            raise TypeError("world, backend, oracle, and cleanup contracts are required")
        if (
            candidate.status != "admissible"
            or candidate.blockers
            or replan.status != "ready"
            or replan.blockers
            or replan.goal_id != candidate.goal.goal_id
            or replan.terminal_operation_id != candidate.goal.terminal_operation_id
            or replan.root_evidence_refs != candidate.goal.evidence_refs
            or world_manifest.requirement != candidate.world_requirement
            or backend.backend.value != candidate.backend
            or oracle.goal_id != candidate.goal.goal_id
            or oracle.security_property is not candidate.goal.security_property
            or oracle.witness_requirements != candidate.goal.witness_requirements
            or not set(backend.source_evidence_refs) & set(candidate.goal.evidence_refs)
        ):
            raise ValueError("payout goal, replan, world, backend, and oracle do not align")

        raw_actions = tuple(actions)
        if any(not isinstance(item, ExperimentAction) for item in raw_actions):
            raise TypeError("actions must contain ExperimentAction values")
        action_values = tuple(sorted(raw_actions, key=lambda item: item.ordinal))
        raw_controls = tuple(controls)
        if any(not isinstance(item, ExperimentControl) for item in raw_controls):
            raise TypeError("controls must contain ExperimentControl values")
        control_values = tuple(sorted(raw_controls, key=lambda item: item.control_id))
        if not any(
            item.phase is ExperimentPhase.TREATMENT
            and item.operation_id == candidate.goal.terminal_operation_id
            for item in action_values
        ):
            raise ValueError("treatment does not exercise the payout goal operation")
        budget = ExperimentBudgetManifest.build(action_values)
        _validate_manifest_relations(
            world_manifest=world_manifest,
            actions=action_values,
            controls=control_values,
            oracle=oracle,
            cleanup=cleanup,
            budget=budget,
        )
        refs = _sorted_refs(provenance_refs, field_name="manifest provenance_refs")
        if not refs:
            raise ValueError("manifest provenance_refs must not be empty")
        blockers = set(_BASE_EXECUTION_BLOCKERS)
        blockers.update(backend.inherited_execution_blockers)
        if cleanup.required:
            blockers.add("cleanup_execution_required")
        blocker_values = tuple(sorted(blockers))
        payload = _manifest_payload(
            candidate_id=candidate.candidate_id,
            goal_id=candidate.goal.goal_id,
            replan_result_id=replan.result_id,
            target_ref=target_ref,
            authority_context_ref=authority_context_ref,
            policy_digest=replan.policy_digest,
            world_manifest=world_manifest,
            backend=backend,
            actions=action_values,
            controls=control_values,
            oracle=oracle,
            cleanup=cleanup,
            budget=budget,
            provenance_refs=refs,
            execution_blockers=blocker_values,
        )
        return ProofExperimentManifest(
            manifest_id=stable_hash("proof_experiment_manifest", payload),
            candidate_id=candidate.candidate_id,
            goal_id=candidate.goal.goal_id,
            replan_result_id=replan.result_id,
            target_ref=target_ref,
            authority_context_ref=authority_context_ref,
            policy_digest=replan.policy_digest,
            world_manifest=world_manifest,
            backend=backend,
            actions=action_values,
            controls=control_values,
            oracle=oracle,
            cleanup=cleanup,
            budget=budget,
            provenance_refs=refs,
            execution_blockers=blocker_values,
        )


class OracleVerdict(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class CleanupOutcome(str, Enum):
    NOT_REQUIRED = "not_required"
    COMPLETE = "complete"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


def _evaluation_payload(
    *,
    manifest_id: str,
    oracle_id: str,
    verdict: OracleVerdict,
    backend_receipt_ref: str,
    control_evidence_refs: Sequence[str],
    treatment_evidence_refs: Sequence[str],
    witness_evidence_refs: Sequence[str],
    cleanup_evidence_refs: Sequence[str],
    provenance_root: str,
    cleanup_required: bool,
    cleanup_outcome: CleanupOutcome,
    uncertainty_reasons: Sequence[str],
) -> Dict[str, Any]:
    return {
        "manifest_id": manifest_id,
        "oracle_id": oracle_id,
        "verdict": verdict.value,
        "backend_receipt_ref": backend_receipt_ref,
        "control_evidence_refs": list(control_evidence_refs),
        "treatment_evidence_refs": list(treatment_evidence_refs),
        "witness_evidence_refs": list(witness_evidence_refs),
        "cleanup_evidence_refs": list(cleanup_evidence_refs),
        "provenance_root": provenance_root,
        "cleanup_required": cleanup_required,
        "cleanup_outcome": cleanup_outcome.value,
        "uncertainty_reasons": list(uncertainty_reasons),
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class ExperimentOracleEvaluation:
    evaluation_id: str
    manifest_id: str
    oracle_id: str
    verdict: OracleVerdict
    backend_receipt_ref: str
    control_evidence_refs: Tuple[str, ...]
    treatment_evidence_refs: Tuple[str, ...]
    witness_evidence_refs: Tuple[str, ...]
    cleanup_evidence_refs: Tuple[str, ...]
    provenance_root: str
    cleanup_required: bool
    cleanup_outcome: CleanupOutcome
    uncertainty_reasons: Tuple[str, ...]
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        manifest: ProofExperimentManifest,
        verdict: OracleVerdict,
        backend_receipt_ref: str,
        control_evidence_refs: Sequence[str],
        treatment_evidence_refs: Sequence[str],
        witness_evidence_refs: Sequence[str],
        cleanup_evidence_refs: Sequence[str],
        provenance_root: str,
        cleanup_outcome: CleanupOutcome,
        uncertainty_reasons: Sequence[str] = (),
    ) -> "ExperimentOracleEvaluation":
        if not isinstance(manifest, ProofExperimentManifest):
            raise TypeError("manifest must be a ProofExperimentManifest")
        controls = _sorted_refs(
            control_evidence_refs,
            field_name="control_evidence_refs",
        )
        treatment = _sorted_refs(
            treatment_evidence_refs,
            field_name="treatment_evidence_refs",
        )
        witnesses = _sorted_refs(
            witness_evidence_refs,
            field_name="witness_evidence_refs",
        )
        cleanup = _sorted_refs(
            cleanup_evidence_refs,
            field_name="cleanup_evidence_refs",
        )
        uncertainty = _sorted_semantics(
            uncertainty_reasons,
            field_name="uncertainty_reasons",
        )
        required_cleanup = manifest.cleanup.required
        conclusive = verdict in {OracleVerdict.CONFIRMED, OracleVerdict.REFUTED}
        if (
            (conclusive and (not controls or not treatment or not witnesses or uncertainty))
            or (
                conclusive
                and cleanup_outcome
                is not (
                    CleanupOutcome.COMPLETE
                    if required_cleanup
                    else CleanupOutcome.NOT_REQUIRED
                )
            )
            or (required_cleanup and conclusive and not cleanup)
            or (
                cleanup_outcome is CleanupOutcome.COMPLETE
                and not cleanup
            )
            or (
                cleanup_outcome is CleanupOutcome.NOT_REQUIRED
                and cleanup
            )
            or (
                not required_cleanup
                and cleanup_outcome is not CleanupOutcome.NOT_REQUIRED
            )
            or (verdict is OracleVerdict.INCONCLUSIVE and not uncertainty)
        ):
            raise ValueError("oracle evidence cannot support the requested verdict")
        payload = _evaluation_payload(
            manifest_id=manifest.manifest_id,
            oracle_id=manifest.oracle.oracle_id,
            verdict=verdict,
            backend_receipt_ref=backend_receipt_ref,
            control_evidence_refs=controls,
            treatment_evidence_refs=treatment,
            witness_evidence_refs=witnesses,
            cleanup_evidence_refs=cleanup,
            provenance_root=provenance_root,
            cleanup_required=required_cleanup,
            cleanup_outcome=cleanup_outcome,
            uncertainty_reasons=uncertainty,
        )
        return cls(
            evaluation_id=stable_hash("proof_experiment_evaluation", payload),
            manifest_id=manifest.manifest_id,
            oracle_id=manifest.oracle.oracle_id,
            verdict=verdict,
            backend_receipt_ref=backend_receipt_ref,
            control_evidence_refs=controls,
            treatment_evidence_refs=treatment,
            witness_evidence_refs=witnesses,
            cleanup_evidence_refs=cleanup,
            provenance_root=provenance_root,
            cleanup_required=required_cleanup,
            cleanup_outcome=cleanup_outcome,
            uncertainty_reasons=uncertainty,
        )

    def __post_init__(self) -> None:
        payload = _evaluation_payload(
            manifest_id=self.manifest_id,
            oracle_id=self.oracle_id,
            verdict=self.verdict,
            backend_receipt_ref=self.backend_receipt_ref,
            control_evidence_refs=self.control_evidence_refs,
            treatment_evidence_refs=self.treatment_evidence_refs,
            witness_evidence_refs=self.witness_evidence_refs,
            cleanup_evidence_refs=self.cleanup_evidence_refs,
            provenance_root=self.provenance_root,
            cleanup_required=self.cleanup_required,
            cleanup_outcome=self.cleanup_outcome,
            uncertainty_reasons=self.uncertainty_reasons,
        )
        conclusive = self.verdict in {OracleVerdict.CONFIRMED, OracleVerdict.REFUTED}
        if (
            self.evaluation_id != stable_hash("proof_experiment_evaluation", payload)
            or not _hash_ref(self.manifest_id, "proof_experiment_manifest")
            or not _hash_ref(self.oracle_id, "proof_experiment_oracle")
            or not _hash_ref(self.backend_receipt_ref, "behavioral_receipt")
            or any(
                values != tuple(sorted(set(values)))
                or any(not _hash_ref(item) for item in values)
                for values in (
                    self.control_evidence_refs,
                    self.treatment_evidence_refs,
                    self.witness_evidence_refs,
                    self.cleanup_evidence_refs,
                )
            )
            or not _hash_ref(self.provenance_root, "provenance")
            or not isinstance(self.cleanup_required, bool)
            or self.uncertainty_reasons
            != tuple(sorted(set(self.uncertainty_reasons)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.uncertainty_reasons)
            or (
                conclusive
                and (
                    not self.control_evidence_refs
                    or not self.treatment_evidence_refs
                    or not self.witness_evidence_refs
                )
            )
            or (conclusive and self.uncertainty_reasons)
            or (
                conclusive
                and self.cleanup_outcome
                is not (
                    CleanupOutcome.COMPLETE
                    if self.cleanup_required
                    else CleanupOutcome.NOT_REQUIRED
                )
            )
            or (self.cleanup_required and conclusive and not self.cleanup_evidence_refs)
            or (
                self.cleanup_outcome is CleanupOutcome.COMPLETE
                and not self.cleanup_evidence_refs
            )
            or (
                self.cleanup_outcome is CleanupOutcome.NOT_REQUIRED
                and self.cleanup_evidence_refs
            )
            or (
                not self.cleanup_required
                and self.cleanup_outcome is not CleanupOutcome.NOT_REQUIRED
            )
            or (self.verdict is OracleVerdict.INCONCLUSIVE and not self.uncertainty_reasons)
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("proof experiment oracle evaluation contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "evaluation_id": self.evaluation_id,
            **_evaluation_payload(
                manifest_id=self.manifest_id,
                oracle_id=self.oracle_id,
                verdict=self.verdict,
                backend_receipt_ref=self.backend_receipt_ref,
                control_evidence_refs=self.control_evidence_refs,
                treatment_evidence_refs=self.treatment_evidence_refs,
                witness_evidence_refs=self.witness_evidence_refs,
                cleanup_evidence_refs=self.cleanup_evidence_refs,
                provenance_root=self.provenance_root,
                cleanup_required=self.cleanup_required,
                cleanup_outcome=self.cleanup_outcome,
                uncertainty_reasons=self.uncertainty_reasons,
            ),
        }


__all__ = [
    "PROOF_EXPERIMENT_SDK_MODE",
    "BackendConformanceContract",
    "CleanupBinding",
    "CleanupOutcome",
    "ExistingBackendAdapter",
    "ExistingBackendKind",
    "ExperimentAction",
    "ExperimentActionClass",
    "ExperimentBudgetClaim",
    "ExperimentBudgetManifest",
    "ExperimentCleanupContract",
    "ExperimentControl",
    "ExperimentControlKind",
    "ExperimentOracleContract",
    "ExperimentOracleEvaluation",
    "ExperimentPhase",
    "ExperimentWorldBinding",
    "ExperimentWorldKind",
    "ExperimentWorldManifest",
    "MutationExpectation",
    "OracleVerdict",
    "ProofExperimentCompiler",
    "ProofExperimentManifest",
]
