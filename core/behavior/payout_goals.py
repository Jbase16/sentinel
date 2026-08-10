"""Passive payout-goal discovery and proof-topology selection.

This module decides which security witness is worth constructing and which controlled
world arrangement it would require.  It has no transport, cannot reserve a proof
budget, cannot admit an experiment, and cannot turn a hypothesis into a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.foundry.authorization import AuthorizationContext, AuthorizationEnvelope

from .compiler import OperationContract, operation_contracts_from_records
from .normalize import stable_hash
from .obligations import SecurityObligationGraph
from .omission import OmissionCompilationResult
from .proposals import CROSS_OBJECT_READ, ProposalBatch
from .state_machine import StateMachineLegalityResult


PAYOUT_GOAL_PLANNER_MODE = "behavioral_payout_goal_topology_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


class PayoutSink(str, Enum):
    EXPORT_DOWNLOAD = "export_download"
    FINANCIAL = "financial"
    MEMBERSHIP = "membership"
    CREDENTIAL_CAPABILITY = "credential_capability"
    AUTHORITY = "authority"
    IDENTITY_RECOVERY = "identity_recovery"
    FILE_ACCESS = "file_access"
    PRIVATE_COMMUNICATION = "private_communication"
    ADMIN_BULK = "admin_bulk"
    ACCOUNT_OWNERSHIP = "account_ownership"


class SecurityProperty(str, Enum):
    OBJECT_AUTHORIZATION = "object_authorization"
    PREREQUISITE_ENFORCEMENT = "prerequisite_enforcement"
    AUTHORITY_MONOTONICITY = "authority_monotonicity"
    CAPABILITY_CONFINEMENT = "capability_confinement"
    OWNED_DATA_INTEGRITY = "owned_data_integrity"
    BOUNDARY_CONSISTENCY = "boundary_consistency"


class ProofTopology(str, Enum):
    ZERO_PERSONA_ANONYMOUS = "zero_persona_anonymous"
    FRESH_ANONYMOUS = "fresh_anonymous"
    SINGLE_OWNED_ACCOUNT = "single_owned_account"
    PAIRED_OWNED_ACCOUNTS = "paired_owned_accounts"
    OWNED_ROLE_DIFFERENTIAL = "owned_role_differential"
    CONTROLLED_LIFECYCLE = "controlled_lifecycle"
    CALLBACK_RECEIVER = "callback_receiver"


_SINK_WEIGHT = {
    PayoutSink.ACCOUNT_OWNERSHIP: 100,
    PayoutSink.CREDENTIAL_CAPABILITY: 96,
    PayoutSink.AUTHORITY: 94,
    PayoutSink.FINANCIAL: 92,
    PayoutSink.IDENTITY_RECOVERY: 90,
    PayoutSink.EXPORT_DOWNLOAD: 88,
    PayoutSink.PRIVATE_COMMUNICATION: 86,
    PayoutSink.FILE_ACCESS: 84,
    PayoutSink.MEMBERSHIP: 82,
    PayoutSink.ADMIN_BULK: 80,
}

_BACKEND_WORKFLOWS = {
    "object_authorization": ("behavioral_object_authorization",),
    "prerequisite_omission": (
        "behavioral_compiled_owned_sequence",
        "behavioral_state_machine_omission",
        "behavioral_state_machine_omission_confirmation",
    ),
}

_WITNESS_REQUIREMENTS = {
    SecurityProperty.OBJECT_AUTHORIZATION: (
        "controlled_counterfactual",
        "controlled_owner_baseline",
        "independent_effect_witness",
        "policy_provenance",
    ),
    SecurityProperty.PREREQUISITE_ENFORCEMENT: (
        "cleanup_proof",
        "independent_effect_witness",
        "policy_provenance",
        "single_prerequisite_delta",
        "valid_baseline_sequence",
    ),
    SecurityProperty.AUTHORITY_MONOTONICITY: (
        "controlled_high_role_baseline",
        "controlled_low_role_counterfactual",
        "independent_effect_witness",
        "policy_provenance",
    ),
    SecurityProperty.CAPABILITY_CONFINEMENT: (
        "capability_issuance_witness",
        "capability_scope_control",
        "independent_effect_witness",
        "policy_provenance",
    ),
    SecurityProperty.OWNED_DATA_INTEGRITY: (
        "authoritative_follow_up_read",
        "cleanup_proof",
        "controlled_write",
        "policy_provenance",
    ),
    SecurityProperty.BOUNDARY_CONSISTENCY: (
        "independent_effect_witness",
        "minimal_request_delta",
        "policy_provenance",
        "stable_control_response",
    ),
}


@dataclass(frozen=True)
class PayoutGoalPlannerLimits:
    max_operations: int = 4_096
    max_candidates: int = 128
    max_evidence_refs_per_goal: int = 64

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class WorldRequirement:
    topology: ProofTopology
    min_owned_worlds: int
    required_role_worlds: int = 0
    requires_fresh_anonymous: bool = False
    requires_controlled_lifecycle: bool = False
    requires_callback_receiver: bool = False
    required_workflows: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        expected = {
            ProofTopology.ZERO_PERSONA_ANONYMOUS: (0, 0, False, False, False),
            ProofTopology.FRESH_ANONYMOUS: (0, 0, True, False, False),
            ProofTopology.SINGLE_OWNED_ACCOUNT: (1, 0, False, False, False),
            ProofTopology.PAIRED_OWNED_ACCOUNTS: (2, 0, False, False, False),
            ProofTopology.OWNED_ROLE_DIFFERENTIAL: (2, 2, False, False, False),
            ProofTopology.CONTROLLED_LIFECYCLE: (1, 0, False, True, False),
            ProofTopology.CALLBACK_RECEIVER: (0, 0, False, False, True),
        }[self.topology]
        actual = (
            self.min_owned_worlds,
            self.required_role_worlds,
            self.requires_fresh_anonymous,
            self.requires_controlled_lifecycle,
            self.requires_callback_receiver,
        )
        workflows = tuple(sorted(set(self.required_workflows)))
        object.__setattr__(self, "required_workflows", workflows)
        if actual != expected or any(_SEMANTIC.fullmatch(item) is None for item in workflows):
            raise ValueError("world requirement contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "topology": self.topology.value,
            "min_owned_worlds": self.min_owned_worlds,
            "required_role_worlds": self.required_role_worlds,
            "requires_fresh_anonymous": self.requires_fresh_anonymous,
            "requires_controlled_lifecycle": self.requires_controlled_lifecycle,
            "requires_callback_receiver": self.requires_callback_receiver,
            "required_workflows": list(self.required_workflows),
        }


@dataclass(frozen=True)
class SecurityWitnessGoal:
    goal_id: str
    terminal_operation_id: str
    operation_label_ref: str
    sink: PayoutSink
    security_property: SecurityProperty
    impact_weight: int
    witness_requirements: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        operation: OperationContract,
        sink: PayoutSink,
        security_property: SecurityProperty,
        evidence_refs: Sequence[str],
    ) -> "SecurityWitnessGoal":
        refs = tuple(sorted(set(evidence_refs)))
        requirements = tuple(sorted(_WITNESS_REQUIREMENTS[security_property]))
        label_ref = stable_hash("payout_operation_label", operation.label)
        payload = {
            "terminal_operation_id": operation.operation_id,
            "operation_label_ref": label_ref,
            "sink": sink.value,
            "security_property": security_property.value,
            "impact_weight": _SINK_WEIGHT[sink],
            "witness_requirements": list(requirements),
            "evidence_refs": list(refs),
        }
        return cls(
            goal_id=stable_hash("security_witness_goal", payload),
            terminal_operation_id=operation.operation_id,
            operation_label_ref=label_ref,
            sink=sink,
            security_property=security_property,
            impact_weight=_SINK_WEIGHT[sink],
            witness_requirements=requirements,
            evidence_refs=refs,
        )

    def __post_init__(self) -> None:
        payload = {
            "terminal_operation_id": self.terminal_operation_id,
            "operation_label_ref": self.operation_label_ref,
            "sink": self.sink.value,
            "security_property": self.security_property.value,
            "impact_weight": self.impact_weight,
            "witness_requirements": list(self.witness_requirements),
            "evidence_refs": list(self.evidence_refs),
        }
        if (
            self.goal_id != stable_hash("security_witness_goal", payload)
            or not _hash_ref(self.terminal_operation_id, "action")
            or not _hash_ref(self.operation_label_ref, "payout_operation_label")
            or self.impact_weight != _SINK_WEIGHT[self.sink]
            or self.witness_requirements
            != tuple(sorted(set(self.witness_requirements)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.witness_requirements)
            or not self.evidence_refs
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or any(not _hash_ref(item) for item in self.evidence_refs)
        ):
            raise ValueError("security witness goal contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "terminal_operation_id": self.terminal_operation_id,
            "operation_label_ref": self.operation_label_ref,
            "sink": self.sink.value,
            "security_property": self.security_property.value,
            "impact_weight": self.impact_weight,
            "witness_requirements": list(self.witness_requirements),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class GoalBlocker:
    blocker_id: str
    code: str
    requirement: Optional[str] = None

    @classmethod
    def build(cls, code: str, requirement: Optional[str] = None) -> "GoalBlocker":
        payload = {"code": code, "requirement": requirement}
        return cls(
            blocker_id=stable_hash("payout_goal_blocker", payload),
            code=code,
            requirement=requirement,
        )

    def __post_init__(self) -> None:
        if (
            self.blocker_id
            != stable_hash(
                "payout_goal_blocker",
                {"code": self.code, "requirement": self.requirement},
            )
            or _SEMANTIC.fullmatch(self.code) is None
            or (
                self.requirement is not None
                and _SEMANTIC.fullmatch(self.requirement) is None
            )
        ):
            raise ValueError("goal blocker contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocker_id": self.blocker_id,
            "code": self.code,
            "requirement": self.requirement,
        }


def _context_payload(
    *,
    target_ref: str,
    authorization_ref: Optional[str],
    authorization_approved: bool,
    origin_authorized: bool,
    allowed_workflows: Sequence[str],
    max_owned_worlds: int,
    owned_world_refs: Sequence[str],
    role_world_refs: Sequence[str],
    fresh_anonymous_available: bool,
    lifecycle_available: bool,
    callback_receiver_available: bool,
    available_backends: Sequence[str],
) -> Dict[str, Any]:
    return {
        "target_ref": target_ref,
        "authorization_ref": authorization_ref,
        "authorization_approved": authorization_approved,
        "origin_authorized": origin_authorized,
        "allowed_workflows": list(allowed_workflows),
        "max_owned_worlds": max_owned_worlds,
        "owned_world_refs": list(owned_world_refs),
        "role_world_refs": list(role_world_refs),
        "fresh_anonymous_available": fresh_anonymous_available,
        "lifecycle_available": lifecycle_available,
        "callback_receiver_available": callback_receiver_available,
        "available_backends": list(available_backends),
    }


@dataclass(frozen=True)
class GoalPlanningContext:
    context_ref: str
    target_ref: str
    authorization_ref: Optional[str]
    authorization_approved: bool
    origin_authorized: bool
    allowed_workflows: Tuple[str, ...]
    max_owned_worlds: int
    owned_world_refs: Tuple[str, ...]
    role_world_refs: Tuple[str, ...]
    fresh_anonymous_available: bool
    lifecycle_available: bool
    callback_receiver_available: bool
    available_backends: Tuple[str, ...]
    mode: str = PAYOUT_GOAL_PLANNER_MODE
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        target_ref: str,
        target_origin: str,
        authorization: Optional[AuthorizationEnvelope],
        owned_world_ids: Sequence[str] = (),
        role_world_ids: Sequence[str] = (),
        fresh_anonymous_available: bool = False,
        lifecycle_available: bool = False,
        callback_receiver_available: bool = False,
        available_backends: Sequence[str] = (),
    ) -> "GoalPlanningContext":
        if authorization is None:
            authorization_ref = None
            authorization_approved = False
            origin_authorized = False
            allowed_workflows: Tuple[str, ...] = ()
            max_owned_worlds = 0
        else:
            authorization_ref = stable_hash(
                "payout_goal_authorization",
                {
                    "envelope_id": authorization.envelope_id,
                    "attestation_signature": authorization.attestation_signature,
                },
            )
            authorization_approved = (
                authorization.context() is AuthorizationContext.APPROVED
            )
            origin_authorized = authorization.authorizes_origin(target_origin)
            allowed_workflows = tuple(sorted(set(authorization.allowed_workflows)))
            max_owned_worlds = authorization.max_accounts_per_service
        owned_refs = tuple(
            sorted({stable_hash("world", value) for value in owned_world_ids})
        )
        role_refs = tuple(
            sorted({stable_hash("world", value) for value in role_world_ids})
        )
        backends = tuple(sorted(set(available_backends)))
        payload = _context_payload(
            target_ref=target_ref,
            authorization_ref=authorization_ref,
            authorization_approved=authorization_approved,
            origin_authorized=origin_authorized,
            allowed_workflows=allowed_workflows,
            max_owned_worlds=max_owned_worlds,
            owned_world_refs=owned_refs,
            role_world_refs=role_refs,
            fresh_anonymous_available=fresh_anonymous_available,
            lifecycle_available=lifecycle_available,
            callback_receiver_available=callback_receiver_available,
            available_backends=backends,
        )
        return cls(
            context_ref=stable_hash("payout_goal_context", payload),
            target_ref=target_ref,
            authorization_ref=authorization_ref,
            authorization_approved=authorization_approved,
            origin_authorized=origin_authorized,
            allowed_workflows=allowed_workflows,
            max_owned_worlds=max_owned_worlds,
            owned_world_refs=owned_refs,
            role_world_refs=role_refs,
            fresh_anonymous_available=fresh_anonymous_available,
            lifecycle_available=lifecycle_available,
            callback_receiver_available=callback_receiver_available,
            available_backends=backends,
        )

    def __post_init__(self) -> None:
        payload = _context_payload(
            target_ref=self.target_ref,
            authorization_ref=self.authorization_ref,
            authorization_approved=self.authorization_approved,
            origin_authorized=self.origin_authorized,
            allowed_workflows=self.allowed_workflows,
            max_owned_worlds=self.max_owned_worlds,
            owned_world_refs=self.owned_world_refs,
            role_world_refs=self.role_world_refs,
            fresh_anonymous_available=self.fresh_anonymous_available,
            lifecycle_available=self.lifecycle_available,
            callback_receiver_available=self.callback_receiver_available,
            available_backends=self.available_backends,
        )
        if (
            self.context_ref != stable_hash("payout_goal_context", payload)
            or self.mode != PAYOUT_GOAL_PLANNER_MODE
            or self.executable
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or (
                self.authorization_ref is not None
                and not _hash_ref(
                    self.authorization_ref,
                    "payout_goal_authorization",
                )
            )
            or isinstance(self.max_owned_worlds, bool)
            or not isinstance(self.max_owned_worlds, int)
            or self.max_owned_worlds < 0
            or self.allowed_workflows != tuple(sorted(set(self.allowed_workflows)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.allowed_workflows)
            or self.owned_world_refs != tuple(sorted(set(self.owned_world_refs)))
            or self.role_world_refs != tuple(sorted(set(self.role_world_refs)))
            or any(not _hash_ref(item, "world") for item in self.owned_world_refs)
            or any(not _hash_ref(item, "world") for item in self.role_world_refs)
            or not set(self.role_world_refs) <= set(self.owned_world_refs)
            or self.available_backends != tuple(sorted(set(self.available_backends)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.available_backends)
        ):
            raise ValueError("goal planning context contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "context_ref": self.context_ref,
            "target_ref": self.target_ref,
            "authorization_ref": self.authorization_ref,
            "authorization_approved": self.authorization_approved,
            "origin_authorized": self.origin_authorized,
            "allowed_workflows": list(self.allowed_workflows),
            "max_owned_worlds": self.max_owned_worlds,
            "owned_world_refs": list(self.owned_world_refs),
            "role_world_refs": list(self.role_world_refs),
            "fresh_anonymous_available": self.fresh_anonymous_available,
            "lifecycle_available": self.lifecycle_available,
            "callback_receiver_available": self.callback_receiver_available,
            "available_backends": list(self.available_backends),
            "mode": self.mode,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class PayoutGoalCandidate:
    candidate_id: str
    goal: SecurityWitnessGoal
    world_requirement: WorldRequirement
    backend: str
    score: int
    blockers: Tuple[GoalBlocker, ...]
    status: str
    mode: str = PAYOUT_GOAL_PLANNER_MODE
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        goal: SecurityWitnessGoal,
        world_requirement: WorldRequirement,
        backend: str,
        score: int,
        blockers: Sequence[GoalBlocker],
    ) -> "PayoutGoalCandidate":
        blocker_values = tuple(sorted(set(blockers), key=lambda item: item.blocker_id))
        status = "admissible" if not blocker_values else "blocked"
        payload = {
            "goal": goal.to_dict(),
            "world_requirement": world_requirement.to_dict(),
            "backend": backend,
            "score": score,
            "blockers": [item.to_dict() for item in blocker_values],
            "status": status,
        }
        return cls(
            candidate_id=stable_hash("payout_goal_candidate", payload),
            goal=goal,
            world_requirement=world_requirement,
            backend=backend,
            score=score,
            blockers=blocker_values,
            status=status,
        )

    def __post_init__(self) -> None:
        payload = {
            "goal": self.goal.to_dict(),
            "world_requirement": self.world_requirement.to_dict(),
            "backend": self.backend,
            "score": self.score,
            "blockers": [item.to_dict() for item in self.blockers],
            "status": self.status,
        }
        expected_status = "admissible" if not self.blockers else "blocked"
        if (
            self.candidate_id != stable_hash("payout_goal_candidate", payload)
            or self.mode != PAYOUT_GOAL_PLANNER_MODE
            or self.executable
            or _SEMANTIC.fullmatch(self.backend) is None
            or isinstance(self.score, bool)
            or not isinstance(self.score, int)
            or self.score < 0
            or self.status != expected_status
            or self.blockers
            != tuple(sorted(set(self.blockers), key=lambda item: item.blocker_id))
        ):
            raise ValueError("payout goal candidate contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "goal": self.goal.to_dict(),
            "world_requirement": self.world_requirement.to_dict(),
            "backend": self.backend,
            "score": self.score,
            "blockers": [item.to_dict() for item in self.blockers],
            "status": self.status,
            "mode": self.mode,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class PayoutGoalDiagnostics:
    operations: int
    high_value_operations: int
    candidates: int
    admissible: int
    blocked: int
    obligations: int
    dropped_candidates: int
    dropped_evidence_refs: int

    def __post_init__(self) -> None:
        values = tuple(vars(self).values())
        if (
            any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values)
            or self.candidates != self.admissible + self.blocked
            or self.high_value_operations > self.operations
        ):
            raise ValueError("payout goal diagnostics are invalid")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


def _plan_payload(
    *,
    status: str,
    target_ref: str,
    graph_digest: str,
    context: GoalPlanningContext,
    selected_goal_id: Optional[str],
    candidates: Sequence[PayoutGoalCandidate],
    input_blockers: Sequence[GoalBlocker],
    diagnostics: PayoutGoalDiagnostics,
) -> Dict[str, Any]:
    return {
        "status": status,
        "target_ref": target_ref,
        "graph_digest": graph_digest,
        "context": context.to_dict(),
        "selected_goal_id": selected_goal_id,
        "candidates": [item.to_dict() for item in candidates],
        "input_blockers": [item.to_dict() for item in input_blockers],
        "diagnostics": diagnostics.to_dict(),
    }


@dataclass(frozen=True)
class PayoutGoalPlan:
    plan_id: str
    status: str
    target_ref: str
    graph_digest: str
    context: GoalPlanningContext
    selected_goal_id: Optional[str]
    candidates: Tuple[PayoutGoalCandidate, ...]
    input_blockers: Tuple[GoalBlocker, ...]
    diagnostics: PayoutGoalDiagnostics
    mode: str = PAYOUT_GOAL_PLANNER_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        admissible = tuple(item for item in self.candidates if item.status == "admissible")
        expected_selected = (
            admissible[0].goal.goal_id
            if admissible and not self.input_blockers
            else None
        )
        if self.input_blockers:
            expected_status = "blocked_input"
        elif not self.candidates:
            expected_status = "no_goals"
        elif admissible:
            expected_status = "ready"
        else:
            expected_status = "blocked"
        payload = _plan_payload(
            status=self.status,
            target_ref=self.target_ref,
            graph_digest=self.graph_digest,
            context=self.context,
            selected_goal_id=self.selected_goal_id,
            candidates=self.candidates,
            input_blockers=self.input_blockers,
            diagnostics=self.diagnostics,
        )
        if (
            self.plan_id != stable_hash("payout_goal_plan", payload)
            or self.status != expected_status
            or self.mode != PAYOUT_GOAL_PLANNER_MODE
            or self.executable
            or self.target_ref != self.context.target_ref
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(self.graph_digest, "security_obligation_graph")
            or self.selected_goal_id != expected_selected
            or self.diagnostics.candidates != len(self.candidates)
            or self.diagnostics.admissible != len(admissible)
            or self.diagnostics.blocked != len(self.candidates) - len(admissible)
            or len({item.candidate_id for item in self.candidates})
            != len(self.candidates)
            or len({item.goal.goal_id for item in self.candidates})
            != len(self.candidates)
            or self.candidates
            != tuple(
                sorted(
                    self.candidates,
                    key=lambda item: (
                        item.status != "admissible",
                        -item.score,
                        item.goal.sink.value,
                        item.goal.security_property.value,
                        item.candidate_id,
                    ),
                )
            )
            or self.input_blockers
            != tuple(sorted(set(self.input_blockers), key=lambda item: item.blocker_id))
        ):
            raise ValueError("payout goal plan contract is invalid")

    @property
    def selected(self) -> Optional[PayoutGoalCandidate]:
        if self.selected_goal_id is None:
            return None
        return next(
            item for item in self.candidates if item.goal.goal_id == self.selected_goal_id
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "plan_id": self.plan_id,
            "status": self.status,
            "target_ref": self.target_ref,
            "graph_digest": self.graph_digest,
            "context": self.context.to_dict(),
            "selected": self.selected.to_dict() if self.selected is not None else None,
            "selected_goal_id": self.selected_goal_id,
            "candidates": [item.to_dict() for item in self.candidates],
            "input_blockers": [item.to_dict() for item in self.input_blockers],
            "diagnostics": self.diagnostics.to_dict(),
        }


def _normalized_label(value: str) -> str:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", snake.lower()).strip("_")


def _sink_for_label(label: str) -> Optional[PayoutSink]:
    value = _normalized_label(label)
    tokens = set(value.split("_"))
    if (
        ({"account", "ownership"} <= tokens)
        or ({"account", "transfer"} <= tokens)
        or ({"account", "delete"} <= tokens)
        or "takeover" in tokens
    ):
        return PayoutSink.ACCOUNT_OWNERSHIP
    if tokens & {"payment", "billing", "balance", "credit", "refund", "payout", "withdraw"}:
        return PayoutSink.FINANCIAL
    if tokens & {"admin", "role", "permission", "impersonate", "privilege"}:
        return PayoutSink.AUTHORITY
    if tokens & {"recover", "recovery", "reset", "password", "email"}:
        return PayoutSink.IDENTITY_RECOVERY
    if tokens & {"invite", "invitation", "membership", "member", "organization", "organisation"}:
        return PayoutSink.MEMBERSHIP
    if tokens & {"credential", "secret", "token", "webhook", "integration"} or (
        "api" in tokens and "key" in tokens
    ):
        return PayoutSink.CREDENTIAL_CAPABILITY
    if tokens & {"message", "messages", "inbox", "chat", "conversation"}:
        return PayoutSink.PRIVATE_COMMUNICATION
    if tokens & {"export", "download", "backup"}:
        return PayoutSink.EXPORT_DOWNLOAD
    if tokens & {"file", "files", "document", "documents", "attachment", "attachments"}:
        return PayoutSink.FILE_ACCESS
    if tokens & {"bulk", "batch", "mass"}:
        return PayoutSink.ADMIN_BULK
    return None


def _inferred_property(sink: PayoutSink) -> SecurityProperty:
    if sink in {PayoutSink.AUTHORITY, PayoutSink.MEMBERSHIP}:
        return SecurityProperty.AUTHORITY_MONOTONICITY
    if sink in {PayoutSink.CREDENTIAL_CAPABILITY, PayoutSink.IDENTITY_RECOVERY}:
        return SecurityProperty.CAPABILITY_CONFINEMENT
    if sink in {
        PayoutSink.FINANCIAL,
        PayoutSink.ADMIN_BULK,
        PayoutSink.ACCOUNT_OWNERSHIP,
    }:
        return SecurityProperty.OWNED_DATA_INTEGRITY
    return SecurityProperty.OBJECT_AUTHORIZATION


def _world_requirement(
    security_property: SecurityProperty,
    *,
    label: str,
    context: GoalPlanningContext,
) -> Tuple[WorldRequirement, str]:
    if security_property is SecurityProperty.PREREQUISITE_ENFORCEMENT:
        return (
            WorldRequirement(
                ProofTopology.CONTROLLED_LIFECYCLE,
                1,
                requires_controlled_lifecycle=True,
                required_workflows=_BACKEND_WORKFLOWS["prerequisite_omission"],
            ),
            "prerequisite_omission",
        )
    if security_property is SecurityProperty.AUTHORITY_MONOTONICITY:
        return (
            WorldRequirement(
                ProofTopology.OWNED_ROLE_DIFFERENTIAL,
                2,
                required_role_worlds=2,
            ),
            "authority_monotonicity",
        )
    if security_property is SecurityProperty.CAPABILITY_CONFINEMENT:
        if "webhook" in _normalized_label(label).split("_"):
            return (
                WorldRequirement(
                    ProofTopology.CALLBACK_RECEIVER,
                    0,
                    requires_callback_receiver=True,
                ),
                "capability_confinement",
            )
        return (
            WorldRequirement(ProofTopology.SINGLE_OWNED_ACCOUNT, 1),
            "capability_confinement",
        )
    if security_property is SecurityProperty.OWNED_DATA_INTEGRITY:
        return (
            WorldRequirement(ProofTopology.SINGLE_OWNED_ACCOUNT, 1),
            "owned_data_integrity",
        )
    if security_property is SecurityProperty.BOUNDARY_CONSISTENCY:
        return (
            WorldRequirement(
                ProofTopology.FRESH_ANONYMOUS,
                0,
                requires_fresh_anonymous=True,
            ),
            "boundary_consistency",
        )
    if len(context.owned_world_refs) >= 2:
        return (
            WorldRequirement(
                ProofTopology.PAIRED_OWNED_ACCOUNTS,
                2,
                required_workflows=_BACKEND_WORKFLOWS["object_authorization"],
            ),
            "object_authorization",
        )
    if context.owned_world_refs:
        return (
            WorldRequirement(ProofTopology.SINGLE_OWNED_ACCOUNT, 1),
            "anonymous_authorization",
        )
    return (
        WorldRequirement(ProofTopology.ZERO_PERSONA_ANONYMOUS, 0),
        "anonymous_exposure",
    )


def _candidate_blockers(
    *,
    context: GoalPlanningContext,
    requirement: WorldRequirement,
    backend: str,
    operation_observed: bool,
) -> Tuple[GoalBlocker, ...]:
    blockers = []
    if not operation_observed:
        blockers.append(GoalBlocker.build("operation_unconfirmed"))
    if context.authorization_ref is None:
        blockers.append(GoalBlocker.build("authorization_unavailable"))
    elif not context.authorization_approved:
        blockers.append(GoalBlocker.build("authorization_not_approved"))
    if not context.origin_authorized:
        blockers.append(GoalBlocker.build("target_origin_not_authorized"))
    if len(context.owned_world_refs) < requirement.min_owned_worlds:
        blockers.append(GoalBlocker.build("insufficient_owned_worlds"))
    if requirement.min_owned_worlds > context.max_owned_worlds:
        blockers.append(GoalBlocker.build("owned_world_limit_exceeded"))
    if len(context.role_world_refs) < requirement.required_role_worlds:
        blockers.append(GoalBlocker.build("distinct_role_worlds_unavailable"))
    if requirement.requires_fresh_anonymous and not context.fresh_anonymous_available:
        blockers.append(GoalBlocker.build("fresh_anonymous_world_unavailable"))
    if requirement.requires_controlled_lifecycle and not context.lifecycle_available:
        blockers.append(GoalBlocker.build("controlled_lifecycle_unavailable"))
    if requirement.requires_callback_receiver and not context.callback_receiver_available:
        blockers.append(GoalBlocker.build("callback_receiver_unavailable"))
    if backend not in context.available_backends:
        blockers.append(GoalBlocker.build("proof_backend_unavailable", backend))
    if backend == "anonymous_exposure" and not context.owned_world_refs:
        blockers.append(GoalBlocker.build("owned_subject_unavailable"))
    allowed = set(context.allowed_workflows)
    for workflow in requirement.required_workflows:
        if workflow not in allowed:
            blockers.append(GoalBlocker.build("required_workflow_missing", workflow))
    return tuple(sorted(set(blockers), key=lambda item: item.blocker_id))


class PayoutGoalTopologyPlanner:
    """Rank payout-relevant witnessed operations and choose passive topologies."""

    def __init__(
        self,
        limits: PayoutGoalPlannerLimits = PayoutGoalPlannerLimits(),
    ) -> None:
        if not isinstance(limits, PayoutGoalPlannerLimits):
            raise TypeError("limits must be PayoutGoalPlannerLimits")
        self.limits = limits

    def plan_from_records(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        graph: SecurityObligationGraph,
        context: GoalPlanningContext,
        proposals: Optional[ProposalBatch] = None,
        state_machine: Optional[StateMachineLegalityResult] = None,
        omissions: Optional[OmissionCompilationResult] = None,
    ) -> PayoutGoalPlan:
        try:
            operations = operation_contracts_from_records(records)
        except (TypeError, ValueError):
            return self.plan(
                (),
                graph=graph,
                context=context,
                proposals=proposals,
                state_machine=state_machine,
                omissions=omissions,
                input_blockers=(GoalBlocker.build("operation_catalog_unavailable"),),
            )
        return self.plan(
            operations,
            graph=graph,
            context=context,
            proposals=proposals,
            state_machine=state_machine,
            omissions=omissions,
        )

    def plan(
        self,
        operations: Sequence[OperationContract],
        *,
        graph: SecurityObligationGraph,
        context: GoalPlanningContext,
        proposals: Optional[ProposalBatch] = None,
        state_machine: Optional[StateMachineLegalityResult] = None,
        omissions: Optional[OmissionCompilationResult] = None,
        input_blockers: Sequence[GoalBlocker] = (),
    ) -> PayoutGoalPlan:
        if graph.target_ref != context.target_ref:
            raise ValueError("payout goal context target does not match obligation graph")
        operation_count = len(operations)
        if len(operations) > self.limits.max_operations:
            input_blockers = (*input_blockers, GoalBlocker.build("operation_limit_exceeded"))
            operations = ()

        authorization_by_action: Dict[str, list[str]] = {}
        if proposals is not None:
            for proposal in proposals.proposals:
                if proposal.risk_class != CROSS_OBJECT_READ:
                    continue
                authorization_by_action.setdefault(proposal.action_id, []).append(
                    proposal.proposal_id
                )
        state_by_terminal: Dict[str, list[str]] = {}
        if state_machine is not None:
            for candidate in state_machine.candidates:
                state_by_terminal.setdefault(candidate.terminal_operation_id, []).append(
                    candidate.candidate_id
                )
        omission_by_terminal: Dict[str, list[str]] = {}
        if omissions is not None:
            for experiment in omissions.experiments:
                omission_by_terminal.setdefault(experiment.terminal_operation_id, []).append(
                    experiment.experiment_id
                )

        candidates = []
        high_value_operations = 0
        dropped_evidence_refs = 0
        for operation in sorted(operations, key=lambda item: item.operation_id):
            sink = _sink_for_label(operation.label)
            if sink is None or not operation.source_refs:
                continue
            high_value_operations += 1
            variants = []
            if operation.operation_id in authorization_by_action:
                variants.append(
                    (
                        SecurityProperty.OBJECT_AUTHORIZATION,
                        tuple(authorization_by_action[operation.operation_id]),
                        12,
                    )
                )
            if operation.operation_id in state_by_terminal:
                variants.append(
                    (
                        SecurityProperty.PREREQUISITE_ENFORCEMENT,
                        tuple(
                            (*state_by_terminal[operation.operation_id],
                             *omission_by_terminal.get(operation.operation_id, ()))
                        ),
                        14,
                    )
                )
            if not variants:
                variants.append((_inferred_property(sink), (), 0))

            for security_property, relation_refs, relation_score in variants:
                relation_evidence = tuple(sorted(set(relation_refs)))
                source_evidence = tuple(
                    sorted(set(operation.source_refs) - set(relation_evidence))
                )
                all_evidence_refs = (*relation_evidence, *source_evidence)
                dropped_evidence_refs += max(
                    0,
                    len(all_evidence_refs) - self.limits.max_evidence_refs_per_goal,
                )
                evidence_refs = tuple(
                    sorted(
                        all_evidence_refs[: self.limits.max_evidence_refs_per_goal]
                    )
                )
                goal = SecurityWitnessGoal.build(
                    operation=operation,
                    sink=sink,
                    security_property=security_property,
                    evidence_refs=evidence_refs,
                )
                requirement, backend = _world_requirement(
                    security_property,
                    label=operation.label,
                    context=context,
                )
                blockers = _candidate_blockers(
                    context=context,
                    requirement=requirement,
                    backend=backend,
                    operation_observed=operation.observed_success,
                )
                score = max(
                    0,
                    goal.impact_weight
                    + (8 if operation.observed_success else 0)
                    + relation_score
                    + (6 if backend in context.available_backends else 0)
                    - operation.cost,
                )
                candidates.append(
                    PayoutGoalCandidate.build(
                        goal=goal,
                        world_requirement=requirement,
                        backend=backend,
                        score=score,
                        blockers=blockers,
                    )
                )

        candidates.sort(
            key=lambda item: (
                item.status != "admissible",
                -item.score,
                item.goal.sink.value,
                item.goal.security_property.value,
                item.candidate_id,
            )
        )
        dropped = max(0, len(candidates) - self.limits.max_candidates)
        candidate_values = tuple(candidates[: self.limits.max_candidates])
        admissible = sum(item.status == "admissible" for item in candidate_values)
        diagnostics = PayoutGoalDiagnostics(
            operations=operation_count,
            high_value_operations=high_value_operations,
            candidates=len(candidate_values),
            admissible=admissible,
            blocked=len(candidate_values) - admissible,
            obligations=len(graph.obligations),
            dropped_candidates=dropped,
            dropped_evidence_refs=dropped_evidence_refs,
        )
        blocker_values = tuple(
            sorted(set(input_blockers), key=lambda item: item.blocker_id)
        )
        if blocker_values:
            status = "blocked_input"
        elif not candidate_values:
            status = "no_goals"
        elif admissible:
            status = "ready"
        else:
            status = "blocked"
        selected_goal_id = (
            next(
                (
                    item.goal.goal_id
                    for item in candidate_values
                    if item.status == "admissible"
                ),
                None,
            )
            if not blocker_values
            else None
        )
        payload = _plan_payload(
            status=status,
            target_ref=graph.target_ref,
            graph_digest=graph.graph_digest,
            context=context,
            selected_goal_id=selected_goal_id,
            candidates=candidate_values,
            input_blockers=blocker_values,
            diagnostics=diagnostics,
        )
        return PayoutGoalPlan(
            plan_id=stable_hash("payout_goal_plan", payload),
            status=status,
            target_ref=graph.target_ref,
            graph_digest=graph.graph_digest,
            context=context,
            selected_goal_id=selected_goal_id,
            candidates=candidate_values,
            input_blockers=blocker_values,
            diagnostics=diagnostics,
        )


__all__ = [
    "GoalBlocker",
    "GoalPlanningContext",
    "PAYOUT_GOAL_PLANNER_MODE",
    "PayoutGoalCandidate",
    "PayoutGoalDiagnostics",
    "PayoutGoalPlan",
    "PayoutGoalPlannerLimits",
    "PayoutGoalTopologyPlanner",
    "PayoutSink",
    "ProofTopology",
    "SecurityProperty",
    "SecurityWitnessGoal",
    "WorldRequirement",
]
