"""Passive R5C2 role-monotonicity oracle and pre-traffic admission.

This module binds the R5C1 owned-membership fixture to one exact high-role
baseline, active low-role counterfactual, revocation, and post-revocation
counterfactual.  Role names do not establish authority, and response success is
not an effect witness.  The resulting proof and admission contract are
content-addressed, non-executable, and grant no budget, dispatch, or finding
authority.
"""

from __future__ import annotations

import copy
import hmac
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.foundry.authorization import AuthorizationEnvelope

from .experiment_admission import experiment_authority_context_ref
from .experiment_sdk import (
    ExperimentAction,
    ExperimentActionClass,
    ExperimentPhase,
    MutationExpectation,
)
from .normalize import stable_hash
from .payout_goals import SecurityProperty, SecurityWitnessGoal
from .role_membership import OwnedMembershipFixture

if TYPE_CHECKING:
    from core.cortex.execution_policy import PolicyExecutor
    from core.foundry.vault import PersonaVault

    from .receipts import BehavioralReceiptStore
    from .role_execution_claim import (
        RoleMonotonicityExecutionClaimConfig,
        RoleMonotonicityExecutionClaimLease,
    )
    from .role_membership_lifecycle import (
        RoleMembershipLifecycleConfig,
        RoleMembershipLifecycleResult,
    )
    from .role_request_binding import (
        RoleMonotonicityRequestBinder,
        RoleMonotonicityRequestBindingContract,
        RoleMonotonicityRuntimeContext,
        RoleRuntimeAuthorityValidator,
    )


ROLE_MONOTONICITY_PROOF_MODE = "behavioral_role_monotonicity_proof_v1"
ROLE_MONOTONICITY_ADMISSION_MODE = "behavioral_role_monotonicity_admission_v1"
ROLE_MONOTONICITY_WORKFLOW = "behavioral_role_membership_monotonicity"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_VERDICTS = (
    "confirmed_active_escalation",
    "confirmed_revocation_survival",
    "refuted",
    "inconclusive",
)
_REVOCATION_WITNESSES = frozenset(
    {
        "membership_revocation_verified",
        "post_revocation_freshness",
        "reversible_owned_membership",
    }
)
_EXECUTION_BLOCKERS = tuple(
    sorted(
        {
            "atomic_budget_reservation_required",
            "durable_execution_receipt_required",
            "effect_evaluation_required",
            "runtime_request_binding_required",
        }
    )
)


class RoleMonotonicityExperimentDenied(RuntimeError):
    """The role experiment does not match its fixture, goal, or authority."""


def _hash_ref(value: object, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and value.startswith(f"{prefix}:")
    )


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RoleMonotonicityExperimentDenied(
            "role_monotonicity_target_origin_is_invalid"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _oracle_payload(
    *,
    goal: SecurityWitnessGoal,
    fixture_id: str,
    higher_baseline_action_id: str,
    active_lower_probe_action_id: str,
    active_effect_witness_action_id: str,
    revoked_lower_probe_action_id: str,
    revoked_effect_witness_action_id: str,
    witness_requirements: Sequence[str],
) -> Dict[str, Any]:
    return {
        "goal": goal.to_dict(),
        "fixture_id": fixture_id,
        "higher_baseline_action_id": higher_baseline_action_id,
        "active_lower_probe_action_id": active_lower_probe_action_id,
        "active_effect_witness_action_id": active_effect_witness_action_id,
        "revoked_lower_probe_action_id": revoked_lower_probe_action_id,
        "revoked_effect_witness_action_id": revoked_effect_witness_action_id,
        "comparison_kind": "owned_role_membership_monotonicity",
        "witness_requirements": list(witness_requirements),
        "verdict_vocabulary": list(_VERDICTS),
        "active_effect_requires_independent_witness": True,
        "revoked_effect_requires_independent_witness": True,
        "adversarial_triage_required": True,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class RoleMonotonicityOracleContract:
    oracle_id: str
    goal_id: str
    goal: SecurityWitnessGoal = field(repr=False, compare=False)
    fixture_id: str
    higher_baseline_action_id: str
    active_lower_probe_action_id: str
    active_effect_witness_action_id: str
    revoked_lower_probe_action_id: str
    revoked_effect_witness_action_id: str
    witness_requirements: Tuple[str, ...]
    comparison_kind: str = "owned_role_membership_monotonicity"
    verdict_vocabulary: Tuple[str, ...] = _VERDICTS
    active_effect_requires_independent_witness: bool = True
    revoked_effect_requires_independent_witness: bool = True
    adversarial_triage_required: bool = True
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        goal: SecurityWitnessGoal,
        fixture: OwnedMembershipFixture,
        higher_baseline: ExperimentAction,
        active_lower_probe: ExperimentAction,
        active_effect_witness: ExperimentAction,
        revoked_lower_probe: ExperimentAction,
        revoked_effect_witness: ExperimentAction,
    ) -> "RoleMonotonicityOracleContract":
        requirements = tuple(
            sorted(set(goal.witness_requirements) | _REVOCATION_WITNESSES)
        )
        payload = _oracle_payload(
            goal=goal,
            fixture_id=fixture.fixture_id,
            higher_baseline_action_id=higher_baseline.action_id,
            active_lower_probe_action_id=active_lower_probe.action_id,
            active_effect_witness_action_id=active_effect_witness.action_id,
            revoked_lower_probe_action_id=revoked_lower_probe.action_id,
            revoked_effect_witness_action_id=revoked_effect_witness.action_id,
            witness_requirements=requirements,
        )
        return cls(
            oracle_id=stable_hash("role_monotonicity_oracle", payload),
            goal_id=goal.goal_id,
            goal=goal,
            fixture_id=fixture.fixture_id,
            higher_baseline_action_id=higher_baseline.action_id,
            active_lower_probe_action_id=active_lower_probe.action_id,
            active_effect_witness_action_id=active_effect_witness.action_id,
            revoked_lower_probe_action_id=revoked_lower_probe.action_id,
            revoked_effect_witness_action_id=revoked_effect_witness.action_id,
            witness_requirements=requirements,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.goal, SecurityWitnessGoal):
            raise TypeError("goal must be a SecurityWitnessGoal")
        payload = _oracle_payload(
            goal=self.goal,
            fixture_id=self.fixture_id,
            higher_baseline_action_id=self.higher_baseline_action_id,
            active_lower_probe_action_id=self.active_lower_probe_action_id,
            active_effect_witness_action_id=self.active_effect_witness_action_id,
            revoked_lower_probe_action_id=self.revoked_lower_probe_action_id,
            revoked_effect_witness_action_id=self.revoked_effect_witness_action_id,
            witness_requirements=self.witness_requirements,
        )
        action_ids = (
            self.higher_baseline_action_id,
            self.active_lower_probe_action_id,
            self.active_effect_witness_action_id,
            self.revoked_lower_probe_action_id,
            self.revoked_effect_witness_action_id,
        )
        expected_requirements = tuple(
            sorted(set(self.goal.witness_requirements) | _REVOCATION_WITNESSES)
        )
        if (
            self.oracle_id != stable_hash("role_monotonicity_oracle", payload)
            or not _hash_ref(self.oracle_id, "role_monotonicity_oracle")
            or self.goal_id != self.goal.goal_id
            or self.goal.security_property
            is not SecurityProperty.AUTHORITY_MONOTONICITY
            or not _hash_ref(self.fixture_id, "owned_membership_fixture")
            or any(
                not _hash_ref(item, "proof_experiment_action")
                for item in action_ids
            )
            or len(set(action_ids)) != len(action_ids)
            or self.witness_requirements != expected_requirements
            or self.comparison_kind != "owned_role_membership_monotonicity"
            or self.verdict_vocabulary != _VERDICTS
            or not self.active_effect_requires_independent_witness
            or not self.revoked_effect_requires_independent_witness
            or not self.adversarial_triage_required
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("role monotonicity oracle contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "oracle_id": self.oracle_id,
            **_oracle_payload(
                goal=self.goal,
                fixture_id=self.fixture_id,
                higher_baseline_action_id=self.higher_baseline_action_id,
                active_lower_probe_action_id=self.active_lower_probe_action_id,
                active_effect_witness_action_id=self.active_effect_witness_action_id,
                revoked_lower_probe_action_id=self.revoked_lower_probe_action_id,
                revoked_effect_witness_action_id=self.revoked_effect_witness_action_id,
                witness_requirements=self.witness_requirements,
            ),
        }


def _validate_monotonicity_actions(
    *,
    fixture: OwnedMembershipFixture,
    goal: SecurityWitnessGoal,
    higher_baseline: ExperimentAction,
    active_lower_probe: ExperimentAction,
    active_effect_witness: ExperimentAction,
    revoked_lower_probe: ExperimentAction,
    revoked_effect_witness: ExperimentAction,
) -> None:
    if not isinstance(fixture, OwnedMembershipFixture):
        raise TypeError("fixture must be an OwnedMembershipFixture")
    if not isinstance(goal, SecurityWitnessGoal):
        raise TypeError("goal must be a SecurityWitnessGoal")
    actions = (
        higher_baseline,
        active_lower_probe,
        active_effect_witness,
        revoked_lower_probe,
        revoked_effect_witness,
    )
    if any(not isinstance(item, ExperimentAction) for item in actions):
        raise TypeError("role monotonicity actions must be ExperimentAction values")
    if goal.security_property is not SecurityProperty.AUTHORITY_MONOTONICITY:
        raise RoleMonotonicityExperimentDenied(
            "role_monotonicity_goal_is_not_authority_monotonicity"
        )
    required_evidence = {
        fixture.fixture_id,
        fixture.lattice.lattice_id,
        fixture.membership_ref,
        goal.goal_id,
    }
    expected_shape = (
        (
            higher_baseline,
            ExperimentPhase.CONTROL,
            ExperimentActionClass.AUTHZ_PROBE,
            fixture.lattice.higher.world_binding_id,
        ),
        (
            active_lower_probe,
            ExperimentPhase.TREATMENT,
            ExperimentActionClass.AUTHZ_PROBE,
            fixture.lattice.lower.world_binding_id,
        ),
        (
            active_effect_witness,
            ExperimentPhase.WITNESS,
            ExperimentActionClass.SAFE_READ,
            fixture.lattice.higher.world_binding_id,
        ),
        (
            revoked_lower_probe,
            ExperimentPhase.TREATMENT,
            ExperimentActionClass.AUTHZ_PROBE,
            fixture.lattice.lower.world_binding_id,
        ),
        (
            revoked_effect_witness,
            ExperimentPhase.WITNESS,
            ExperimentActionClass.SAFE_READ,
            fixture.lattice.higher.world_binding_id,
        ),
    )
    if any(
        action.phase is not phase
        or action.action_class is not action_class
        or action.mutation is not MutationExpectation.NONE
        or action.world_binding_id != world_binding_id
        or not required_evidence <= set(action.evidence_refs)
        for action, phase, action_class, world_binding_id in expected_shape
    ):
        raise RoleMonotonicityExperimentDenied(
            "role_monotonicity_action_shape_is_invalid"
        )
    ordered_actions = (
        fixture.setup_action,
        higher_baseline,
        active_lower_probe,
        active_effect_witness,
        fixture.revocation_action,
        fixture.revocation_verification_action,
        revoked_lower_probe,
        revoked_effect_witness,
    )
    if (
        tuple(item.ordinal for item in ordered_actions) != tuple(range(8))
        or len({item.action_id for item in ordered_actions}) != len(ordered_actions)
    ):
        raise RoleMonotonicityExperimentDenied(
            "role_monotonicity_action_sequence_is_invalid"
        )
    probe_actions = (higher_baseline, active_lower_probe, revoked_lower_probe)
    witness_actions = (active_effect_witness, revoked_effect_witness)
    if (
        len({item.operation_id for item in probe_actions}) != 1
        or len({item.endpoint_ref for item in probe_actions}) != 1
        or len({item.operation_id for item in witness_actions}) != 1
        or len({item.endpoint_ref for item in witness_actions}) != 1
        or probe_actions[0].operation_id == witness_actions[0].operation_id
        or probe_actions[0].endpoint_ref == witness_actions[0].endpoint_ref
    ):
        raise RoleMonotonicityExperimentDenied(
            "role_monotonicity_probe_or_witness_is_not_equivalent"
        )


def _proof_payload(
    *,
    target_ref: str,
    authority_context_ref: str,
    fixture: OwnedMembershipFixture,
    oracle: RoleMonotonicityOracleContract,
    higher_baseline: ExperimentAction,
    active_lower_probe: ExperimentAction,
    active_effect_witness: ExperimentAction,
    revoked_lower_probe: ExperimentAction,
    revoked_effect_witness: ExperimentAction,
) -> Dict[str, Any]:
    return {
        "mode": ROLE_MONOTONICITY_PROOF_MODE,
        "workflow": ROLE_MONOTONICITY_WORKFLOW,
        "target_ref": target_ref,
        "authority_context_ref": authority_context_ref,
        "fixture": fixture.to_dict(),
        "oracle": oracle.to_dict(),
        "higher_baseline": higher_baseline.to_dict(),
        "active_lower_probe": active_lower_probe.to_dict(),
        "active_effect_witness": active_effect_witness.to_dict(),
        "revoked_lower_probe": revoked_lower_probe.to_dict(),
        "revoked_effect_witness": revoked_effect_witness.to_dict(),
        "execution_blockers": list(_EXECUTION_BLOCKERS),
        "target_requests_sent": 0,
        "budget_reserved": False,
        "single_use_claim_available": False,
        "backend_dispatch_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class RoleMonotonicityExperimentProof:
    proof_id: str
    target_ref: str
    authority_context_ref: str
    fixture: OwnedMembershipFixture
    oracle: RoleMonotonicityOracleContract
    higher_baseline: ExperimentAction
    active_lower_probe: ExperimentAction
    active_effect_witness: ExperimentAction
    revoked_lower_probe: ExperimentAction
    revoked_effect_witness: ExperimentAction
    mode: str = ROLE_MONOTONICITY_PROOF_MODE
    workflow: str = ROLE_MONOTONICITY_WORKFLOW
    execution_blockers: Tuple[str, ...] = _EXECUTION_BLOCKERS
    target_requests_sent: int = 0
    budget_reserved: bool = False
    single_use_claim_available: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.oracle, RoleMonotonicityOracleContract):
            raise TypeError("oracle must be a RoleMonotonicityOracleContract")
        _validate_monotonicity_actions(
            fixture=self.fixture,
            goal=self.oracle.goal,
            higher_baseline=self.higher_baseline,
            active_lower_probe=self.active_lower_probe,
            active_effect_witness=self.active_effect_witness,
            revoked_lower_probe=self.revoked_lower_probe,
            revoked_effect_witness=self.revoked_effect_witness,
        )
        payload = _proof_payload(
            target_ref=self.target_ref,
            authority_context_ref=self.authority_context_ref,
            fixture=self.fixture,
            oracle=self.oracle,
            higher_baseline=self.higher_baseline,
            active_lower_probe=self.active_lower_probe,
            active_effect_witness=self.active_effect_witness,
            revoked_lower_probe=self.revoked_lower_probe,
            revoked_effect_witness=self.revoked_effect_witness,
        )
        if (
            self.proof_id != stable_hash("role_monotonicity_proof", payload)
            or not _hash_ref(self.proof_id, "role_monotonicity_proof")
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(
                self.authority_context_ref,
                "experiment_authority_context",
            )
            or self.oracle.fixture_id != self.fixture.fixture_id
            or self.oracle.higher_baseline_action_id
            != self.higher_baseline.action_id
            or self.oracle.active_lower_probe_action_id
            != self.active_lower_probe.action_id
            or self.oracle.active_effect_witness_action_id
            != self.active_effect_witness.action_id
            or self.oracle.revoked_lower_probe_action_id
            != self.revoked_lower_probe.action_id
            or self.oracle.revoked_effect_witness_action_id
            != self.revoked_effect_witness.action_id
            or self.mode != ROLE_MONOTONICITY_PROOF_MODE
            or self.workflow != ROLE_MONOTONICITY_WORKFLOW
            or self.execution_blockers != _EXECUTION_BLOCKERS
            or self.target_requests_sent != 0
            or self.budget_reserved
            or self.single_use_claim_available
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("role monotonicity experiment proof is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "proof_id": self.proof_id,
            **_proof_payload(
                target_ref=self.target_ref,
                authority_context_ref=self.authority_context_ref,
                fixture=self.fixture,
                oracle=self.oracle,
                higher_baseline=self.higher_baseline,
                active_lower_probe=self.active_lower_probe,
                active_effect_witness=self.active_effect_witness,
                revoked_lower_probe=self.revoked_lower_probe,
                revoked_effect_witness=self.revoked_effect_witness,
            ),
        }


class RoleMonotonicityExperimentCompiler:
    """Seal the exact R5C1 fixture and role comparison without execution authority."""

    def compile(
        self,
        *,
        fixture: OwnedMembershipFixture,
        goal: SecurityWitnessGoal,
        target_ref: str,
        authority_context_ref: str,
        higher_baseline: ExperimentAction,
        active_lower_probe: ExperimentAction,
        active_effect_witness: ExperimentAction,
        revoked_lower_probe: ExperimentAction,
        revoked_effect_witness: ExperimentAction,
    ) -> RoleMonotonicityExperimentProof:
        _validate_monotonicity_actions(
            fixture=fixture,
            goal=goal,
            higher_baseline=higher_baseline,
            active_lower_probe=active_lower_probe,
            active_effect_witness=active_effect_witness,
            revoked_lower_probe=revoked_lower_probe,
            revoked_effect_witness=revoked_effect_witness,
        )
        if not _hash_ref(target_ref, "security_obligation_target") or not _hash_ref(
            authority_context_ref,
            "experiment_authority_context",
        ):
            raise RoleMonotonicityExperimentDenied(
                "role_monotonicity_target_or_authority_ref_is_invalid"
            )
        oracle = RoleMonotonicityOracleContract.build(
            goal=goal,
            fixture=fixture,
            higher_baseline=higher_baseline,
            active_lower_probe=active_lower_probe,
            active_effect_witness=active_effect_witness,
            revoked_lower_probe=revoked_lower_probe,
            revoked_effect_witness=revoked_effect_witness,
        )
        payload = _proof_payload(
            target_ref=target_ref,
            authority_context_ref=authority_context_ref,
            fixture=fixture,
            oracle=oracle,
            higher_baseline=higher_baseline,
            active_lower_probe=active_lower_probe,
            active_effect_witness=active_effect_witness,
            revoked_lower_probe=revoked_lower_probe,
            revoked_effect_witness=revoked_effect_witness,
        )
        return RoleMonotonicityExperimentProof(
            proof_id=stable_hash("role_monotonicity_proof", payload),
            target_ref=target_ref,
            authority_context_ref=authority_context_ref,
            fixture=fixture,
            oracle=oracle,
            higher_baseline=higher_baseline,
            active_lower_probe=active_lower_probe,
            active_effect_witness=active_effect_witness,
            revoked_lower_probe=revoked_lower_probe,
            revoked_effect_witness=revoked_effect_witness,
        )


def _admission_payload(
    *,
    proof_id: str,
    fixture_id: str,
    oracle_id: str,
    target_ref: str,
    authority_context_ref: str,
) -> Dict[str, Any]:
    return {
        "mode": ROLE_MONOTONICITY_ADMISSION_MODE,
        "workflow": ROLE_MONOTONICITY_WORKFLOW,
        "proof_id": proof_id,
        "fixture_id": fixture_id,
        "oracle_id": oracle_id,
        "target_ref": target_ref,
        "authority_context_ref": authority_context_ref,
        "signed_authority_revalidated": True,
        "role_contract_revalidated": True,
        "revocation_contract_revalidated": True,
        "execution_blockers": list(_EXECUTION_BLOCKERS),
        "target_requests_sent": 0,
        "budget_reserved": False,
        "single_use_claim_available": False,
        "backend_dispatch_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class RoleMonotonicityAdmissionContract:
    admission_id: str
    proof_id: str
    fixture_id: str
    oracle_id: str
    target_ref: str
    authority_context_ref: str
    mode: str = ROLE_MONOTONICITY_ADMISSION_MODE
    workflow: str = ROLE_MONOTONICITY_WORKFLOW
    signed_authority_revalidated: bool = True
    role_contract_revalidated: bool = True
    revocation_contract_revalidated: bool = True
    execution_blockers: Tuple[str, ...] = _EXECUTION_BLOCKERS
    target_requests_sent: int = 0
    budget_reserved: bool = False
    single_use_claim_available: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _admission_payload(
            proof_id=self.proof_id,
            fixture_id=self.fixture_id,
            oracle_id=self.oracle_id,
            target_ref=self.target_ref,
            authority_context_ref=self.authority_context_ref,
        )
        if (
            self.admission_id != stable_hash("role_monotonicity_admission", payload)
            or not _hash_ref(self.admission_id, "role_monotonicity_admission")
            or not _hash_ref(self.proof_id, "role_monotonicity_proof")
            or not _hash_ref(self.fixture_id, "owned_membership_fixture")
            or not _hash_ref(self.oracle_id, "role_monotonicity_oracle")
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(
                self.authority_context_ref,
                "experiment_authority_context",
            )
            or self.mode != ROLE_MONOTONICITY_ADMISSION_MODE
            or self.workflow != ROLE_MONOTONICITY_WORKFLOW
            or not self.signed_authority_revalidated
            or not self.role_contract_revalidated
            or not self.revocation_contract_revalidated
            or self.execution_blockers != _EXECUTION_BLOCKERS
            or self.target_requests_sent != 0
            or self.budget_reserved
            or self.single_use_claim_available
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("role monotonicity admission contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "admission_id": self.admission_id,
            **_admission_payload(
                proof_id=self.proof_id,
                fixture_id=self.fixture_id,
                oracle_id=self.oracle_id,
                target_ref=self.target_ref,
                authority_context_ref=self.authority_context_ref,
            ),
        }


class RoleMonotonicityExperimentAdmission:
    """Revalidate one R5C2 proof and signed workflow before any target traffic."""

    def __init__(
        self,
        *,
        proof: RoleMonotonicityExperimentProof,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        compiler: Optional[RoleMonotonicityExperimentCompiler] = None,
    ) -> None:
        if not isinstance(proof, RoleMonotonicityExperimentProof):
            raise TypeError("proof must be a RoleMonotonicityExperimentProof")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        self.proof = proof
        self.target_origin = _canonical_origin(target_origin)
        self.authorization = copy.deepcopy(authorization)
        self.compiler = compiler or RoleMonotonicityExperimentCompiler()

    def _validate_authority(self) -> None:
        signature = self.authorization.attestation_signature
        if not signature:
            raise RoleMonotonicityExperimentDenied(
                "role_monotonicity_authorization_is_unsigned"
            )
        copied = copy.deepcopy(self.authorization)
        if not hmac.compare_digest(signature, copied.sign()):
            raise RoleMonotonicityExperimentDenied(
                "role_monotonicity_authorization_signature_mismatch"
            )
        try:
            self.authorization.authorize_action(
                target_origin=self.target_origin,
                workflow=ROLE_MONOTONICITY_WORKFLOW,
            )
        except Exception as exc:
            raise RoleMonotonicityExperimentDenied(
                "role_monotonicity_authorization_denied"
            ) from exc
        expected_target_ref = stable_hash(
            "security_obligation_target",
            self.target_origin,
        )
        expected_context_ref = experiment_authority_context_ref(
            self.authorization,
            self.target_origin,
            (ROLE_MONOTONICITY_WORKFLOW,),
        )
        if (
            self.proof.target_ref != expected_target_ref
            or self.proof.authority_context_ref != expected_context_ref
        ):
            raise RoleMonotonicityExperimentDenied(
                "role_monotonicity_target_or_authority_context_mismatch"
            )

    def admit(self) -> RoleMonotonicityAdmissionContract:
        self._validate_authority()
        fresh = self.compiler.compile(
            fixture=self.proof.fixture,
            goal=self.proof.oracle.goal,
            target_ref=self.proof.target_ref,
            authority_context_ref=self.proof.authority_context_ref,
            higher_baseline=self.proof.higher_baseline,
            active_lower_probe=self.proof.active_lower_probe,
            active_effect_witness=self.proof.active_effect_witness,
            revoked_lower_probe=self.proof.revoked_lower_probe,
            revoked_effect_witness=self.proof.revoked_effect_witness,
        )
        if fresh.to_dict() != self.proof.to_dict():
            raise RoleMonotonicityExperimentDenied(
                "role_monotonicity_proof_does_not_match_current_contract"
            )
        payload = _admission_payload(
            proof_id=self.proof.proof_id,
            fixture_id=self.proof.fixture.fixture_id,
            oracle_id=self.proof.oracle.oracle_id,
            target_ref=self.proof.target_ref,
            authority_context_ref=self.proof.authority_context_ref,
        )
        return RoleMonotonicityAdmissionContract(
            admission_id=stable_hash("role_monotonicity_admission", payload),
            proof_id=self.proof.proof_id,
            fixture_id=self.proof.fixture.fixture_id,
            oracle_id=self.proof.oracle.oracle_id,
            target_ref=self.proof.target_ref,
            authority_context_ref=self.proof.authority_context_ref,
        )

    def bind_requests(
        self,
        *,
        executor: "PolicyExecutor",
        persona_vault: "PersonaVault",
        runtime: "RoleMonotonicityRuntimeContext",
        authority_validator: "RoleRuntimeAuthorityValidator",
        binder: Optional["RoleMonotonicityRequestBinder"] = None,
    ) -> "RoleMonotonicityRequestBindingContract":
        """Revalidate R5C2, then bind exact R5C3 intent without dispatch."""

        from .role_request_binding import RoleMonotonicityRequestBinder

        admission = self.admit()
        request_binder = binder or RoleMonotonicityRequestBinder()
        return request_binder.bind(
            proof=self.proof,
            admission=admission,
            target_origin=self.target_origin,
            authorization=self.authorization,
            executor=executor,
            persona_vault=persona_vault,
            runtime=runtime,
            authority_validator=authority_validator,
        )

    def reserve_execution_claim(
        self,
        *,
        request_binding: "RoleMonotonicityRequestBindingContract",
        executor: "PolicyExecutor",
        persona_vault: "PersonaVault",
        runtime: "RoleMonotonicityRuntimeContext",
        authority_validator: "RoleRuntimeAuthorityValidator",
        config: Optional["RoleMonotonicityExecutionClaimConfig"] = None,
        receipt_store: Optional["BehavioralReceiptStore"] = None,
    ) -> "RoleMonotonicityExecutionClaimLease":
        """Revalidate R5C3 and reserve one transport-free R5C4 claim."""

        from .role_execution_claim import (
            RoleMonotonicityExecutionClaimAdmission,
        )

        return RoleMonotonicityExecutionClaimAdmission(
            proof=self.proof,
            request_binding=request_binding,
            target_origin=self.target_origin,
            authorization=self.authorization,
            executor=executor,
            persona_vault=persona_vault,
            runtime=runtime,
            authority_validator=authority_validator,
            config=config,
            receipt_store=receipt_store,
        ).admit()

    async def run_membership_lifecycle_probe(
        self,
        *,
        request_binding: "RoleMonotonicityRequestBindingContract",
        executor: "PolicyExecutor",
        persona_vault: "PersonaVault",
        runtime: "RoleMonotonicityRuntimeContext",
        authority_validator: "RoleRuntimeAuthorityValidator",
        claim_config: Optional[
            "RoleMonotonicityExecutionClaimConfig"
        ] = None,
        lifecycle_config: Optional[
            "RoleMembershipLifecycleConfig"
        ] = None,
        receipt_store: Optional["BehavioralReceiptStore"] = None,
    ) -> "RoleMembershipLifecycleResult":
        """Consume R5C4 for the default-off R5C5 setup/cleanup probe."""

        from .role_membership_lifecycle import (
            RoleMembershipLifecycleConfig,
            RoleMembershipLifecycleDenied,
            RoleMembershipLifecycleExecutor,
        )

        if lifecycle_config is not None and not isinstance(
            lifecycle_config,
            RoleMembershipLifecycleConfig,
        ):
            raise TypeError(
                "lifecycle_config must be a RoleMembershipLifecycleConfig"
            )
        active_lifecycle_config = (
            lifecycle_config
            if lifecycle_config is not None
            else RoleMembershipLifecycleConfig.from_environment()
        )
        if not active_lifecycle_config.enabled:
            raise RoleMembershipLifecycleDenied(
                "role_membership_lifecycle_is_disabled",
                category="configuration",
            )
        lease = self.reserve_execution_claim(
            request_binding=request_binding,
            executor=executor,
            persona_vault=persona_vault,
            runtime=runtime,
            authority_validator=authority_validator,
            config=claim_config,
            receipt_store=receipt_store,
        )
        claim = lease.claim()
        return await RoleMembershipLifecycleExecutor(
            claim,
            config=active_lifecycle_config,
        ).execute()


__all__ = [
    "ROLE_MONOTONICITY_ADMISSION_MODE",
    "ROLE_MONOTONICITY_PROOF_MODE",
    "ROLE_MONOTONICITY_WORKFLOW",
    "RoleMonotonicityAdmissionContract",
    "RoleMonotonicityExperimentAdmission",
    "RoleMonotonicityExperimentCompiler",
    "RoleMonotonicityExperimentDenied",
    "RoleMonotonicityExperimentProof",
    "RoleMonotonicityOracleContract",
]
