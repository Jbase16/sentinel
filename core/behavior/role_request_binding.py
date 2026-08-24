"""Transport-free runtime request binding for R5C role experiments.

This boundary binds one passive :mod:`role_monotonicity` admission to exact
owned runtime identities, sessions, membership generations, request material,
cleanup lineage, and a future receipt lineage.  It reuses the generalized R4
runtime world/action binders and the current policy budget preview.  It cannot
reserve budget, create a receipt, acquire a claim, or invoke transport.
"""

from __future__ import annotations

import copy
import hmac
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import CandidateAction, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
from core.safety.proof_mode import ProofMode

from .experiment_admission import (
    ExperimentRuntimeActionBinding,
    ExperimentRuntimeWorldBinding,
    ProofExperimentAdmissionDenied,
    experiment_authority_context_ref,
)
from .experiment_sdk import ExperimentAction
from .normalize import stable_hash
from .receipts import redacted_receipt_context, request_fingerprint
from .role_monotonicity import (
    ROLE_MONOTONICITY_WORKFLOW,
    RoleMonotonicityAdmissionContract,
    RoleMonotonicityExperimentProof,
)


ROLE_MONOTONICITY_REQUEST_BINDING_MODE = (
    "behavioral_role_monotonicity_request_binding_v1"
)

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_REMAINING_EXECUTION_BLOCKERS = (
    "atomic_budget_reservation_required",
    "durable_execution_receipt_required",
    "effect_evaluation_required",
)
_MEMBERSHIP_STATES = frozenset({"active", "revoking", "revoked"})
_JSON_POINTER = re.compile(r"^(?:/(?:[^~/]|~[01])*)+$")


class RoleMonotonicityRequestBindingDenied(RuntimeError):
    """The admitted role experiment does not match current runtime intent."""


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _runtime_value(value: object, *, field_name: str) -> str:
    normalized = str(value or "").strip()
    if (
        not normalized
        or len(normalized) > 512
        or any(ord(character) < 32 for character in normalized)
    ):
        raise ValueError(f"{field_name} is invalid")
    return normalized


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
        raise RoleMonotonicityRequestBindingDenied(
            "role_request_target_origin_is_invalid"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def role_tenant_ownership_ref(
    authorization: AuthorizationEnvelope,
    tenant_id: str,
) -> str:
    """Bind an owned tenant identity to the current signed envelope."""

    if not isinstance(authorization, AuthorizationEnvelope):
        raise TypeError("authorization must be an AuthorizationEnvelope")
    signature = str(authorization.attestation_signature or "")
    if not signature:
        raise ValueError("signed authorization is required for tenant ownership")
    tenant_value = _runtime_value(tenant_id, field_name="runtime tenant id")
    return stable_hash(
        "ownership_proof",
        {
            "attestation_signature": signature,
            "tenant_ref": stable_hash("owned_tenant", tenant_value),
        },
    )


def _request_material(candidate: CandidateAction) -> Dict[str, Any]:
    return {
        "method": str(candidate.method or "").strip().upper(),
        "url": str(candidate.url),
        "body": copy.deepcopy(candidate.body),
        "hint": candidate.hint,
        "actor_persona_id": candidate.actor_persona_id,
        "target_owner_persona_id": candidate.target_owner_persona_id,
        "target_is_researcher_owned": candidate.target_is_researcher_owned,
        "expected_side_effect": candidate.expected_side_effect,
        "proof_goal": candidate.proof_goal,
    }


def _request_intent_ref(
    *,
    action_id: str,
    run_ref: str,
    candidate: CandidateAction,
) -> str:
    return stable_hash(
        "role_runtime_request_intent",
        {
            "action_id": action_id,
            "run_ref": run_ref,
            "request_material_fingerprint": request_fingerprint(
                _request_material(candidate)
            ),
        },
    )


def _session_ref(
    *,
    run_ref: str,
    persona_ref: str,
    session_id: str,
    lifecycle_state: str,
) -> str:
    return stable_hash(
        "role_runtime_session",
        {
            "run_ref": run_ref,
            "persona_ref": persona_ref,
            "session_id": session_id,
            "lifecycle_state": lifecycle_state,
        },
    )


def _role_evidence_ref(
    *,
    authority_context_ref: str,
    run_ref: str,
    tenant_ref: str,
    tenant_ownership_ref: str,
    world_binding_id: str,
    persona_ref: str,
    role_ref: str,
) -> str:
    return stable_hash(
        "role_runtime_authority_evidence",
        {
            "authority_context_ref": authority_context_ref,
            "run_ref": run_ref,
            "tenant_ref": tenant_ref,
            "tenant_ownership_ref": tenant_ownership_ref,
            "world_binding_id": world_binding_id,
            "persona_ref": persona_ref,
            "role_ref": role_ref,
        },
    )


def _generation_ref(
    *,
    run_ref: str,
    membership_ref: str,
    generation: int,
    state: str,
) -> str:
    return stable_hash(
        "role_membership_generation",
        {
            "run_ref": run_ref,
            "membership_ref": membership_ref,
            "generation": generation,
            "state": state,
        },
    )


def _active_membership_evidence_ref(
    *,
    proof: RoleMonotonicityExperimentProof,
    run_ref: str,
    tenant_ref: str,
    session_ref: str,
    generation_ref: str,
) -> str:
    return stable_hash(
        "role_membership_active_evidence",
        {
            "proof_id": proof.proof_id,
            "fixture_id": proof.fixture.fixture_id,
            "run_ref": run_ref,
            "tenant_ref": tenant_ref,
            "membership_ref": proof.fixture.membership_ref,
            "subject_role_binding_id": proof.fixture.subject_role_binding_id,
            "active_lower_session_ref": session_ref,
            "generation_ref": generation_ref,
            "setup_action_id": proof.fixture.setup_action.action_id,
        },
    )


def _revocation_evidence_ref(
    *,
    proof: RoleMonotonicityExperimentProof,
    run_ref: str,
    active_evidence_ref: str,
    revoked_session_ref: str,
    revoked_generation_ref: str,
) -> str:
    return stable_hash(
        "role_membership_revocation_evidence",
        {
            "proof_id": proof.proof_id,
            "fixture_id": proof.fixture.fixture_id,
            "run_ref": run_ref,
            "membership_ref": proof.fixture.membership_ref,
            "active_evidence_ref": active_evidence_ref,
            "revocation_action_id": proof.fixture.revocation_action.action_id,
            "revoked_lower_session_ref": revoked_session_ref,
            "revoked_generation_ref": revoked_generation_ref,
        },
    )


def _revocation_verification_ref(
    *,
    proof: RoleMonotonicityExperimentProof,
    run_ref: str,
    revocation_evidence_ref: str,
) -> str:
    return stable_hash(
        "role_membership_revocation_verification",
        {
            "proof_id": proof.proof_id,
            "run_ref": run_ref,
            "revocation_evidence_ref": revocation_evidence_ref,
            "verification_action_id": (
                proof.fixture.revocation_verification_action.action_id
            ),
        },
    )


def _membership_observation_payload(
    *,
    setup_action_id: str,
    revocation_verification_action_id: str,
    tenant_pointer: str,
    subject_pointer: str,
    role_pointer: str,
    state_pointer: str,
    generation_pointer: str,
) -> Dict[str, Any]:
    return {
        "setup_action_id": setup_action_id,
        "revocation_verification_action_id": (
            revocation_verification_action_id
        ),
        "response_format": "json",
        "tenant_pointer": tenant_pointer,
        "subject_pointer": subject_pointer,
        "role_pointer": role_pointer,
        "state_pointer": state_pointer,
        "generation_pointer": generation_pointer,
    }


@dataclass(frozen=True)
class RoleMembershipObservationBinding:
    """Exact target-response projection required by a future active lifecycle.

    The binding contains JSON pointers only. Runtime tenant, persona, role, state,
    and generation values remain private and are compared only after transport.
    """

    binding_id: str
    setup_action_id: str
    revocation_verification_action_id: str
    tenant_pointer: str
    subject_pointer: str
    role_pointer: str
    state_pointer: str
    generation_pointer: str
    response_format: str = "json"

    @classmethod
    def build(
        cls,
        *,
        proof: RoleMonotonicityExperimentProof,
        tenant_pointer: str,
        subject_pointer: str,
        role_pointer: str,
        state_pointer: str,
        generation_pointer: str,
    ) -> "RoleMembershipObservationBinding":
        if not isinstance(proof, RoleMonotonicityExperimentProof):
            raise TypeError("proof must be a RoleMonotonicityExperimentProof")
        pointers = tuple(
            str(value or "")
            for value in (
                tenant_pointer,
                subject_pointer,
                role_pointer,
                state_pointer,
                generation_pointer,
            )
        )
        payload = _membership_observation_payload(
            setup_action_id=proof.fixture.setup_action.action_id,
            revocation_verification_action_id=(
                proof.fixture.revocation_verification_action.action_id
            ),
            tenant_pointer=pointers[0],
            subject_pointer=pointers[1],
            role_pointer=pointers[2],
            state_pointer=pointers[3],
            generation_pointer=pointers[4],
        )
        return cls(
            binding_id=stable_hash(
                "role_membership_observation_binding",
                payload,
            ),
            setup_action_id=proof.fixture.setup_action.action_id,
            revocation_verification_action_id=(
                proof.fixture.revocation_verification_action.action_id
            ),
            tenant_pointer=pointers[0],
            subject_pointer=pointers[1],
            role_pointer=pointers[2],
            state_pointer=pointers[3],
            generation_pointer=pointers[4],
        )

    def __post_init__(self) -> None:
        pointers = (
            self.tenant_pointer,
            self.subject_pointer,
            self.role_pointer,
            self.state_pointer,
            self.generation_pointer,
        )
        payload = _membership_observation_payload(
            setup_action_id=self.setup_action_id,
            revocation_verification_action_id=(
                self.revocation_verification_action_id
            ),
            tenant_pointer=self.tenant_pointer,
            subject_pointer=self.subject_pointer,
            role_pointer=self.role_pointer,
            state_pointer=self.state_pointer,
            generation_pointer=self.generation_pointer,
        )
        if (
            self.binding_id
            != stable_hash("role_membership_observation_binding", payload)
            or not _hash_ref(
                self.binding_id,
                "role_membership_observation_binding",
            )
            or not _hash_ref(
                self.setup_action_id,
                "proof_experiment_action",
            )
            or not _hash_ref(
                self.revocation_verification_action_id,
                "proof_experiment_action",
            )
            or self.setup_action_id
            == self.revocation_verification_action_id
            or self.response_format != "json"
            or len(set(pointers)) != len(pointers)
            or any(
                not isinstance(pointer, str)
                or len(pointer) > 256
                or any(ord(character) < 32 for character in pointer)
                or _JSON_POINTER.fullmatch(pointer) is None
                for pointer in pointers
            )
        ):
            raise ValueError("role membership observation binding is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            **_membership_observation_payload(
                setup_action_id=self.setup_action_id,
                revocation_verification_action_id=(
                    self.revocation_verification_action_id
                ),
                tenant_pointer=self.tenant_pointer,
                subject_pointer=self.subject_pointer,
                role_pointer=self.role_pointer,
                state_pointer=self.state_pointer,
                generation_pointer=self.generation_pointer,
            ),
        }


def _protected_effect_observation_payload(
    *,
    higher_baseline_action_id: str,
    active_lower_probe_action_id: str,
    active_effect_witness_action_id: str,
    revoked_lower_probe_action_id: str,
    revoked_effect_witness_action_id: str,
    probe_authorized_pointer: str,
    probe_effect_pointer: str,
    witness_effect_pointer: str,
) -> Dict[str, Any]:
    return {
        "higher_baseline_action_id": higher_baseline_action_id,
        "active_lower_probe_action_id": active_lower_probe_action_id,
        "active_effect_witness_action_id": active_effect_witness_action_id,
        "revoked_lower_probe_action_id": revoked_lower_probe_action_id,
        "revoked_effect_witness_action_id": revoked_effect_witness_action_id,
        "response_format": "json",
        "probe_authorized_pointer": probe_authorized_pointer,
        "probe_effect_pointer": probe_effect_pointer,
        "witness_effect_pointer": witness_effect_pointer,
        "allowed_value": True,
        "denied_value": False,
        "denied_effect_must_be_null": True,
    }


@dataclass(frozen=True)
class RoleProtectedEffectObservationBinding:
    """Exact response projection used by the independent R5C6 oracle.

    Only JSON pointers and already-content-addressed action identities are public.
    Runtime effect values remain private and are reduced to content hashes after
    exact-session transport.
    """

    binding_id: str
    higher_baseline_action_id: str
    active_lower_probe_action_id: str
    active_effect_witness_action_id: str
    revoked_lower_probe_action_id: str
    revoked_effect_witness_action_id: str
    probe_authorized_pointer: str
    probe_effect_pointer: str
    witness_effect_pointer: str
    response_format: str = "json"
    allowed_value: bool = True
    denied_value: bool = False
    denied_effect_must_be_null: bool = True

    @classmethod
    def build(
        cls,
        *,
        proof: RoleMonotonicityExperimentProof,
        probe_authorized_pointer: str,
        probe_effect_pointer: str,
        witness_effect_pointer: str,
    ) -> "RoleProtectedEffectObservationBinding":
        if not isinstance(proof, RoleMonotonicityExperimentProof):
            raise TypeError("proof must be a RoleMonotonicityExperimentProof")
        pointers = tuple(
            str(value or "")
            for value in (
                probe_authorized_pointer,
                probe_effect_pointer,
                witness_effect_pointer,
            )
        )
        payload = _protected_effect_observation_payload(
            higher_baseline_action_id=proof.higher_baseline.action_id,
            active_lower_probe_action_id=proof.active_lower_probe.action_id,
            active_effect_witness_action_id=(
                proof.active_effect_witness.action_id
            ),
            revoked_lower_probe_action_id=proof.revoked_lower_probe.action_id,
            revoked_effect_witness_action_id=(
                proof.revoked_effect_witness.action_id
            ),
            probe_authorized_pointer=pointers[0],
            probe_effect_pointer=pointers[1],
            witness_effect_pointer=pointers[2],
        )
        return cls(
            binding_id=stable_hash(
                "role_protected_effect_observation_binding",
                payload,
            ),
            higher_baseline_action_id=proof.higher_baseline.action_id,
            active_lower_probe_action_id=proof.active_lower_probe.action_id,
            active_effect_witness_action_id=(
                proof.active_effect_witness.action_id
            ),
            revoked_lower_probe_action_id=proof.revoked_lower_probe.action_id,
            revoked_effect_witness_action_id=(
                proof.revoked_effect_witness.action_id
            ),
            probe_authorized_pointer=pointers[0],
            probe_effect_pointer=pointers[1],
            witness_effect_pointer=pointers[2],
        )

    def __post_init__(self) -> None:
        action_ids = (
            self.higher_baseline_action_id,
            self.active_lower_probe_action_id,
            self.active_effect_witness_action_id,
            self.revoked_lower_probe_action_id,
            self.revoked_effect_witness_action_id,
        )
        pointers = (
            self.probe_authorized_pointer,
            self.probe_effect_pointer,
            self.witness_effect_pointer,
        )
        payload = _protected_effect_observation_payload(
            higher_baseline_action_id=self.higher_baseline_action_id,
            active_lower_probe_action_id=self.active_lower_probe_action_id,
            active_effect_witness_action_id=self.active_effect_witness_action_id,
            revoked_lower_probe_action_id=self.revoked_lower_probe_action_id,
            revoked_effect_witness_action_id=(
                self.revoked_effect_witness_action_id
            ),
            probe_authorized_pointer=self.probe_authorized_pointer,
            probe_effect_pointer=self.probe_effect_pointer,
            witness_effect_pointer=self.witness_effect_pointer,
        )
        if (
            self.binding_id
            != stable_hash("role_protected_effect_observation_binding", payload)
            or not _hash_ref(
                self.binding_id,
                "role_protected_effect_observation_binding",
            )
            or any(
                not _hash_ref(action_id, "proof_experiment_action")
                for action_id in action_ids
            )
            or len(set(action_ids)) != len(action_ids)
            or self.response_format != "json"
            or self.allowed_value is not True
            or self.denied_value is not False
            or self.denied_effect_must_be_null is not True
            or self.probe_authorized_pointer == self.probe_effect_pointer
            or any(
                not isinstance(pointer, str)
                or len(pointer) > 256
                or any(ord(character) < 32 for character in pointer)
                or _JSON_POINTER.fullmatch(pointer) is None
                for pointer in pointers
            )
        ):
            raise ValueError(
                "role protected effect observation binding is invalid"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            **_protected_effect_observation_payload(
                higher_baseline_action_id=self.higher_baseline_action_id,
                active_lower_probe_action_id=self.active_lower_probe_action_id,
                active_effect_witness_action_id=(
                    self.active_effect_witness_action_id
                ),
                revoked_lower_probe_action_id=(
                    self.revoked_lower_probe_action_id
                ),
                revoked_effect_witness_action_id=(
                    self.revoked_effect_witness_action_id
                ),
                probe_authorized_pointer=self.probe_authorized_pointer,
                probe_effect_pointer=self.probe_effect_pointer,
                witness_effect_pointer=self.witness_effect_pointer,
            ),
        }


@dataclass(frozen=True)
class RoleMonotonicityRuntimeContext:
    """Sensitive owned runtime values supplied to the admission boundary."""

    run_id: str = field(repr=False)
    tenant_id: str = field(repr=False)
    higher_persona_id: str = field(repr=False)
    lower_persona_id: str = field(repr=False)
    higher_session_id: str = field(repr=False)
    active_lower_session_id: str = field(repr=False)
    revoked_lower_session_id: str = field(repr=False)
    active_membership_generation: int
    revoked_membership_generation: int
    run_ref: str
    tenant_ref: str
    tenant_ownership_ref: str
    membership_ref: str
    higher_role_ref: str
    lower_role_ref: str
    higher_session_ref: str
    active_lower_session_ref: str
    revoked_lower_session_ref: str
    higher_role_evidence_ref: str
    lower_role_evidence_ref: str
    active_generation_ref: str
    revoked_generation_ref: str
    active_membership_evidence_ref: str
    revocation_evidence_ref: str
    revocation_verification_ref: str
    membership_observation_binding: RoleMembershipObservationBinding
    effect_observation_binding: RoleProtectedEffectObservationBinding
    request_intent_refs: Mapping[str, str]
    runtime_actions: Mapping[str, CandidateAction] = field(
        repr=False,
        compare=False,
    )

    @classmethod
    def build(
        cls,
        *,
        proof: RoleMonotonicityExperimentProof,
        authorization: AuthorizationEnvelope,
        run_id: str,
        tenant_id: str,
        higher_persona_id: str,
        lower_persona_id: str,
        higher_session_id: str,
        active_lower_session_id: str,
        revoked_lower_session_id: str,
        active_membership_generation: int,
        revoked_membership_generation: int,
        membership_observation_binding: RoleMembershipObservationBinding,
        effect_observation_binding: RoleProtectedEffectObservationBinding,
        runtime_actions: Mapping[str, CandidateAction],
    ) -> "RoleMonotonicityRuntimeContext":
        if not isinstance(proof, RoleMonotonicityExperimentProof):
            raise TypeError("proof must be a RoleMonotonicityExperimentProof")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        if not isinstance(
            membership_observation_binding,
            RoleMembershipObservationBinding,
        ):
            raise TypeError(
                "membership_observation_binding must be a "
                "RoleMembershipObservationBinding"
            )
        if (
            membership_observation_binding.setup_action_id
            != proof.fixture.setup_action.action_id
            or membership_observation_binding.revocation_verification_action_id
            != proof.fixture.revocation_verification_action.action_id
        ):
            raise ValueError(
                "membership observation binding does not match the proof"
            )
        if not isinstance(
            effect_observation_binding,
            RoleProtectedEffectObservationBinding,
        ):
            raise TypeError(
                "effect_observation_binding must be a "
                "RoleProtectedEffectObservationBinding"
            )
        expected_effect_actions = (
            proof.higher_baseline.action_id,
            proof.active_lower_probe.action_id,
            proof.active_effect_witness.action_id,
            proof.revoked_lower_probe.action_id,
            proof.revoked_effect_witness.action_id,
        )
        bound_effect_actions = (
            effect_observation_binding.higher_baseline_action_id,
            effect_observation_binding.active_lower_probe_action_id,
            effect_observation_binding.active_effect_witness_action_id,
            effect_observation_binding.revoked_lower_probe_action_id,
            effect_observation_binding.revoked_effect_witness_action_id,
        )
        if bound_effect_actions != expected_effect_actions:
            raise ValueError(
                "effect observation binding does not match the proof"
            )
        run_value = _runtime_value(run_id, field_name="runtime run id")
        tenant_value = _runtime_value(tenant_id, field_name="runtime tenant id")
        higher_persona = _runtime_value(
            higher_persona_id,
            field_name="higher runtime persona id",
        )
        lower_persona = _runtime_value(
            lower_persona_id,
            field_name="lower runtime persona id",
        )
        higher_session = _runtime_value(
            higher_session_id,
            field_name="higher runtime session id",
        )
        active_session = _runtime_value(
            active_lower_session_id,
            field_name="active lower runtime session id",
        )
        revoked_session = _runtime_value(
            revoked_lower_session_id,
            field_name="revoked lower runtime session id",
        )
        try:
            action_values = copy.deepcopy(dict(runtime_actions))
        except Exception as exc:
            raise TypeError("runtime actions must be safely copyable") from exc
        if any(
            not isinstance(key, str) or not isinstance(value, CandidateAction)
            for key, value in action_values.items()
        ):
            raise TypeError("runtime actions must map action ids to CandidateAction")

        fixture = proof.fixture
        run_ref = stable_hash("role_monotonicity_run", run_value)
        tenant_ref = stable_hash("owned_tenant", tenant_value)
        tenant_ownership_ref = role_tenant_ownership_ref(
            authorization,
            tenant_value,
        )
        higher_session_ref = _session_ref(
            run_ref=run_ref,
            persona_ref=fixture.lattice.higher.persona_ref,
            session_id=higher_session,
            lifecycle_state="experiment",
        )
        active_lower_session_ref = _session_ref(
            run_ref=run_ref,
            persona_ref=fixture.lattice.lower.persona_ref,
            session_id=active_session,
            lifecycle_state="active_membership",
        )
        revoked_lower_session_ref = _session_ref(
            run_ref=run_ref,
            persona_ref=fixture.lattice.lower.persona_ref,
            session_id=revoked_session,
            lifecycle_state="post_revocation",
        )
        active_generation_ref = _generation_ref(
            run_ref=run_ref,
            membership_ref=fixture.membership_ref,
            generation=active_membership_generation,
            state="active",
        )
        revoked_generation_ref = _generation_ref(
            run_ref=run_ref,
            membership_ref=fixture.membership_ref,
            generation=revoked_membership_generation,
            state="revoked",
        )
        active_membership_ref = _active_membership_evidence_ref(
            proof=proof,
            run_ref=run_ref,
            tenant_ref=tenant_ref,
            session_ref=active_lower_session_ref,
            generation_ref=active_generation_ref,
        )
        revocation_ref = _revocation_evidence_ref(
            proof=proof,
            run_ref=run_ref,
            active_evidence_ref=active_membership_ref,
            revoked_session_ref=revoked_lower_session_ref,
            revoked_generation_ref=revoked_generation_ref,
        )
        verification_ref = _revocation_verification_ref(
            proof=proof,
            run_ref=run_ref,
            revocation_evidence_ref=revocation_ref,
        )
        request_refs = {
            action_id: _request_intent_ref(
                action_id=action_id,
                run_ref=run_ref,
                candidate=candidate,
            )
            for action_id, candidate in action_values.items()
        }
        return cls(
            run_id=run_value,
            tenant_id=tenant_value,
            higher_persona_id=higher_persona,
            lower_persona_id=lower_persona,
            higher_session_id=higher_session,
            active_lower_session_id=active_session,
            revoked_lower_session_id=revoked_session,
            active_membership_generation=active_membership_generation,
            revoked_membership_generation=revoked_membership_generation,
            run_ref=run_ref,
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
            membership_ref=fixture.membership_ref,
            higher_role_ref=fixture.lattice.higher.role_ref,
            lower_role_ref=fixture.lattice.lower.role_ref,
            higher_session_ref=higher_session_ref,
            active_lower_session_ref=active_lower_session_ref,
            revoked_lower_session_ref=revoked_lower_session_ref,
            higher_role_evidence_ref=_role_evidence_ref(
                authority_context_ref=proof.authority_context_ref,
                run_ref=run_ref,
                tenant_ref=tenant_ref,
                tenant_ownership_ref=tenant_ownership_ref,
                world_binding_id=fixture.lattice.higher.world_binding_id,
                persona_ref=fixture.lattice.higher.persona_ref,
                role_ref=fixture.lattice.higher.role_ref,
            ),
            lower_role_evidence_ref=_role_evidence_ref(
                authority_context_ref=proof.authority_context_ref,
                run_ref=run_ref,
                tenant_ref=tenant_ref,
                tenant_ownership_ref=tenant_ownership_ref,
                world_binding_id=fixture.lattice.lower.world_binding_id,
                persona_ref=fixture.lattice.lower.persona_ref,
                role_ref=fixture.lattice.lower.role_ref,
            ),
            active_generation_ref=active_generation_ref,
            revoked_generation_ref=revoked_generation_ref,
            active_membership_evidence_ref=active_membership_ref,
            revocation_evidence_ref=revocation_ref,
            revocation_verification_ref=verification_ref,
            membership_observation_binding=membership_observation_binding,
            effect_observation_binding=effect_observation_binding,
            request_intent_refs=request_refs,
            runtime_actions=action_values,
        )

    def __post_init__(self) -> None:
        for field_name in (
            "run_id",
            "tenant_id",
            "higher_persona_id",
            "lower_persona_id",
            "higher_session_id",
            "active_lower_session_id",
            "revoked_lower_session_id",
        ):
            _runtime_value(getattr(self, field_name), field_name=field_name)
        for field_name in (
            "active_membership_generation",
            "revoked_membership_generation",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} is invalid")
        ref_prefixes = {
            "run_ref": "role_monotonicity_run",
            "tenant_ref": "owned_tenant",
            "tenant_ownership_ref": "ownership_proof",
            "membership_ref": "owned_membership",
            "higher_role_ref": "experiment_role",
            "lower_role_ref": "experiment_role",
            "higher_session_ref": "role_runtime_session",
            "active_lower_session_ref": "role_runtime_session",
            "revoked_lower_session_ref": "role_runtime_session",
            "higher_role_evidence_ref": "role_runtime_authority_evidence",
            "lower_role_evidence_ref": "role_runtime_authority_evidence",
            "active_generation_ref": "role_membership_generation",
            "revoked_generation_ref": "role_membership_generation",
            "active_membership_evidence_ref": "role_membership_active_evidence",
            "revocation_evidence_ref": "role_membership_revocation_evidence",
            "revocation_verification_ref": (
                "role_membership_revocation_verification"
            ),
        }
        if any(
            not _hash_ref(getattr(self, field_name), prefix)
            for field_name, prefix in ref_prefixes.items()
        ):
            raise ValueError("role runtime context contains an invalid reference")
        if not isinstance(
            self.membership_observation_binding,
            RoleMembershipObservationBinding,
        ):
            raise ValueError(
                "role runtime membership observation binding is invalid"
            )
        if not isinstance(
            self.effect_observation_binding,
            RoleProtectedEffectObservationBinding,
        ):
            raise ValueError(
                "role runtime effect observation binding is invalid"
            )
        if any(
            not isinstance(key, str)
            or not _hash_ref(value, "role_runtime_request_intent")
            for key, value in self.request_intent_refs.items()
        ):
            raise ValueError("role runtime request-intent references are invalid")
        if any(
            not isinstance(key, str) or not isinstance(value, CandidateAction)
            for key, value in self.runtime_actions.items()
        ):
            raise ValueError("role runtime actions are invalid")
        try:
            object.__setattr__(
                self,
                "request_intent_refs",
                dict(self.request_intent_refs),
            )
            object.__setattr__(
                self,
                "runtime_actions",
                copy.deepcopy(dict(self.runtime_actions)),
            )
        except Exception as exc:
            raise ValueError("role runtime context is not safely copyable") from exc


RoleRuntimeAuthorityValidator = Callable[
    [
        RoleMonotonicityExperimentProof,
        RoleMonotonicityAdmissionContract,
        RoleMonotonicityRuntimeContext,
    ],
    bool,
]


def _action_authority_payload(
    *,
    request_binding: ExperimentRuntimeActionBinding,
    request_intent_ref: str,
    run_ref: str,
    tenant_ref: str,
    role_binding_id: str,
    role_evidence_ref: str,
    session_ref: str,
    membership_ref: str,
    membership_state: str,
    membership_generation_ref: str,
    membership_evidence_ref: str,
    cleanup_lineage_ref: str,
) -> Dict[str, Any]:
    return {
        "request_binding": request_binding.to_dict(),
        "request_intent_ref": request_intent_ref,
        "run_ref": run_ref,
        "tenant_ref": tenant_ref,
        "role_binding_id": role_binding_id,
        "role_evidence_ref": role_evidence_ref,
        "session_ref": session_ref,
        "membership_ref": membership_ref,
        "membership_state": membership_state,
        "membership_generation_ref": membership_generation_ref,
        "membership_evidence_ref": membership_evidence_ref,
        "cleanup_lineage_ref": cleanup_lineage_ref,
    }


@dataclass(frozen=True)
class RoleRuntimeActionAuthorityBinding:
    binding_id: str
    request_binding: ExperimentRuntimeActionBinding
    request_intent_ref: str
    run_ref: str
    tenant_ref: str
    role_binding_id: str
    role_evidence_ref: str
    session_ref: str
    membership_ref: str
    membership_state: str
    membership_generation_ref: str
    membership_evidence_ref: str
    cleanup_lineage_ref: str

    @classmethod
    def build(
        cls,
        *,
        request_binding: ExperimentRuntimeActionBinding,
        request_intent_ref: str,
        run_ref: str,
        tenant_ref: str,
        role_binding_id: str,
        role_evidence_ref: str,
        session_ref: str,
        membership_ref: str,
        membership_state: str,
        membership_generation_ref: str,
        membership_evidence_ref: str,
        cleanup_lineage_ref: str,
    ) -> "RoleRuntimeActionAuthorityBinding":
        payload = _action_authority_payload(
            request_binding=request_binding,
            request_intent_ref=request_intent_ref,
            run_ref=run_ref,
            tenant_ref=tenant_ref,
            role_binding_id=role_binding_id,
            role_evidence_ref=role_evidence_ref,
            session_ref=session_ref,
            membership_ref=membership_ref,
            membership_state=membership_state,
            membership_generation_ref=membership_generation_ref,
            membership_evidence_ref=membership_evidence_ref,
            cleanup_lineage_ref=cleanup_lineage_ref,
        )
        return cls(
            binding_id=stable_hash("role_runtime_action_authority", payload),
            request_binding=request_binding,
            request_intent_ref=request_intent_ref,
            run_ref=run_ref,
            tenant_ref=tenant_ref,
            role_binding_id=role_binding_id,
            role_evidence_ref=role_evidence_ref,
            session_ref=session_ref,
            membership_ref=membership_ref,
            membership_state=membership_state,
            membership_generation_ref=membership_generation_ref,
            membership_evidence_ref=membership_evidence_ref,
            cleanup_lineage_ref=cleanup_lineage_ref,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.request_binding, ExperimentRuntimeActionBinding):
            raise TypeError(
                "request_binding must be an ExperimentRuntimeActionBinding"
            )
        payload = _action_authority_payload(
            request_binding=self.request_binding,
            request_intent_ref=self.request_intent_ref,
            run_ref=self.run_ref,
            tenant_ref=self.tenant_ref,
            role_binding_id=self.role_binding_id,
            role_evidence_ref=self.role_evidence_ref,
            session_ref=self.session_ref,
            membership_ref=self.membership_ref,
            membership_state=self.membership_state,
            membership_generation_ref=self.membership_generation_ref,
            membership_evidence_ref=self.membership_evidence_ref,
            cleanup_lineage_ref=self.cleanup_lineage_ref,
        )
        if (
            self.binding_id
            != stable_hash("role_runtime_action_authority", payload)
            or not _hash_ref(self.binding_id, "role_runtime_action_authority")
            or not _hash_ref(
                self.request_intent_ref,
                "role_runtime_request_intent",
            )
            or not _hash_ref(self.run_ref, "role_monotonicity_run")
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.role_binding_id, "role_lattice_binding")
            or not _hash_ref(
                self.role_evidence_ref,
                "role_runtime_authority_evidence",
            )
            or not _hash_ref(self.session_ref, "role_runtime_session")
            or not _hash_ref(self.membership_ref, "owned_membership")
            or self.membership_state not in _MEMBERSHIP_STATES
            or not _hash_ref(
                self.membership_generation_ref,
                "role_membership_generation",
            )
            or not _hash_ref(self.membership_evidence_ref)
            or not _hash_ref(
                self.membership_evidence_ref,
                {
                    "active": "role_membership_active_evidence",
                    "revoking": "role_membership_revocation_evidence",
                    "revoked": "role_membership_revocation_verification",
                }[self.membership_state],
            )
            or not _hash_ref(
                self.cleanup_lineage_ref,
                "role_membership_cleanup_lineage",
            )
        ):
            raise ValueError("role runtime action authority binding is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            **_action_authority_payload(
                request_binding=self.request_binding,
                request_intent_ref=self.request_intent_ref,
                run_ref=self.run_ref,
                tenant_ref=self.tenant_ref,
                role_binding_id=self.role_binding_id,
                role_evidence_ref=self.role_evidence_ref,
                session_ref=self.session_ref,
                membership_ref=self.membership_ref,
                membership_state=self.membership_state,
                membership_generation_ref=self.membership_generation_ref,
                membership_evidence_ref=self.membership_evidence_ref,
                cleanup_lineage_ref=self.cleanup_lineage_ref,
            ),
        }


def _binding_payload(
    *,
    proof_id: str,
    admission_id: str,
    fixture_id: str,
    oracle_id: str,
    target_ref: str,
    authority_context_ref: str,
    run_ref: str,
    tenant_ref: str,
    tenant_ownership_ref: str,
    active_generation_ref: str,
    revoked_generation_ref: str,
    membership_observation_binding: RoleMembershipObservationBinding,
    effect_observation_binding: RoleProtectedEffectObservationBinding,
    world_bindings: Sequence[ExperimentRuntimeWorldBinding],
    action_bindings: Sequence[RoleRuntimeActionAuthorityBinding],
    cleanup_lineage_ref: str,
    receipt_context_ref: str,
    receipt_lineage_ref: str,
    execution_policy_digest: str,
) -> Dict[str, Any]:
    return {
        "mode": ROLE_MONOTONICITY_REQUEST_BINDING_MODE,
        "workflow": ROLE_MONOTONICITY_WORKFLOW,
        "proof_id": proof_id,
        "admission_id": admission_id,
        "fixture_id": fixture_id,
        "oracle_id": oracle_id,
        "target_ref": target_ref,
        "authority_context_ref": authority_context_ref,
        "run_ref": run_ref,
        "tenant_ref": tenant_ref,
        "tenant_ownership_ref": tenant_ownership_ref,
        "active_generation_ref": active_generation_ref,
        "revoked_generation_ref": revoked_generation_ref,
        "membership_observation_binding": (
            membership_observation_binding.to_dict()
        ),
        "effect_observation_binding": effect_observation_binding.to_dict(),
        "world_bindings": [item.to_dict() for item in world_bindings],
        "action_bindings": [item.to_dict() for item in action_bindings],
        "cleanup_lineage_ref": cleanup_lineage_ref,
        "receipt_context_ref": receipt_context_ref,
        "receipt_lineage_ref": receipt_lineage_ref,
        "execution_policy_digest": execution_policy_digest,
        "signed_authority_revalidated": True,
        "owned_runtime_state_attested": True,
        "request_bindings_complete": True,
        "revocation_freshness_bound": True,
        "target_membership_observation_bound": True,
        "target_effect_observation_bound": True,
        "cleanup_lineage_bound": True,
        "receipt_lineage_bound": True,
        "policy_preflight_complete": True,
        "budget_preview_only": True,
        "remaining_execution_blockers": list(_REMAINING_EXECUTION_BLOCKERS),
        "target_requests_sent": 0,
        "budget_reserved": False,
        "durable_execution_receipt": False,
        "single_use_claim_available": False,
        "backend_dispatch_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class RoleMonotonicityRequestBindingContract:
    binding_id: str
    proof_id: str
    admission_id: str
    fixture_id: str
    oracle_id: str
    target_ref: str
    authority_context_ref: str
    run_ref: str
    tenant_ref: str
    tenant_ownership_ref: str
    active_generation_ref: str
    revoked_generation_ref: str
    membership_observation_binding: RoleMembershipObservationBinding
    effect_observation_binding: RoleProtectedEffectObservationBinding
    world_bindings: Tuple[ExperimentRuntimeWorldBinding, ...]
    action_bindings: Tuple[RoleRuntimeActionAuthorityBinding, ...]
    cleanup_lineage_ref: str
    receipt_context_ref: str
    receipt_lineage_ref: str
    execution_policy_digest: str
    mode: str = ROLE_MONOTONICITY_REQUEST_BINDING_MODE
    workflow: str = ROLE_MONOTONICITY_WORKFLOW
    signed_authority_revalidated: bool = True
    owned_runtime_state_attested: bool = True
    request_bindings_complete: bool = True
    revocation_freshness_bound: bool = True
    target_membership_observation_bound: bool = True
    target_effect_observation_bound: bool = True
    cleanup_lineage_bound: bool = True
    receipt_lineage_bound: bool = True
    policy_preflight_complete: bool = True
    budget_preview_only: bool = True
    remaining_execution_blockers: Tuple[str, ...] = _REMAINING_EXECUTION_BLOCKERS
    target_requests_sent: int = 0
    budget_reserved: bool = False
    durable_execution_receipt: bool = False
    single_use_claim_available: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        if any(
            not isinstance(item, ExperimentRuntimeWorldBinding)
            for item in self.world_bindings
        ) or any(
            not isinstance(item, RoleRuntimeActionAuthorityBinding)
            for item in self.action_bindings
        ):
            raise TypeError("role request binding contains invalid bindings")
        if not isinstance(
            self.membership_observation_binding,
            RoleMembershipObservationBinding,
        ):
            raise TypeError(
                "role request binding observation contract is invalid"
            )
        if not isinstance(
            self.effect_observation_binding,
            RoleProtectedEffectObservationBinding,
        ):
            raise TypeError(
                "role request binding effect observation contract is invalid"
            )
        ordered_actions = tuple(
            sorted(
                self.action_bindings,
                key=lambda item: item.request_binding.ordinal,
            )
        )
        world_by_slot = {item.slot: item for item in self.world_bindings}
        action_ordinals = tuple(
            item.request_binding.ordinal for item in ordered_actions
        )
        relations_valid = False
        if (
            action_ordinals == tuple(range(8))
            and set(world_by_slot) == {"high_role", "low_role"}
        ):
            high_world = world_by_slot["high_role"]
            low_world = world_by_slot["low_role"]
            high_actions = tuple(
                item
                for item in ordered_actions
                if item.request_binding.ordinal in {0, 1, 3, 4, 5, 7}
            )
            low_actions = tuple(
                item
                for item in ordered_actions
                if item.request_binding.ordinal in {2, 6}
            )
            active_actions = ordered_actions[:4]
            revoking_action = ordered_actions[4]
            revoked_actions = ordered_actions[5:]
            active_evidence = {
                item.membership_evidence_ref for item in active_actions
            }
            revoked_evidence = {
                item.membership_evidence_ref for item in revoked_actions
            }
            high_role_bindings = {
                item.role_binding_id for item in high_actions
            }
            low_role_bindings = {
                item.role_binding_id for item in low_actions
            }
            high_role_evidence = {
                item.role_evidence_ref for item in high_actions
            }
            low_role_evidence = {
                item.role_evidence_ref for item in low_actions
            }
            high_sessions = {item.session_ref for item in high_actions}
            low_sessions = {item.session_ref for item in low_actions}
            membership_refs = {
                item.membership_ref for item in ordered_actions
            }
            relations_valid = (
                tuple(item.membership_state for item in ordered_actions)
                == (
                    "active",
                    "active",
                    "active",
                    "active",
                    "revoking",
                    "revoked",
                    "revoked",
                    "revoked",
                )
                and all(
                    item.run_ref == self.run_ref
                    and item.tenant_ref == self.tenant_ref
                    and item.cleanup_lineage_ref == self.cleanup_lineage_ref
                    for item in ordered_actions
                )
                and all(
                    item.membership_generation_ref
                    == self.active_generation_ref
                    for item in active_actions
                )
                and all(
                    item.membership_generation_ref
                    == self.revoked_generation_ref
                    for item in ordered_actions[4:]
                )
                and len(active_evidence) == 1
                and _hash_ref(
                    next(iter(active_evidence)),
                    "role_membership_active_evidence",
                )
                and _hash_ref(
                    revoking_action.membership_evidence_ref,
                    "role_membership_revocation_evidence",
                )
                and len(revoked_evidence) == 1
                and _hash_ref(
                    next(iter(revoked_evidence)),
                    "role_membership_revocation_verification",
                )
                and len(membership_refs) == 1
                and len(high_role_bindings) == 1
                and len(low_role_bindings) == 1
                and high_role_bindings != low_role_bindings
                and len(high_role_evidence) == 1
                and len(low_role_evidence) == 1
                and high_role_evidence != low_role_evidence
                and len(high_sessions) == 1
                and len(low_sessions) == 2
                and high_sessions.isdisjoint(low_sessions)
                and all(
                    item.request_binding.world_binding_id
                    == high_world.manifest_binding_id
                    and item.request_binding.actor_identity_ref
                    == high_world.runtime_identity_ref
                    for item in high_actions
                )
                and all(
                    item.request_binding.world_binding_id
                    == low_world.manifest_binding_id
                    and item.request_binding.actor_identity_ref
                    == low_world.runtime_identity_ref
                    for item in low_actions
                )
                and len(
                    {
                        item.request_binding.action_id
                        for item in ordered_actions
                    }
                )
                == 8
                and len(
                    {item.request_intent_ref for item in ordered_actions}
                )
                == 8
            )
        expected_receipt_lineage_ref = stable_hash(
            "role_monotonicity_receipt_lineage",
            {
                "proof_id": self.proof_id,
                "admission_id": self.admission_id,
                "run_ref": self.run_ref,
                "receipt_context_ref": self.receipt_context_ref,
                "cleanup_lineage_ref": self.cleanup_lineage_ref,
                "action_binding_ids": [
                    item.binding_id for item in ordered_actions
                ],
                "durable_receipt_created": False,
            },
        )
        payload = _binding_payload(
            proof_id=self.proof_id,
            admission_id=self.admission_id,
            fixture_id=self.fixture_id,
            oracle_id=self.oracle_id,
            target_ref=self.target_ref,
            authority_context_ref=self.authority_context_ref,
            run_ref=self.run_ref,
            tenant_ref=self.tenant_ref,
            tenant_ownership_ref=self.tenant_ownership_ref,
            active_generation_ref=self.active_generation_ref,
            revoked_generation_ref=self.revoked_generation_ref,
            membership_observation_binding=(
                self.membership_observation_binding
            ),
            effect_observation_binding=self.effect_observation_binding,
            world_bindings=self.world_bindings,
            action_bindings=self.action_bindings,
            cleanup_lineage_ref=self.cleanup_lineage_ref,
            receipt_context_ref=self.receipt_context_ref,
            receipt_lineage_ref=self.receipt_lineage_ref,
            execution_policy_digest=self.execution_policy_digest,
        )
        if (
            self.binding_id != stable_hash("role_monotonicity_request_binding", payload)
            or not _hash_ref(
                self.binding_id,
                "role_monotonicity_request_binding",
            )
            or not _hash_ref(self.proof_id, "role_monotonicity_proof")
            or not _hash_ref(self.admission_id, "role_monotonicity_admission")
            or not _hash_ref(self.fixture_id, "owned_membership_fixture")
            or not _hash_ref(self.oracle_id, "role_monotonicity_oracle")
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(
                self.authority_context_ref,
                "experiment_authority_context",
            )
            or not _hash_ref(self.run_ref, "role_monotonicity_run")
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.tenant_ownership_ref, "ownership_proof")
            or not _hash_ref(
                self.active_generation_ref,
                "role_membership_generation",
            )
            or not _hash_ref(
                self.revoked_generation_ref,
                "role_membership_generation",
            )
            or len(ordered_actions) != 8
            or self.membership_observation_binding.setup_action_id
            != ordered_actions[0].request_binding.action_id
            or self.membership_observation_binding.revocation_verification_action_id
            != ordered_actions[5].request_binding.action_id
            or (
                self.effect_observation_binding.higher_baseline_action_id,
                self.effect_observation_binding.active_lower_probe_action_id,
                self.effect_observation_binding.active_effect_witness_action_id,
                self.effect_observation_binding.revoked_lower_probe_action_id,
                self.effect_observation_binding.revoked_effect_witness_action_id,
            )
            != tuple(
                ordered_actions[index].request_binding.action_id
                for index in (1, 2, 3, 6, 7)
            )
            or tuple(item.slot for item in self.world_bindings)
            != ("high_role", "low_role")
            or len({item.runtime_binding_id for item in self.world_bindings}) != 2
            or tuple(
                item.request_binding.ordinal for item in self.action_bindings
            )
            != tuple(range(8))
            or len({item.binding_id for item in self.action_bindings}) != 8
            or not relations_valid
            or not _hash_ref(
                self.cleanup_lineage_ref,
                "role_membership_cleanup_lineage",
            )
            or not _hash_ref(
                self.receipt_context_ref,
                "role_monotonicity_receipt_context",
            )
            or not _hash_ref(
                self.receipt_lineage_ref,
                "role_monotonicity_receipt_lineage",
            )
            or self.receipt_lineage_ref != expected_receipt_lineage_ref
            or not _hash_ref(self.execution_policy_digest, "sha256")
            or self.mode != ROLE_MONOTONICITY_REQUEST_BINDING_MODE
            or self.workflow != ROLE_MONOTONICITY_WORKFLOW
            or not self.signed_authority_revalidated
            or not self.owned_runtime_state_attested
            or not self.request_bindings_complete
            or not self.revocation_freshness_bound
            or not self.target_membership_observation_bound
            or not self.target_effect_observation_bound
            or not self.cleanup_lineage_bound
            or not self.receipt_lineage_bound
            or not self.policy_preflight_complete
            or not self.budget_preview_only
            or self.remaining_execution_blockers != _REMAINING_EXECUTION_BLOCKERS
            or self.target_requests_sent != 0
            or self.budget_reserved
            or self.durable_execution_receipt
            or self.single_use_claim_available
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("role monotonicity request binding is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "binding_id": self.binding_id,
            **_binding_payload(
                proof_id=self.proof_id,
                admission_id=self.admission_id,
                fixture_id=self.fixture_id,
                oracle_id=self.oracle_id,
                target_ref=self.target_ref,
                authority_context_ref=self.authority_context_ref,
                run_ref=self.run_ref,
                tenant_ref=self.tenant_ref,
                tenant_ownership_ref=self.tenant_ownership_ref,
                active_generation_ref=self.active_generation_ref,
                revoked_generation_ref=self.revoked_generation_ref,
                membership_observation_binding=(
                    self.membership_observation_binding
                ),
                effect_observation_binding=self.effect_observation_binding,
                world_bindings=self.world_bindings,
                action_bindings=self.action_bindings,
                cleanup_lineage_ref=self.cleanup_lineage_ref,
                receipt_context_ref=self.receipt_context_ref,
                receipt_lineage_ref=self.receipt_lineage_ref,
                execution_policy_digest=self.execution_policy_digest,
            ),
        }


def _proof_actions(
    proof: RoleMonotonicityExperimentProof,
) -> Tuple[ExperimentAction, ...]:
    return (
        proof.fixture.setup_action,
        proof.higher_baseline,
        proof.active_lower_probe,
        proof.active_effect_witness,
        proof.fixture.revocation_action,
        proof.fixture.revocation_verification_action,
        proof.revoked_lower_probe,
        proof.revoked_effect_witness,
    )


class RoleMonotonicityRequestBinder:
    """Bind an admitted R5C2 contract to exact requests without authority."""

    def bind(
        self,
        *,
        proof: RoleMonotonicityExperimentProof,
        admission: RoleMonotonicityAdmissionContract,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor,
        persona_vault: PersonaVault,
        runtime: RoleMonotonicityRuntimeContext,
        authority_validator: RoleRuntimeAuthorityValidator,
    ) -> RoleMonotonicityRequestBindingContract:
        if not isinstance(proof, RoleMonotonicityExperimentProof):
            raise TypeError("proof must be a RoleMonotonicityExperimentProof")
        if not isinstance(admission, RoleMonotonicityAdmissionContract):
            raise TypeError("admission must be a RoleMonotonicityAdmissionContract")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("executor must be a PolicyExecutor")
        if not isinstance(persona_vault, PersonaVault):
            raise TypeError("persona_vault must be a PersonaVault")
        if not isinstance(runtime, RoleMonotonicityRuntimeContext):
            raise TypeError("runtime must be a RoleMonotonicityRuntimeContext")
        if not callable(authority_validator):
            raise TypeError("authority_validator must be callable")
        try:
            authorization = copy.deepcopy(authorization)
            runtime = copy.deepcopy(runtime)
        except Exception as exc:
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_runtime_context_is_not_safely_copyable"
            ) from exc

        origin = _canonical_origin(target_origin)
        fixture = proof.fixture
        lattice = fixture.lattice
        signature = authorization.attestation_signature
        copied_authorization = copy.deepcopy(authorization)
        if (
            not signature
            or not hmac.compare_digest(signature, copied_authorization.sign())
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_authorization_is_unsigned_or_changed"
            )
        try:
            authorization.authorize_action(
                target_origin=origin,
                workflow=ROLE_MONOTONICITY_WORKFLOW,
            )
        except Exception as exc:
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_authorization_denied"
            ) from exc
        if proof.authority_context_ref != experiment_authority_context_ref(
            authorization,
            origin,
            (ROLE_MONOTONICITY_WORKFLOW,),
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_authority_context_mismatch"
            )
        if (
            admission.proof_id != proof.proof_id
            or admission.fixture_id != fixture.fixture_id
            or admission.oracle_id != proof.oracle.oracle_id
            or admission.target_ref != proof.target_ref
            or admission.authority_context_ref != proof.authority_context_ref
            or proof.target_ref
            != stable_hash("security_obligation_target", origin)
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_admission_identity_mismatch"
            )

        expected_run_ref = stable_hash("role_monotonicity_run", runtime.run_id)
        expected_tenant_ref = stable_hash("owned_tenant", runtime.tenant_id)
        expected_tenant_ownership_ref = role_tenant_ownership_ref(
            authorization,
            runtime.tenant_id,
        )
        if (
            runtime.run_ref != expected_run_ref
            or runtime.tenant_ref != expected_tenant_ref
            or runtime.tenant_ref != lattice.tenant_ref
            or runtime.tenant_ownership_ref != expected_tenant_ownership_ref
            or runtime.tenant_ownership_ref != lattice.tenant_ownership_ref
            or runtime.membership_ref != fixture.membership_ref
            or runtime.higher_role_ref != lattice.higher.role_ref
            or runtime.lower_role_ref != lattice.lower.role_ref
            or runtime.higher_role_ref == runtime.lower_role_ref
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_runtime_authority_identity_mismatch"
            )
        if (
            runtime.higher_persona_id == runtime.lower_persona_id
            or len(
                {
                    runtime.higher_session_id,
                    runtime.active_lower_session_id,
                    runtime.revoked_lower_session_id,
                }
            )
            != 3
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_runtime_actor_or_session_reuse"
            )
        if (
            runtime.revoked_membership_generation
            != runtime.active_membership_generation + 1
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_revocation_generation_is_stale"
            )

        expected_higher_session_ref = _session_ref(
            run_ref=expected_run_ref,
            persona_ref=lattice.higher.persona_ref,
            session_id=runtime.higher_session_id,
            lifecycle_state="experiment",
        )
        expected_active_session_ref = _session_ref(
            run_ref=expected_run_ref,
            persona_ref=lattice.lower.persona_ref,
            session_id=runtime.active_lower_session_id,
            lifecycle_state="active_membership",
        )
        expected_revoked_session_ref = _session_ref(
            run_ref=expected_run_ref,
            persona_ref=lattice.lower.persona_ref,
            session_id=runtime.revoked_lower_session_id,
            lifecycle_state="post_revocation",
        )
        expected_active_generation_ref = _generation_ref(
            run_ref=expected_run_ref,
            membership_ref=fixture.membership_ref,
            generation=runtime.active_membership_generation,
            state="active",
        )
        expected_revoked_generation_ref = _generation_ref(
            run_ref=expected_run_ref,
            membership_ref=fixture.membership_ref,
            generation=runtime.revoked_membership_generation,
            state="revoked",
        )
        expected_higher_role_evidence_ref = _role_evidence_ref(
            authority_context_ref=proof.authority_context_ref,
            run_ref=expected_run_ref,
            tenant_ref=expected_tenant_ref,
            tenant_ownership_ref=expected_tenant_ownership_ref,
            world_binding_id=lattice.higher.world_binding_id,
            persona_ref=lattice.higher.persona_ref,
            role_ref=lattice.higher.role_ref,
        )
        expected_lower_role_evidence_ref = _role_evidence_ref(
            authority_context_ref=proof.authority_context_ref,
            run_ref=expected_run_ref,
            tenant_ref=expected_tenant_ref,
            tenant_ownership_ref=expected_tenant_ownership_ref,
            world_binding_id=lattice.lower.world_binding_id,
            persona_ref=lattice.lower.persona_ref,
            role_ref=lattice.lower.role_ref,
        )
        expected_active_evidence_ref = _active_membership_evidence_ref(
            proof=proof,
            run_ref=expected_run_ref,
            tenant_ref=expected_tenant_ref,
            session_ref=expected_active_session_ref,
            generation_ref=expected_active_generation_ref,
        )
        expected_revocation_evidence_ref = _revocation_evidence_ref(
            proof=proof,
            run_ref=expected_run_ref,
            active_evidence_ref=expected_active_evidence_ref,
            revoked_session_ref=expected_revoked_session_ref,
            revoked_generation_ref=expected_revoked_generation_ref,
        )
        expected_verification_ref = _revocation_verification_ref(
            proof=proof,
            run_ref=expected_run_ref,
            revocation_evidence_ref=expected_revocation_evidence_ref,
        )
        if (
            runtime.higher_session_ref != expected_higher_session_ref
            or runtime.active_lower_session_ref != expected_active_session_ref
            or runtime.revoked_lower_session_ref != expected_revoked_session_ref
            or runtime.active_generation_ref != expected_active_generation_ref
            or runtime.revoked_generation_ref != expected_revoked_generation_ref
            or runtime.higher_role_evidence_ref
            != expected_higher_role_evidence_ref
            or runtime.lower_role_evidence_ref != expected_lower_role_evidence_ref
            or runtime.active_membership_evidence_ref
            != expected_active_evidence_ref
            or runtime.revocation_evidence_ref
            != expected_revocation_evidence_ref
            or runtime.revocation_verification_ref != expected_verification_ref
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_runtime_evidence_or_freshness_mismatch"
            )

        for persona_id in (
            runtime.higher_persona_id,
            runtime.lower_persona_id,
        ):
            persona = persona_vault.get_persona(persona_id)
            if persona is None or persona.persona_id != persona_id:
                raise RoleMonotonicityRequestBindingDenied(
                    "role_request_owned_persona_is_not_in_vault"
                )
        try:
            owned_state_valid = bool(
                authority_validator(
                    proof,
                    admission,
                    copy.deepcopy(runtime),
                )
            )
        except Exception:
            owned_state_valid = False
        if not owned_state_valid:
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_owned_runtime_state_attestation_denied"
            )

        manifest_by_id = {
            item.binding_id: item
            for item in lattice.world_manifest.bindings
        }
        runtime_world_ids = {
            lattice.higher.world_binding_id: runtime.higher_persona_id,
            lattice.lower.world_binding_id: runtime.lower_persona_id,
        }
        attestation_refs = {
            lattice.higher.world_binding_id: (
                lattice.higher.role_ref,
                lattice.tenant_ownership_ref,
                runtime.higher_role_evidence_ref,
            ),
            lattice.lower.world_binding_id: (
                lattice.lower.role_ref,
                lattice.tenant_ownership_ref,
                fixture.membership_ref,
                runtime.lower_role_evidence_ref,
                runtime.active_membership_evidence_ref,
                runtime.revocation_evidence_ref,
                runtime.revocation_verification_ref,
            ),
        }
        try:
            world_bindings = tuple(
                sorted(
                    (
                        ExperimentRuntimeWorldBinding.bind(
                            manifest_binding=manifest_by_id[binding_id],
                            runtime_identity=persona_id,
                            authorization=authorization,
                            attestation_refs=attestation_refs[binding_id],
                        )
                        for binding_id, persona_id in runtime_world_ids.items()
                    ),
                    key=lambda item: item.slot,
                )
            )
        except (ProofExperimentAdmissionDenied, ValueError) as exc:
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_runtime_world_binding_denied"
            ) from exc
        runtime_world_map = {
            binding_id: (persona_id, manifest_by_id[binding_id].kind)
            for binding_id, persona_id in runtime_world_ids.items()
        }

        policy = executor.policy
        if (
            policy.mode != ProofMode.BOUNTY_SAFE
            or policy.scope_filter is None
            or policy.ownership_registry is None
            or executor.provenance is None
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_requires_complete_bounty_safe_policy"
            )
        execution_policy_digest = policy.digest()
        if not _hash_ref(execution_policy_digest, "sha256"):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_execution_policy_digest_is_invalid"
            )

        actions = _proof_actions(proof)
        expected_action_ids = {item.action_id for item in actions}
        if (
            set(runtime.runtime_actions) != expected_action_ids
            or set(runtime.request_intent_refs) != expected_action_ids
        ):
            raise RoleMonotonicityRequestBindingDenied(
                "role_request_runtime_action_set_mismatch"
            )
        cleanup_lineage_ref = stable_hash(
            "role_membership_cleanup_lineage",
            {
                "proof_id": proof.proof_id,
                "fixture_id": fixture.fixture_id,
                "run_ref": runtime.run_ref,
                "cleanup": fixture.cleanup.to_dict(),
                "setup_action_id": fixture.setup_action.action_id,
                "revocation_action_id": fixture.revocation_action.action_id,
                "verification_action_id": (
                    fixture.revocation_verification_action.action_id
                ),
            },
        )

        active_action_ids = {
            fixture.setup_action.action_id,
            proof.higher_baseline.action_id,
            proof.active_lower_probe.action_id,
            proof.active_effect_witness.action_id,
        }
        revoked_action_ids = {
            fixture.revocation_verification_action.action_id,
            proof.revoked_lower_probe.action_id,
            proof.revoked_effect_witness.action_id,
        }
        action_bindings = []
        owned_personas = {
            runtime.higher_persona_id,
            runtime.lower_persona_id,
        }
        for action in actions:
            candidate = runtime.runtime_actions[action.action_id]
            if (
                candidate.proof_goal != action.operation_id
                or candidate.target_is_researcher_owned is not True
                or candidate.target_owner_persona_id not in owned_personas
            ):
                raise RoleMonotonicityRequestBindingDenied(
                    "role_request_action_intent_or_ownership_mismatch"
                )
            try:
                request_binding = ExperimentRuntimeActionBinding.bind(
                    action=action,
                    candidate=candidate,
                    target_origin=origin,
                    runtime_worlds=runtime_world_map,
                )
            except (ProofExperimentAdmissionDenied, ValueError) as exc:
                raise RoleMonotonicityRequestBindingDenied(
                    "role_request_runtime_action_binding_denied"
                ) from exc
            expected_request_intent_ref = _request_intent_ref(
                action_id=action.action_id,
                run_ref=runtime.run_ref,
                candidate=candidate,
            )
            if (
                runtime.request_intent_refs[action.action_id]
                != expected_request_intent_ref
            ):
                raise RoleMonotonicityRequestBindingDenied(
                    "role_request_material_substitution"
                )
            decision = policy.evaluate_action(candidate)
            if (
                not decision.allowed
                or decision.action_class != action.action_class.value
            ):
                raise RoleMonotonicityRequestBindingDenied(
                    f"role_request_policy_preflight_denied:{decision.reason}"
                )

            is_higher = action.world_binding_id == lattice.higher.world_binding_id
            role_binding = lattice.higher if is_higher else lattice.lower
            role_evidence_ref = (
                runtime.higher_role_evidence_ref
                if is_higher
                else runtime.lower_role_evidence_ref
            )
            if action.action_id == proof.active_lower_probe.action_id:
                session_ref = runtime.active_lower_session_ref
            elif action.action_id == proof.revoked_lower_probe.action_id:
                session_ref = runtime.revoked_lower_session_ref
            elif is_higher:
                session_ref = runtime.higher_session_ref
            else:
                raise RoleMonotonicityRequestBindingDenied(
                    "role_request_lower_session_assignment_is_invalid"
                )

            if action.action_id in active_action_ids:
                membership_state = "active"
                generation_ref = runtime.active_generation_ref
                membership_evidence_ref = (
                    runtime.active_membership_evidence_ref
                )
            elif action.action_id == fixture.revocation_action.action_id:
                membership_state = "revoking"
                generation_ref = runtime.revoked_generation_ref
                membership_evidence_ref = runtime.revocation_evidence_ref
            elif action.action_id in revoked_action_ids:
                membership_state = "revoked"
                generation_ref = runtime.revoked_generation_ref
                membership_evidence_ref = runtime.revocation_verification_ref
            else:
                raise RoleMonotonicityRequestBindingDenied(
                    "role_request_membership_state_assignment_is_invalid"
                )
            action_bindings.append(
                RoleRuntimeActionAuthorityBinding.build(
                    request_binding=request_binding,
                    request_intent_ref=expected_request_intent_ref,
                    run_ref=runtime.run_ref,
                    tenant_ref=runtime.tenant_ref,
                    role_binding_id=role_binding.binding_id,
                    role_evidence_ref=role_evidence_ref,
                    session_ref=session_ref,
                    membership_ref=fixture.membership_ref,
                    membership_state=membership_state,
                    membership_generation_ref=generation_ref,
                    membership_evidence_ref=membership_evidence_ref,
                    cleanup_lineage_ref=cleanup_lineage_ref,
                )
            )
        ordered_actions = tuple(
            sorted(
                action_bindings,
                key=lambda item: item.request_binding.ordinal,
            )
        )
        budget_sequence = tuple(
            (
                item.request_binding.action_class.value,
                item.request_binding.endpoint_key,
            )
            for item in ordered_actions
        )
        budget_allowed, budget_reason = policy.budget.preview_reservation(
            budget_sequence
        )
        if not budget_allowed:
            raise RoleMonotonicityRequestBindingDenied(
                f"role_request_budget_preview_denied:{budget_reason}"
            )

        receipt_context = redacted_receipt_context(
            target_origin=origin,
            envelope_id=authorization.envelope_id,
            source_persona_id=runtime.higher_persona_id,
            peer_persona_id=runtime.lower_persona_id,
        )
        receipt_context_ref = stable_hash(
            "role_monotonicity_receipt_context",
            receipt_context.to_dict(),
        )
        receipt_lineage_ref = stable_hash(
            "role_monotonicity_receipt_lineage",
            {
                "proof_id": proof.proof_id,
                "admission_id": admission.admission_id,
                "run_ref": runtime.run_ref,
                "receipt_context_ref": receipt_context_ref,
                "cleanup_lineage_ref": cleanup_lineage_ref,
                "action_binding_ids": [
                    item.binding_id for item in ordered_actions
                ],
                "durable_receipt_created": False,
            },
        )
        payload = _binding_payload(
            proof_id=proof.proof_id,
            admission_id=admission.admission_id,
            fixture_id=fixture.fixture_id,
            oracle_id=proof.oracle.oracle_id,
            target_ref=proof.target_ref,
            authority_context_ref=proof.authority_context_ref,
            run_ref=runtime.run_ref,
            tenant_ref=runtime.tenant_ref,
            tenant_ownership_ref=runtime.tenant_ownership_ref,
            active_generation_ref=runtime.active_generation_ref,
            revoked_generation_ref=runtime.revoked_generation_ref,
            membership_observation_binding=(
                runtime.membership_observation_binding
            ),
            effect_observation_binding=runtime.effect_observation_binding,
            world_bindings=world_bindings,
            action_bindings=ordered_actions,
            cleanup_lineage_ref=cleanup_lineage_ref,
            receipt_context_ref=receipt_context_ref,
            receipt_lineage_ref=receipt_lineage_ref,
            execution_policy_digest=execution_policy_digest,
        )
        return RoleMonotonicityRequestBindingContract(
            binding_id=stable_hash("role_monotonicity_request_binding", payload),
            proof_id=proof.proof_id,
            admission_id=admission.admission_id,
            fixture_id=fixture.fixture_id,
            oracle_id=proof.oracle.oracle_id,
            target_ref=proof.target_ref,
            authority_context_ref=proof.authority_context_ref,
            run_ref=runtime.run_ref,
            tenant_ref=runtime.tenant_ref,
            tenant_ownership_ref=runtime.tenant_ownership_ref,
            active_generation_ref=runtime.active_generation_ref,
            revoked_generation_ref=runtime.revoked_generation_ref,
            membership_observation_binding=(
                runtime.membership_observation_binding
            ),
            effect_observation_binding=runtime.effect_observation_binding,
            world_bindings=world_bindings,
            action_bindings=ordered_actions,
            cleanup_lineage_ref=cleanup_lineage_ref,
            receipt_context_ref=receipt_context_ref,
            receipt_lineage_ref=receipt_lineage_ref,
            execution_policy_digest=execution_policy_digest,
        )


__all__ = [
    "ROLE_MONOTONICITY_REQUEST_BINDING_MODE",
    "RoleMonotonicityRequestBinder",
    "RoleMonotonicityRequestBindingContract",
    "RoleMonotonicityRequestBindingDenied",
    "RoleMonotonicityRuntimeContext",
    "RoleMembershipObservationBinding",
    "RoleProtectedEffectObservationBinding",
    "RoleRuntimeActionAuthorityBinding",
    "RoleRuntimeAuthorityValidator",
    "role_tenant_ownership_ref",
]
