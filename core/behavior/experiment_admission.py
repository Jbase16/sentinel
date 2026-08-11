"""Atomic admission for one sealed generalized proof experiment.

This explicit-only boundary binds an R4A manifest to the current signed envelope,
runtime worlds, redacted request identities, bounty-safe policy, durable receipt, and
one complete ``ProofBudget`` reservation.  It never calls transport and grants no
finding or backend-dispatch authority.
"""

from __future__ import annotations

import copy
import hmac
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import CandidateAction, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
from core.safety.action_classifier import classify
from core.safety.proof_budget import ProofBudget, endpoint_key
from core.safety.proof_mode import ProofMode

from .experiment_sdk import (
    ExistingBackendKind,
    ExperimentAction,
    ExperimentActionClass,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ProofExperimentManifest,
)
from .normalize import stable_hash
from .receipts import (
    BehavioralReceiptContext,
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_receipt_context,
    request_fingerprint,
)


PROOF_EXPERIMENT_ADMISSION_ENV = "SENTINELFORGE_BEHAVIOR_PROOF_EXPERIMENT_ADMISSION"
PROOF_EXPERIMENT_ADMISSION_MODE = "behavioral_proof_experiment_admission_v1"

_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_BARE_HASH = re.compile(r"^[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_.:-]{0,191}$")
_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")
_METHOD = re.compile(r"^[A-Z]{3,12}$")
_BACKEND_WORKFLOWS = {
    ExistingBackendKind.OBJECT_AUTHORIZATION: (
        "behavioral_object_authorization",
    ),
    ExistingBackendKind.PREREQUISITE_OMISSION: (
        "behavioral_compiled_owned_sequence",
        "behavioral_state_machine_omission",
        "behavioral_state_machine_omission_confirmation",
    ),
}
_NON_MUTATING_CLASSES = frozenset(
    {
        ExperimentActionClass.SAFE_READ,
        ExperimentActionClass.AUTHZ_PROBE,
        ExperimentActionClass.CROSS_OBJECT_READ,
        ExperimentActionClass.CALLBACK_OBSERVATION,
    }
)
_OWNED_ACTOR_CLASSES = frozenset(
    {
        ExperimentActionClass.OWNED_CREATE,
        ExperimentActionClass.OWNED_UPDATE_LOW_RISK,
        ExperimentActionClass.PRIVILEGE_MUTATION,
        ExperimentActionClass.CROSS_OBJECT_READ,
    }
)

WorldAttestationValidator = Callable[
    [ExperimentWorldBinding, str, Tuple[str, ...]],
    bool,
]


class ProofExperimentAdmissionDenied(RuntimeError):
    """Admission failed before any target request could be sent."""


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ProofExperimentAdmissionDenied(
            "proof_experiment_target_origin_is_invalid"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _normalized_method(method: str) -> str:
    normalized = str(method or "").strip().upper()
    if _METHOD.fullmatch(normalized) is None:
        raise ValueError("experiment request method is invalid")
    return normalized


def _ordered_refs(values: Sequence[str], *, field_name: str) -> Tuple[str, ...]:
    raw = tuple(values)
    if any(not isinstance(item, str) for item in raw):
        raise ValueError(f"{field_name} must contain content-addressed references")
    ordered = tuple(sorted(set(raw)))
    if any(not _hash_ref(item) for item in ordered):
        raise ValueError(f"{field_name} must contain content-addressed references")
    return ordered


def experiment_endpoint_ref(method: str, url: str) -> str:
    """Bind an R4A endpoint reference to one method and normalized endpoint bucket."""

    normalized_method = _normalized_method(method)
    origin = _canonical_origin(url)
    key = endpoint_key(url)
    if not key or len(key) > 2048 or any(ord(char) < 32 for char in key):
        raise ValueError("experiment endpoint key is invalid")
    return stable_hash(
        "experiment_endpoint",
        {
            "method": normalized_method,
            "origin": origin,
            "endpoint_key": key,
        },
    )


def experiment_persona_ref(persona_id: str) -> str:
    value = str(persona_id or "").strip()
    if not value:
        raise ValueError("experiment persona id is required")
    return stable_hash("experiment_persona", value)


def experiment_ownership_ref(
    authorization: AuthorizationEnvelope,
    persona_id: str,
) -> str:
    if not isinstance(authorization, AuthorizationEnvelope):
        raise TypeError("authorization must be an AuthorizationEnvelope")
    return stable_hash(
        "ownership_proof",
        {
            "attestation_signature": authorization.attestation_signature,
            "persona_ref": experiment_persona_ref(persona_id),
        },
    )


def experiment_authority_context_ref(
    authorization: AuthorizationEnvelope,
    target_origin: str,
    required_workflows: Sequence[str],
) -> str:
    if not isinstance(authorization, AuthorizationEnvelope):
        raise TypeError("authorization must be an AuthorizationEnvelope")
    workflows = tuple(sorted(set(required_workflows)))
    if not workflows or any(_SEMANTIC.fullmatch(item) is None for item in workflows):
        raise ValueError("experiment authority workflows are invalid")
    return stable_hash(
        "experiment_authority_context",
        {
            "attestation_signature": authorization.attestation_signature,
            "target_origin": _canonical_origin(target_origin),
            "required_workflows": list(workflows),
        },
    )


@dataclass(frozen=True)
class ProofExperimentAdmissionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("proof experiment admission enabled must be a boolean")

    @classmethod
    def from_environment(cls) -> "ProofExperimentAdmissionConfig":
        enabled = (
            os.environ.get(PROOF_EXPERIMENT_ADMISSION_ENV, "").strip().lower()
            in _TRUE
        )
        return cls(enabled=enabled)


def _runtime_world_payload(
    *,
    manifest_binding_id: str,
    slot: str,
    kind: ExperimentWorldKind,
    world_ref: str,
    runtime_identity_ref: str,
    persona_ref: Optional[str],
    ownership_ref: Optional[str],
    attestation_refs: Sequence[str],
) -> Dict[str, Any]:
    return {
        "manifest_binding_id": manifest_binding_id,
        "slot": slot,
        "kind": kind.value,
        "world_ref": world_ref,
        "runtime_identity_ref": runtime_identity_ref,
        "persona_ref": persona_ref,
        "ownership_ref": ownership_ref,
        "attestation_refs": list(attestation_refs),
    }


@dataclass(frozen=True)
class ExperimentRuntimeWorldBinding:
    runtime_binding_id: str
    manifest_binding_id: str
    slot: str
    kind: ExperimentWorldKind
    world_ref: str
    runtime_identity_ref: str
    persona_ref: Optional[str]
    ownership_ref: Optional[str]
    attestation_refs: Tuple[str, ...]

    @classmethod
    def bind(
        cls,
        *,
        manifest_binding: ExperimentWorldBinding,
        runtime_identity: str,
        authorization: AuthorizationEnvelope,
        attestation_refs: Sequence[str] = (),
    ) -> "ExperimentRuntimeWorldBinding":
        if not isinstance(manifest_binding, ExperimentWorldBinding):
            raise TypeError("manifest_binding must be an ExperimentWorldBinding")
        value = str(runtime_identity or "").strip()
        if not value or len(value) > 256 or any(ord(char) < 32 for char in value):
            raise ValueError("experiment runtime world identity is invalid")
        expected_world = stable_hash("world", value)
        if manifest_binding.world_ref != expected_world:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_runtime_world_ref_mismatch"
            )
        if manifest_binding.kind is ExperimentWorldKind.OWNED_ACCOUNT:
            expected_persona = experiment_persona_ref(value)
            expected_ownership = experiment_ownership_ref(authorization, value)
            if (
                manifest_binding.persona_ref != expected_persona
                or manifest_binding.ownership_ref != expected_ownership
            ):
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_owned_world_authority_mismatch"
                )
        refs = _ordered_refs(
            attestation_refs,
            field_name="runtime world attestation_refs",
        )
        required_refs = {
            item
            for item in (
                manifest_binding.role_ref,
                manifest_binding.lifecycle_ref,
                manifest_binding.callback_ref,
            )
            if item is not None
        }
        if not required_refs <= set(refs):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_runtime_world_attestation_is_incomplete"
            )
        payload = _runtime_world_payload(
            manifest_binding_id=manifest_binding.binding_id,
            slot=manifest_binding.slot,
            kind=manifest_binding.kind,
            world_ref=manifest_binding.world_ref,
            runtime_identity_ref=stable_hash("experiment_runtime_identity", value),
            persona_ref=manifest_binding.persona_ref,
            ownership_ref=manifest_binding.ownership_ref,
            attestation_refs=refs,
        )
        return cls(
            runtime_binding_id=stable_hash("experiment_runtime_world_binding", payload),
            manifest_binding_id=manifest_binding.binding_id,
            slot=manifest_binding.slot,
            kind=manifest_binding.kind,
            world_ref=manifest_binding.world_ref,
            runtime_identity_ref=payload["runtime_identity_ref"],
            persona_ref=manifest_binding.persona_ref,
            ownership_ref=manifest_binding.ownership_ref,
            attestation_refs=refs,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ExperimentWorldKind):
            raise ValueError("runtime experiment world kind is invalid")
        payload = _runtime_world_payload(
            manifest_binding_id=self.manifest_binding_id,
            slot=self.slot,
            kind=self.kind,
            world_ref=self.world_ref,
            runtime_identity_ref=self.runtime_identity_ref,
            persona_ref=self.persona_ref,
            ownership_ref=self.ownership_ref,
            attestation_refs=self.attestation_refs,
        )
        if (
            self.runtime_binding_id
            != stable_hash("experiment_runtime_world_binding", payload)
            or not _hash_ref(
                self.manifest_binding_id,
                "experiment_world_binding",
            )
            or _SEMANTIC.fullmatch(self.slot) is None
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(
                self.runtime_identity_ref,
                "experiment_runtime_identity",
            )
            or (
                self.persona_ref is not None
                and not _hash_ref(self.persona_ref, "experiment_persona")
            )
            or (
                self.ownership_ref is not None
                and not _hash_ref(self.ownership_ref, "ownership_proof")
            )
            or self.attestation_refs
            != tuple(sorted(set(self.attestation_refs)))
            or any(not _hash_ref(item) for item in self.attestation_refs)
        ):
            raise ValueError("runtime experiment world binding contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runtime_binding_id": self.runtime_binding_id,
            **_runtime_world_payload(
                manifest_binding_id=self.manifest_binding_id,
                slot=self.slot,
                kind=self.kind,
                world_ref=self.world_ref,
                runtime_identity_ref=self.runtime_identity_ref,
                persona_ref=self.persona_ref,
                ownership_ref=self.ownership_ref,
                attestation_refs=self.attestation_refs,
            ),
        }


def _request_material(candidate: CandidateAction) -> Dict[str, Any]:
    return {
        "method": _normalized_method(candidate.method),
        "url": str(candidate.url),
        "body": candidate.body,
        "hint": candidate.hint,
        "actor_persona_id": candidate.actor_persona_id,
        "target_owner_persona_id": candidate.target_owner_persona_id,
        "target_is_researcher_owned": candidate.target_is_researcher_owned,
        "expected_side_effect": candidate.expected_side_effect,
        "proof_goal": candidate.proof_goal,
    }


def _runtime_action_payload(
    *,
    action_id: str,
    ordinal: int,
    phase: ExperimentPhase,
    action_class: ExperimentActionClass,
    endpoint_ref: str,
    world_binding_id: Optional[str],
    request_units: int,
    method: str,
    endpoint_key_value: str,
    request_material_fingerprint: str,
    actor_identity_ref: Optional[str],
    target_owner_identity_ref: Optional[str],
) -> Dict[str, Any]:
    return {
        "action_id": action_id,
        "ordinal": ordinal,
        "phase": phase.value,
        "action_class": action_class.value,
        "endpoint_ref": endpoint_ref,
        "method": method,
        "endpoint_key": endpoint_key_value,
        "request_material_fingerprint": request_material_fingerprint,
        "world_binding_id": world_binding_id,
        "actor_identity_ref": actor_identity_ref,
        "target_owner_identity_ref": target_owner_identity_ref,
        "request_units": request_units,
    }


@dataclass(frozen=True)
class ExperimentRuntimeActionBinding:
    runtime_action_binding_id: str
    action_id: str
    ordinal: int
    phase: ExperimentPhase
    action_class: ExperimentActionClass
    endpoint_ref: str
    method: str
    endpoint_key: str
    request_material_fingerprint: str
    world_binding_id: Optional[str]
    actor_identity_ref: Optional[str]
    target_owner_identity_ref: Optional[str]
    request_units: int = 1

    @classmethod
    def bind(
        cls,
        *,
        action: ExperimentAction,
        candidate: CandidateAction,
        target_origin: str,
        runtime_worlds: Mapping[
            str,
            Tuple[str, ExperimentWorldKind],
        ],
    ) -> "ExperimentRuntimeActionBinding":
        if not isinstance(action, ExperimentAction):
            raise TypeError("action must be an ExperimentAction")
        if not isinstance(candidate, CandidateAction):
            raise TypeError("candidate must be a CandidateAction")
        if candidate.budget_reservation_id is not None:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_action_already_has_budget_authority"
            )
        method = _normalized_method(candidate.method)
        if _canonical_origin(candidate.url) != target_origin:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_action_origin_mismatch"
            )
        if candidate.hint != action.action_class.value:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_action_intent_mismatch"
            )
        actual_class = classify(
            method,
            candidate.url,
            candidate.body,
            hint=candidate.hint,
        )
        if actual_class != action.action_class.value:
            raise ProofExperimentAdmissionDenied(
                f"proof_experiment_structural_classification_mismatch:{actual_class}"
            )
        if experiment_endpoint_ref(method, candidate.url) != action.endpoint_ref:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_action_endpoint_mismatch"
            )
        runtime_world = (
            runtime_worlds.get(action.world_binding_id)
            if action.world_binding_id is not None
            else None
        )
        expected_actor = runtime_world[0] if runtime_world is not None else None
        actor_world_kind = runtime_world[1] if runtime_world is not None else None
        if candidate.actor_persona_id != expected_actor:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_action_actor_world_mismatch"
            )
        if (
            action.action_class in _OWNED_ACTOR_CLASSES
            and actor_world_kind is not ExperimentWorldKind.OWNED_ACCOUNT
        ):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_action_requires_owned_actor_world"
            )
        if (
            action.action_class is ExperimentActionClass.CALLBACK_OBSERVATION
            and actor_world_kind is not ExperimentWorldKind.CALLBACK_RECEIVER
        ):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_callback_action_requires_callback_world"
            )
        owned_runtime_ids = {
            runtime_id
            for runtime_id, kind in runtime_worlds.values()
            if kind is ExperimentWorldKind.OWNED_ACCOUNT
        }
        if action.action_class is ExperimentActionClass.CROSS_OBJECT_READ:
            if (
                candidate.target_is_researcher_owned is not True
                or candidate.target_owner_persona_id not in owned_runtime_ids
                or candidate.target_owner_persona_id == candidate.actor_persona_id
            ):
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_cross_object_ownership_mismatch"
                )
        expected_effect = str(candidate.expected_side_effect or "").strip()
        if action.action_class in _NON_MUTATING_CLASSES:
            if expected_effect != "none":
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_non_mutating_action_claims_side_effect"
                )
        elif not expected_effect or expected_effect == "none":
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_mutating_action_lacks_side_effect_intent"
            )
        if (
            action.phase is ExperimentPhase.CLEANUP
            and expected_effect != "cleanup_owned_test_object"
        ):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_cleanup_intent_mismatch"
            )
        proof_goal = str(candidate.proof_goal or "").strip()
        if not proof_goal or len(proof_goal) > 192:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_action_proof_goal_is_missing"
            )
        try:
            material_fingerprint = request_fingerprint(_request_material(candidate))
        except (TypeError, ValueError) as exc:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_request_identity_is_not_deterministic"
            ) from exc
        key = endpoint_key(candidate.url)
        actor_ref = (
            stable_hash("experiment_runtime_identity", expected_actor)
            if expected_actor is not None
            else None
        )
        owner_ref = (
            stable_hash(
                "experiment_runtime_identity",
                candidate.target_owner_persona_id,
            )
            if candidate.target_owner_persona_id is not None
            else None
        )
        payload = _runtime_action_payload(
            action_id=action.action_id,
            ordinal=action.ordinal,
            phase=action.phase,
            action_class=action.action_class,
            endpoint_ref=action.endpoint_ref,
            world_binding_id=action.world_binding_id,
            request_units=action.request_units,
            method=method,
            endpoint_key_value=key,
            request_material_fingerprint=material_fingerprint,
            actor_identity_ref=actor_ref,
            target_owner_identity_ref=owner_ref,
        )
        return cls(
            runtime_action_binding_id=stable_hash(
                "experiment_runtime_action_binding",
                payload,
            ),
            action_id=action.action_id,
            ordinal=action.ordinal,
            phase=action.phase,
            action_class=action.action_class,
            endpoint_ref=action.endpoint_ref,
            method=method,
            endpoint_key=key,
            request_material_fingerprint=material_fingerprint,
            world_binding_id=action.world_binding_id,
            actor_identity_ref=actor_ref,
            target_owner_identity_ref=owner_ref,
        )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.phase, ExperimentPhase)
            or not isinstance(self.action_class, ExperimentActionClass)
        ):
            raise ValueError("runtime experiment action enums are invalid")
        payload = _runtime_action_payload(
            action_id=self.action_id,
            ordinal=self.ordinal,
            phase=self.phase,
            action_class=self.action_class,
            endpoint_ref=self.endpoint_ref,
            world_binding_id=self.world_binding_id,
            request_units=self.request_units,
            method=self.method,
            endpoint_key_value=self.endpoint_key,
            request_material_fingerprint=self.request_material_fingerprint,
            actor_identity_ref=self.actor_identity_ref,
            target_owner_identity_ref=self.target_owner_identity_ref,
        )
        if (
            self.runtime_action_binding_id
            != stable_hash("experiment_runtime_action_binding", payload)
            or not _hash_ref(self.action_id, "proof_experiment_action")
            or isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or self.ordinal < 0
            or not _hash_ref(self.endpoint_ref, "experiment_endpoint")
            or _METHOD.fullmatch(self.method) is None
            or not self.endpoint_key
            or len(self.endpoint_key) > 2048
            or _BARE_HASH.fullmatch(self.request_material_fingerprint) is None
            or (
                self.world_binding_id is not None
                and not _hash_ref(
                    self.world_binding_id,
                    "experiment_world_binding",
                )
            )
            or any(
                item is not None
                and not _hash_ref(item, "experiment_runtime_identity")
                for item in (
                    self.actor_identity_ref,
                    self.target_owner_identity_ref,
                )
            )
            or self.request_units != 1
        ):
            raise ValueError("runtime experiment action binding contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runtime_action_binding_id": self.runtime_action_binding_id,
            "action_id": self.action_id,
            "ordinal": self.ordinal,
            "phase": self.phase.value,
            "action_class": self.action_class.value,
            "endpoint_ref": self.endpoint_ref,
            "method": self.method,
            "endpoint_key_ref": stable_hash(
                "experiment_endpoint_key",
                self.endpoint_key,
            ),
            "request_material_fingerprint": self.request_material_fingerprint,
            "world_binding_id": self.world_binding_id,
            "actor_identity_ref": self.actor_identity_ref,
            "target_owner_identity_ref": self.target_owner_identity_ref,
            "request_units": self.request_units,
        }


def _admission_payload(
    *,
    manifest_id: str,
    receipt_id: str,
    receipt_fingerprint: str,
    authority_context_ref: str,
    execution_policy_digest: str,
    world_binding_ids: Sequence[str],
    action_binding_ids: Sequence[str],
    budget_id: str,
    total_request_units: int,
    required_workflows: Sequence[str],
    backend: ExistingBackendKind,
) -> Dict[str, Any]:
    return {
        "mode": PROOF_EXPERIMENT_ADMISSION_MODE,
        "manifest_id": manifest_id,
        "receipt_id": receipt_id,
        "receipt_fingerprint": receipt_fingerprint,
        "authority_context_ref": authority_context_ref,
        "execution_policy_digest": execution_policy_digest,
        "world_binding_ids": list(world_binding_ids),
        "action_binding_ids": list(action_binding_ids),
        "budget_id": budget_id,
        "total_request_units": total_request_units,
        "required_workflows": list(required_workflows),
        "backend": backend.value,
        "atomic_budget_reserved": True,
        "single_use_claim_available": True,
        "backend_dispatch_authority": False,
        "ambient_authority": False,
        "finding_authority": False,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class ProofExperimentAdmissionContract:
    admission_id: str
    manifest_id: str
    receipt_id: str
    receipt_fingerprint: str
    authority_context_ref: str
    execution_policy_digest: str
    world_binding_ids: Tuple[str, ...]
    action_binding_ids: Tuple[str, ...]
    budget_id: str
    total_request_units: int
    required_workflows: Tuple[str, ...]
    backend: ExistingBackendKind
    mode: str = PROOF_EXPERIMENT_ADMISSION_MODE
    atomic_budget_reserved: bool = True
    single_use_claim_available: bool = True
    backend_dispatch_authority: bool = False
    ambient_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.backend, ExistingBackendKind):
            raise ValueError("proof experiment admission backend is invalid")
        payload = _admission_payload(
            manifest_id=self.manifest_id,
            receipt_id=self.receipt_id,
            receipt_fingerprint=self.receipt_fingerprint,
            authority_context_ref=self.authority_context_ref,
            execution_policy_digest=self.execution_policy_digest,
            world_binding_ids=self.world_binding_ids,
            action_binding_ids=self.action_binding_ids,
            budget_id=self.budget_id,
            total_request_units=self.total_request_units,
            required_workflows=self.required_workflows,
            backend=self.backend,
        )
        if (
            self.admission_id != stable_hash("proof_experiment_admission", payload)
            or self.mode != PROOF_EXPERIMENT_ADMISSION_MODE
            or not _hash_ref(self.manifest_id, "proof_experiment_manifest")
            or _RECEIPT_ID.fullmatch(self.receipt_id) is None
            or _BARE_HASH.fullmatch(self.receipt_fingerprint) is None
            or self.receipt_id != f"behavioral-{self.receipt_fingerprint}"
            or not _hash_ref(
                self.authority_context_ref,
                "experiment_authority_context",
            )
            or not _hash_ref(self.execution_policy_digest, "sha256")
            or self.world_binding_ids
            != tuple(sorted(set(self.world_binding_ids)))
            or any(
                not _hash_ref(item, "experiment_runtime_world_binding")
                for item in self.world_binding_ids
            )
            or not self.action_binding_ids
            or len(set(self.action_binding_ids)) != len(self.action_binding_ids)
            or any(
                not _hash_ref(item, "experiment_runtime_action_binding")
                for item in self.action_binding_ids
            )
            or not _hash_ref(self.budget_id, "proof_experiment_budget")
            or isinstance(self.total_request_units, bool)
            or not isinstance(self.total_request_units, int)
            or self.total_request_units != len(self.action_binding_ids)
            or self.required_workflows != _BACKEND_WORKFLOWS[self.backend]
            or not self.atomic_budget_reserved
            or not self.single_use_claim_available
            or self.backend_dispatch_authority
            or self.ambient_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
        ):
            raise ValueError("proof experiment admission contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "admission_id": self.admission_id,
            **_admission_payload(
                manifest_id=self.manifest_id,
                receipt_id=self.receipt_id,
                receipt_fingerprint=self.receipt_fingerprint,
                authority_context_ref=self.authority_context_ref,
                execution_policy_digest=self.execution_policy_digest,
                world_binding_ids=self.world_binding_ids,
                action_binding_ids=self.action_binding_ids,
                budget_id=self.budget_id,
                total_request_units=self.total_request_units,
                required_workflows=self.required_workflows,
                backend=self.backend,
            ),
        }


@dataclass(frozen=True)
class _AdmissionPreflight:
    fingerprint: str
    context: BehavioralReceiptContext
    descriptor: Dict[str, Any] = field(repr=False, compare=False)
    world_bindings: Tuple[ExperimentRuntimeWorldBinding, ...]
    action_bindings: Tuple[ExperimentRuntimeActionBinding, ...]
    reserved_actions: Tuple[Tuple[str, str], ...]
    execution_policy_digest: str
    required_workflows: Tuple[str, ...]


class _AdmissionResources:
    def __init__(
        self,
        *,
        budget: ProofBudget,
        budget_reservation_id: str,
        receipt_store: BehavioralReceiptStore,
        fingerprint: str,
        receipt_reservation_token: str,
    ) -> None:
        self.budget = budget
        self.budget_reservation_id = budget_reservation_id
        self.receipt_store = receipt_store
        self.fingerprint = fingerprint
        self.receipt_reservation_token = receipt_reservation_token
        self._lock = threading.RLock()
        self._state = "active"

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def claim(self) -> None:
        with self._lock:
            if self._state != "active":
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_admission_is_not_claimable"
                )
            self._state = "claimed"

    def abort(self, *, expected_state: str, reason: str) -> int:
        if _SEMANTIC.fullmatch(reason) is None:
            raise ValueError("proof experiment admission abort reason is invalid")
        with self._lock:
            if self._state != expected_state:
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_admission_cannot_be_aborted_from_this_state"
                )
            receipt_error: Optional[BaseException] = None
            try:
                self.receipt_store.abort(
                    self.fingerprint,
                    reservation_token=self.receipt_reservation_token,
                    reason=reason,
                )
            except (OSError, ReceiptStoreError) as exc:
                receipt_error = exc
            released = self.budget.release_reservation(
                self.budget_reservation_id
            )
            self._state = "aborted"
            if receipt_error is not None:
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_admission_budget_released_but_receipt_abort_failed"
                ) from receipt_error
            return released


class ProofExperimentAdmissionClaim:
    """Single-use R4C handoff; contains no method that can send target traffic."""

    def __init__(
        self,
        contract: ProofExperimentAdmissionContract,
        resources: _AdmissionResources,
    ) -> None:
        self.contract = contract
        self._resources = resources

    @property
    def state(self) -> str:
        return self._resources.state

    @property
    def reserved_units(self) -> int:
        return self._resources.budget.reservation_remaining(
            self._resources.budget_reservation_id
        )

    def _runtime_credentials(
        self,
        *,
        manifest_id: str,
        execution_policy_digest: str,
    ) -> Tuple[str, str]:
        """Private R4C seam; bind secret handles to the admitted immutable identity."""

        if (
            self.state != "claimed"
            or manifest_id != self.contract.manifest_id
            or execution_policy_digest != self.contract.execution_policy_digest
        ):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_claim_identity_mismatch"
            )
        return (
            self._resources.budget_reservation_id,
            self._resources.receipt_reservation_token,
        )

    def abort(self, reason: str = "proof_experiment_claim_aborted") -> int:
        return self._resources.abort(expected_state="claimed", reason=reason)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "admission": self.contract.to_dict(),
            "claim_state": self.state,
            "backend_dispatch_authority": False,
            "target_requests_sent": 0,
        }


class ProofExperimentAdmissionLease:
    """Active atomic reservation that can be claimed or safely aborted once."""

    def __init__(
        self,
        contract: ProofExperimentAdmissionContract,
        resources: _AdmissionResources,
    ) -> None:
        self.contract = contract
        self._resources = resources

    @property
    def state(self) -> str:
        return self._resources.state

    def claim(self) -> ProofExperimentAdmissionClaim:
        self._resources.claim()
        return ProofExperimentAdmissionClaim(self.contract, self._resources)

    def abort(self, reason: str = "proof_experiment_admission_aborted") -> int:
        return self._resources.abort(expected_state="active", reason=reason)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "admission": self.contract.to_dict(),
            "lease_state": self.state,
            "backend_dispatch_authority": False,
            "target_requests_sent": 0,
        }


class GeneralizedExperimentAdmission:
    """Validate and atomically reserve one exact R4A experiment, without dispatch."""

    def __init__(
        self,
        *,
        manifest: ProofExperimentManifest,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor,
        runtime_actions: Mapping[str, CandidateAction],
        runtime_world_ids: Mapping[str, str],
        persona_vault: PersonaVault,
        world_attestation_refs: Optional[Mapping[str, Sequence[str]]] = None,
        world_attestation_validator: Optional[WorldAttestationValidator] = None,
        config: Optional[ProofExperimentAdmissionConfig] = None,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        if not isinstance(manifest, ProofExperimentManifest):
            raise TypeError("manifest must be a ProofExperimentManifest")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("executor must be a PolicyExecutor")
        if not isinstance(persona_vault, PersonaVault):
            raise TypeError("persona_vault must be a PersonaVault")
        self.manifest = manifest
        self.target_origin = _canonical_origin(target_origin)
        self.authorization = authorization
        self.executor = executor
        try:
            self.runtime_actions = copy.deepcopy(dict(runtime_actions))
        except Exception as exc:
            raise TypeError("runtime actions must be safely copyable") from exc
        self.runtime_world_ids = {
            str(key): str(value) for key, value in runtime_world_ids.items()
        }
        self.persona_vault = persona_vault
        self.world_attestation_refs = {
            str(key): tuple(value)
            for key, value in (world_attestation_refs or {}).items()
        }
        self.world_attestation_validator = world_attestation_validator
        self.config = config or ProofExperimentAdmissionConfig.from_environment()
        self.receipt_store = receipt_store or BehavioralReceiptStore()

    def _validate_authority(self) -> Tuple[str, ...]:
        if not self.config.enabled:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_admission_is_disabled"
            )
        signature = self.authorization.attestation_signature
        if not signature:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_authorization_is_unsigned"
            )
        copied = copy.deepcopy(self.authorization)
        if not hmac.compare_digest(signature, copied.sign()):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_authorization_signature_mismatch"
            )
        if self.manifest.target_ref != stable_hash(
            "security_obligation_target",
            self.target_origin,
        ):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_target_ref_mismatch"
            )
        required_workflows = tuple(
            self.manifest.world_manifest.requirement.required_workflows
        )
        expected_workflows = _BACKEND_WORKFLOWS[self.manifest.backend.backend]
        if required_workflows != expected_workflows:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_backend_workflow_contract_mismatch"
            )
        for workflow in required_workflows:
            try:
                self.authorization.authorize_action(
                    target_origin=self.target_origin,
                    workflow=workflow,
                )
            except Exception as exc:
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_authorization_denied"
                ) from exc
        expected_context_ref = experiment_authority_context_ref(
            self.authorization,
            self.target_origin,
            required_workflows,
        )
        if self.manifest.authority_context_ref != expected_context_ref:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_authority_context_mismatch"
            )
        return required_workflows

    def _validate_policy(self) -> str:
        policy = self.executor.policy
        if (
            policy.mode != ProofMode.BOUNTY_SAFE
            or policy.scope_filter is None
            or policy.ownership_registry is None
            or self.executor.provenance is None
        ):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_requires_complete_bounty_safe_policy"
            )
        digest = policy.digest()
        if not _hash_ref(digest, "sha256"):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_execution_policy_digest_is_invalid"
            )
        return digest

    def _bind_worlds(
        self,
    ) -> Tuple[
        Tuple[ExperimentRuntimeWorldBinding, ...],
        Dict[str, Tuple[str, ExperimentWorldKind]],
    ]:
        manifest_bindings = self.manifest.world_manifest.bindings
        expected_ids = {item.binding_id for item in manifest_bindings}
        if set(self.runtime_world_ids) != expected_ids:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_runtime_world_set_mismatch"
            )
        if set(self.world_attestation_refs) - expected_ids:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_runtime_world_attestation_has_unknown_binding"
            )
        owned_count = sum(
            item.kind is ExperimentWorldKind.OWNED_ACCOUNT
            for item in manifest_bindings
        )
        if owned_count > self.authorization.max_accounts_per_service:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_owned_world_limit_exceeded"
            )
        values = []
        seen_runtime_ids = set()
        by_binding_id: Dict[str, Tuple[str, ExperimentWorldKind]] = {}
        for binding in manifest_bindings:
            runtime_id = self.runtime_world_ids[binding.binding_id]
            if runtime_id in seen_runtime_ids:
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_runtime_worlds_are_not_distinct"
                )
            seen_runtime_ids.add(runtime_id)
            refs = self.world_attestation_refs.get(binding.binding_id, ())
            special_attestation = (
                binding.kind is not ExperimentWorldKind.OWNED_ACCOUNT
                or binding.role_ref is not None
                or binding.lifecycle_ref is not None
            )
            if binding.kind is ExperimentWorldKind.OWNED_ACCOUNT:
                persona = self.persona_vault.get_persona(runtime_id)
                if persona is None or persona.persona_id != runtime_id:
                    raise ProofExperimentAdmissionDenied(
                        "proof_experiment_owned_persona_is_not_in_vault"
                    )
            if special_attestation:
                validator = self.world_attestation_validator
                try:
                    valid = bool(validator and validator(binding, runtime_id, tuple(refs)))
                except Exception:
                    valid = False
                if not valid:
                    raise ProofExperimentAdmissionDenied(
                        "proof_experiment_runtime_world_attestation_denied"
                    )
            runtime_binding = ExperimentRuntimeWorldBinding.bind(
                manifest_binding=binding,
                runtime_identity=runtime_id,
                authorization=self.authorization,
                attestation_refs=refs,
            )
            values.append(runtime_binding)
            by_binding_id[binding.binding_id] = (runtime_id, binding.kind)
        return tuple(sorted(values, key=lambda item: item.slot)), by_binding_id

    def _bind_actions(
        self,
        runtime_worlds: Mapping[
            str,
            Tuple[str, ExperimentWorldKind],
        ],
    ) -> Tuple[ExperimentRuntimeActionBinding, ...]:
        expected_ids = {item.action_id for item in self.manifest.actions}
        if set(self.runtime_actions) != expected_ids:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_runtime_action_set_mismatch"
            )
        values = []
        for action in self.manifest.actions:
            candidate = self.runtime_actions[action.action_id]
            binding = ExperimentRuntimeActionBinding.bind(
                action=action,
                candidate=candidate,
                target_origin=self.target_origin,
                runtime_worlds=runtime_worlds,
            )
            if action.action_class is ExperimentActionClass.CROSS_OBJECT_READ:
                registry = self.executor.policy.ownership_registry
                if (
                    registry is None
                    or registry.owner_of(candidate.url)
                    != candidate.target_owner_persona_id
                ):
                    raise ProofExperimentAdmissionDenied(
                        "proof_experiment_cross_object_owner_proof_mismatch"
                    )
            decision = self.executor.policy.evaluate_action(candidate)
            if (
                not decision.allowed
                or decision.action_class != action.action_class.value
            ):
                raise ProofExperimentAdmissionDenied(
                    f"proof_experiment_policy_preflight_denied:{decision.reason}"
                )
            values.append(binding)
        ordered = tuple(sorted(values, key=lambda item: item.ordinal))
        if tuple(item.ordinal for item in ordered) != tuple(range(len(ordered))):
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_runtime_action_order_mismatch"
            )
        return ordered

    def _context(
        self,
        runtime_worlds: Mapping[
            str,
            Tuple[str, ExperimentWorldKind],
        ],
    ) -> BehavioralReceiptContext:
        identities = tuple(
            runtime_worlds[item.binding_id][0]
            for item in self.manifest.world_manifest.bindings
        )
        source = identities[0] if identities else self.manifest.world_manifest.world_manifest_id
        peer = identities[1] if len(identities) > 1 else source
        return redacted_receipt_context(
            target_origin=self.target_origin,
            envelope_id=self.authorization.envelope_id,
            source_persona_id=source,
            peer_persona_id=peer,
        )

    def _preflight(self) -> _AdmissionPreflight:
        required_workflows = self._validate_authority()
        policy_digest = self._validate_policy()
        world_bindings, world_ids = self._bind_worlds()
        action_bindings = self._bind_actions(world_ids)
        reserved_actions = tuple(
            (item.action_class.value, item.endpoint_key)
            for item in action_bindings
        )
        if len(reserved_actions) != self.manifest.budget.total_request_units:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_complete_budget_sequence_mismatch"
            )
        descriptor = {
            "schema_version": 1,
            "mode": PROOF_EXPERIMENT_ADMISSION_MODE,
            "manifest_id": self.manifest.manifest_id,
            "backend_conformance_id": self.manifest.backend.conformance_id,
            "target_origin_ref": stable_hash(
                "proof_experiment_target_origin",
                self.target_origin,
            ),
            "envelope_ref": stable_hash(
                "proof_experiment_envelope",
                self.authorization.attestation_signature,
            ),
            "authority_context_ref": self.manifest.authority_context_ref,
            "compiler_policy_digest": self.manifest.policy_digest,
            "execution_policy_digest": policy_digest,
            "world_bindings": [item.to_dict() for item in world_bindings],
            "action_bindings": [item.to_dict() for item in action_bindings],
            "budget_id": self.manifest.budget.budget_id,
            "total_request_units": self.manifest.budget.total_request_units,
            "required_workflows": list(required_workflows),
        }
        try:
            fingerprint = request_fingerprint(descriptor)
        except (TypeError, ValueError) as exc:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_admission_identity_is_not_deterministic"
            ) from exc
        return _AdmissionPreflight(
            fingerprint=fingerprint,
            context=self._context(world_ids),
            descriptor=descriptor,
            world_bindings=world_bindings,
            action_bindings=action_bindings,
            reserved_actions=reserved_actions,
            execution_policy_digest=policy_digest,
            required_workflows=required_workflows,
        )

    def validate_preflight(self) -> str:
        """Return the deterministic admission fingerprint without persistent writes."""

        return self._preflight().fingerprint

    def _abort_receipt_after_budget_denial(
        self,
        *,
        fingerprint: str,
        reservation_token: str,
    ) -> None:
        try:
            self.receipt_store.abort(
                fingerprint,
                reservation_token=reservation_token,
                reason="proof_experiment_budget_reservation_denied",
            )
        except (OSError, ReceiptStoreError) as exc:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_budget_denied_and_receipt_abort_failed"
            ) from exc

    def admit(self) -> ProofExperimentAdmissionLease:
        preflight = self._preflight()
        try:
            receipt_reservation = self.receipt_store.reserve(
                preflight.fingerprint,
                context=preflight.context,
            )
        except (OSError, ReceiptStoreError) as exc:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_receipt_store_unavailable"
            ) from exc
        if not receipt_reservation.created:
            if receipt_reservation.receipt.context != preflight.context:
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_receipt_context_mismatch"
                )
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_is_already_reserved_or_terminal"
            )
        receipt_token = receipt_reservation.reservation_token
        if receipt_token is None:
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_receipt_reservation_token_is_missing"
            )
        budget = self.executor.policy.budget
        try:
            budget_reservation_id, reason = budget.try_reserve(
                preflight.reserved_actions
            )
        except Exception as exc:
            self._abort_receipt_after_budget_denial(
                fingerprint=preflight.fingerprint,
                reservation_token=receipt_token,
            )
            raise ProofExperimentAdmissionDenied(
                "proof_experiment_budget_reservation_failed"
            ) from exc
        if budget_reservation_id is None:
            self._abort_receipt_after_budget_denial(
                fingerprint=preflight.fingerprint,
                reservation_token=receipt_token,
            )
            raise ProofExperimentAdmissionDenied(
                f"proof_experiment_budget_reservation_denied:{reason}"
            )
        try:
            action_ids = tuple(
                item.runtime_action_binding_id for item in preflight.action_bindings
            )
            world_ids = tuple(
                sorted(
                    item.runtime_binding_id for item in preflight.world_bindings
                )
            )
            receipt_id = receipt_reservation.receipt.receipt_id
            payload = _admission_payload(
                manifest_id=self.manifest.manifest_id,
                receipt_id=receipt_id,
                receipt_fingerprint=preflight.fingerprint,
                authority_context_ref=self.manifest.authority_context_ref,
                execution_policy_digest=preflight.execution_policy_digest,
                world_binding_ids=world_ids,
                action_binding_ids=action_ids,
                budget_id=self.manifest.budget.budget_id,
                total_request_units=self.manifest.budget.total_request_units,
                required_workflows=preflight.required_workflows,
                backend=self.manifest.backend.backend,
            )
            contract = ProofExperimentAdmissionContract(
                admission_id=stable_hash("proof_experiment_admission", payload),
                manifest_id=self.manifest.manifest_id,
                receipt_id=receipt_id,
                receipt_fingerprint=preflight.fingerprint,
                authority_context_ref=self.manifest.authority_context_ref,
                execution_policy_digest=preflight.execution_policy_digest,
                world_binding_ids=world_ids,
                action_binding_ids=action_ids,
                budget_id=self.manifest.budget.budget_id,
                total_request_units=self.manifest.budget.total_request_units,
                required_workflows=preflight.required_workflows,
                backend=self.manifest.backend.backend,
            )
        except Exception:
            budget.release_reservation(budget_reservation_id)
            try:
                self.receipt_store.abort(
                    preflight.fingerprint,
                    reservation_token=receipt_token,
                    reason="proof_experiment_admission_contract_failed",
                )
            except (OSError, ReceiptStoreError) as exc:
                raise ProofExperimentAdmissionDenied(
                    "proof_experiment_admission_rollback_failed"
                ) from exc
            raise
        resources = _AdmissionResources(
            budget=budget,
            budget_reservation_id=budget_reservation_id,
            receipt_store=self.receipt_store,
            fingerprint=preflight.fingerprint,
            receipt_reservation_token=receipt_token,
        )
        return ProofExperimentAdmissionLease(contract, resources)


__all__ = [
    "PROOF_EXPERIMENT_ADMISSION_ENV",
    "PROOF_EXPERIMENT_ADMISSION_MODE",
    "ExperimentRuntimeActionBinding",
    "ExperimentRuntimeWorldBinding",
    "GeneralizedExperimentAdmission",
    "ProofExperimentAdmissionClaim",
    "ProofExperimentAdmissionConfig",
    "ProofExperimentAdmissionContract",
    "ProofExperimentAdmissionDenied",
    "ProofExperimentAdmissionLease",
    "experiment_authority_context_ref",
    "experiment_endpoint_ref",
    "experiment_ownership_ref",
    "experiment_persona_ref",
]
