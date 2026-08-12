"""R5A2 passive binding and admission for generalized ownership experiments.

The contracts in this module bind two exact R5A1 ownership lineages to one R4
object-authorization manifest: the actor's legitimate object and the target
owner's equivalent object.  Admission reconstructs both lineages from current
captures and revalidates the signed authority context.  It has no transport,
does not reserve a proof budget, and cannot register ownership or dispatch an
experiment.
"""

from __future__ import annotations

import copy
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from core.foundry.authorization import AuthorizationEnvelope

from .experiment_admission import (
    experiment_authority_context_ref,
    experiment_endpoint_ref,
)
from .experiment_sdk import (
    ExistingBackendKind,
    ExperimentAction,
    ExperimentActionClass,
    ExperimentControl,
    ExperimentControlKind,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    MutationExpectation,
    ProofExperimentManifest,
)
from .lineage import LineageBinding, RehydrationDenied
from .normalize import stable_hash
from .ownership_locators import (
    GeneralizedOwnershipEvidence,
    GeneralizedOwnershipIndex,
    GeneralizedOwnershipLocatorCompiler,
    OwnershipLocatorKind,
    OwnershipProtocol,
    OwnershipUseEvidence,
)
from .payout_goals import ProofTopology, SecurityProperty


OWNERSHIP_EXPERIMENT_BINDING_MODE = (
    "behavioral_generalized_ownership_experiment_binding_v1"
)
OWNERSHIP_EXPERIMENT_ADMISSION_MODE = (
    "behavioral_generalized_ownership_experiment_admission_v1"
)
OBJECT_AUTHORIZATION_WORKFLOW = "behavioral_object_authorization"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")


class GeneralizedOwnershipExperimentDenied(RuntimeError):
    """The ownership proof does not match the manifest, capture, or authority."""


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return bool(
        isinstance(value, str)
        and _HASH_REF.fullmatch(value)
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
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_target_origin_is_invalid"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


class OwnershipExperimentRole(str, Enum):
    ACTOR = "actor"
    TARGET_OWNER = "target_owner"


def _role_payload(
    *,
    role: OwnershipExperimentRole,
    world_binding_id: str,
    world_ref: str,
    capture_digest: str,
    ownership_evidence_id: str,
    ownership_use_id: str,
    lineage_binding_id: str,
    capability_key: str,
    value_hash: str,
    create_operation_id: str,
    operation_id: str,
    source_ref: str,
    request_digest: str,
    endpoint_ref: str,
    locator_kind: OwnershipLocatorKind,
    locator_pointer: str,
    protocol: OwnershipProtocol,
) -> Dict[str, Any]:
    return {
        "role": role.value,
        "world_binding_id": world_binding_id,
        "world_ref": world_ref,
        "capture_digest": capture_digest,
        "ownership_evidence_id": ownership_evidence_id,
        "ownership_use_id": ownership_use_id,
        "lineage_binding_id": lineage_binding_id,
        "capability_key": capability_key,
        "value_hash": value_hash,
        "create_operation_id": create_operation_id,
        "operation_id": operation_id,
        "source_ref": source_ref,
        "request_digest": request_digest,
        "endpoint_ref": endpoint_ref,
        "locator_kind": locator_kind.value,
        "locator_pointer": locator_pointer,
        "protocol": protocol.value,
    }


@dataclass(frozen=True)
class OwnershipExperimentRoleBinding:
    """One capture-bound side of a generalized authorization counterfactual."""

    role_binding_id: str
    role: OwnershipExperimentRole
    world_binding_id: str
    world_ref: str
    capture_digest: str
    ownership_evidence_id: str
    ownership_use_id: str
    lineage_binding_id: str
    capability_key: str
    value_hash: str
    create_operation_id: str
    operation_id: str
    source_ref: str
    request_digest: str
    endpoint_ref: str
    locator_kind: OwnershipLocatorKind
    locator_pointer: str
    protocol: OwnershipProtocol

    def __post_init__(self) -> None:
        payload = _role_payload(
            role=self.role,
            world_binding_id=self.world_binding_id,
            world_ref=self.world_ref,
            capture_digest=self.capture_digest,
            ownership_evidence_id=self.ownership_evidence_id,
            ownership_use_id=self.ownership_use_id,
            lineage_binding_id=self.lineage_binding_id,
            capability_key=self.capability_key,
            value_hash=self.value_hash,
            create_operation_id=self.create_operation_id,
            operation_id=self.operation_id,
            source_ref=self.source_ref,
            request_digest=self.request_digest,
            endpoint_ref=self.endpoint_ref,
            locator_kind=self.locator_kind,
            locator_pointer=self.locator_pointer,
            protocol=self.protocol,
        )
        if (
            not isinstance(self.role, OwnershipExperimentRole)
            or not _hash_ref(self.role_binding_id, "ownership_experiment_role")
            or self.role_binding_id != stable_hash("ownership_experiment_role", payload)
            or not _hash_ref(self.world_binding_id, "experiment_world_binding")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.capture_digest, "capture_set")
            or not _hash_ref(self.ownership_evidence_id, "ownership_evidence")
            or not _hash_ref(self.ownership_use_id, "ownership_use")
            or not _hash_ref(self.lineage_binding_id, "lineage_binding")
            or not self.capability_key
            or len(self.capability_key) > 256
            or not _hash_ref(self.value_hash, "lineage_value")
            or not _hash_ref(self.create_operation_id, "action")
            or not _hash_ref(self.operation_id, "action")
            or not _hash_ref(self.source_ref, "source_ref")
            or not _hash_ref(self.request_digest, "request_template")
            or not _hash_ref(self.endpoint_ref, "experiment_endpoint")
            or not isinstance(self.locator_kind, OwnershipLocatorKind)
            or not isinstance(self.protocol, OwnershipProtocol)
            or not self.locator_pointer.startswith("/")
            or len(self.locator_pointer) > 1_024
            or any(ord(character) < 0x20 for character in self.locator_pointer)
            or (
                self.locator_kind is OwnershipLocatorKind.GRAPHQL_VARIABLE
                and self.protocol is not OwnershipProtocol.GRAPHQL
            )
            or (
                self.locator_kind is not OwnershipLocatorKind.GRAPHQL_VARIABLE
                and self.protocol is not OwnershipProtocol.HTTP
            )
        ):
            raise ValueError("ownership experiment role binding is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role_binding_id": self.role_binding_id,
            **_role_payload(
                role=self.role,
                world_binding_id=self.world_binding_id,
                world_ref=self.world_ref,
                capture_digest=self.capture_digest,
                ownership_evidence_id=self.ownership_evidence_id,
                ownership_use_id=self.ownership_use_id,
                lineage_binding_id=self.lineage_binding_id,
                capability_key=self.capability_key,
                value_hash=self.value_hash,
                create_operation_id=self.create_operation_id,
                operation_id=self.operation_id,
                source_ref=self.source_ref,
                request_digest=self.request_digest,
                endpoint_ref=self.endpoint_ref,
                locator_kind=self.locator_kind,
                locator_pointer=self.locator_pointer,
                protocol=self.protocol,
            ),
        }


def _proof_payload(
    *,
    manifest_id: str,
    backend_conformance_id: str,
    source_contract_ref: str,
    authority_context_ref: str,
    goal_id: str,
    oracle_id: str,
    actor: OwnershipExperimentRoleBinding,
    target_owner: OwnershipExperimentRoleBinding,
    actor_control_id: str,
    owner_control_id: str,
    treatment_action_id: str,
    witness_action_id: str,
) -> Dict[str, Any]:
    return {
        "mode": OWNERSHIP_EXPERIMENT_BINDING_MODE,
        "manifest_id": manifest_id,
        "backend_conformance_id": backend_conformance_id,
        "source_contract_ref": source_contract_ref,
        "authority_context_ref": authority_context_ref,
        "goal_id": goal_id,
        "oracle_id": oracle_id,
        "actor": actor.to_dict(),
        "target_owner": target_owner.to_dict(),
        "actor_control_id": actor_control_id,
        "owner_control_id": owner_control_id,
        "treatment_action_id": treatment_action_id,
        "witness_action_id": witness_action_id,
        "target_requests_sent": 0,
        "ownership_registry_writes": 0,
        "budget_reserved": False,
        "backend_dispatch_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class GeneralizedOwnershipExperimentProof:
    """A non-executable R4 manifest plus its exact paired R5A1 ownership proof."""

    proof_id: str
    manifest_id: str
    backend_conformance_id: str
    source_contract_ref: str
    authority_context_ref: str
    goal_id: str
    oracle_id: str
    actor: OwnershipExperimentRoleBinding
    target_owner: OwnershipExperimentRoleBinding
    actor_control_id: str
    owner_control_id: str
    treatment_action_id: str
    witness_action_id: str
    mode: str = OWNERSHIP_EXPERIMENT_BINDING_MODE
    target_requests_sent: int = 0
    ownership_registry_writes: int = 0
    budget_reserved: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _proof_payload(
            manifest_id=self.manifest_id,
            backend_conformance_id=self.backend_conformance_id,
            source_contract_ref=self.source_contract_ref,
            authority_context_ref=self.authority_context_ref,
            goal_id=self.goal_id,
            oracle_id=self.oracle_id,
            actor=self.actor,
            target_owner=self.target_owner,
            actor_control_id=self.actor_control_id,
            owner_control_id=self.owner_control_id,
            treatment_action_id=self.treatment_action_id,
            witness_action_id=self.witness_action_id,
        )
        paired_semantics = (
            self.actor.capability_key == self.target_owner.capability_key
            and self.actor.create_operation_id == self.target_owner.create_operation_id
            and self.actor.operation_id == self.target_owner.operation_id
            and self.actor.endpoint_ref == self.target_owner.endpoint_ref
            and self.actor.locator_kind is self.target_owner.locator_kind
            and self.actor.locator_pointer == self.target_owner.locator_pointer
            and self.actor.protocol is self.target_owner.protocol
        )
        if (
            self.mode != OWNERSHIP_EXPERIMENT_BINDING_MODE
            or not _hash_ref(self.proof_id, "ownership_experiment_proof")
            or self.proof_id != stable_hash("ownership_experiment_proof", payload)
            or not _hash_ref(self.manifest_id, "proof_experiment_manifest")
            or not _hash_ref(self.backend_conformance_id, "backend_conformance")
            or not _hash_ref(self.source_contract_ref, "authorization_proposal")
            or not _hash_ref(self.authority_context_ref, "experiment_authority_context")
            or not _hash_ref(self.goal_id, "security_witness_goal")
            or not _hash_ref(self.oracle_id, "proof_experiment_oracle")
            or self.actor.role is not OwnershipExperimentRole.ACTOR
            or self.target_owner.role is not OwnershipExperimentRole.TARGET_OWNER
            or self.actor.world_binding_id == self.target_owner.world_binding_id
            or self.actor.world_ref == self.target_owner.world_ref
            or self.actor.value_hash == self.target_owner.value_hash
            or not paired_semantics
            or not _hash_ref(self.actor_control_id, "proof_experiment_control")
            or not _hash_ref(self.owner_control_id, "proof_experiment_control")
            or self.actor_control_id == self.owner_control_id
            or not _hash_ref(self.treatment_action_id, "proof_experiment_action")
            or not _hash_ref(self.witness_action_id, "proof_experiment_action")
            or self.treatment_action_id == self.witness_action_id
            or self.target_requests_sent != 0
            or self.ownership_registry_writes != 0
            or self.budget_reserved
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("generalized ownership experiment proof is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "proof_id": self.proof_id,
            **_proof_payload(
                manifest_id=self.manifest_id,
                backend_conformance_id=self.backend_conformance_id,
                source_contract_ref=self.source_contract_ref,
                authority_context_ref=self.authority_context_ref,
                goal_id=self.goal_id,
                oracle_id=self.oracle_id,
                actor=self.actor,
                target_owner=self.target_owner,
                actor_control_id=self.actor_control_id,
                owner_control_id=self.owner_control_id,
                treatment_action_id=self.treatment_action_id,
                witness_action_id=self.witness_action_id,
            ),
        }


@dataclass(frozen=True)
class _SelectedOwnership:
    index: GeneralizedOwnershipIndex
    evidence: GeneralizedOwnershipEvidence
    use: OwnershipUseEvidence
    binding: LineageBinding
    raw_value: str
    endpoint_ref: str


def _select_ownership(
    index: GeneralizedOwnershipIndex,
    lineage_binding_id: str,
) -> _SelectedOwnership:
    evidence = index.evidence_for_binding(lineage_binding_id)
    bindings = tuple(
        item for item in index.ledger.bindings if item.binding_id == lineage_binding_id
    )
    if evidence is None or len(bindings) != 1:
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_lineage_binding_is_missing_or_ambiguous"
        )
    uses = tuple(
        item for item in evidence.uses if item.lineage_binding_id == lineage_binding_id
    )
    if len(uses) != 1:
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_use_is_missing_or_ambiguous"
        )
    binding = bindings[0]
    observation_matches = tuple(
        item
        for item in index.ledger.observations
        if item.source_ref == binding.consumer_source_ref
    )
    if len(observation_matches) != 1:
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_observation_is_missing_or_ambiguous"
        )
    try:
        request = index.ledger._rehydrate_observation(observation_matches[0])
        occurrence = index.ledger._occurrence(binding, producer=False)
        endpoint_ref = experiment_endpoint_ref(request.method, request.url)
    except (RehydrationDenied, TypeError, ValueError) as exc:
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_capture_cannot_be_revalidated"
        ) from exc
    return _SelectedOwnership(
        index=index,
        evidence=evidence,
        use=uses[0],
        binding=binding,
        raw_value=occurrence.raw_value,
        endpoint_ref=endpoint_ref,
    )


def _role_binding(
    *,
    role: OwnershipExperimentRole,
    world: ExperimentWorldBinding,
    selected: _SelectedOwnership,
) -> OwnershipExperimentRoleBinding:
    payload = _role_payload(
        role=role,
        world_binding_id=world.binding_id,
        world_ref=world.world_ref,
        capture_digest=selected.evidence.capture_digest,
        ownership_evidence_id=selected.evidence.evidence_id,
        ownership_use_id=selected.use.use_id,
        lineage_binding_id=selected.binding.binding_id,
        capability_key=selected.evidence.capability_key,
        value_hash=selected.evidence.value_hash,
        create_operation_id=selected.evidence.create_operation_id,
        operation_id=selected.use.operation_id,
        source_ref=selected.use.source_ref,
        request_digest=selected.use.request_digest,
        endpoint_ref=selected.endpoint_ref,
        locator_kind=selected.use.locator_kind,
        locator_pointer=selected.use.locator_pointer,
        protocol=selected.use.protocol,
    )
    return OwnershipExperimentRoleBinding(
        role_binding_id=stable_hash("ownership_experiment_role", payload),
        role=role,
        world_binding_id=world.binding_id,
        world_ref=world.world_ref,
        capture_digest=selected.evidence.capture_digest,
        ownership_evidence_id=selected.evidence.evidence_id,
        ownership_use_id=selected.use.use_id,
        lineage_binding_id=selected.binding.binding_id,
        capability_key=selected.evidence.capability_key,
        value_hash=selected.evidence.value_hash,
        create_operation_id=selected.evidence.create_operation_id,
        operation_id=selected.use.operation_id,
        source_ref=selected.use.source_ref,
        request_digest=selected.use.request_digest,
        endpoint_ref=selected.endpoint_ref,
        locator_kind=selected.use.locator_kind,
        locator_pointer=selected.use.locator_pointer,
        protocol=selected.use.protocol,
    )


@dataclass(frozen=True)
class _ManifestRoles:
    actor_world: ExperimentWorldBinding
    owner_world: ExperimentWorldBinding
    actor_control: ExperimentControl
    owner_control: ExperimentControl
    treatment: ExperimentAction
    witness: ExperimentAction


def _manifest_roles(
    manifest: ProofExperimentManifest,
    actor: _SelectedOwnership,
    owner: _SelectedOwnership,
) -> _ManifestRoles:
    requirement = manifest.world_manifest.requirement
    if (
        manifest.backend.backend is not ExistingBackendKind.OBJECT_AUTHORIZATION
        or manifest.oracle.security_property
        is not SecurityProperty.OBJECT_AUTHORIZATION
        or requirement.topology is not ProofTopology.PAIRED_OWNED_ACCOUNTS
        or requirement.min_owned_worlds != 2
        or requirement.required_workflows != (OBJECT_AUTHORIZATION_WORKFLOW,)
        or len(manifest.world_manifest.bindings) != 2
        or any(
            item.kind is not ExperimentWorldKind.OWNED_ACCOUNT
            for item in manifest.world_manifest.bindings
        )
        or manifest.cleanup.bindings
    ):
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_manifest_backend_or_topology_is_unsupported"
        )
    actor_worlds = tuple(
        item
        for item in manifest.world_manifest.bindings
        if item.world_ref == actor.evidence.world_ref
    )
    owner_worlds = tuple(
        item
        for item in manifest.world_manifest.bindings
        if item.world_ref == owner.evidence.world_ref
    )
    if (
        len(actor_worlds) != 1
        or len(owner_worlds) != 1
        or actor_worlds[0].binding_id == owner_worlds[0].binding_id
    ):
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_manifest_world_binding_mismatch"
        )
    actor_world = actor_worlds[0]
    owner_world = owner_worlds[0]
    controls_by_kind = {item.kind: item for item in manifest.controls}
    if (
        len(manifest.controls) != 2
        or len(controls_by_kind) != 2
        or set(controls_by_kind)
        != {
            ExperimentControlKind.OWNER_BASELINE,
            ExperimentControlKind.PEER_BASELINE,
        }
    ):
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_manifest_controls_are_unsupported"
        )
    actor_control = controls_by_kind[ExperimentControlKind.OWNER_BASELINE]
    owner_control = controls_by_kind[ExperimentControlKind.PEER_BASELINE]
    treatments = tuple(
        item for item in manifest.actions if item.phase is ExperimentPhase.TREATMENT
    )
    witnesses = tuple(
        item for item in manifest.actions if item.phase is ExperimentPhase.WITNESS
    )
    control_actions = {
        item.action_id: item
        for item in manifest.actions
        if item.phase is ExperimentPhase.CONTROL
    }
    if (
        len(manifest.actions) != 4
        or len(treatments) != 1
        or len(witnesses) != 1
        or len(control_actions) != 2
        or len(actor_control.action_ids) != 1
        or len(owner_control.action_ids) != 1
    ):
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_manifest_action_shape_is_unsupported"
        )
    actor_control_action = control_actions.get(actor_control.action_ids[0])
    owner_control_action = control_actions.get(owner_control.action_ids[0])
    treatment = treatments[0]
    witness = witnesses[0]
    expected_operation = actor.use.operation_id
    expected_endpoint = actor.endpoint_ref
    all_actions = (
        actor_control_action,
        owner_control_action,
        treatment,
        witness,
    )
    if (
        actor_control_action is None
        or owner_control_action is None
        or owner.use.operation_id != expected_operation
        or owner.endpoint_ref != expected_endpoint
        or actor_control.world_binding_ids != (actor_world.binding_id,)
        or owner_control.world_binding_ids != (owner_world.binding_id,)
        or actor_control_action.world_binding_id != actor_world.binding_id
        or owner_control_action.world_binding_id != owner_world.binding_id
        or treatment.world_binding_id != actor_world.binding_id
        or witness.world_binding_id != owner_world.binding_id
        or treatment.action_class is not ExperimentActionClass.CROSS_OBJECT_READ
        or any(
            item.action_class is not ExperimentActionClass.SAFE_READ
            for item in (actor_control_action, owner_control_action, witness)
        )
        or any(item.mutation is not MutationExpectation.NONE for item in all_actions)
        or any(item.operation_id != expected_operation for item in all_actions)
        or any(item.endpoint_ref != expected_endpoint for item in all_actions)
        or any(
            item.evidence_refs != manifest.backend.source_evidence_refs
            for item in all_actions
        )
        or manifest.oracle.comparison_kind != "owned_object_counterfactual"
        or manifest.oracle.treatment_action_ids != (treatment.action_id,)
        or manifest.oracle.witness_action_ids != (witness.action_id,)
        or set(manifest.oracle.control_ids)
        != {actor_control.control_id, owner_control.control_id}
    ):
        raise GeneralizedOwnershipExperimentDenied(
            "generalized_ownership_manifest_relations_do_not_match_capture"
        )
    return _ManifestRoles(
        actor_world=actor_world,
        owner_world=owner_world,
        actor_control=actor_control,
        owner_control=owner_control,
        treatment=treatment,
        witness=witness,
    )


class GeneralizedOwnershipExperimentCompiler:
    """Seal two exact R5A1 lineages into one non-executable R4 manifest proof."""

    def __init__(
        self,
        *,
        locator_compiler: Optional[GeneralizedOwnershipLocatorCompiler] = None,
    ) -> None:
        self.locator_compiler = (
            locator_compiler or GeneralizedOwnershipLocatorCompiler()
        )

    def compile(
        self,
        *,
        manifest: ProofExperimentManifest,
        actor_records: Sequence[Mapping[str, Any]],
        target_owner_records: Sequence[Mapping[str, Any]],
        actor_lineage_binding_id: str,
        target_owner_lineage_binding_id: str,
    ) -> GeneralizedOwnershipExperimentProof:
        if not isinstance(manifest, ProofExperimentManifest):
            raise TypeError("manifest must be a ProofExperimentManifest")
        try:
            actor_snapshot = copy.deepcopy(tuple(actor_records))
            owner_snapshot = copy.deepcopy(tuple(target_owner_records))
        except Exception as exc:
            raise TypeError(
                "ownership capture records must be safely copyable"
            ) from exc
        actor_index = self.locator_compiler.compile(actor_snapshot)
        owner_index = self.locator_compiler.compile(owner_snapshot)
        actor = _select_ownership(actor_index, actor_lineage_binding_id)
        owner = _select_ownership(owner_index, target_owner_lineage_binding_id)
        if (
            actor.raw_value == owner.raw_value
            or actor.evidence.capability_key != owner.evidence.capability_key
            or actor.evidence.create_operation_id != owner.evidence.create_operation_id
            or actor.use.operation_id != owner.use.operation_id
            or actor.use.locator_kind is not owner.use.locator_kind
            or actor.use.locator_pointer != owner.use.locator_pointer
            or actor.use.protocol is not owner.use.protocol
            or actor.endpoint_ref != owner.endpoint_ref
        ):
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_counterfactual_pair_is_not_equivalent"
            )
        roles = _manifest_roles(manifest, actor, owner)
        actor_binding = _role_binding(
            role=OwnershipExperimentRole.ACTOR,
            world=roles.actor_world,
            selected=actor,
        )
        owner_binding = _role_binding(
            role=OwnershipExperimentRole.TARGET_OWNER,
            world=roles.owner_world,
            selected=owner,
        )
        payload = _proof_payload(
            manifest_id=manifest.manifest_id,
            backend_conformance_id=manifest.backend.conformance_id,
            source_contract_ref=manifest.backend.source_contract_ref,
            authority_context_ref=manifest.authority_context_ref,
            goal_id=manifest.goal_id,
            oracle_id=manifest.oracle.oracle_id,
            actor=actor_binding,
            target_owner=owner_binding,
            actor_control_id=roles.actor_control.control_id,
            owner_control_id=roles.owner_control.control_id,
            treatment_action_id=roles.treatment.action_id,
            witness_action_id=roles.witness.action_id,
        )
        return GeneralizedOwnershipExperimentProof(
            proof_id=stable_hash("ownership_experiment_proof", payload),
            manifest_id=manifest.manifest_id,
            backend_conformance_id=manifest.backend.conformance_id,
            source_contract_ref=manifest.backend.source_contract_ref,
            authority_context_ref=manifest.authority_context_ref,
            goal_id=manifest.goal_id,
            oracle_id=manifest.oracle.oracle_id,
            actor=actor_binding,
            target_owner=owner_binding,
            actor_control_id=roles.actor_control.control_id,
            owner_control_id=roles.owner_control.control_id,
            treatment_action_id=roles.treatment.action_id,
            witness_action_id=roles.witness.action_id,
        )


def _admission_payload(
    *,
    proof_id: str,
    manifest_id: str,
    authority_context_ref: str,
    actor_capture_digest: str,
    target_owner_capture_digest: str,
) -> Dict[str, Any]:
    return {
        "mode": OWNERSHIP_EXPERIMENT_ADMISSION_MODE,
        "proof_id": proof_id,
        "manifest_id": manifest_id,
        "authority_context_ref": authority_context_ref,
        "actor_capture_digest": actor_capture_digest,
        "target_owner_capture_digest": target_owner_capture_digest,
        "capture_revalidated": True,
        "target_requests_sent": 0,
        "ownership_registry_writes": 0,
        "budget_reserved": False,
        "single_use_claim_available": False,
        "backend_dispatch_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class OwnershipExperimentAdmissionContract:
    admission_id: str
    proof_id: str
    manifest_id: str
    authority_context_ref: str
    actor_capture_digest: str
    target_owner_capture_digest: str
    mode: str = OWNERSHIP_EXPERIMENT_ADMISSION_MODE
    capture_revalidated: bool = True
    target_requests_sent: int = 0
    ownership_registry_writes: int = 0
    budget_reserved: bool = False
    single_use_claim_available: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _admission_payload(
            proof_id=self.proof_id,
            manifest_id=self.manifest_id,
            authority_context_ref=self.authority_context_ref,
            actor_capture_digest=self.actor_capture_digest,
            target_owner_capture_digest=self.target_owner_capture_digest,
        )
        if (
            self.mode != OWNERSHIP_EXPERIMENT_ADMISSION_MODE
            or not _hash_ref(self.admission_id, "ownership_experiment_admission")
            or self.admission_id
            != stable_hash("ownership_experiment_admission", payload)
            or not _hash_ref(self.proof_id, "ownership_experiment_proof")
            or not _hash_ref(self.manifest_id, "proof_experiment_manifest")
            or not _hash_ref(self.authority_context_ref, "experiment_authority_context")
            or not _hash_ref(self.actor_capture_digest, "capture_set")
            or not _hash_ref(self.target_owner_capture_digest, "capture_set")
            or not self.capture_revalidated
            or self.target_requests_sent != 0
            or self.ownership_registry_writes != 0
            or self.budget_reserved
            or self.single_use_claim_available
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("ownership experiment admission contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "admission_id": self.admission_id,
            **_admission_payload(
                proof_id=self.proof_id,
                manifest_id=self.manifest_id,
                authority_context_ref=self.authority_context_ref,
                actor_capture_digest=self.actor_capture_digest,
                target_owner_capture_digest=self.target_owner_capture_digest,
            ),
        }


class GeneralizedOwnershipExperimentAdmission:
    """Reconstruct one R5A2 proof under the current signed authority context."""

    def __init__(
        self,
        *,
        proof: GeneralizedOwnershipExperimentProof,
        manifest: ProofExperimentManifest,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_records: Sequence[Mapping[str, Any]],
        target_owner_records: Sequence[Mapping[str, Any]],
        compiler: Optional[GeneralizedOwnershipExperimentCompiler] = None,
    ) -> None:
        if not isinstance(proof, GeneralizedOwnershipExperimentProof):
            raise TypeError("proof must be a GeneralizedOwnershipExperimentProof")
        if not isinstance(manifest, ProofExperimentManifest):
            raise TypeError("manifest must be a ProofExperimentManifest")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("authorization must be an AuthorizationEnvelope")
        self.proof = proof
        self.manifest = manifest
        self.target_origin = _canonical_origin(target_origin)
        self.authorization = copy.deepcopy(authorization)
        try:
            self.actor_records = copy.deepcopy(tuple(actor_records))
            self.target_owner_records = copy.deepcopy(tuple(target_owner_records))
        except Exception as exc:
            raise TypeError(
                "ownership capture records must be safely copyable"
            ) from exc
        self.compiler = compiler or GeneralizedOwnershipExperimentCompiler()

    def _validate_capture_origins(self) -> None:
        for records in (self.actor_records, self.target_owner_records):
            if not records:
                raise GeneralizedOwnershipExperimentDenied(
                    "generalized_ownership_capture_is_empty"
                )
            for record in records:
                if not isinstance(record, Mapping):
                    raise GeneralizedOwnershipExperimentDenied(
                        "generalized_ownership_capture_record_is_invalid"
                    )
                try:
                    origin = _canonical_origin(str(record.get("url") or ""))
                except GeneralizedOwnershipExperimentDenied as exc:
                    raise GeneralizedOwnershipExperimentDenied(
                        "generalized_ownership_capture_origin_is_invalid"
                    ) from exc
                if origin != self.target_origin:
                    raise GeneralizedOwnershipExperimentDenied(
                        "generalized_ownership_capture_origin_mismatch"
                    )

    def _validate_authority(self) -> None:
        signature = self.authorization.attestation_signature
        if not signature:
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_authorization_is_unsigned"
            )
        copied = copy.deepcopy(self.authorization)
        if not hmac.compare_digest(signature, copied.sign()):
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_authorization_signature_mismatch"
            )
        workflows = self.manifest.world_manifest.requirement.required_workflows
        if workflows != (OBJECT_AUTHORIZATION_WORKFLOW,):
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_workflow_contract_mismatch"
            )
        if self.manifest.target_ref != stable_hash(
            "security_obligation_target", self.target_origin
        ):
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_target_ref_mismatch"
            )
        for workflow in workflows:
            try:
                self.authorization.authorize_action(
                    target_origin=self.target_origin,
                    workflow=workflow,
                )
            except Exception as exc:
                raise GeneralizedOwnershipExperimentDenied(
                    "generalized_ownership_authorization_denied"
                ) from exc
        expected_context = experiment_authority_context_ref(
            self.authorization,
            self.target_origin,
            workflows,
        )
        if (
            self.manifest.authority_context_ref != expected_context
            or self.proof.authority_context_ref != expected_context
        ):
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_authority_context_mismatch"
            )

    def admit(self) -> OwnershipExperimentAdmissionContract:
        self._validate_authority()
        self._validate_capture_origins()
        if self.proof.manifest_id != self.manifest.manifest_id:
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_manifest_identity_mismatch"
            )
        fresh = self.compiler.compile(
            manifest=self.manifest,
            actor_records=self.actor_records,
            target_owner_records=self.target_owner_records,
            actor_lineage_binding_id=self.proof.actor.lineage_binding_id,
            target_owner_lineage_binding_id=(
                self.proof.target_owner.lineage_binding_id
            ),
        )
        if fresh.to_dict() != self.proof.to_dict():
            raise GeneralizedOwnershipExperimentDenied(
                "generalized_ownership_proof_does_not_match_current_capture"
            )
        payload = _admission_payload(
            proof_id=self.proof.proof_id,
            manifest_id=self.manifest.manifest_id,
            authority_context_ref=self.manifest.authority_context_ref,
            actor_capture_digest=fresh.actor.capture_digest,
            target_owner_capture_digest=fresh.target_owner.capture_digest,
        )
        return OwnershipExperimentAdmissionContract(
            admission_id=stable_hash("ownership_experiment_admission", payload),
            proof_id=self.proof.proof_id,
            manifest_id=self.manifest.manifest_id,
            authority_context_ref=self.manifest.authority_context_ref,
            actor_capture_digest=fresh.actor.capture_digest,
            target_owner_capture_digest=fresh.target_owner.capture_digest,
        )


__all__ = [
    "OWNERSHIP_EXPERIMENT_ADMISSION_MODE",
    "OWNERSHIP_EXPERIMENT_BINDING_MODE",
    "GeneralizedOwnershipExperimentAdmission",
    "GeneralizedOwnershipExperimentCompiler",
    "GeneralizedOwnershipExperimentDenied",
    "GeneralizedOwnershipExperimentProof",
    "OwnershipExperimentAdmissionContract",
    "OwnershipExperimentRole",
    "OwnershipExperimentRoleBinding",
]
