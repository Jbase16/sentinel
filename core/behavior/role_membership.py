"""Transport-free R5C1 role lattice and owned-membership fixture contracts.

Role order is explicit and content-addressed; display names such as ``admin`` or
``member`` never establish authority.  The fixture binds one same-tenant role
differential to an exact reversible membership mutation and an independent
post-revocation check.  It performs no target I/O, reserves no budget, and grants
no execution or finding authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict

from .experiment_sdk import (
    CleanupBinding,
    ExperimentAction,
    ExperimentActionClass,
    ExperimentCleanupContract,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ExperimentWorldManifest,
    MutationExpectation,
)
from .normalize import stable_hash
from .payout_goals import ProofTopology


ROLE_MEMBERSHIP_FIXTURE_MODE = "behavioral_role_membership_fixture_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")


def _hash_ref(value: object, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and value.startswith(f"{prefix}:")
    )


class RoleLatticePosition(str, Enum):
    LOWER = "lower"
    HIGHER = "higher"


def _role_binding_payload(
    *,
    position: RoleLatticePosition,
    world: ExperimentWorldBinding,
    tenant_ref: str,
    tenant_ownership_ref: str,
) -> Dict[str, Any]:
    return {
        "position": position.value,
        "world_slot": world.slot,
        "world_binding_id": world.binding_id,
        "world_ref": world.world_ref,
        "persona_ref": world.persona_ref,
        "ownership_ref": world.ownership_ref,
        "role_ref": world.role_ref,
        "tenant_ref": tenant_ref,
        "tenant_ownership_ref": tenant_ownership_ref,
    }


@dataclass(frozen=True)
class RoleLatticeBinding:
    binding_id: str
    position: RoleLatticePosition
    world_slot: str
    world_binding_id: str
    world_ref: str
    persona_ref: str
    ownership_ref: str
    role_ref: str
    tenant_ref: str
    tenant_ownership_ref: str

    @classmethod
    def build(
        cls,
        *,
        position: RoleLatticePosition,
        world: ExperimentWorldBinding,
        tenant_ref: str,
        tenant_ownership_ref: str,
    ) -> "RoleLatticeBinding":
        if not isinstance(world, ExperimentWorldBinding):
            raise TypeError("world must be an ExperimentWorldBinding")
        if (
            world.kind is not ExperimentWorldKind.OWNED_ACCOUNT
            or world.persona_ref is None
            or world.ownership_ref is None
            or world.role_ref is None
            or world.lifecycle_ref is not None
        ):
            raise ValueError("role lattice requires a role-bound owned world")
        payload = _role_binding_payload(
            position=position,
            world=world,
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
        )
        return cls(
            binding_id=stable_hash("role_lattice_binding", payload),
            position=position,
            world_slot=world.slot,
            world_binding_id=world.binding_id,
            world_ref=world.world_ref,
            persona_ref=world.persona_ref,
            ownership_ref=world.ownership_ref,
            role_ref=world.role_ref,
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
        )

    def __post_init__(self) -> None:
        expected_slot = {
            RoleLatticePosition.LOWER: "low_role",
            RoleLatticePosition.HIGHER: "high_role",
        }[self.position]
        payload = {
            "position": self.position.value,
            "world_slot": self.world_slot,
            "world_binding_id": self.world_binding_id,
            "world_ref": self.world_ref,
            "persona_ref": self.persona_ref,
            "ownership_ref": self.ownership_ref,
            "role_ref": self.role_ref,
            "tenant_ref": self.tenant_ref,
            "tenant_ownership_ref": self.tenant_ownership_ref,
        }
        if (
            not isinstance(self.position, RoleLatticePosition)
            or self.binding_id != stable_hash("role_lattice_binding", payload)
            or not _hash_ref(self.binding_id, "role_lattice_binding")
            or self.world_slot != expected_slot
            or not _hash_ref(self.world_binding_id, "experiment_world_binding")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.persona_ref, "experiment_persona")
            or not _hash_ref(self.ownership_ref, "ownership_proof")
            or not _hash_ref(self.role_ref, "experiment_role")
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.tenant_ownership_ref, "ownership_proof")
        ):
            raise ValueError("role lattice binding is invalid")
    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "position": self.position.value,
            "world_slot": self.world_slot,
            "world_binding_id": self.world_binding_id,
            "world_ref": self.world_ref,
            "persona_ref": self.persona_ref,
            "ownership_ref": self.ownership_ref,
            "role_ref": self.role_ref,
            "tenant_ref": self.tenant_ref,
            "tenant_ownership_ref": self.tenant_ownership_ref,
        }


def _lattice_payload(
    *,
    world_manifest_id: str,
    tenant_ref: str,
    tenant_ownership_ref: str,
    lower: RoleLatticeBinding,
    higher: RoleLatticeBinding,
) -> Dict[str, Any]:
    return {
        "world_manifest_id": world_manifest_id,
        "tenant_ref": tenant_ref,
        "tenant_ownership_ref": tenant_ownership_ref,
        "lower": lower.to_dict(),
        "higher": higher.to_dict(),
        "relation": "lower_strictly_below_higher",
        "same_tenant_required": True,
        "owned_tenant_required": True,
    }


@dataclass(frozen=True)
class RoleAuthorityLattice:
    lattice_id: str
    world_manifest_id: str
    world_manifest: ExperimentWorldManifest = field(repr=False, compare=False)
    tenant_ref: str
    tenant_ownership_ref: str
    lower: RoleLatticeBinding
    higher: RoleLatticeBinding
    relation: str = "lower_strictly_below_higher"
    same_tenant_required: bool = True
    owned_tenant_required: bool = True

    @classmethod
    def build(
        cls,
        *,
        world_manifest: ExperimentWorldManifest,
        tenant_ref: str,
        tenant_ownership_ref: str,
    ) -> "RoleAuthorityLattice":
        if not isinstance(world_manifest, ExperimentWorldManifest):
            raise TypeError("world_manifest must be an ExperimentWorldManifest")
        requirement = world_manifest.requirement
        by_slot = {item.slot: item for item in world_manifest.bindings}
        if (
            requirement.topology is not ProofTopology.OWNED_ROLE_DIFFERENTIAL
            or requirement.min_owned_worlds != 2
            or requirement.required_role_worlds != 2
            or set(by_slot) != {"high_role", "low_role"}
        ):
            raise ValueError("role lattice requires the owned role differential topology")
        lower = RoleLatticeBinding.build(
            position=RoleLatticePosition.LOWER,
            world=by_slot["low_role"],
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
        )
        higher = RoleLatticeBinding.build(
            position=RoleLatticePosition.HIGHER,
            world=by_slot["high_role"],
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
        )
        payload = _lattice_payload(
            world_manifest_id=world_manifest.world_manifest_id,
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
            lower=lower,
            higher=higher,
        )
        return cls(
            lattice_id=stable_hash("role_authority_lattice", payload),
            world_manifest_id=world_manifest.world_manifest_id,
            world_manifest=world_manifest,
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
            lower=lower,
            higher=higher,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.world_manifest, ExperimentWorldManifest):
            raise TypeError("world_manifest must be an ExperimentWorldManifest")
        by_slot = {item.slot: item for item in self.world_manifest.bindings}
        requirement = self.world_manifest.requirement
        if (
            self.world_manifest_id != self.world_manifest.world_manifest_id
            or requirement.topology is not ProofTopology.OWNED_ROLE_DIFFERENTIAL
            or requirement.min_owned_worlds != 2
            or requirement.required_role_worlds != 2
            or set(by_slot) != {"high_role", "low_role"}
        ):
            raise ValueError("role authority lattice manifest is invalid")
        expected_lower = RoleLatticeBinding.build(
            position=RoleLatticePosition.LOWER,
            world=by_slot["low_role"],
            tenant_ref=self.tenant_ref,
            tenant_ownership_ref=self.tenant_ownership_ref,
        )
        expected_higher = RoleLatticeBinding.build(
            position=RoleLatticePosition.HIGHER,
            world=by_slot["high_role"],
            tenant_ref=self.tenant_ref,
            tenant_ownership_ref=self.tenant_ownership_ref,
        )
        payload = _lattice_payload(
            world_manifest_id=self.world_manifest_id,
            tenant_ref=self.tenant_ref,
            tenant_ownership_ref=self.tenant_ownership_ref,
            lower=self.lower,
            higher=self.higher,
        )
        distinct_pairs = (
            (self.lower.binding_id, self.higher.binding_id),
            (self.lower.world_binding_id, self.higher.world_binding_id),
            (self.lower.world_ref, self.higher.world_ref),
            (self.lower.persona_ref, self.higher.persona_ref),
            (self.lower.ownership_ref, self.higher.ownership_ref),
            (self.lower.role_ref, self.higher.role_ref),
        )
        if (
            self.lattice_id != stable_hash("role_authority_lattice", payload)
            or not _hash_ref(self.lattice_id, "role_authority_lattice")
            or not _hash_ref(self.world_manifest_id, "experiment_world_manifest")
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.tenant_ownership_ref, "ownership_proof")
            or self.lower != expected_lower
            or self.higher != expected_higher
            or self.lower.tenant_ref != self.tenant_ref
            or self.higher.tenant_ref != self.tenant_ref
            or self.lower.tenant_ownership_ref != self.tenant_ownership_ref
            or self.higher.tenant_ownership_ref != self.tenant_ownership_ref
            or any(left == right for left, right in distinct_pairs)
            or self.relation != "lower_strictly_below_higher"
            or not self.same_tenant_required
            or not self.owned_tenant_required
        ):
            raise ValueError("role authority lattice is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "lattice_id": self.lattice_id,
            **_lattice_payload(
                world_manifest_id=self.world_manifest_id,
                tenant_ref=self.tenant_ref,
                tenant_ownership_ref=self.tenant_ownership_ref,
                lower=self.lower,
                higher=self.higher,
            ),
        }


def owned_membership_ref(lattice: RoleAuthorityLattice) -> str:
    if not isinstance(lattice, RoleAuthorityLattice):
        raise TypeError("lattice must be a RoleAuthorityLattice")
    return stable_hash(
        "owned_membership",
        {
            "lattice_id": lattice.lattice_id,
            "tenant_ref": lattice.tenant_ref,
            "subject_role_binding_id": lattice.lower.binding_id,
            "subject_world_ref": lattice.lower.world_ref,
            "subject_persona_ref": lattice.lower.persona_ref,
            "subject_role_ref": lattice.lower.role_ref,
        },
    )


def _fixture_payload(
    *,
    lattice: RoleAuthorityLattice,
    membership_ref: str,
    setup_action: ExperimentAction,
    revocation_action: ExperimentAction,
    revocation_verification_action: ExperimentAction,
    cleanup: ExperimentCleanupContract,
) -> Dict[str, Any]:
    return {
        "mode": ROLE_MEMBERSHIP_FIXTURE_MODE,
        "lattice": lattice.to_dict(),
        "membership_ref": membership_ref,
        "subject_role_binding_id": lattice.lower.binding_id,
        "setup_action": setup_action.to_dict(),
        "revocation_action": revocation_action.to_dict(),
        "revocation_verification_action": revocation_verification_action.to_dict(),
        "cleanup": cleanup.to_dict(),
        "initial_state": "absent",
        "provisioned_state": "active",
        "terminal_state": "revoked",
        "revocation_freshness_required": True,
        "cleanup_uncertainty_is_terminal": True,
        "target_requests_sent": 0,
        "budget_reserved": False,
        "backend_dispatch_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class OwnedMembershipFixture:
    fixture_id: str
    lattice: RoleAuthorityLattice
    membership_ref: str
    subject_role_binding_id: str
    setup_action: ExperimentAction
    revocation_action: ExperimentAction
    revocation_verification_action: ExperimentAction
    cleanup: ExperimentCleanupContract
    mode: str = ROLE_MEMBERSHIP_FIXTURE_MODE
    initial_state: str = "absent"
    provisioned_state: str = "active"
    terminal_state: str = "revoked"
    revocation_freshness_required: bool = True
    cleanup_uncertainty_is_terminal: bool = True
    target_requests_sent: int = 0
    budget_reserved: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        lattice: RoleAuthorityLattice,
        setup_action: ExperimentAction,
        revocation_action: ExperimentAction,
        revocation_verification_action: ExperimentAction,
    ) -> "OwnedMembershipFixture":
        if not isinstance(lattice, RoleAuthorityLattice):
            raise TypeError("lattice must be a RoleAuthorityLattice")
        if any(
            not isinstance(item, ExperimentAction)
            for item in (
                setup_action,
                revocation_action,
                revocation_verification_action,
            )
        ):
            raise TypeError("membership fixture actions must be ExperimentAction values")
        membership_ref = owned_membership_ref(lattice)
        cleanup = ExperimentCleanupContract.build(
            (
                CleanupBinding.build(
                    mutation_action_id=setup_action.action_id,
                    cleanup_action_id=revocation_action.action_id,
                    verification_action_id=revocation_verification_action.action_id,
                ),
            )
        )
        payload = _fixture_payload(
            lattice=lattice,
            membership_ref=membership_ref,
            setup_action=setup_action,
            revocation_action=revocation_action,
            revocation_verification_action=revocation_verification_action,
            cleanup=cleanup,
        )
        return cls(
            fixture_id=stable_hash("owned_membership_fixture", payload),
            lattice=lattice,
            membership_ref=membership_ref,
            subject_role_binding_id=lattice.lower.binding_id,
            setup_action=setup_action,
            revocation_action=revocation_action,
            revocation_verification_action=revocation_verification_action,
            cleanup=cleanup,
        )

    def __post_init__(self) -> None:
        payload = _fixture_payload(
            lattice=self.lattice,
            membership_ref=self.membership_ref,
            setup_action=self.setup_action,
            revocation_action=self.revocation_action,
            revocation_verification_action=self.revocation_verification_action,
            cleanup=self.cleanup,
        )
        actions = (
            self.setup_action,
            self.revocation_action,
            self.revocation_verification_action,
        )
        required_evidence = {
            self.lattice.lattice_id,
            self.lattice.tenant_ownership_ref,
            self.membership_ref,
        }
        expected_cleanup = ExperimentCleanupContract.build(
            (
                CleanupBinding.build(
                    mutation_action_id=self.setup_action.action_id,
                    cleanup_action_id=self.revocation_action.action_id,
                    verification_action_id=self.revocation_verification_action.action_id,
                ),
            )
        )
        if (
            self.fixture_id != stable_hash("owned_membership_fixture", payload)
            or not _hash_ref(self.fixture_id, "owned_membership_fixture")
            or self.membership_ref != owned_membership_ref(self.lattice)
            or self.subject_role_binding_id != self.lattice.lower.binding_id
            or self.setup_action.phase is not ExperimentPhase.SETUP
            or self.setup_action.action_class
            is not ExperimentActionClass.PRIVILEGE_MUTATION
            or self.setup_action.mutation
            is not MutationExpectation.PRIVILEGE_REVERSIBLE
            or self.revocation_action.phase is not ExperimentPhase.CLEANUP
            or self.revocation_action.action_class
            is not ExperimentActionClass.PRIVILEGE_MUTATION
            or self.revocation_action.mutation is not MutationExpectation.CLEANUP
            or self.revocation_verification_action.phase
            is not ExperimentPhase.CLEANUP_VERIFICATION
            or self.revocation_verification_action.action_class
            is not ExperimentActionClass.SAFE_READ
            or self.revocation_verification_action.mutation
            is not MutationExpectation.NONE
            or any(
                item.world_binding_id != self.lattice.higher.world_binding_id
                for item in actions
            )
            or any(not required_evidence <= set(item.evidence_refs) for item in actions)
            or not (
                self.setup_action.ordinal
                < self.revocation_action.ordinal
                < self.revocation_verification_action.ordinal
            )
            or self.cleanup != expected_cleanup
            or self.mode != ROLE_MEMBERSHIP_FIXTURE_MODE
            or (self.initial_state, self.provisioned_state, self.terminal_state)
            != ("absent", "active", "revoked")
            or not self.revocation_freshness_required
            or not self.cleanup_uncertainty_is_terminal
            or self.target_requests_sent != 0
            or self.budget_reserved
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("owned membership fixture is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "fixture_id": self.fixture_id,
            **_fixture_payload(
                lattice=self.lattice,
                membership_ref=self.membership_ref,
                setup_action=self.setup_action,
                revocation_action=self.revocation_action,
                revocation_verification_action=self.revocation_verification_action,
                cleanup=self.cleanup,
            ),
        }


__all__ = [
    "OwnedMembershipFixture",
    "ROLE_MEMBERSHIP_FIXTURE_MODE",
    "RoleAuthorityLattice",
    "RoleLatticeBinding",
    "RoleLatticePosition",
    "owned_membership_ref",
]
