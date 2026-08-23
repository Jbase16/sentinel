"""R5C1 typed role-lattice and reversible owned-membership tests."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from core.behavior.experiment_sdk import (
    ExperimentAction,
    ExperimentActionClass,
    ExperimentCleanupContract,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ExperimentWorldManifest,
    MutationExpectation,
)
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import ProofTopology, WorldRequirement
from core.behavior.role_membership import (
    ROLE_MEMBERSHIP_FIXTURE_MODE,
    OwnedMembershipFixture,
    RoleAuthorityLattice,
    RoleLatticePosition,
    owned_membership_ref,
)


def _role_world(slot: str, suffix: str, role_label: str) -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot=slot,
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", suffix),
        persona_ref=stable_hash("experiment_persona", suffix),
        ownership_ref=stable_hash("ownership_proof", suffix),
        role_ref=stable_hash("experiment_role", role_label),
    )


def _lattice() -> RoleAuthorityLattice:
    manifest = ExperimentWorldManifest.build(
        requirement=WorldRequirement(
            ProofTopology.OWNED_ROLE_DIFFERENTIAL,
            2,
            required_role_worlds=2,
        ),
        bindings=(
            _role_world("high_role", "alice", "ordinary-looking-role"),
            _role_world("low_role", "bob", "admin-looking-role"),
        ),
    )
    return RoleAuthorityLattice.build(
        world_manifest=manifest,
        tenant_ref=stable_hash("owned_tenant", "tenant-r5c1"),
        tenant_ownership_ref=stable_hash(
            "ownership_proof",
            "tenant-r5c1-created-by-researcher",
        ),
    )


def _action(
    *,
    lattice: RoleAuthorityLattice,
    ordinal: int,
    phase: ExperimentPhase,
    operation_id: str,
    action_class: ExperimentActionClass,
    mutation: MutationExpectation,
    world_binding_id: str | None = None,
    include_membership: bool = True,
) -> ExperimentAction:
    membership_ref = owned_membership_ref(lattice)
    evidence_refs = [lattice.lattice_id, lattice.tenant_ownership_ref]
    if include_membership:
        evidence_refs.append(membership_ref)
    return ExperimentAction.build(
        ordinal=ordinal,
        phase=phase,
        operation_id=operation_id,
        world_binding_id=(
            lattice.higher.world_binding_id
            if world_binding_id is None
            else world_binding_id
        ),
        action_class=action_class,
        endpoint_ref=stable_hash("experiment_endpoint", operation_id),
        mutation=mutation,
        evidence_refs=evidence_refs,
    )


def _fixture(
    *,
    setup_world_binding_id: str | None = None,
    setup_includes_membership: bool = True,
) -> OwnedMembershipFixture:
    lattice = _lattice()
    return OwnedMembershipFixture.build(
        lattice=lattice,
        setup_action=_action(
            lattice=lattice,
            ordinal=0,
            phase=ExperimentPhase.SETUP,
            operation_id="invite_owned_member",
            action_class=ExperimentActionClass.PRIVILEGE_MUTATION,
            mutation=MutationExpectation.PRIVILEGE_REVERSIBLE,
            world_binding_id=setup_world_binding_id,
            include_membership=setup_includes_membership,
        ),
        revocation_action=_action(
            lattice=lattice,
            ordinal=4,
            phase=ExperimentPhase.CLEANUP,
            operation_id="revoke_owned_member",
            action_class=ExperimentActionClass.PRIVILEGE_MUTATION,
            mutation=MutationExpectation.CLEANUP,
        ),
        revocation_verification_action=_action(
            lattice=lattice,
            ordinal=5,
            phase=ExperimentPhase.CLEANUP_VERIFICATION,
            operation_id="verify_owned_member_revoked",
            action_class=ExperimentActionClass.SAFE_READ,
            mutation=MutationExpectation.NONE,
        ),
    )


def test_fixture_seals_explicit_role_order_and_reversible_membership_without_authority():
    first = _fixture()
    second = _fixture()

    assert first == second
    assert first.mode == ROLE_MEMBERSHIP_FIXTURE_MODE
    assert first.lattice.lower.position is RoleLatticePosition.LOWER
    assert first.lattice.higher.position is RoleLatticePosition.HIGHER
    assert first.lattice.lower.role_ref != first.lattice.higher.role_ref
    assert first.lattice.lower.tenant_ref == first.lattice.higher.tenant_ref
    assert first.subject_role_binding_id == first.lattice.lower.binding_id
    assert first.cleanup.required is True
    assert len(first.cleanup.bindings) == 1
    assert first.cleanup.bindings[0].mutation_action_id == first.setup_action.action_id
    assert first.cleanup.bindings[0].cleanup_action_id == first.revocation_action.action_id
    assert (
        first.cleanup.bindings[0].verification_action_id
        == first.revocation_verification_action.action_id
    )
    assert first.revocation_freshness_required is True
    assert first.cleanup_uncertainty_is_terminal is True
    assert first.target_requests_sent == 0
    assert first.budget_reserved is False
    assert first.backend_dispatch_authority is False
    assert first.finding_authority is False
    assert first.executable is False

    public = json.dumps(first.to_dict(), sort_keys=True)
    assert "ordinary-looking-role" not in public
    assert "admin-looking-role" not in public


def test_role_order_comes_from_typed_positions_not_display_labels():
    lattice = _lattice()

    assert lattice.higher.position is RoleLatticePosition.HIGHER
    assert lattice.lower.position is RoleLatticePosition.LOWER
    assert lattice.higher.role_ref == stable_hash(
        "experiment_role",
        "ordinary-looking-role",
    )
    assert lattice.lower.role_ref == stable_hash(
        "experiment_role",
        "admin-looking-role",
    )


def test_lattice_rejects_a_non_role_world_topology():
    manifest = ExperimentWorldManifest.build(
        requirement=WorldRequirement(ProofTopology.PAIRED_OWNED_ACCOUNTS, 2),
        bindings=(
            ExperimentWorldBinding.build(
                slot="actor",
                kind=ExperimentWorldKind.OWNED_ACCOUNT,
                world_ref=stable_hash("world", "alice"),
                persona_ref=stable_hash("experiment_persona", "alice"),
                ownership_ref=stable_hash("ownership_proof", "alice"),
            ),
            ExperimentWorldBinding.build(
                slot="peer",
                kind=ExperimentWorldKind.OWNED_ACCOUNT,
                world_ref=stable_hash("world", "bob"),
                persona_ref=stable_hash("experiment_persona", "bob"),
                ownership_ref=stable_hash("ownership_proof", "bob"),
            ),
        ),
    )

    with pytest.raises(ValueError, match="owned role differential topology"):
        RoleAuthorityLattice.build(
            world_manifest=manifest,
            tenant_ref=stable_hash("owned_tenant", "tenant-r5c1"),
            tenant_ownership_ref=stable_hash("ownership_proof", "tenant-r5c1"),
        )


def test_membership_setup_cannot_be_substituted_to_the_low_role_world():
    lattice = _lattice()

    with pytest.raises(ValueError, match="owned membership fixture"):
        _fixture(setup_world_binding_id=lattice.lower.world_binding_id)


def test_membership_actions_must_bind_the_exact_membership_evidence():
    with pytest.raises(ValueError, match="owned membership fixture"):
        _fixture(setup_includes_membership=False)


def test_cleanup_and_content_addressing_cannot_be_removed_or_forged():
    fixture = _fixture()

    with pytest.raises(ValueError, match="owned membership fixture"):
        replace(fixture, cleanup=ExperimentCleanupContract.build())
    with pytest.raises(ValueError, match="role authority lattice"):
        replace(
            fixture.lattice,
            lattice_id=stable_hash("role_authority_lattice", "forged"),
        )
    with pytest.raises(ValueError, match="owned membership fixture"):
        replace(
            fixture,
            fixture_id=stable_hash("owned_membership_fixture", "forged"),
        )
