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
from core.behavior.experiment_admission import experiment_authority_context_ref
from core.behavior.compiler import OperationContract
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import (
    PayoutSink,
    ProofTopology,
    SecurityProperty,
    SecurityWitnessGoal,
    WorldRequirement,
)
from core.behavior.role_membership import (
    ROLE_MEMBERSHIP_FIXTURE_MODE,
    OwnedMembershipFixture,
    RoleAuthorityLattice,
    RoleLatticePosition,
    owned_membership_ref,
)
from core.behavior.role_monotonicity import (
    ROLE_MONOTONICITY_ADMISSION_MODE,
    ROLE_MONOTONICITY_PROOF_MODE,
    ROLE_MONOTONICITY_WORKFLOW,
    RoleMonotonicityExperimentAdmission,
    RoleMonotonicityExperimentCompiler,
    RoleMonotonicityExperimentDenied,
)
from core.foundry.authorization import AuthorizationEnvelope


ORIGIN = "https://roles.example.test"


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


def _goal() -> SecurityWitnessGoal:
    operation = OperationContract(
        operation_id=stable_hash("action", "read-owned-admin-effect"),
        label="read owned administrative effect",
        requires=(),
        produces=(),
        observed_success=True,
        source_refs=(stable_hash("source_ref", "r5c2-admin-effect"),),
    )
    return SecurityWitnessGoal.build(
        operation=operation,
        sink=PayoutSink.AUTHORITY,
        security_property=SecurityProperty.AUTHORITY_MONOTONICITY,
        evidence_refs=(stable_hash("provenance", "r5c2-goal"),),
    )


def _authorization(
    *,
    workflows: tuple[str, ...] = (ROLE_MONOTONICITY_WORKFLOW,),
    sign: bool = True,
) -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="r5c2-role-monotonicity",
        researcher_identity="researcher",
        target_handle="owned-role-twin",
        authorized_origins=[ORIGIN],
        authorization_basis="owned role monotonicity contract test",
        disclosure_attestation=True,
        allowed_workflows=list(workflows),
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    if sign:
        envelope.sign()
    return envelope


def _monotonicity_action(
    *,
    fixture: OwnedMembershipFixture,
    goal: SecurityWitnessGoal,
    ordinal: int,
    phase: ExperimentPhase,
    operation_id: str,
    endpoint_name: str,
    action_class: ExperimentActionClass,
    world_binding_id: str,
    include_goal: bool = True,
) -> ExperimentAction:
    evidence_refs = [
        fixture.fixture_id,
        fixture.lattice.lattice_id,
        fixture.membership_ref,
    ]
    if include_goal:
        evidence_refs.append(goal.goal_id)
    return ExperimentAction.build(
        ordinal=ordinal,
        phase=phase,
        operation_id=operation_id,
        world_binding_id=world_binding_id,
        action_class=action_class,
        endpoint_ref=stable_hash("experiment_endpoint", endpoint_name),
        mutation=MutationExpectation.NONE,
        evidence_refs=evidence_refs,
    )


def _proof_context(
    *,
    active_lower_on_higher: bool = False,
    active_witness_endpoint: str = "authoritative-effect-witness",
    revoked_ordinal: int = 6,
    active_lower_includes_goal: bool = True,
    authorization: AuthorizationEnvelope | None = None,
):
    fixture = _fixture()
    goal = _goal()
    envelope = authorization or _authorization()
    higher = fixture.lattice.higher.world_binding_id
    lower = fixture.lattice.lower.world_binding_id
    actions = {
        "higher_baseline": _monotonicity_action(
            fixture=fixture,
            goal=goal,
            ordinal=1,
            phase=ExperimentPhase.CONTROL,
            operation_id="probe_admin_effect",
            endpoint_name="admin-effect",
            action_class=ExperimentActionClass.AUTHZ_PROBE,
            world_binding_id=higher,
        ),
        "active_lower_probe": _monotonicity_action(
            fixture=fixture,
            goal=goal,
            ordinal=2,
            phase=ExperimentPhase.TREATMENT,
            operation_id="probe_admin_effect",
            endpoint_name="admin-effect",
            action_class=ExperimentActionClass.AUTHZ_PROBE,
            world_binding_id=(higher if active_lower_on_higher else lower),
            include_goal=active_lower_includes_goal,
        ),
        "active_effect_witness": _monotonicity_action(
            fixture=fixture,
            goal=goal,
            ordinal=3,
            phase=ExperimentPhase.WITNESS,
            operation_id="read_authoritative_effect",
            endpoint_name=active_witness_endpoint,
            action_class=ExperimentActionClass.SAFE_READ,
            world_binding_id=higher,
        ),
        "revoked_lower_probe": _monotonicity_action(
            fixture=fixture,
            goal=goal,
            ordinal=revoked_ordinal,
            phase=ExperimentPhase.TREATMENT,
            operation_id="probe_admin_effect",
            endpoint_name="admin-effect",
            action_class=ExperimentActionClass.AUTHZ_PROBE,
            world_binding_id=lower,
        ),
        "revoked_effect_witness": _monotonicity_action(
            fixture=fixture,
            goal=goal,
            ordinal=7,
            phase=ExperimentPhase.WITNESS,
            operation_id="read_authoritative_effect",
            endpoint_name="authoritative-effect-witness",
            action_class=ExperimentActionClass.SAFE_READ,
            world_binding_id=higher,
        ),
    }
    compiler = RoleMonotonicityExperimentCompiler()
    proof = compiler.compile(
        fixture=fixture,
        goal=goal,
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        authority_context_ref=experiment_authority_context_ref(
            envelope,
            ORIGIN,
            (ROLE_MONOTONICITY_WORKFLOW,),
        ),
        **actions,
    )
    return {
        "fixture": fixture,
        "goal": goal,
        "authorization": envelope,
        "actions": actions,
        "compiler": compiler,
        "proof": proof,
    }


def test_monotonicity_compiler_seals_active_and_revoked_comparisons_without_authority():
    first = _proof_context()
    second = _proof_context()
    proof = first["proof"]

    assert proof == second["proof"]
    assert proof.mode == ROLE_MONOTONICITY_PROOF_MODE
    assert proof.oracle.goal.security_property is SecurityProperty.AUTHORITY_MONOTONICITY
    assert proof.oracle.fixture_id == proof.fixture.fixture_id
    assert proof.oracle.active_effect_requires_independent_witness is True
    assert proof.oracle.revoked_effect_requires_independent_witness is True
    assert "membership_revocation_verified" in proof.oracle.witness_requirements
    assert "post_revocation_freshness" in proof.oracle.witness_requirements
    assert proof.execution_blockers == (
        "atomic_budget_reservation_required",
        "durable_execution_receipt_required",
        "effect_evaluation_required",
        "runtime_request_binding_required",
    )
    assert proof.target_requests_sent == 0
    assert proof.budget_reserved is False
    assert proof.single_use_claim_available is False
    assert proof.backend_dispatch_authority is False
    assert proof.finding_authority is False
    assert proof.executable is False


def test_monotonicity_admission_revalidates_signed_workflow_without_claim_authority():
    context = _proof_context()

    contract = RoleMonotonicityExperimentAdmission(
        proof=context["proof"],
        target_origin=ORIGIN,
        authorization=context["authorization"],
    ).admit()

    assert contract.mode == ROLE_MONOTONICITY_ADMISSION_MODE
    assert contract.proof_id == context["proof"].proof_id
    assert contract.fixture_id == context["fixture"].fixture_id
    assert contract.oracle_id == context["proof"].oracle.oracle_id
    assert contract.signed_authority_revalidated is True
    assert contract.role_contract_revalidated is True
    assert contract.revocation_contract_revalidated is True
    assert contract.target_requests_sent == 0
    assert contract.budget_reserved is False
    assert contract.single_use_claim_available is False
    assert contract.backend_dispatch_authority is False
    assert contract.finding_authority is False
    assert contract.executable is False


@pytest.mark.parametrize(
    "options,reason",
    (
        ({"active_lower_on_higher": True}, "action_shape_is_invalid"),
        (
            {"active_witness_endpoint": "admin-effect"},
            "probe_or_witness_is_not_equivalent",
        ),
        ({"revoked_ordinal": 5}, "action_sequence_is_invalid"),
        ({"active_lower_includes_goal": False}, "action_shape_is_invalid"),
    ),
)
def test_monotonicity_compiler_rejects_world_witness_sequence_and_evidence_splices(
    options,
    reason,
):
    with pytest.raises(RoleMonotonicityExperimentDenied, match=reason):
        _proof_context(**options)


def test_monotonicity_proof_revalidates_semantics_without_trusting_its_hash():
    context = _proof_context()
    proof = context["proof"]
    spliced = _monotonicity_action(
        fixture=context["fixture"],
        goal=context["goal"],
        ordinal=2,
        phase=ExperimentPhase.TREATMENT,
        operation_id="probe_admin_effect",
        endpoint_name="admin-effect",
        action_class=ExperimentActionClass.AUTHZ_PROBE,
        world_binding_id=context["fixture"].lattice.higher.world_binding_id,
    )

    with pytest.raises(RoleMonotonicityExperimentDenied, match="action_shape_is_invalid"):
        replace(proof, active_lower_probe=spliced)


def test_monotonicity_admission_rejects_unsigned_or_missing_workflow_before_traffic():
    context = _proof_context()

    with pytest.raises(RoleMonotonicityExperimentDenied, match="unsigned"):
        RoleMonotonicityExperimentAdmission(
            proof=context["proof"],
            target_origin=ORIGIN,
            authorization=_authorization(sign=False),
        ).admit()
    with pytest.raises(RoleMonotonicityExperimentDenied, match="authorization_denied"):
        RoleMonotonicityExperimentAdmission(
            proof=context["proof"],
            target_origin=ORIGIN,
            authorization=_authorization(workflows=()),
        ).admit()


def test_monotonicity_admission_rejects_origin_or_authority_context_substitution():
    context = _proof_context()

    with pytest.raises(RoleMonotonicityExperimentDenied, match="authorization_denied"):
        RoleMonotonicityExperimentAdmission(
            proof=context["proof"],
            target_origin="https://outside.example.test",
            authorization=context["authorization"],
        ).admit()
    changed = _authorization()
    changed.target_handle = "changed-after-proof"
    changed.sign()
    with pytest.raises(
        RoleMonotonicityExperimentDenied,
        match="target_or_authority_context_mismatch",
    ):
        RoleMonotonicityExperimentAdmission(
            proof=context["proof"],
            target_origin=ORIGIN,
            authorization=changed,
        ).admit()


def test_monotonicity_public_contract_contains_no_role_labels_or_origin():
    context = _proof_context()
    public = json.dumps(context["proof"].to_dict(), sort_keys=True)

    assert "ordinary-looking-role" not in public
    assert "admin-looking-role" not in public
    assert ORIGIN not in public
