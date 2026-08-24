"""R5C3 exact runtime request-binding and pre-traffic denial tests."""

from __future__ import annotations

import ast
import copy
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.behavior.compiler import OperationContract
from core.behavior.experiment_admission import (
    experiment_authority_context_ref,
    experiment_endpoint_ref,
    experiment_ownership_ref,
    experiment_persona_ref,
)
from core.behavior.experiment_sdk import (
    ExperimentAction,
    ExperimentActionClass,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ExperimentWorldManifest,
    MutationExpectation,
)
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import (
    PayoutSink,
    ProofTopology,
    SecurityProperty,
    SecurityWitnessGoal,
    WorldRequirement,
)
from core.behavior.role_membership import (
    OwnedMembershipFixture,
    RoleAuthorityLattice,
    owned_membership_ref,
)
from core.behavior.role_monotonicity import (
    ROLE_MONOTONICITY_WORKFLOW,
    RoleMonotonicityExperimentAdmission,
    RoleMonotonicityExperimentCompiler,
    RoleMonotonicityExperimentDenied,
)
from core.behavior.role_request_binding import (
    ROLE_MONOTONICITY_REQUEST_BINDING_MODE,
    RoleMonotonicityRequestBindingDenied,
    RoleMonotonicityRuntimeContext,
    role_tenant_ownership_ref,
)
from core.cortex.execution_policy import (
    CandidateAction,
    ExecutionPolicy,
    PolicyExecutor,
)
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.proof_mode import ProofMode
from core.safety.provenance import ProvenanceSink


ORIGIN = "https://roles.example.test"
TENANT_ID = "tenant_018f8f44d5b649db"
RUN_ID = "r5c3-run-001"
HIGH_SESSION = "high-session-secret"
ACTIVE_LOW_SESSION = "active-low-session-secret"
REVOKED_LOW_SESSION = "revoked-low-session-secret"
QUERY_SECRET = "query-secret-r5c3"
BODY_SECRET = "body-secret-r5c3"


def _authorization(
    *,
    workflows: tuple[str, ...] = (ROLE_MONOTONICITY_WORKFLOW,),
    sign: bool = True,
) -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="r5c3-runtime-binding",
        researcher_identity="researcher",
        target_handle="owned-role-twin",
        authorized_origins=[ORIGIN],
        authorization_basis="owned role request-binding test",
        disclosure_attestation=True,
        allowed_workflows=list(workflows),
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    if sign:
        envelope.sign()
    return envelope


def _goal() -> SecurityWitnessGoal:
    operation = OperationContract(
        operation_id=stable_hash("action", "r5c3-owned-admin-effect"),
        label="read owned administrative effect",
        requires=(),
        produces=(),
        observed_success=True,
        source_refs=(stable_hash("source_ref", "r5c3-admin-effect"),),
    )
    return SecurityWitnessGoal.build(
        operation=operation,
        sink=PayoutSink.AUTHORITY,
        security_property=SecurityProperty.AUTHORITY_MONOTONICITY,
        evidence_refs=(stable_hash("provenance", "r5c3-goal"),),
    )


def _experiment_action(
    *,
    ordinal: int,
    phase: ExperimentPhase,
    operation_id: str,
    method: str,
    url: str,
    world_binding_id: str,
    action_class: ExperimentActionClass,
    mutation: MutationExpectation,
    evidence_refs: tuple[str, ...],
) -> ExperimentAction:
    return ExperimentAction.build(
        ordinal=ordinal,
        phase=phase,
        operation_id=operation_id,
        world_binding_id=world_binding_id,
        action_class=action_class,
        endpoint_ref=experiment_endpoint_ref(method, url),
        mutation=mutation,
        evidence_refs=evidence_refs,
    )


def _candidate(
    action: ExperimentAction,
    *,
    method: str,
    url: str,
    actor_persona_id: str,
    target_owner_persona_id: str,
    body=None,
    expected_side_effect: str = "none",
) -> CandidateAction:
    return CandidateAction(
        method=method,
        url=url,
        body=body,
        hint=action.action_class.value,
        actor_persona_id=actor_persona_id,
        target_owner_persona_id=target_owner_persona_id,
        target_is_researcher_owned=True,
        expected_side_effect=expected_side_effect,
        proof_goal=action.operation_id,
    )


def _context(tmp_path, monkeypatch) -> SimpleNamespace:
    monkeypatch.setenv(
        "SENTINELFORGE_PERSONA_VAULT",
        str(tmp_path / "personas"),
    )
    vault = PersonaVault()
    higher = vault.add_persona(
        label="R5C3 higher",
        email="higher-r5c3@example.test",
    )
    lower = vault.add_persona(
        label="R5C3 lower",
        email="lower-r5c3@example.test",
    )
    authorization = _authorization()
    higher_world = ExperimentWorldBinding.build(
        slot="high_role",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", higher.persona_id),
        persona_ref=experiment_persona_ref(higher.persona_id),
        ownership_ref=experiment_ownership_ref(
            authorization,
            higher.persona_id,
        ),
        role_ref=stable_hash("experiment_role", "ordinary-looking-role"),
    )
    lower_world = ExperimentWorldBinding.build(
        slot="low_role",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", lower.persona_id),
        persona_ref=experiment_persona_ref(lower.persona_id),
        ownership_ref=experiment_ownership_ref(
            authorization,
            lower.persona_id,
        ),
        role_ref=stable_hash("experiment_role", "admin-looking-role"),
    )
    manifest = ExperimentWorldManifest.build(
        requirement=WorldRequirement(
            ProofTopology.OWNED_ROLE_DIFFERENTIAL,
            2,
            required_role_worlds=2,
        ),
        bindings=(higher_world, lower_world),
    )
    lattice = RoleAuthorityLattice.build(
        world_manifest=manifest,
        tenant_ref=stable_hash("owned_tenant", TENANT_ID),
        tenant_ownership_ref=role_tenant_ownership_ref(
            authorization,
            TENANT_ID,
        ),
    )
    membership_ref = owned_membership_ref(lattice)
    fixture_evidence = (
        lattice.lattice_id,
        lattice.tenant_ownership_ref,
        membership_ref,
    )
    membership_collection = f"{ORIGIN}/api/tenants/{TENANT_ID}/memberships"
    membership_item = f"{membership_collection}/{lower.persona_id}"
    probe_base = f"{ORIGIN}/api/tenants/{TENANT_ID}/admin-effect"
    witness_base = f"{ORIGIN}/api/tenants/{TENANT_ID}/authoritative-effect"
    setup = _experiment_action(
        ordinal=0,
        phase=ExperimentPhase.SETUP,
        operation_id="invite_owned_member",
        method="POST",
        url=membership_collection,
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.PRIVILEGE_MUTATION,
        mutation=MutationExpectation.PRIVILEGE_REVERSIBLE,
        evidence_refs=fixture_evidence,
    )
    revocation = _experiment_action(
        ordinal=4,
        phase=ExperimentPhase.CLEANUP,
        operation_id="revoke_owned_member",
        method="PATCH",
        url=membership_item,
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.PRIVILEGE_MUTATION,
        mutation=MutationExpectation.CLEANUP,
        evidence_refs=fixture_evidence,
    )
    revocation_verification = _experiment_action(
        ordinal=5,
        phase=ExperimentPhase.CLEANUP_VERIFICATION,
        operation_id="verify_owned_member_revoked",
        method="GET",
        url=membership_item,
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        mutation=MutationExpectation.NONE,
        evidence_refs=fixture_evidence,
    )
    fixture = OwnedMembershipFixture.build(
        lattice=lattice,
        setup_action=setup,
        revocation_action=revocation,
        revocation_verification_action=revocation_verification,
    )
    goal = _goal()
    proof_evidence = (
        fixture.fixture_id,
        fixture.lattice.lattice_id,
        fixture.membership_ref,
        goal.goal_id,
    )
    higher_baseline = _experiment_action(
        ordinal=1,
        phase=ExperimentPhase.CONTROL,
        operation_id="probe_admin_effect",
        method="GET",
        url=probe_base,
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.AUTHZ_PROBE,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    active_lower_probe = _experiment_action(
        ordinal=2,
        phase=ExperimentPhase.TREATMENT,
        operation_id="probe_admin_effect",
        method="GET",
        url=probe_base,
        world_binding_id=lattice.lower.world_binding_id,
        action_class=ExperimentActionClass.AUTHZ_PROBE,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    active_witness = _experiment_action(
        ordinal=3,
        phase=ExperimentPhase.WITNESS,
        operation_id="read_authoritative_effect",
        method="GET",
        url=witness_base,
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    revoked_lower_probe = _experiment_action(
        ordinal=6,
        phase=ExperimentPhase.TREATMENT,
        operation_id="probe_admin_effect",
        method="GET",
        url=probe_base,
        world_binding_id=lattice.lower.world_binding_id,
        action_class=ExperimentActionClass.AUTHZ_PROBE,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    revoked_witness = _experiment_action(
        ordinal=7,
        phase=ExperimentPhase.WITNESS,
        operation_id="read_authoritative_effect",
        method="GET",
        url=witness_base,
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    proof = RoleMonotonicityExperimentCompiler().compile(
        fixture=fixture,
        goal=goal,
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        authority_context_ref=experiment_authority_context_ref(
            authorization,
            ORIGIN,
            (ROLE_MONOTONICITY_WORKFLOW,),
        ),
        higher_baseline=higher_baseline,
        active_lower_probe=active_lower_probe,
        active_effect_witness=active_witness,
        revoked_lower_probe=revoked_lower_probe,
        revoked_effect_witness=revoked_witness,
    )
    runtime_actions = {
        setup.action_id: _candidate(
            setup,
            method="POST",
            url=membership_collection,
            actor_persona_id=higher.persona_id,
            target_owner_persona_id=lower.persona_id,
            body={
                "member_id": lower.persona_id,
                "role_assignment": lattice.lower.role_ref,
                "nonce": BODY_SECRET,
            },
            expected_side_effect="provision_owned_membership",
        ),
        higher_baseline.action_id: _candidate(
            higher_baseline,
            method="GET",
            url=f"{probe_base}?state=baseline&token={QUERY_SECRET}",
            actor_persona_id=higher.persona_id,
            target_owner_persona_id=higher.persona_id,
        ),
        active_lower_probe.action_id: _candidate(
            active_lower_probe,
            method="GET",
            url=f"{probe_base}?state=active&token={QUERY_SECRET}",
            actor_persona_id=lower.persona_id,
            target_owner_persona_id=higher.persona_id,
        ),
        active_witness.action_id: _candidate(
            active_witness,
            method="GET",
            url=f"{witness_base}?state=active&token={QUERY_SECRET}",
            actor_persona_id=higher.persona_id,
            target_owner_persona_id=higher.persona_id,
        ),
        revocation.action_id: _candidate(
            revocation,
            method="PATCH",
            url=membership_item,
            actor_persona_id=higher.persona_id,
            target_owner_persona_id=lower.persona_id,
            body={"state": "revoked", "nonce": BODY_SECRET},
            expected_side_effect="cleanup_owned_test_object",
        ),
        revocation_verification.action_id: _candidate(
            revocation_verification,
            method="GET",
            url=membership_item,
            actor_persona_id=higher.persona_id,
            target_owner_persona_id=lower.persona_id,
        ),
        revoked_lower_probe.action_id: _candidate(
            revoked_lower_probe,
            method="GET",
            url=f"{probe_base}?state=revoked&token={QUERY_SECRET}",
            actor_persona_id=lower.persona_id,
            target_owner_persona_id=higher.persona_id,
        ),
        revoked_witness.action_id: _candidate(
            revoked_witness,
            method="GET",
            url=f"{witness_base}?state=revoked&token={QUERY_SECRET}",
            actor_persona_id=higher.persona_id,
            target_owner_persona_id=higher.persona_id,
        ),
    }
    runtime = RoleMonotonicityRuntimeContext.build(
        proof=proof,
        authorization=authorization,
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        higher_persona_id=higher.persona_id,
        lower_persona_id=lower.persona_id,
        higher_session_id=HIGH_SESSION,
        active_lower_session_id=ACTIVE_LOW_SESSION,
        revoked_lower_session_id=REVOKED_LOW_SESSION,
        active_membership_generation=41,
        revoked_membership_generation=42,
        runtime_actions=runtime_actions,
    )

    calls = []

    async def forbidden_transport(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("R5C3 request binding must not invoke transport")

    policy = ExecutionPolicy(
        ProofMode.BOUNTY_SAFE,
        scope_filter=lambda url: str(url).startswith(f"{ORIGIN}/"),
        budget=ProofBudget(
            max_total_requests=20,
            max_requests_per_endpoint=5,
            max_cross_object_reads=0,
            max_privilege_mutations=2,
            max_creates=0,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
        ownership_registry=OwnershipRegistry(),
    )
    executor = PolicyExecutor(
        forbidden_transport,
        policy,
        provenance=ProvenanceSink(),
    )
    validator_calls = []

    def authority_validator(current_proof, admission, current_runtime):
        validator_calls.append(
            (current_proof.proof_id, admission.admission_id, current_runtime.run_ref)
        )
        return (
            current_proof.proof_id == proof.proof_id
            and current_runtime.run_id == RUN_ID
            and current_runtime.tenant_id == TENANT_ID
            and current_runtime.higher_persona_id == higher.persona_id
            and current_runtime.lower_persona_id == lower.persona_id
        )

    coordinator = RoleMonotonicityExperimentAdmission(
        proof=proof,
        target_origin=ORIGIN,
        authorization=authorization,
    )
    return SimpleNamespace(
        authorization=authorization,
        vault=vault,
        higher=higher,
        lower=lower,
        proof=proof,
        runtime=runtime,
        executor=executor,
        calls=calls,
        validator=authority_validator,
        validator_calls=validator_calls,
        coordinator=coordinator,
    )


def _bind(context, *, runtime=None, validator=None, coordinator=None):
    return (coordinator or context.coordinator).bind_requests(
        executor=context.executor,
        persona_vault=context.vault,
        runtime=runtime or context.runtime,
        authority_validator=validator or context.validator,
    )


def test_admission_boundary_binds_exact_owned_runtime_intent_without_authority(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    before = context.executor.policy.budget.snapshot()

    result = _bind(context)

    assert result.mode == ROLE_MONOTONICITY_REQUEST_BINDING_MODE
    assert result.proof_id == context.proof.proof_id
    assert result.request_bindings_complete is True
    assert result.owned_runtime_state_attested is True
    assert result.revocation_freshness_bound is True
    assert result.cleanup_lineage_bound is True
    assert result.receipt_lineage_bound is True
    assert result.policy_preflight_complete is True
    assert result.budget_preview_only is True
    assert result.remaining_execution_blockers == (
        "atomic_budget_reservation_required",
        "durable_execution_receipt_required",
        "effect_evaluation_required",
    )
    assert tuple(item.slot for item in result.world_bindings) == (
        "high_role",
        "low_role",
    )
    assert tuple(
        item.request_binding.ordinal for item in result.action_bindings
    ) == tuple(range(8))
    assert tuple(item.membership_state for item in result.action_bindings) == (
        "active",
        "active",
        "active",
        "active",
        "revoking",
        "revoked",
        "revoked",
        "revoked",
    )
    assert result.target_requests_sent == 0
    assert result.budget_reserved is False
    assert result.durable_execution_receipt is False
    assert result.single_use_claim_available is False
    assert result.backend_dispatch_authority is False
    assert result.finding_authority is False
    assert result.executable is False
    assert context.proof.execution_blockers == (
        "atomic_budget_reservation_required",
        "durable_execution_receipt_required",
        "effect_evaluation_required",
        "runtime_request_binding_required",
    )
    assert context.coordinator.admit().execution_blockers == (
        "atomic_budget_reservation_required",
        "durable_execution_receipt_required",
        "effect_evaluation_required",
        "runtime_request_binding_required",
    )
    assert context.executor.policy.budget.snapshot() == before
    assert context.calls == []
    assert len(context.validator_calls) == 1


def test_binding_is_deterministic_content_addressed_and_publicly_redacted(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)

    first = _bind(context)
    second = _bind(context)
    public = json.dumps(first.to_dict(), sort_keys=True)

    assert first.to_dict() == second.to_dict()
    assert "ordinary-looking-role" not in public
    assert "admin-looking-role" not in public
    for secret in (
        ORIGIN,
        TENANT_ID,
        context.higher.persona_id,
        context.lower.persona_id,
        HIGH_SESSION,
        ACTIVE_LOW_SESSION,
        REVOKED_LOW_SESSION,
        QUERY_SECRET,
        BODY_SECRET,
        context.authorization.envelope_id,
    ):
        assert secret not in public
    assert "request_material_fingerprint" in public
    assert "endpoint_key_ref" in public
    assert "runtime_actions" not in public
    assert context.calls == []
    with pytest.raises(ValueError, match="request binding is invalid"):
        replace(first, target_requests_sent=1)
    with pytest.raises(ValueError, match="action authority binding is invalid"):
        replace(
            first.action_bindings[0],
            session_ref=stable_hash("role_runtime_session", "forged"),
        )


def _changed_action_runtime(context, action_id, **changes):
    actions = copy.deepcopy(dict(context.runtime.runtime_actions))
    for key, value in changes.items():
        setattr(actions[action_id], key, value)
    return replace(context.runtime, runtime_actions=actions)


def _mutated_runtime(context, case):
    runtime = context.runtime
    if case == "role_label_forgery":
        return replace(
            runtime,
            higher_role_ref=stable_hash("experiment_role", "forged-admin-label"),
        )
    if case == "higher_lower_world_substitution":
        return replace(
            runtime,
            higher_persona_id=runtime.lower_persona_id,
            lower_persona_id=runtime.higher_persona_id,
        )
    if case == "cross_tenant_splice":
        return replace(runtime, tenant_id="tenant_ffffffffffffffff")
    if case == "cross_run_splice":
        return replace(runtime, run_id="r5c3-run-spliced")
    if case == "unowned_tenant_evidence":
        return replace(
            runtime,
            tenant_ownership_ref=stable_hash("ownership_proof", "unowned"),
        )
    if case == "unowned_membership_evidence":
        return replace(
            runtime,
            membership_ref=stable_hash("owned_membership", "other"),
        )
    if case == "actor_substitution":
        return _changed_action_runtime(
            context,
            context.proof.active_lower_probe.action_id,
            actor_persona_id=runtime.higher_persona_id,
        )
    if case == "origin_substitution":
        return _changed_action_runtime(
            context,
            context.proof.active_lower_probe.action_id,
            url="https://outside.example.test/api/admin-effect",
        )
    if case == "method_substitution":
        return _changed_action_runtime(
            context,
            context.proof.active_lower_probe.action_id,
            method="POST",
        )
    if case == "route_substitution":
        return _changed_action_runtime(
            context,
            context.proof.active_lower_probe.action_id,
            url=f"{ORIGIN}/api/tenants/{TENANT_ID}/other-effect",
        )
    if case == "query_substitution":
        action = runtime.runtime_actions[context.proof.active_lower_probe.action_id]
        return _changed_action_runtime(
            context,
            context.proof.active_lower_probe.action_id,
            url=f"{action.url}&extra=forged",
        )
    if case == "body_substitution":
        return _changed_action_runtime(
            context,
            context.proof.fixture.setup_action.action_id,
            body={"member_id": runtime.higher_persona_id, "nonce": "forged"},
        )
    if case == "action_not_admitted":
        actions = copy.deepcopy(dict(runtime.runtime_actions))
        actions.pop(context.proof.revoked_effect_witness.action_id)
        return replace(runtime, runtime_actions=actions)
    if case == "session_reuse":
        return replace(
            runtime,
            revoked_lower_session_id=runtime.active_lower_session_id,
        )
    if case == "stale_revocation_generation":
        return replace(
            runtime,
            revoked_membership_generation=runtime.active_membership_generation,
        )
    if case == "stale_revocation_evidence":
        return replace(
            runtime,
            revocation_verification_ref=stable_hash(
                "role_membership_revocation_verification",
                runtime.active_membership_evidence_ref,
            ),
        )
    raise AssertionError(f"unknown mutation case: {case}")


@pytest.mark.parametrize(
    "case",
    (
        "role_label_forgery",
        "higher_lower_world_substitution",
        "cross_tenant_splice",
        "cross_run_splice",
        "unowned_tenant_evidence",
        "unowned_membership_evidence",
        "actor_substitution",
        "origin_substitution",
        "method_substitution",
        "route_substitution",
        "query_substitution",
        "body_substitution",
        "action_not_admitted",
        "session_reuse",
        "stale_revocation_generation",
        "stale_revocation_evidence",
    ),
)
def test_runtime_splices_and_request_substitutions_fail_before_transport(
    tmp_path,
    monkeypatch,
    case,
):
    context = _context(tmp_path, monkeypatch)

    with pytest.raises(RoleMonotonicityRequestBindingDenied):
        _bind(context, runtime=_mutated_runtime(context, case))

    assert context.executor.policy.budget.snapshot()["total_requests"] == 0
    assert context.calls == []


def test_missing_or_mismatched_signed_authority_fails_before_binding_or_transport(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    unsigned = RoleMonotonicityExperimentAdmission(
        proof=context.proof,
        target_origin=ORIGIN,
        authorization=_authorization(sign=False),
    )
    missing_workflow = RoleMonotonicityExperimentAdmission(
        proof=context.proof,
        target_origin=ORIGIN,
        authorization=_authorization(workflows=()),
    )
    changed = copy.deepcopy(context.authorization)
    changed.target_handle = "changed-after-proof"
    changed.sign()
    mismatched = RoleMonotonicityExperimentAdmission(
        proof=context.proof,
        target_origin=ORIGIN,
        authorization=changed,
    )

    for coordinator in (unsigned, missing_workflow, mismatched):
        with pytest.raises(RoleMonotonicityExperimentDenied):
            _bind(context, coordinator=coordinator)

    assert context.calls == []


def test_missing_owned_state_attestation_or_persona_fails_before_transport(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)

    with pytest.raises(
        RoleMonotonicityRequestBindingDenied,
        match="owned_runtime_state_attestation_denied",
    ):
        _bind(context, validator=lambda *_args: False)

    monkeypatch.setenv(
        "SENTINELFORGE_PERSONA_VAULT",
        str(tmp_path / "empty-personas"),
    )
    empty_vault = PersonaVault()
    with pytest.raises(
        RoleMonotonicityRequestBindingDenied,
        match="owned_persona_is_not_in_vault",
    ):
        context.coordinator.bind_requests(
            executor=context.executor,
            persona_vault=empty_vault,
            runtime=context.runtime,
            authority_validator=context.validator,
        )

    assert context.calls == []


def test_request_binding_module_has_no_transport_or_execution_surface():
    source_path = (
        Path(__file__).parents[2]
        / "core"
        / "behavior"
        / "role_request_binding.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert ".send(" not in source
    assert ".send_action(" not in source
    assert ".try_reserve(" not in source
    assert "PolicyExecutor(" not in source
    assert ".preview_reservation(" in source
