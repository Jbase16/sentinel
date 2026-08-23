import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.behavior.normalize import stable_hash
from core.behavior.orchestrator import (
    BehavioralShadowOrchestrator,
    OwnedExperimentShadowContext,
)
from core.behavior.prerequisite_admission import (
    GRAPH_BOUND_PREREQUISITE_WORKFLOW,
    GraphBoundManifestAdmissionPlanner,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink
from tests.unit.test_behavior_prerequisite_experiments import (
    ORIGIN,
    _branch_join_records,
    _compile,
    _omission_records,
)


def _authorization(*, workflows=(GRAPH_BOUND_PREREQUISITE_WORKFLOW,)):
    envelope = AuthorizationEnvelope(
        envelope_id="graph-bound-admission-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized graph-bound admission test",
        disclosure_attestation=True,
        allowed_workflows=list(workflows),
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def _executor(*, max_total_requests=96):
    calls = []

    async def forbidden_transport(method, url, body=None, **kwargs):
        calls.append((method, url, body, kwargs))
        raise AssertionError("static graph-bound admission must not invoke transport")

    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=max_total_requests,
            max_requests_per_endpoint=20,
            max_creates=20,
            allow_real_user_data_access=False,
        ),
        ownership_registry=OwnershipRegistry(),
    )
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    return PolicyExecutor(forbidden_transport, policy, provenance=provenance), calls


def _plan(*, authorization=None, executor=None):
    _lifecycle, _state_machine, compilation = _compile(_branch_join_records())
    planner = GraphBoundManifestAdmissionPlanner()
    context = {}
    if authorization is not None or executor is not None:
        context = {
            "authorization": authorization or _authorization(),
            "executor": executor or _executor()[0],
            "actor_persona_id": "alice",
        }
    result = planner.plan(
        compilation=compilation,
        target_origin=ORIGIN,
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        world_id="alice",
        **context,
    )
    return compilation, result


def test_static_admission_requires_an_explicit_complete_authority_context():
    compilation, result = _plan()

    assert result.status == "not_requested"
    assert result.compilation_result_id == compilation.result_id
    assert result.manifests == ()
    assert result.blocker == "graph_bound_manifest_authority_context_not_requested"
    assert result.static_admission_only is True
    assert result.dispatch_authority is False
    assert result.finding_authority is False
    assert result.target_requests_sent == 0
    assert result.executable is False

    with pytest.raises(ValueError, match="context must be complete"):
        GraphBoundManifestAdmissionPlanner().plan(
            compilation=compilation,
            target_origin=ORIGIN,
            target_ref=stable_hash("security_obligation_target", ORIGIN),
            world_id="alice",
            authorization=_authorization(),
        )


def test_valid_context_seals_each_graph_specification_without_dispatch_authority():
    executor, calls = _executor()
    compilation, result = _plan(
        authorization=_authorization(),
        executor=executor,
    )

    assert result.status == "ready_for_explicit_execution_boundary"
    assert len(result.manifests) == len(compilation.specifications) == 3
    assert result.diagnostics.manifests_compiled == 3
    assert calls == []

    by_family = {
        item.specification.delta.family.value: item for item in result.manifests
    }
    omission = by_family["omission"]
    reordering = by_family["reordering"]
    assert omission.budget.baseline_request_units == 4
    assert omission.budget.treatment_request_units == 3
    assert omission.budget.control_request_units == 4
    assert omission.budget.cleanup_request_units == 3
    assert omission.budget.cleanup_verification_request_units == 3
    assert omission.budget.total_request_units == 17
    assert reordering.budget.treatment_request_units == 4
    assert reordering.budget.cleanup_verification_request_units == 3
    assert reordering.budget.total_request_units == 18

    for manifest in result.manifests:
        assert tuple(item.role for item in manifest.world_slots) == (
            "counterfactual_treatment",
            "independent_control",
            "valid_baseline",
        )
        assert all(item.provisioned is False for item in manifest.world_slots)
        assert manifest.budget.reserved is False
        assert manifest.static_admission_ready is True
        assert manifest.dispatch_authority is False
        assert manifest.finding_authority is False
        assert manifest.target_requests_sent == 0
        assert manifest.executable is False
        assert "endpoint_budget_bindings_not_compiled" in (
            manifest.pending_execution_blockers
        )
        assert "single_use_receipt_not_acquired" in (
            manifest.pending_execution_blockers
        )


def test_manifest_is_deterministic_redacted_and_content_addressed():
    executor, calls = _executor()
    authorization = _authorization()
    _compilation, first = _plan(
        authorization=authorization,
        executor=executor,
    )
    _compilation, second = _plan(
        authorization=authorization,
        executor=executor,
    )

    assert first.to_dict() == second.to_dict()
    public = json.dumps(first.to_dict(), sort_keys=True)
    assert authorization.envelope_id not in public
    assert authorization.attestation_signature not in public
    assert calls == []

    with pytest.raises(ValueError, match="manifest contract is invalid"):
        replace(
            first.manifests[0],
            target_ref=stable_hash(
                "security_obligation_target",
                "https://different.example",
            ),
        )
    with pytest.raises(ValueError, match="admission result is invalid"):
        replace(first, target_requests_sent=1)


@pytest.mark.parametrize(
    ("authorization", "blocker"),
    (
        (
            _authorization(workflows=("different_workflow",)),
            "graph_bound_authorization_scope_or_workflow_denied",
        ),
        (
            replace(_authorization(), attestation_signature=""),
            "graph_bound_authorization_unsigned",
        ),
        (
            replace(_authorization(), expires_at=1.0),
            "graph_bound_authorization_signature_invalid",
        ),
    ),
)
def test_unsigned_modified_or_wrong_workflow_authority_fails_closed(
    authorization,
    blocker,
):
    executor, calls = _executor()
    _compilation, result = _plan(
        authorization=authorization,
        executor=executor,
    )

    assert result.status == "authority_denied"
    assert result.blocker == blocker
    assert result.manifests == ()
    assert result.authorization_ref is None
    assert result.policy_ref is None
    assert calls == []


def test_expired_but_correctly_signed_authority_fails_closed():
    authorization = _authorization()
    authorization.expires_at = 1.0
    authorization.sign()
    executor, calls = _executor()

    _compilation, result = _plan(
        authorization=authorization,
        executor=executor,
    )

    assert result.status == "authority_denied"
    assert result.blocker == "graph_bound_authorization_expired"
    assert calls == []


def test_policy_request_ceiling_blocks_manifest_before_budget_reservation():
    executor, calls = _executor(max_total_requests=5)
    compilation, result = _plan(
        authorization=_authorization(),
        executor=executor,
    )

    assert result.status == "no_admissible_specifications"
    assert result.manifests == ()
    assert result.diagnostics.budget_blocked_specifications == len(
        compilation.specifications
    )
    assert executor.policy.budget.snapshot()["total_requests"] == 0
    assert calls == []


def test_unresolved_safety_and_cleanup_blockers_cannot_enter_a_manifest():
    _lifecycle, _state_machine, compilation = _compile(_omission_records())
    executor, calls = _executor()

    result = GraphBoundManifestAdmissionPlanner().plan(
        compilation=compilation,
        target_origin=ORIGIN,
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        world_id="alice",
        authorization=_authorization(),
        executor=executor,
        actor_persona_id="alice",
    )

    assert len(compilation.specifications) == 1
    assert result.status == "no_admissible_specifications"
    assert result.manifests == ()
    assert result.diagnostics.safety_blocked_specifications == 1
    assert result.diagnostics.budget_blocked_specifications == 0
    assert calls == []


def test_static_admission_rejects_target_and_world_rebinding():
    _lifecycle, _state_machine, compilation = _compile(_branch_join_records())
    planner = GraphBoundManifestAdmissionPlanner()

    with pytest.raises(ValueError, match="target_ref mismatch"):
        planner.plan(
            compilation=compilation,
            target_origin=ORIGIN,
            target_ref=stable_hash("security_obligation_target", "https://other.test"),
            world_id="alice",
        )
    with pytest.raises(ValueError, match="source-world mismatch"):
        planner.plan(
            compilation=compilation,
            target_origin=ORIGIN,
            target_ref=stable_hash("security_obligation_target", ORIGIN),
            world_id="bob",
        )


def test_ordinary_shadow_run_carries_static_admission_without_executing_it():
    executor, calls = _executor()
    orchestrator = BehavioralShadowOrchestrator()

    passive = orchestrator.run(
        _branch_join_records(),
        target_origin=ORIGIN,
        world_id="alice",
    )
    admitted = orchestrator.run(
        _branch_join_records(),
        target_origin=ORIGIN,
        world_id="alice",
        experiment_context=OwnedExperimentShadowContext(
            authorization=_authorization(),
            actor_persona_id="alice",
            executor=executor,
        ),
    )

    assert passive.prerequisite_admission.status == "not_requested"
    assert admitted.prerequisite_admission.status == (
        "ready_for_explicit_execution_boundary"
    )
    assert len(admitted.prerequisite_admission.manifests) == 3
    assert admitted.to_dict()["prerequisite_admission"] == (
        admitted.prerequisite_admission.to_dict()
    )
    assert admitted.prerequisite_admission.dispatch_authority is False
    assert admitted.prerequisite_admission.target_requests_sent == 0
    assert calls == []


def test_static_admission_module_has_no_async_or_transport_surface():
    source_path = (
        Path(__file__).parents[2]
        / "core"
        / "behavior"
        / "prerequisite_admission.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert "raw_send" not in source
    assert ".execute(" not in source
    assert ".try_reserve(" not in source


def test_static_admission_rejects_multiple_cleanup_lifecycles_before_budget():
    lifecycle, state_machine, compilation = _compile(_branch_join_records())
    original = compilation.specifications[0]
    candidate = next(
        item
        for item in state_machine.candidates
        if item.candidate_id == original.state_machine_candidate_id
    )
    support_rule = next(
        item
        for item in compilation.support_matrix
        if item.rule_id == original.support_rule_id
    )
    first_lifecycle = next(
        item
        for item in lifecycle.candidates
        if item.lifecycle_id == original.cleanup.bindings[0].lifecycle_id
    )
    second_lifecycle = replace(
        first_lifecycle,
        lifecycle_id=stable_hash(
            "owned_lifecycle",
            "static-admission-second-cleanup",
        ),
        create_operation_id=stable_hash(
            "action",
            "static-admission-second-create",
        ),
        cleanup_operation_id=stable_hash(
            "action",
            "static-admission-second-cleanup",
        ),
        cleanup_binding_id=stable_hash(
            "lineage_binding",
            "static-admission-second-cleanup",
        ),
    )
    fresh_state = type(original.fresh_state).build(
        world_ref=original.fresh_state.world_ref,
        lifecycle_ids=(
            first_lifecycle.lifecycle_id,
            second_lifecycle.lifecycle_id,
        ),
        baseline_source_ref=original.fresh_state.baseline_source_ref,
        reference_state_id=original.fresh_state.reference_state_id,
        reference_response_status=(
            original.fresh_state.reference_response_status
        ),
        reference_response_body_hash=(
            original.fresh_state.reference_response_body_hash
        ),
    )
    cleanup = type(original.cleanup).build(
        (first_lifecycle, second_lifecycle)
    )
    two_cleanup_spec = type(original).build(
        candidate=candidate,
        support_rule=support_rule,
        delta=original.delta,
        fresh_state=fresh_state,
        cleanup=cleanup,
        execution_blockers=original.execution_blockers,
    )
    specifications = tuple(
        sorted(
            (
                two_cleanup_spec,
                *(
                    item
                    for item in compilation.specifications
                    if item.spec_id != original.spec_id
                ),
            ),
            key=lambda item: item.spec_id,
        )
    )
    compilation_payload = compilation.to_dict()
    compilation_payload.pop("schema_version")
    compilation_payload.pop("result_id")
    compilation_payload["specifications"] = [
        item.to_dict() for item in specifications
    ]
    compilation = replace(
        compilation,
        result_id=stable_hash(
            "graph_bound_experiment_compilation",
            compilation_payload,
        ),
        specifications=specifications,
    )

    executor, calls = _executor()
    result = GraphBoundManifestAdmissionPlanner().plan(
        compilation=compilation,
        target_origin=ORIGIN,
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        world_id="alice",
        authorization=_authorization(),
        executor=executor,
        actor_persona_id="alice",
    )

    assert len(two_cleanup_spec.cleanup.bindings) == 2
    assert result.status == "ready_for_explicit_execution_boundary"
    assert len(result.manifests) == len(compilation.specifications) - 1
    assert result.diagnostics.safety_blocked_specifications == 1
    assert result.diagnostics.budget_blocked_specifications == 0
    assert all(
        manifest.specification.spec_id != two_cleanup_spec.spec_id
        for manifest in result.manifests
    )
    assert executor.policy.budget.snapshot()["total_requests"] == 0
    assert calls == []
