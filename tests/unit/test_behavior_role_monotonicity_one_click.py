"""Family-C ordinary-click selection, gating, execution, and finding tests."""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import replace

import pytest

from core.behavior.orchestrator import (
    BehavioralShadowOrchestrator,
    OwnedExperimentShadowContext,
)
from core.behavior.receipts import BehavioralReceiptStore, ReceiptStoreError
from core.behavior.role_effect_evaluation import (
    ROLE_PROTECTED_EFFECT_EXECUTION_ENV,
    RoleProtectedEffectExecutionConfig,
)
from core.behavior.role_execution_claim import (
    ROLE_MONOTONICITY_EXECUTION_CLAIM_ENV,
    RoleMonotonicityExecutionClaimConfig,
)
from core.behavior.role_membership_lifecycle import (
    ROLE_MEMBERSHIP_LIFECYCLE_ENV,
    RoleMembershipLifecycleConfig,
    RoleSessionPolicyExecutor,
)
from core.behavior.role_monotonicity_one_click import (
    ROLE_MONOTONICITY_ONE_CLICK_ENV,
    RoleMonotonicityFindingCandidate,
    RoleMonotonicityOneClickConfig,
    RoleMonotonicityOneClickDenied,
    RoleMonotonicityOneClickDispatcher,
    RoleMonotonicityOneClickSpecification,
    _prepare_role_run,
)
from tests.unit.test_behavior_role_effect_evaluation import _EffectTransport
from tests.unit.test_behavior_role_request_binding import ORIGIN, _context


def _specification_mapping(context):
    proof = context.proof
    runtime = context.runtime
    ordered = (
        proof.fixture.setup_action,
        proof.higher_baseline,
        proof.active_lower_probe,
        proof.active_effect_witness,
        proof.fixture.revocation_action,
        proof.fixture.revocation_verification_action,
        proof.revoked_lower_probe,
        proof.revoked_effect_witness,
    )
    names = (
        "setup",
        "higher_baseline",
        "active_lower_probe",
        "active_effect_witness",
        "revocation",
        "revocation_verification",
        "revoked_lower_probe",
        "revoked_effect_witness",
    )
    actions = {}
    for name, action in zip(names, ordered):
        candidate = runtime.runtime_actions[action.action_id]
        actions[name] = {"url": candidate.url}
        if candidate.body is not None:
            actions[name]["body"] = copy.deepcopy(candidate.body)
    membership = runtime.membership_observation_binding
    effects = runtime.effect_observation_binding
    return {
        "schema_version": 1,
        "run_id": runtime.run_id,
        "tenant_id": runtime.tenant_id,
        "higher_role_ref": runtime.higher_role_ref,
        "lower_role_ref": runtime.lower_role_ref,
        "higher_session_id": runtime.higher_session_id,
        "active_lower_session_id": runtime.active_lower_session_id,
        "revoked_lower_session_id": runtime.revoked_lower_session_id,
        "active_membership_generation": runtime.active_membership_generation,
        "revoked_membership_generation": runtime.revoked_membership_generation,
        "actions": actions,
        "membership_pointers": {
            "tenant": membership.tenant_pointer,
            "subject": membership.subject_pointer,
            "role": membership.role_pointer,
            "state": membership.state_pointer,
            "generation": membership.generation_pointer,
        },
        "effect_pointers": {
            "probe_authorized": effects.probe_authorized_pointer,
            "probe_effect": effects.probe_effect_pointer,
            "witness_effect": effects.witness_effect_pointer,
        },
    }


def _shadow_run(context):
    source = {
        "id": "role-operation",
        "persona_id": context.higher.persona_id,
        "method": "POST",
        "url": f"{ORIGIN}/api/admin/role/permission",
        "request_body": "{}",
        "response_status": 200,
        "response_body": json.dumps({"ok": True}),
    }
    peer = {
        **source,
        "id": "peer-role-operation",
        "persona_id": context.lower.persona_id,
    }
    return BehavioralShadowOrchestrator().run(
        (source,),
        target_origin=ORIGIN,
        world_id=context.higher.persona_id,
        peer_records=(peer,),
        peer_world_id=context.lower.persona_id,
        experiment_context=OwnedExperimentShadowContext(
            authorization=context.authorization,
            actor_persona_id=context.higher.persona_id,
            peer_persona_id=context.lower.persona_id,
            executor=context.executor,
            role_world_ids=(
                context.higher.persona_id,
                context.lower.persona_id,
            ),
        ),
    )


def _dispatcher(
    context,
    specification,
    store,
    *,
    executor=None,
    gates=(True, True, True, True),
):
    return RoleMonotonicityOneClickDispatcher(
        target_origin=ORIGIN,
        higher_persona_id=context.higher.persona_id,
        lower_persona_id=context.lower.persona_id,
        specification=specification,
        authorization=context.authorization,
        executor=executor or context.executor,
        persona_vault=context.vault,
        receipt_store=store,
        one_click_config=RoleMonotonicityOneClickConfig(gates[0]),
        claim_config=RoleMonotonicityExecutionClaimConfig(gates[1]),
        lifecycle_config=RoleMembershipLifecycleConfig(gates[2]),
        execution_config=RoleProtectedEffectExecutionConfig(gates[3]),
    )


def test_specification_builds_exact_r5c3_binding_without_transport(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    raw = _specification_mapping(context)
    specification = RoleMonotonicityOneClickSpecification.from_mapping(
        raw,
        target_origin=ORIGIN,
    )
    prepared = _prepare_role_run(
        specification=specification,
        goal=context.proof.oracle.goal,
        target_origin=ORIGIN,
        authorization=context.authorization,
        higher_persona_id=context.higher.persona_id,
        lower_persona_id=context.lower.persona_id,
    )
    binding = prepared.coordinator.bind_requests(
        executor=context.executor,
        persona_vault=context.vault,
        runtime=prepared.runtime,
        authority_validator=prepared.authority_validator,
    )

    assert specification.private_payload() == raw
    assert specification.specification_id.startswith(
        "role_monotonicity_one_click_specification:"
    )
    assert binding.request_bindings_complete is True
    assert tuple(
        item.request_binding.ordinal for item in binding.action_bindings
    ) == tuple(range(8))
    assert context.calls == []

    changed = copy.deepcopy(raw)
    changed["revoked_lower_session_id"] = raw["active_lower_session_id"]
    with pytest.raises(ValueError, match="sessions must be distinct"):
        RoleMonotonicityOneClickSpecification.from_mapping(
            changed,
            target_origin=ORIGIN,
        )

    with pytest.raises(ValueError, match="action specification is invalid"):
        replace(specification.actions[0], method="GET")

    changed = copy.deepcopy(raw)
    changed["actions"]["revoked_lower_probe"]["url"] = (
        "https://outside.example.test/api/admin-effect"
    )
    with pytest.raises(ValueError, match="leaves the signed target origin"):
        RoleMonotonicityOneClickSpecification.from_mapping(
            changed,
            target_origin=ORIGIN,
        )


@pytest.mark.parametrize(
    ("gates", "disabled_gate"),
    (
        ((False, True, True, True), ROLE_MONOTONICITY_ONE_CLICK_ENV),
        ((True, False, True, True), ROLE_MONOTONICITY_EXECUTION_CLAIM_ENV),
        ((True, True, False, True), ROLE_MEMBERSHIP_LIFECYCLE_ENV),
        ((True, True, True, False), ROLE_PROTECTED_EFFECT_EXECUTION_ENV),
    ),
)
def test_selected_role_candidate_reports_each_default_off_gate_without_traffic(
    tmp_path,
    monkeypatch,
    gates,
    disabled_gate,
):
    context = _context(tmp_path, monkeypatch)
    specification = RoleMonotonicityOneClickSpecification.from_mapping(
        _specification_mapping(context),
        target_origin=ORIGIN,
    )
    shadow = _shadow_run(context)

    result = asyncio.run(
        _dispatcher(
            context,
            specification,
            BehavioralReceiptStore(tmp_path / "receipts"),
            gates=gates,
        ).run(
            payout_goal_plan=shadow.payout_goal_plan,
            graph=shadow.graph,
        )
    )

    assert shadow.payout_goal_plan.selected.backend == "authority_monotonicity"
    assert result.status == "selected_execution_disabled"
    assert result.disabled_gates == (disabled_gate,)
    assert result.selected is True
    assert result.dispatched is False
    assert context.calls == []


@pytest.mark.parametrize(
    ("active_outcome", "revoked_outcome", "expected_verdict", "confirmed"),
    (
        (
            "allowed",
            "denied",
            "confirmed_active_escalation",
            True,
        ),
        ("denied", "denied", "refuted", False),
    ),
)
def test_completed_role_proof_is_receipt_bound_and_only_positive_adapts(
    tmp_path,
    monkeypatch,
    active_outcome,
    revoked_outcome,
    expected_verdict,
    confirmed,
):
    context = _context(tmp_path, monkeypatch)
    specification = RoleMonotonicityOneClickSpecification.from_mapping(
        _specification_mapping(context),
        target_origin=ORIGIN,
    )
    shadow = _shadow_run(context)
    transport = _EffectTransport(
        context,
        active_outcome=active_outcome,
        revoked_outcome=revoked_outcome,
    )
    executor = RoleSessionPolicyExecutor(
        transport,
        context.executor.policy,
        provenance=context.executor.provenance,
    )
    store = BehavioralReceiptStore(tmp_path / "receipts")

    result = asyncio.run(
        _dispatcher(
            context,
            specification,
            store,
            executor=executor,
        ).run(
            payout_goal_plan=shadow.payout_goal_plan,
            graph=shadow.graph,
        )
    )
    response = result.execution_response()

    assert result.status == "completed"
    assert result.execution.oracle.verdict.value == expected_verdict
    assert len(transport.calls) == 8
    assert (result.finding is not None) is confirmed
    assert (response["finding"] is not None) is confirmed
    assert response["finding_confirmed"] is confirmed
    assert response["selection_ref"] == result.selection_ref
    assert response["role_receipt_id"] == result.execution.receipt_id
    assert store.load(
        result.execution.receipt_id.removeprefix("behavioral-")
    ).state == ("completed")

    if confirmed:
        rebuilt = RoleMonotonicityFindingCandidate.from_completed_outcome(response)
        assert rebuilt.to_finding() == response["finding"]
        tampered = dict(response)
        tampered["effect_observation_binding_id"] = (
            "role_protected_effect_observation_binding:" + "0" * 64
        )
        with pytest.raises((ReceiptStoreError, RoleMonotonicityOneClickDenied)):
            RoleMonotonicityFindingCandidate.from_completed_outcome(tampered)
    else:
        with pytest.raises(RoleMonotonicityOneClickDenied):
            RoleMonotonicityFindingCandidate.from_completed_outcome(response)
