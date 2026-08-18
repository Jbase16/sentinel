"""Passive payout-goal and proof-topology planner tests."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.behavior as behavior_package

from core.behavior.normalize import stable_hash
from core.behavior.compiler import OperationContract
from core.behavior.payout_goals import (
    GoalPlanningContext,
    PayoutGoalPlannerLimits,
    PayoutGoalTopologyPlanner,
    PayoutSink,
    ProofTopology,
)
from core.foundry.authorization import AuthorizationEnvelope


ORIGIN = "https://planner.example.test"
OTHER_ORIGIN = "https://outside.example.test"
OBJECT_ID = "file_7fa9f13a2b4c5d6e"


def _graph():
    return SimpleNamespace(
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        graph_digest=stable_hash("security_obligation_graph", {"fixture": "r1"}),
        obligations=(),
    )


def _authorization(*, workflows=()):
    envelope = AuthorizationEnvelope(
        envelope_id="payout-goal-test-envelope",
        researcher_identity="researcher",
        target_handle="planner-test",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized payout goal planning test",
        disclosure_attestation=True,
        allowed_workflows=list(workflows),
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def _context(
    *,
    selected_world="alice-secret-world",
    owned_worlds=(),
    role_worlds=(),
    backends=(),
    workflows=(),
    target_origin=ORIGIN,
    authorization=True,
    fresh_anonymous=False,
    lifecycle=False,
    callback=False,
):
    graph = _graph()
    return GoalPlanningContext.build(
        target_ref=graph.target_ref,
        target_origin=target_origin,
        authorization=_authorization(workflows=workflows) if authorization else None,
        selected_world_id=selected_world,
        owned_world_ids=owned_worlds,
        role_world_ids=role_worlds,
        fresh_anonymous_available=fresh_anonymous,
        lifecycle_available=lifecycle,
        callback_receiver_available=callback,
        available_backends=backends,
    )


def _record(name: str, path: str, *, method: str = "GET"):
    return {
        "id": name,
        "persona_id": "alice-secret-world",
        "method": method,
        "url": f"{ORIGIN}{path}",
        "request_body": "{}" if method != "GET" else None,
        "response_status": 200,
        "response_body": json.dumps({"id": OBJECT_ID, "ok": True}),
    }


def _plan(records, context, *, limits=None):
    planner = PayoutGoalTopologyPlanner(limits or PayoutGoalPlannerLimits())
    return planner.plan_from_records(records, graph=_graph(), context=context)


def _operation(name: str, label: str):
    return OperationContract(
        operation_id=stable_hash("action", name),
        label=label,
        requires=(),
        produces=(),
        observed_success=True,
        source_refs=(stable_hash("source_ref", name),),
    )


def _blocker_codes(candidate):
    return {item.code for item in candidate.blockers}


def test_planning_context_rejects_an_invalid_selected_world():
    with pytest.raises(ValueError, match="selected_world_id"):
        _context(selected_world="")


def test_unconfirmed_semantic_operation_cannot_become_an_admissible_goal():
    operation = OperationContract(
        operation_id=stable_hash("action", "published-export"),
        label="artifact_route.get.api.export.id",
        requires=(),
        produces=(),
        observed_success=False,
        source_refs=(stable_hash("source_ref", "published-export"),),
    )
    plan = PayoutGoalTopologyPlanner().plan(
        (operation,),
        graph=_graph(),
        context=_context(
            owned_worlds=("alice", "bob"),
            backends=("object_authorization",),
            workflows=("behavioral_object_authorization",),
        ),
    )

    assert plan.status == "blocked"
    assert plan.selected is None
    assert "operation_unconfirmed" in _blocker_codes(plan.candidates[0])


def test_planner_preserves_all_initial_payout_sink_classes():
    operations = (
        _operation("ownership", "TransferAccountOwnership"),
        _operation("financial", "WithdrawPayout"),
        _operation("membership", "InviteMembership"),
        _operation("credential", "ReadApiKeyToken"),
        _operation("authority", "ReadRolePermission"),
        _operation("recovery", "ResetPasswordRecovery"),
        _operation("file", "ReadPrivateFile"),
        _operation("private-data", "ReadPrivateObject"),
        _operation("message", "ReadPrivateMessage"),
        _operation("bulk", "RunBulkOperation"),
        _operation("export", "DownloadExportBackup"),
    )

    plan = PayoutGoalTopologyPlanner().plan(
        operations,
        graph=_graph(),
        context=_context(authorization=False),
    )

    assert {item.goal.sink for item in plan.candidates} == set(PayoutSink)
    assert plan.diagnostics.high_value_operations == len(PayoutSink)
    assert plan.status == "blocked"


def test_same_object_goal_selects_zero_one_and_two_account_topologies():
    records = (_record("file", f"/api/files/{OBJECT_ID}"),)
    zero = _plan(
        records,
        _context(backends=("anonymous_exposure",)),
    )
    one = _plan(
        records,
        _context(
            owned_worlds=("alice",),
            backends=("anonymous_authorization",),
        ),
    )
    two = _plan(
        records,
        _context(
            owned_worlds=("alice", "bob"),
            backends=("object_authorization",),
            workflows=("behavioral_object_authorization",),
        ),
    )

    assert (
        zero.candidates[0].world_requirement.topology
        is ProofTopology.ZERO_PERSONA_ANONYMOUS
    )
    assert one.selected.world_requirement.topology is ProofTopology.SINGLE_OWNED_ACCOUNT
    assert two.selected.world_requirement.topology is ProofTopology.PAIRED_OWNED_ACCOUNTS
    assert "owned_subject_unavailable" in _blocker_codes(zero.candidates[0])
    assert zero.status == "blocked"
    assert one.status == two.status == "ready"


def test_role_and_callback_topologies_keep_unavailable_resources_as_blockers():
    records = (
        _record("role", "/api/admin/role/permission", method="POST"),
        _record("webhook", "/api/webhook/token", method="POST"),
    )
    context = _context(
        owned_worlds=("alice", "bob"),
        backends=("authority_monotonicity", "capability_confinement"),
    )

    plan = _plan(records, context)
    by_topology = {
        item.world_requirement.topology: item for item in plan.candidates
    }

    role = by_topology[ProofTopology.OWNED_ROLE_DIFFERENTIAL]
    callback = by_topology[ProofTopology.CALLBACK_RECEIVER]
    assert "distinct_role_worlds_unavailable" in _blocker_codes(role)
    assert "callback_receiver_unavailable" in _blocker_codes(callback)
    assert plan.selected is None


def test_missing_or_wrong_origin_authority_is_descriptive_and_never_admissible():
    records = (_record("file", f"/api/files/{OBJECT_ID}"),)
    missing = _plan(
        records,
        _context(authorization=False, backends=("anonymous_exposure",)),
    )
    wrong_origin = _plan(
        records,
        _context(
            target_origin=OTHER_ORIGIN,
            backends=("anonymous_exposure",),
        ),
    )

    assert "authorization_unavailable" in _blocker_codes(missing.candidates[0])
    assert "target_origin_not_authorized" in _blocker_codes(missing.candidates[0])
    assert "target_origin_not_authorized" in _blocker_codes(wrong_origin.candidates[0])
    assert missing.selected is None and wrong_origin.selected is None


def test_planning_is_deterministic_across_record_order():
    records = (
        _record("export", f"/api/exports/{OBJECT_ID}/download"),
        _record("role", "/api/admin/role/permission"),
        _record("file", f"/api/files/{OBJECT_ID}"),
    )
    context = _context(
        owned_worlds=("alice", "bob"),
        backends=("object_authorization",),
        workflows=("behavioral_object_authorization",),
    )

    first = _plan(records, context)
    second = _plan(tuple(reversed(records)), context)

    assert first.to_dict() == second.to_dict()


def test_public_plan_contains_hashes_not_raw_target_identity_or_object_values():
    records = (_record("file", f"/api/files/{OBJECT_ID}"),)
    context = _context(
        owned_worlds=("alice-secret-world", "bob-secret-world"),
        backends=("object_authorization",),
        workflows=("behavioral_object_authorization",),
    )

    serialized = json.dumps(_plan(records, context).to_dict(), sort_keys=True)

    for raw in (
        ORIGIN,
        OBJECT_ID,
        "alice-secret-world",
        "bob-secret-world",
        "/api/files/",
    ):
        assert raw not in serialized


def test_candidate_bound_and_operation_limit_are_explicit():
    records = (
        _record("file", f"/api/files/{OBJECT_ID}"),
        _record("export", f"/api/exports/{OBJECT_ID}/download"),
        _record("role", "/api/admin/role/permission"),
    )
    context = _context(authorization=False)
    bounded = _plan(
        records,
        context,
        limits=PayoutGoalPlannerLimits(max_candidates=2),
    )
    blocked_input = _plan(
        records,
        context,
        limits=PayoutGoalPlannerLimits(max_operations=1),
    )

    assert len(bounded.candidates) == 2
    assert bounded.diagnostics.dropped_candidates == 1
    assert blocked_input.status == "blocked_input"
    assert [item.code for item in blocked_input.input_blockers] == [
        "operation_limit_exceeded"
    ]
    assert blocked_input.diagnostics.operations == 3


def test_evidence_reference_bound_is_accounted_not_silently_truncated():
    operation = OperationContract(
        operation_id=stable_hash("action", "download"),
        label="DownloadExportBackup",
        requires=(),
        produces=(),
        observed_success=True,
        source_refs=tuple(stable_hash("source_ref", str(index)) for index in range(4)),
    )
    planner = PayoutGoalTopologyPlanner(
        PayoutGoalPlannerLimits(max_evidence_refs_per_goal=2)
    )

    plan = planner.plan(
        (operation,),
        graph=_graph(),
        context=_context(authorization=False),
    )

    assert len(plan.candidates[0].goal.evidence_refs) == 2
    assert plan.diagnostics.dropped_evidence_refs == 2


def test_content_addressed_plan_rejects_tampering():
    plan = _plan(
        (_record("file", f"/api/files/{OBJECT_ID}"),),
        _context(backends=("anonymous_exposure",)),
    )

    with pytest.raises(ValueError, match="payout goal plan contract is invalid"):
        replace(
            plan,
            selected_goal_id="security_witness_goal:" + "0" * 64,
        )


def test_planner_source_has_no_transport_or_execution_import_surface():
    source = Path("core/behavior/payout_goals.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert not ({"httpx", "requests", "urllib3", "socket"} & imported)
    assert "PolicyExecutor" not in source
    assert "ProofBudget" not in source
    assert "ProvenanceSink" not in source
    assert not hasattr(behavior_package, "PayoutGoalTopologyPlanner")
