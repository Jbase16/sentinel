import asyncio
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

import core.behavior.prerequisite_execution as execution_module
import core.behavior.prerequisite_one_click as one_click_module
from core.behavior.orchestrator import (
    BehavioralShadowOrchestrator,
    OwnedExperimentShadowContext,
)
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import (
    GoalPlanningContext,
    PayoutGoalPlan,
    _plan_payload,
)
from core.behavior.prerequisite_execution import (
    GraphBoundPrerequisiteExecutionConfig,
    GraphBoundPrerequisiteExecutionDenied,
    GraphBoundPrerequisiteExperimentExecutor,
)
from core.behavior.prerequisite_execution_claim import (
    GraphBoundExecutionClaimAdmission,
    GraphBoundExecutionClaimConfig,
    GraphBoundExecutionClaimDenied,
)
from core.behavior.prerequisite_one_click import (
    GraphBoundPrerequisiteFindingCandidate,
    GraphBoundPrerequisiteOneClickDenied,
    GraphBoundPrerequisiteOneClickDispatcher,
    GraphBoundPrerequisiteOneClickInternalError,
)
from core.behavior.receipts import (
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_outcome,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink
from tests.unit.test_behavior_prerequisite_admission import _authorization
from tests.unit.test_behavior_prerequisite_experiments import (
    ORIGIN,
    PRIVATE_MARKER,
    WORKFLOW_ID,
    _branch_join_records,
)
from tests.unit.test_behavior_prerequisite_request_binding import _context


def test_execution_module_has_no_direct_finding_or_promotion_surface():
    source = (
        Path(__file__).parents[2]
        / "core"
        / "behavior"
        / "prerequisite_execution.py"
    ).read_text(encoding="utf-8")

    assert "Finding(" not in source
    assert "SubmissionCandidate" not in source
    assert "promote_canonical_finding" not in source


def test_environment_gate_requires_provisioning_and_execution(monkeypatch):
    monkeypatch.setenv(
        execution_module.GRAPH_BOUND_PREREQUISITE_EXECUTION_ENV,
        "1",
    )
    monkeypatch.delenv(
        execution_module.GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV,
        raising=False,
    )
    assert GraphBoundPrerequisiteExecutionConfig.from_environment().enabled is False

    monkeypatch.setenv(
        execution_module.GRAPH_BOUND_FRESH_WORLD_PROVISIONING_ENV,
        "1",
    )
    assert GraphBoundPrerequisiteExecutionConfig.from_environment().enabled is True


def _case(
    tmp_path,
    *,
    family="omission",
    secure=False,
    verification_fails=False,
    terminal_transport_fails=False,
    cleanup_cancels=False,
    accept_foreign_capability=False,
    global_capability=False,
    wire_equivalent_capability=False,
    single_use_capability=False,
    records=None,
):
    calls = []
    worlds = {}
    single_prerequisite = records is not None and not any(
        record.get("id") == "second-prerequisite" for record in records
    )
    create_count = 0
    cleanup_cancelled = False
    used_capabilities = set()
    reference = {"status": "ready", "artifact": PRIVATE_MARKER}

    async def transport(method, url, body=None, **kwargs):
        nonlocal cleanup_cancelled, create_count
        calls.append((method, url, body, kwargs))
        parsed = urlsplit(url)
        path = parsed.path
        if method == "POST" and path == "/api/workflows":
            create_count += 1
            object_id = f"runtime-workflow-{create_count}"
            worlds[object_id] = {"archived": False, "prerequisites": []}
            return 201, {"workflowId": object_id}
        parts = path.strip("/").split("/")
        object_id = parts[2] if len(parts) >= 3 else None
        world = worlds.get(object_id)
        if world is None:
            raise AssertionError(f"unknown runtime world for {method} {url}")
        if method == "GET" and path.endswith("/first"):
            world["prerequisites"].append("first")
            return 200, {
                "firstToken": (
                    (
                        1 if object_id == "runtime-workflow-1" else "1"
                    )
                    if wire_equivalent_capability
                    else (
                        "runtime-global-first-token"
                        if global_capability
                        else f"runtime-first-token-{object_id}"
                    )
                )
            }
        if method == "GET" and path.endswith("/second"):
            world["prerequisites"].append("second")
            return 200, {
                "secondToken": (
                    (
                        2 if object_id == "runtime-workflow-1" else "2"
                    )
                    if wire_equivalent_capability
                    else (
                        "runtime-global-second-token"
                        if global_capability
                        else f"runtime-second-token-{object_id}"
                    )
                )
            }
        if method == "POST" and path.endswith("/approve"):
            world["prerequisites"].append("approve")
            return 200, {"exportToken": f"runtime-export-token-{object_id}"}
        if method == "GET" and path.endswith("/export"):
            if world["archived"]:
                if verification_fails:
                    return 200, reference
                return 404, {"error": "not found"}
            if terminal_transport_fails and object_id == "runtime-workflow-2":
                raise RuntimeError("simulated terminal transport failure")
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            required_capability_count = 1 if single_prerequisite else 2
            if secure and len(query) < required_capability_count:
                return 403, {"error": "prerequisite required"}
            for key, prefix in (
                ("firstToken", "runtime-first-token"),
                ("secondToken", "runtime-second-token"),
                ("exportToken", "runtime-export-token"),
            ):
                capability = query.get(key)
                if capability is None:
                    continue
                if single_use_capability:
                    if capability in used_capabilities:
                        return 403, {"error": "capability already used"}
                    used_capabilities.add(capability)
                expected = (
                    f"runtime-global-{key.removesuffix('Token').lower()}-token"
                    if global_capability
                    else f"{prefix}-{object_id}"
                )
                if not accept_foreign_capability and capability != expected:
                    return 403, {"error": "capability object mismatch"}
            return 200, reference
        if method == "PATCH" and len(parts) == 3:
            if cleanup_cancels and not cleanup_cancelled:
                cleanup_cancelled = True
                raise asyncio.CancelledError
            world["archived"] = True
            return 200, {"archived": True}
        raise AssertionError(f"unexpected request: {method} {url}")

    registry = OwnershipRegistry()
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=96,
            max_requests_per_endpoint=24,
            max_creates=20,
            allow_real_user_data_access=False,
        ),
        ownership_registry=registry,
    )
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    executor = PolicyExecutor(transport, policy, provenance=provenance)
    records, lifecycle, state, compilation, admission, binding = _context(
        records=records,
        executor=executor
    )
    plan = next(item for item in binding.plans if item.family == family)
    store = BehavioralReceiptStore(tmp_path / "receipts")
    boundary = GraphBoundExecutionClaimAdmission(
        records,
        target_origin=ORIGIN,
        world_id="alice",
        actor_persona_id="alice",
        authorization=_authorization(),
        executor=executor,
        lifecycle=lifecycle,
        state_machine=state,
        compilation=compilation,
        admission=admission,
        request_binding=binding,
        plan_id=plan.plan_id,
        config=GraphBoundExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )
    return boundary, store, executor, registry, calls, worlds, plan


def _receipt(store):
    path = next(store.root.glob("behavioral-*.json"))
    return store.load(path.stem.removeprefix("behavioral-")), path


def _shadow_for_boundary(boundary):
    return BehavioralShadowOrchestrator().run(
        boundary.records,
        target_origin=boundary.target_origin,
        world_id=boundary.world_id,
        experiment_context=OwnedExperimentShadowContext(
            authorization=boundary.authorization,
            actor_persona_id=boundary.actor_persona_id,
            executor=boundary.executor,
        ),
    )


def _single_prerequisite_records():
    records = []
    for record in _branch_join_records():
        if record["id"] == "second-prerequisite":
            continue
        value = dict(record)
        if value["id"] == "export-workflow":
            value["url"] = value["url"].split("&secondToken=", 1)[0]
        records.append(value)
    return tuple(records)


@pytest.mark.asyncio
async def test_one_click_dispatches_exact_graph_plan_and_builds_strict_finding(
    tmp_path,
):
    boundary, store, executor, _registry, calls, worlds, _plan = _case(
        tmp_path,
        records=_single_prerequisite_records(),
    )
    shadow = _shadow_for_boundary(boundary)

    run = await GraphBoundPrerequisiteOneClickDispatcher(
        target_origin=boundary.target_origin,
        world_id=boundary.world_id,
        actor_persona_id=boundary.actor_persona_id,
        authorization=boundary.authorization,
        executor=executor,
        receipt_store=store,
        claim_config=GraphBoundExecutionClaimConfig(enabled=True),
        execution_config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
    ).run(
        boundary.records,
        lifecycle=shadow.lifecycle,
        state_machine=shadow.state_machine,
        compilation=shadow.prerequisite_experiments,
        payout_goal_plan=shadow.payout_goal_plan,
        graph=shadow.graph,
    )

    assert run.status == "completed"
    assert run.dispatched is True
    assert run.finding is not None
    assert run.finding.finding_id == run.execution.oracle.finding_candidate_ref
    response = run.execution_response()
    assert response["finding"]["id"] == run.finding.finding_id
    assert response["finding"]["metadata"]["selection_ref"] == run.selection_ref
    durable = redacted_outcome(response)
    reconstructed = GraphBoundPrerequisiteFindingCandidate.from_completed_outcome(
        durable
    )
    assert reconstructed == run.finding
    assert durable["selection_ref"] == run.selection_ref
    tampered = dict(response)
    tampered["payout_goal_id"] = f"security_witness_goal:{'0' * 64}"
    with pytest.raises(ReceiptStoreError, match="outcome is invalid"):
        redacted_outcome(tampered)
    assert len(calls) == run.execution.target_requests_sent
    assert all(world["archived"] for world in worlds.values())


@pytest.mark.asyncio
async def test_one_click_refuted_graph_plan_never_builds_finding(tmp_path):
    boundary, store, executor, _registry, calls, worlds, _plan = _case(
        tmp_path,
        secure=True,
        records=_single_prerequisite_records(),
    )
    shadow = _shadow_for_boundary(boundary)

    run = await GraphBoundPrerequisiteOneClickDispatcher(
        target_origin=boundary.target_origin,
        world_id=boundary.world_id,
        actor_persona_id=boundary.actor_persona_id,
        authorization=boundary.authorization,
        executor=executor,
        receipt_store=store,
        claim_config=GraphBoundExecutionClaimConfig(enabled=True),
        execution_config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
    ).run(
        boundary.records,
        lifecycle=shadow.lifecycle,
        state_machine=shadow.state_machine,
        compilation=shadow.prerequisite_experiments,
        payout_goal_plan=shadow.payout_goal_plan,
        graph=shadow.graph,
    )

    assert run.status == "completed"
    assert run.execution.status == "refuted"
    assert run.finding is None
    assert run.execution_response()["finding"] is None
    assert len(calls) == run.execution.target_requests_sent
    assert all(world["archived"] for world in worlds.values())


@pytest.mark.asyncio
async def test_one_click_selected_graph_plan_is_default_off_without_traffic(tmp_path):
    boundary, store, executor, _registry, calls, _worlds, _plan = _case(
        tmp_path,
        records=_single_prerequisite_records(),
    )
    shadow = _shadow_for_boundary(boundary)

    run = await GraphBoundPrerequisiteOneClickDispatcher(
        target_origin=boundary.target_origin,
        world_id=boundary.world_id,
        actor_persona_id=boundary.actor_persona_id,
        authorization=boundary.authorization,
        executor=executor,
        receipt_store=store,
        claim_config=GraphBoundExecutionClaimConfig(enabled=False),
        execution_config=GraphBoundPrerequisiteExecutionConfig(enabled=False),
    ).run(
        boundary.records,
        lifecycle=shadow.lifecycle,
        state_machine=shadow.state_machine,
        compilation=shadow.prerequisite_experiments,
        payout_goal_plan=shadow.payout_goal_plan,
        graph=shadow.graph,
    )

    assert run.status == "selected_execution_disabled"
    assert run.selected is True
    assert run.dispatched is False
    assert len(run.disabled_gates) == 3
    assert calls == []

    partial = await GraphBoundPrerequisiteOneClickDispatcher(
        target_origin=boundary.target_origin,
        world_id=boundary.world_id,
        actor_persona_id=boundary.actor_persona_id,
        authorization=boundary.authorization,
        executor=executor,
        receipt_store=store,
        claim_config=GraphBoundExecutionClaimConfig(enabled=True),
        execution_config=GraphBoundPrerequisiteExecutionConfig(enabled=False),
        claim_gate_enabled=True,
        provisioning_gate_enabled=True,
        execution_gate_enabled=False,
    ).run(
        boundary.records,
        lifecycle=shadow.lifecycle,
        state_machine=shadow.state_machine,
        compilation=shadow.prerequisite_experiments,
        payout_goal_plan=shadow.payout_goal_plan,
        graph=shadow.graph,
    )

    assert partial.disabled_gates == (
        execution_module.GRAPH_BOUND_PREREQUISITE_EXECUTION_ENV,
    )
    assert calls == []


@pytest.mark.asyncio
async def test_one_click_rejects_ambiguous_same_terminal_omission_plans(tmp_path):
    boundary, store, executor, _registry, calls, _worlds, _plan = _case(tmp_path)
    shadow = _shadow_for_boundary(boundary)
    assert sum(
        plan.family == "omission"
        and plan.baseline_operation_ids[-1]
        == shadow.payout_goal_plan.selected.goal.terminal_operation_id
        for plan in shadow.prerequisite_requests.plans
    ) == 2

    run = await GraphBoundPrerequisiteOneClickDispatcher(
        target_origin=boundary.target_origin,
        world_id=boundary.world_id,
        actor_persona_id=boundary.actor_persona_id,
        authorization=boundary.authorization,
        executor=executor,
        receipt_store=store,
        claim_config=GraphBoundExecutionClaimConfig(enabled=True),
        execution_config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
    ).run(
        boundary.records,
        lifecycle=shadow.lifecycle,
        state_machine=shadow.state_machine,
        compilation=shadow.prerequisite_experiments,
        payout_goal_plan=shadow.payout_goal_plan,
        graph=shadow.graph,
    )

    assert run.status == "selected_plan_unavailable"
    assert run.dispatched is False
    assert calls == []


@pytest.mark.asyncio
async def test_one_click_rejects_payout_graph_splice_before_traffic(tmp_path):
    boundary, store, executor, _registry, calls, _worlds, _plan = _case(
        tmp_path,
        records=_single_prerequisite_records(),
    )
    shadow = _shadow_for_boundary(boundary)
    other_records = (
        *boundary.records,
        {
            "id": "unrelated-status",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/status",
            "response_status": 200,
            "response_body": '{"status":"ok"}',
        },
    )
    other_shadow = BehavioralShadowOrchestrator().run(
        other_records,
        target_origin=boundary.target_origin,
        world_id=boundary.world_id,
        experiment_context=OwnedExperimentShadowContext(
            authorization=boundary.authorization,
            actor_persona_id=boundary.actor_persona_id,
            executor=executor,
        ),
    )
    assert other_shadow.graph.graph_digest != shadow.graph.graph_digest

    with pytest.raises(
        RuntimeError,
        match="payout_graph_context_mismatch",
    ):
        await GraphBoundPrerequisiteOneClickDispatcher(
            target_origin=boundary.target_origin,
            world_id=boundary.world_id,
            actor_persona_id=boundary.actor_persona_id,
            authorization=boundary.authorization,
            executor=executor,
            receipt_store=store,
            claim_config=GraphBoundExecutionClaimConfig(enabled=True),
            execution_config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).run(
            boundary.records,
            lifecycle=shadow.lifecycle,
            state_machine=shadow.state_machine,
            compilation=shadow.prerequisite_experiments,
            payout_goal_plan=other_shadow.payout_goal_plan,
            graph=shadow.graph,
        )

    assert calls == []


@pytest.mark.parametrize("missing_context_binding", ("terminal", "backend"))
@pytest.mark.asyncio
async def test_one_click_rejects_selected_candidate_missing_from_context(
    tmp_path,
    missing_context_binding,
):
    boundary, store, executor, _registry, calls, _worlds, _plan = _case(
        tmp_path,
        records=_single_prerequisite_records(),
    )
    shadow = _shadow_for_boundary(boundary)
    payout_plan = shadow.payout_goal_plan
    mismatched_context = GoalPlanningContext.build(
        target_ref=payout_plan.target_ref,
        target_origin=boundary.target_origin,
        authorization=boundary.authorization,
        selected_world_id=boundary.world_id,
        owned_world_ids=(boundary.actor_persona_id,),
        fresh_anonymous_available=(
            payout_plan.context.fresh_anonymous_available
        ),
        lifecycle_available=payout_plan.context.lifecycle_available,
        callback_receiver_available=(
            payout_plan.context.callback_receiver_available
        ),
        available_backends=(
            tuple(
                item
                for item in payout_plan.context.available_backends
                if item != "graph_bound_prerequisite"
            )
            if missing_context_binding == "backend"
            else payout_plan.context.available_backends
        ),
        graph_bound_prerequisite_terminal_ids=(
            ()
            if missing_context_binding == "terminal"
            else payout_plan.context.graph_bound_prerequisite_terminal_ids
        ),
    )
    payload = _plan_payload(
        status=payout_plan.status,
        target_ref=payout_plan.target_ref,
        graph_digest=payout_plan.graph_digest,
        context=mismatched_context,
        selected_goal_id=payout_plan.selected_goal_id,
        candidates=payout_plan.candidates,
        input_blockers=payout_plan.input_blockers,
        diagnostics=payout_plan.diagnostics,
    )
    mismatched_plan = PayoutGoalPlan(
        plan_id=stable_hash("payout_goal_plan", payload),
        status=payout_plan.status,
        target_ref=payout_plan.target_ref,
        graph_digest=payout_plan.graph_digest,
        context=mismatched_context,
        selected_goal_id=payout_plan.selected_goal_id,
        candidates=payout_plan.candidates,
        input_blockers=payout_plan.input_blockers,
        diagnostics=payout_plan.diagnostics,
    )

    with pytest.raises(
        GraphBoundPrerequisiteOneClickDenied,
        match="payout_terminal_context_mismatch",
    ):
        await GraphBoundPrerequisiteOneClickDispatcher(
            target_origin=boundary.target_origin,
            world_id=boundary.world_id,
            actor_persona_id=boundary.actor_persona_id,
            authorization=boundary.authorization,
            executor=executor,
            receipt_store=store,
            claim_config=GraphBoundExecutionClaimConfig(enabled=True),
            execution_config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).run(
            boundary.records,
            lifecycle=shadow.lifecycle,
            state_machine=shadow.state_machine,
            compilation=shadow.prerequisite_experiments,
            payout_goal_plan=mismatched_plan,
            graph=shadow.graph,
        )

    assert calls == []


@pytest.mark.asyncio
async def test_one_click_constructor_fault_aborts_claim_and_releases_budget(
    tmp_path,
    monkeypatch,
):
    boundary, store, executor, _registry, calls, _worlds, _plan = _case(
        tmp_path,
        records=_single_prerequisite_records(),
    )
    shadow = _shadow_for_boundary(boundary)

    def fail_constructor(*_args, **_kwargs):
        raise ValueError("simulated coordinator constructor fault")

    monkeypatch.setattr(
        one_click_module,
        "GraphBoundPrerequisiteExperimentExecutor",
        fail_constructor,
    )

    with pytest.raises(
        GraphBoundPrerequisiteOneClickInternalError,
        match="coordination_failed",
    ):
        await GraphBoundPrerequisiteOneClickDispatcher(
            target_origin=boundary.target_origin,
            world_id=boundary.world_id,
            actor_persona_id=boundary.actor_persona_id,
            authorization=boundary.authorization,
            executor=executor,
            receipt_store=store,
            claim_config=GraphBoundExecutionClaimConfig(enabled=True),
            execution_config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).run(
            boundary.records,
            lifecycle=shadow.lifecycle,
            state_machine=shadow.state_machine,
            compilation=shadow.prerequisite_experiments,
            payout_goal_plan=shadow.payout_goal_plan,
            graph=shadow.graph,
        )

    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"
    assert executor.policy.budget._reservations == {}
    assert calls == []


@pytest.mark.asyncio
async def test_dispatch_is_default_off_and_sends_zero_requests(tmp_path):
    boundary, store, _executor, _registry, calls, _worlds, _plan = _case(
        tmp_path
    )
    claim = boundary.admit().claim()

    with pytest.raises(
        GraphBoundPrerequisiteExecutionDenied,
        match="execution_is_disabled",
    ):
        await GraphBoundPrerequisiteExperimentExecutor(
            claim,
            config=GraphBoundPrerequisiteExecutionConfig(enabled=False),
        ).execute()

    assert calls == []
    assert claim.state == "claimed"
    claim.abort()
    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"


@pytest.mark.asyncio
async def test_vulnerable_omission_requires_independent_effect_witness(
    tmp_path,
):
    boundary, store, executor, registry, calls, worlds, plan = _case(tmp_path)
    result = await GraphBoundPrerequisiteExperimentExecutor(
        boundary.admit().claim(),
        config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
    ).execute()

    assert result.status == "confirmed"
    assert result.family == "omission"
    assert result.finding_confirmed is True
    assert result.oracle.finding_candidate_ref is not None
    assert result.oracle.independent_effect_witness_observed is True
    assert result.oracle.effect_witness_ref is not None
    assert result.oracle.runtime_value_inequality_ref is not None
    assert result.oracle.uncertainty_reasons == ()
    assert result.oracle.finding_authority is False
    assert result.cleanup.status == "verified"
    assert result.cleanup.cleanup_steps_completed == 3
    assert result.cleanup.cleanup_verifications_completed == 3
    assert result.cleanup.ownership_grants_removed == 3
    assert result.target_requests_sent == len(plan.request_bindings)
    assert len(result.terminal_observations) == 3
    baseline, treatment, witness = result.terminal_observations
    assert baseline.reference_match is True
    assert treatment.reference_match is True
    assert witness.reference_match is False
    assert witness.status == 403
    assert witness.runtime_binding_override_ref is not None
    assert witness.runtime_value_inequality_ref is not None
    terminal_calls = [
        item for item in calls if item[0] == "GET" and "/export" in item[1]
    ][:3]
    witness_url = terminal_calls[0][1]
    assert "/runtime-workflow-3/export" in witness_url
    witness_query = dict(parse_qsl(urlsplit(witness_url).query))
    assert sum("runtime-workflow-1" in item for item in witness_query.values()) == 1
    assert sum("runtime-workflow-3" in item for item in witness_query.values()) == 1
    assert len(calls) == len(plan.request_bindings)
    assert WORKFLOW_ID not in json.dumps(calls, sort_keys=True)
    assert all(world["archived"] for world in worlds.values())
    for object_id in worlds:
        assert not registry.is_owned(f"{ORIGIN}/api/workflows/{object_id}")

    receipt, path = _receipt(store)
    persisted = path.read_text(encoding="utf-8")
    assert receipt.state == "completed"
    assert receipt.outcome["oracle_verdict"] == "confirmed"
    assert receipt.outcome["finding_confirmed"] is True
    assert receipt.outcome["effect_witness_ref"] == result.oracle.effect_witness_ref
    assert receipt.outcome["runtime_value_inequality_ref"] == (
        result.oracle.runtime_value_inequality_ref
    )
    assert redacted_outcome(result.execution_response()) == receipt.outcome
    assert ORIGIN not in persisted
    assert WORKFLOW_ID not in persisted
    assert "runtime-workflow" not in persisted
    assert "runtime-first-token" not in persisted
    assert "runtime-second-token" not in persisted
    before = len(calls)
    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="replay_denied",
    ):
        boundary.admit()
    assert len(calls) == before
    assert executor.policy.budget.snapshot()["total_requests"] == len(calls)


@pytest.mark.asyncio
async def test_secure_omission_is_refuted_and_still_cleans_every_world(tmp_path):
    boundary, store, _executor, registry, calls, worlds, _plan = _case(
        tmp_path,
        secure=True,
    )
    result = await GraphBoundPrerequisiteExperimentExecutor(
        boundary.admit().claim(),
        config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
    ).execute()

    assert result.status == "refuted"
    assert result.finding_confirmed is False
    assert result.oracle.finding_candidate_ref is None
    assert result.cleanup.status == "verified"
    assert any(item.status == 403 for item in result.terminal_observations)
    assert all(world["archived"] for world in worlds.values())
    assert all(
        not registry.is_owned(f"{ORIGIN}/api/workflows/{object_id}")
        for object_id in worlds
    )
    receipt, _path = _receipt(store)
    assert receipt.state == "completed"
    assert receipt.outcome["oracle_verdict"] == "refuted"
    assert receipt.outcome["finding_confirmed"] is False
    assert calls


@pytest.mark.asyncio
async def test_public_constant_response_without_capability_rejection_cannot_confirm(
    tmp_path,
):
    boundary, store, _executor, _registry, _calls, _worlds, _plan = _case(
        tmp_path,
        accept_foreign_capability=True,
    )
    result = await GraphBoundPrerequisiteExperimentExecutor(
        boundary.admit().claim(),
        config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
    ).execute()

    assert result.status == "inconclusive"
    assert result.finding_confirmed is False
    assert result.oracle.finding_candidate_ref is None
    assert result.oracle.effect_witness_ref is None
    assert result.oracle.uncertainty_reasons == (
        "independent_effect_witness_unavailable",
    )
    receipt, _path = _receipt(store)
    assert receipt.state == "completed"
    assert receipt.outcome["finding_confirmed"] is False


@pytest.mark.asyncio
async def test_single_use_capability_cannot_fake_wrong_object_witness(tmp_path):
    boundary, store, _executor, _registry, _calls, _worlds, _plan = _case(
        tmp_path,
        single_use_capability=True,
    )
    result = await GraphBoundPrerequisiteExperimentExecutor(
        boundary.admit().claim(),
        config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
    ).execute()

    assert result.status == "inconclusive"
    assert result.finding_confirmed is False
    assert result.oracle.valid_baseline_observed is False
    assert result.oracle.independent_effect_witness_observed is True
    assert result.oracle.finding_candidate_ref is None
    assert "valid_baseline_reference_mismatch" in (
        result.oracle.uncertainty_reasons
    )
    receipt, _path = _receipt(store)
    assert receipt.state == "completed"
    assert receipt.outcome["finding_confirmed"] is False


@pytest.mark.asyncio
async def test_global_capability_override_is_rejected_before_terminal_traffic(
    tmp_path,
):
    boundary, store, _executor, _registry, calls, _worlds, _plan = _case(
        tmp_path,
        global_capability=True,
    )

    with pytest.raises(
        GraphBoundPrerequisiteExecutionDenied,
        match="runtime_override_wire_values_not_distinct",
    ) as raised:
        await GraphBoundPrerequisiteExperimentExecutor(
            boundary.admit().claim(),
            config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).execute()

    assert raised.value.cleanup is not None
    assert raised.value.cleanup.status == "verified"
    terminal_calls = [
        item for item in calls if item[0] == "GET" and "/export" in item[1]
    ]
    assert len(terminal_calls) == 3
    assert all("runtime-workflow" in item[1] for item in terminal_calls)
    first_export_index = next(
        index
        for index, item in enumerate(calls)
        if item[0] == "GET" and "/export" in item[1]
    )
    last_cleanup_index = max(
        index for index, item in enumerate(calls) if item[0] == "PATCH"
    )
    assert first_export_index > last_cleanup_index
    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"


@pytest.mark.asyncio
async def test_wire_equivalent_capability_override_is_rejected(tmp_path):
    boundary, store, _executor, _registry, calls, _worlds, _plan = _case(
        tmp_path,
        wire_equivalent_capability=True,
    )

    with pytest.raises(
        GraphBoundPrerequisiteExecutionDenied,
        match="runtime_override_wire_values_not_distinct",
    ):
        await GraphBoundPrerequisiteExperimentExecutor(
            boundary.admit().claim(),
            config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).execute()

    first_export_index = next(
        index
        for index, item in enumerate(calls)
        if item[0] == "GET" and "/export" in item[1]
    )
    last_cleanup_index = max(
        index for index, item in enumerate(calls) if item[0] == "PATCH"
    )
    assert first_export_index > last_cleanup_index
    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"


@pytest.mark.asyncio
async def test_reordering_response_match_remains_non_promoting_inconclusive(
    tmp_path,
):
    boundary, store, _executor, _registry, _calls, _worlds, _plan = _case(
        tmp_path,
        family="reordering",
    )
    result = await GraphBoundPrerequisiteExperimentExecutor(
        boundary.admit().claim(),
        config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
    ).execute()

    assert result.status == "inconclusive"
    assert result.finding_confirmed is False
    assert result.oracle.finding_candidate_ref is None
    assert result.oracle.uncertainty_reasons == (
        "reordering_security_effect_not_defined",
    )
    receipt, _path = _receipt(store)
    assert receipt.state == "completed"
    assert receipt.outcome["family"] == "reordering"
    assert receipt.outcome["finding_confirmed"] is False


@pytest.mark.asyncio
async def test_cleanup_verification_failure_aborts_and_preserves_orphan_risk(
    tmp_path,
):
    boundary, store, _executor, registry, calls, worlds, _plan = _case(
        tmp_path,
        verification_fails=True,
    )

    with pytest.raises(
        GraphBoundPrerequisiteExecutionDenied,
        match="cleanup_unverified",
    ) as raised:
        await GraphBoundPrerequisiteExperimentExecutor(
            boundary.admit().claim(),
            config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).execute()

    assert raised.value.category == "cleanup"
    assert raised.value.cleanup is not None
    assert raised.value.cleanup.status == "uncertain"
    assert raised.value.orphaned_owned_state_possible is True
    assert all(world["archived"] for world in worlds.values())
    assert any(
        registry.is_owned(f"{ORIGIN}/api/workflows/{object_id}")
        for object_id in worlds
    )
    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"
    before = len(calls)
    with pytest.raises(GraphBoundExecutionClaimDenied, match="replay_denied"):
        boundary.admit()
    assert len(calls) == before


@pytest.mark.asyncio
async def test_terminal_transport_failure_still_verifies_cleanup_and_aborts(
    tmp_path,
):
    boundary, store, _executor, registry, _calls, worlds, _plan = _case(
        tmp_path,
        terminal_transport_fails=True,
    )

    with pytest.raises(
        GraphBoundPrerequisiteExecutionDenied,
        match="terminal_failed",
    ) as raised:
        await GraphBoundPrerequisiteExperimentExecutor(
            boundary.admit().claim(),
            config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).execute()

    assert raised.value.cleanup is not None
    assert raised.value.cleanup.status == "verified"
    assert raised.value.orphaned_owned_state_possible is False
    assert all(world["archived"] for world in worlds.values())
    assert all(
        not registry.is_owned(f"{ORIGIN}/api/workflows/{object_id}")
        for object_id in worlds
    )
    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"


@pytest.mark.asyncio
async def test_cleanup_cancellation_finishes_other_cleanup_and_aborts_receipt(
    tmp_path,
):
    boundary, store, _executor, registry, _calls, worlds, _plan = _case(
        tmp_path,
        cleanup_cancels=True,
    )

    with pytest.raises(asyncio.CancelledError):
        await GraphBoundPrerequisiteExperimentExecutor(
            boundary.admit().claim(),
            config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).execute()

    assert sum(world["archived"] for world in worlds.values()) == 2
    assert sum(
        registry.is_owned(f"{ORIGIN}/api/workflows/{object_id}")
        for object_id in worlds
    ) == 1
    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"


@pytest.mark.asyncio
async def test_unexpected_cleanup_fault_terminalizes_receipt_and_budget(
    tmp_path,
    monkeypatch,
):
    boundary, store, executor, _registry, _calls, _worlds, _plan = _case(
        tmp_path
    )
    claim = boundary.admit().claim()
    reservation_id = claim._resources.budget_reservation_id

    async def fail_cleanup(**_kwargs):
        raise RuntimeError("injected cleanup coordinator fault")

    monkeypatch.setattr(
        execution_module,
        "_cleanup_and_verify",
        fail_cleanup,
    )
    with pytest.raises(
        GraphBoundPrerequisiteExecutionDenied,
        match="terminal_failed",
    ) as raised:
        await GraphBoundPrerequisiteExperimentExecutor(
            claim,
            config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).execute()

    assert raised.value.cleanup is not None
    assert raised.value.cleanup.status == "uncertain"
    assert claim.state == "aborted"
    assert executor.policy.budget.reservation_remaining(reservation_id) == 0
    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"


@pytest.mark.asyncio
async def test_receipt_completion_precondition_fault_aborts_reserved_receipt(
    tmp_path,
    monkeypatch,
):
    boundary, store, executor, _registry, _calls, _worlds, _plan = _case(
        tmp_path
    )
    claim = boundary.admit().claim()
    reservation_id = claim._resources.budget_reservation_id
    resources_type = type(claim._resources)

    def fail_complete(_resources, *, outcome):
        assert outcome["receipt_state"] == "completed"
        raise GraphBoundExecutionClaimDenied(
            "injected_completion_precondition_failure",
            category="budget",
        )

    monkeypatch.setattr(resources_type, "complete", fail_complete)
    with pytest.raises(
        GraphBoundPrerequisiteExecutionDenied,
        match="injected_completion_precondition_failure",
    ):
        await GraphBoundPrerequisiteExperimentExecutor(
            claim,
            config=GraphBoundPrerequisiteExecutionConfig(enabled=True),
        ).execute()

    assert claim.state == "aborted"
    assert executor.policy.budget.reservation_remaining(reservation_id) == 0
    receipt, _path = _receipt(store)
    assert receipt.state == "aborted"
