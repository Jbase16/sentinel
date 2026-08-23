from pathlib import Path
from urllib.parse import urlsplit

import pytest

from core.behavior.prerequisite_execution_claim import (
    GraphBoundExecutionClaimAdmission,
    GraphBoundExecutionClaimConfig,
)
from core.behavior.prerequisite_provisioning import (
    GraphBoundFreshWorldProvisioner,
    GraphBoundFreshWorldProvisioningConfig,
    GraphBoundFreshWorldProvisioningDenied,
)
from core.behavior.receipts import BehavioralReceiptStore
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink
from tests.unit.test_behavior_prerequisite_admission import _authorization
from tests.unit.test_behavior_prerequisite_experiments import ORIGIN, WORKFLOW_ID
from tests.unit.test_behavior_prerequisite_request_binding import _context


def _receipt_fingerprint(tmp_path):
    return next((tmp_path / "receipts").glob("behavioral-*.json")).stem.removeprefix(
        "behavioral-"
    )


def test_provisioning_module_has_no_finding_or_promotion_surface():
    source = (
        Path(__file__).parents[2]
        / "core"
        / "behavior"
        / "prerequisite_provisioning.py"
    ).read_text(encoding="utf-8")

    assert "Finding" not in source
    assert "SubmissionCandidate" not in source
    assert "promote" not in source


def _active_case(
    tmp_path,
    *,
    fail_second_world_read=False,
    fail_cleanup=False,
    reuse_captured_identifier=False,
):
    calls = []
    create_count = 0

    async def transport(method, url, body=None, **kwargs):
        nonlocal create_count
        calls.append((method, url, body, kwargs))
        path = urlsplit(url).path
        if method == "POST" and path == "/api/workflows":
            create_count += 1
            object_id = (
                WORKFLOW_ID
                if reuse_captured_identifier and create_count == 1
                else f"runtime-workflow-{create_count}"
            )
            return 201, {"workflowId": object_id}
        if method == "GET" and fail_second_world_read and create_count == 2:
            return 500, {"error": "simulated prerequisite failure"}
        if method == "GET" and path.endswith("/first"):
            object_id = path.split("/")[3]
            return 200, {"firstToken": f"runtime-first-token-{object_id}"}
        if method == "GET" and path.endswith("/second"):
            object_id = path.split("/")[3]
            return 200, {"secondToken": f"runtime-second-token-{object_id}"}
        if method == "PATCH" and path.startswith("/api/workflows/"):
            if fail_cleanup and path.endswith("/runtime-workflow-1"):
                return 500, {"error": "simulated cleanup failure"}
            return 200, {"archived": True}
        raise AssertionError(f"terminal or unknown request dispatched: {method} {url}")

    registry = OwnershipRegistry()
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=96,
            max_requests_per_endpoint=20,
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
        executor=executor
    )
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
        plan_id=binding.plans[0].plan_id,
        config=GraphBoundExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )
    return boundary, store, executor, registry, calls


@pytest.mark.asyncio
async def test_provisioning_is_default_off_and_sends_zero_requests(tmp_path):
    boundary, store, executor, _registry, calls = _active_case(tmp_path)
    claim = boundary.admit().claim()

    with pytest.raises(
        GraphBoundFreshWorldProvisioningDenied,
        match="provisioning_is_disabled",
    ):
        await GraphBoundFreshWorldProvisioner(
            claim,
            config=GraphBoundFreshWorldProvisioningConfig(enabled=False),
        ).provision()

    assert calls == []
    assert claim.state == "claimed"
    assert claim.abort() == claim.contract.total_request_units
    assert store.load(_receipt_fingerprint(tmp_path)).state == "aborted"
    assert executor.policy.budget.snapshot()["total_requests"] == 0


@pytest.mark.asyncio
async def test_authority_expiry_after_claim_fails_before_target_traffic(tmp_path):
    boundary, store, executor, _registry, calls = _active_case(tmp_path)
    claim = boundary.admit().claim()
    authorization = claim._resources.runtime_plan.authorization
    authorization.expires_at = 0
    authorization.sign()

    with pytest.raises(
        GraphBoundFreshWorldProvisioningDenied,
        match="authority_is_not_current",
    ):
        await GraphBoundFreshWorldProvisioner(
            claim,
            config=GraphBoundFreshWorldProvisioningConfig(enabled=True),
        ).provision()

    assert calls == []
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert store.load(_receipt_fingerprint(tmp_path)).state == "aborted"
    assert executor.policy.budget.snapshot()["total_requests"] == 0


@pytest.mark.asyncio
async def test_policy_change_after_claim_fails_before_target_traffic(tmp_path):
    boundary, store, executor, _registry, calls = _active_case(tmp_path)
    claim = boundary.admit().claim()
    executor.policy.budget.max_creates += 1

    with pytest.raises(
        GraphBoundFreshWorldProvisioningDenied,
        match="policy_context_changed",
    ):
        await GraphBoundFreshWorldProvisioner(
            claim,
            config=GraphBoundFreshWorldProvisioningConfig(enabled=True),
        ).provision()

    assert calls == []
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert store.load(_receipt_fingerprint(tmp_path)).state == "aborted"
    assert executor.policy.budget.snapshot()["total_requests"] == 0


@pytest.mark.asyncio
async def test_signed_authority_change_after_claim_is_not_rebound(tmp_path):
    boundary, store, executor, _registry, calls = _active_case(tmp_path)
    claim = boundary.admit().claim()
    authorization = claim._resources.runtime_plan.authorization
    authorization.allowed_workflows.append("additional_workflow")
    authorization.sign()

    with pytest.raises(
        GraphBoundFreshWorldProvisioningDenied,
        match="authority_context_changed",
    ):
        await GraphBoundFreshWorldProvisioner(
            claim,
            config=GraphBoundFreshWorldProvisioningConfig(enabled=True),
        ).provision()

    assert calls == []
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert store.load(_receipt_fingerprint(tmp_path)).state == "aborted"
    assert executor.policy.budget.snapshot()["total_requests"] == 0


@pytest.mark.asyncio
async def test_claim_provisions_three_fresh_worlds_without_terminal_dispatch(tmp_path):
    boundary, store, executor, registry, calls = _active_case(tmp_path)
    claim = boundary.admit().claim()
    receipt_fingerprint = _receipt_fingerprint(tmp_path)

    result = await GraphBoundFreshWorldProvisioner(
        claim,
        config=GraphBoundFreshWorldProvisioningConfig(enabled=True),
    ).provision()

    public = result.to_dict()
    provisioning = public["provisioning"]
    assert claim.state == "aborted"
    assert tuple(item["world_role"] for item in provisioning["worlds"]) == (
        "valid_baseline",
        "counterfactual_treatment",
        "independent_control",
    )
    assert provisioning["runtime_lineage_substituted"] is True
    assert provisioning["terminal_actions_dispatched"] == 0
    assert public["backend_dispatch_authority"] is False
    assert public["finding_authority"] is False
    assert public["provenance_ref"].startswith(
        "graph_bound_provisioning_provenance:"
    )
    assert public["remaining_request_units"] == 0
    assert public["target_requests_sent"] == len(calls)
    cleanup = result.cleanup
    assert cleanup.status == "cleaned"
    assert cleanup.cleanup_steps_attempted == 3
    assert cleanup.cleanup_steps_completed == 3
    assert cleanup.ownership_grants_removed == 3
    assert cleanup.orphaned_owned_state_possible is False
    assert cleanup.terminal_actions_dispatched == 0
    assert claim.reserved_units == 0
    assert store.load(receipt_fingerprint).state == "aborted"
    assert all("/export" not in url for _method, url, _body, _kwargs in calls)
    assert all(WORKFLOW_ID not in url for _method, url, _body, _kwargs in calls)
    assert sum(method == "POST" for method, *_rest in calls) == 3
    for index in range(1, 4):
        assert any(
            f"/runtime-workflow-{index}/" in url
            for method, url, _body, _kwargs in calls
            if method == "GET"
        )
    for index in range(1, 4):
        assert not registry.is_owned(
            f"{ORIGIN}/api/workflows/runtime-workflow-{index}"
        )
    assert executor.policy.budget.snapshot()["total_requests"] == len(calls)


@pytest.mark.asyncio
async def test_captured_identifier_reuse_is_not_accepted_as_fresh_state(tmp_path):
    boundary, store, _executor, _registry, calls = _active_case(
        tmp_path,
        reuse_captured_identifier=True,
    )
    claim = boundary.admit().claim()
    receipt_fingerprint = _receipt_fingerprint(tmp_path)

    with pytest.raises(
        GraphBoundFreshWorldProvisioningDenied,
        match="create_reused_captured_identifier",
    ) as raised:
        await GraphBoundFreshWorldProvisioner(
            claim,
            config=GraphBoundFreshWorldProvisioningConfig(enabled=True),
        ).provision()

    assert raised.value.category == "freshness"
    assert raised.value.orphaned_owned_state_possible is True
    assert raised.value.cleanup is not None
    assert raised.value.cleanup.status == "cleanup_failed"
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert store.load(receipt_fingerprint).state == "aborted"
    assert len(calls) == 1
    assert all("/export" not in url for _method, url, _body, _kwargs in calls)


@pytest.mark.asyncio
async def test_cleanup_failure_is_terminal_and_reports_orphan_risk(tmp_path):
    boundary, store, _executor, registry, calls = _active_case(
        tmp_path,
        fail_cleanup=True,
    )
    claim = boundary.admit().claim()
    receipt_fingerprint = _receipt_fingerprint(tmp_path)

    with pytest.raises(
        GraphBoundFreshWorldProvisioningDenied,
        match="provisioning_cleanup_failed",
    ) as raised:
        await GraphBoundFreshWorldProvisioner(
            claim,
            config=GraphBoundFreshWorldProvisioningConfig(enabled=True),
        ).provision()

    assert raised.value.category == "cleanup"
    assert raised.value.orphaned_owned_state_possible is True
    assert raised.value.cleanup is not None
    assert raised.value.cleanup.status == "cleanup_failed"
    assert raised.value.cleanup.cleanup_steps_attempted == 3
    assert raised.value.cleanup.cleanup_steps_completed == 2
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert store.load(receipt_fingerprint).state == "aborted"
    assert all("/export" not in url for _method, url, _body, _kwargs in calls)
    assert registry.is_owned(f"{ORIGIN}/api/workflows/runtime-workflow-1")


@pytest.mark.asyncio
async def test_provisioning_failure_skips_dispatch_cleans_created_worlds_and_burns_claim(
    tmp_path,
):
    boundary, store, executor, registry, calls = _active_case(
        tmp_path,
        fail_second_world_read=True,
    )
    claim = boundary.admit().claim()
    receipt_fingerprint = _receipt_fingerprint(tmp_path)

    with pytest.raises(
        GraphBoundFreshWorldProvisioningDenied,
        match="provisioning_request_failed",
    ) as raised:
        await GraphBoundFreshWorldProvisioner(
            claim,
            config=GraphBoundFreshWorldProvisioningConfig(enabled=True),
        ).provision()

    assert raised.value.cleanup is not None
    assert raised.value.cleanup.status == "cleaned"
    assert raised.value.cleanup.cleanup_steps_attempted == 2
    assert raised.value.cleanup.cleanup_steps_completed == 2
    assert raised.value.orphaned_owned_state_possible is False
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert store.load(receipt_fingerprint).state == "aborted"
    assert all("/export" not in url for _method, url, _body, _kwargs in calls)
    assert not registry.is_owned(f"{ORIGIN}/api/workflows/runtime-workflow-1")
    assert not registry.is_owned(f"{ORIGIN}/api/workflows/runtime-workflow-2")
    assert executor.policy.budget.snapshot()["total_requests"] == len(calls)
