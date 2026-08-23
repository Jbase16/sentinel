import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.behavior.prerequisite_execution_claim import (
    GraphBoundExecutionClaimAdmission,
    GraphBoundExecutionClaimConfig,
    GraphBoundExecutionClaimDenied,
)
from core.behavior.receipts import BehavioralReceiptStore
from tests.unit.test_behavior_prerequisite_admission import _authorization
from tests.unit.test_behavior_prerequisite_experiments import ORIGIN
from tests.unit.test_behavior_prerequisite_request_binding import (
    _context,
    _executor,
)


class _RecordingReceiptStore(BehavioralReceiptStore):
    def __init__(self, root):
        super().__init__(root)
        self.last_fingerprint = None

    def reserve(self, fingerprint, *, context):
        self.last_fingerprint = fingerprint
        return super().reserve(fingerprint, context=context)


class _RacingReceiptStore(_RecordingReceiptStore):
    def __init__(self, root, *, budget, actions):
        super().__init__(root)
        self.budget = budget
        self.actions = actions
        self.competing_reservation_id = None

    def reserve(self, fingerprint, *, context):
        reservation = super().reserve(fingerprint, context=context)
        if reservation.created:
            self.competing_reservation_id, reason = self.budget.try_reserve(
                self.actions
            )
            assert reason == "ok"
            assert self.competing_reservation_id is not None
        return reservation


class _FailingAbortReceiptStore(_RecordingReceiptStore):
    def abort(self, fingerprint, *, reservation_token, reason):
        raise RuntimeError("simulated durable store failure")


def _expected_actions(binding):
    plan = binding.plans[0]
    raw_by_id = {item.binding_id: item for item in plan.ephemeral_requests}
    return tuple(
        (
            item.action_class,
            raw_by_id[item.binding_id].endpoint_key_value,
        )
        for item in plan.request_bindings
    )


def _boundary(tmp_path, *, executor=None, receipt_store=None, config=None):
    executor = executor or _executor()[0]
    records, lifecycle, state, compilation, admission, binding = _context(
        executor=executor
    )
    store = receipt_store or _RecordingReceiptStore(tmp_path / "receipts")
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
        config=config or GraphBoundExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )
    return boundary, store, executor, records, binding


def test_preflight_is_default_off_deterministic_and_side_effect_free(tmp_path):
    disabled, store, executor, _records, _binding = _boundary(
        tmp_path,
        config=GraphBoundExecutionClaimConfig(enabled=False),
    )
    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="claim_is_disabled",
    ):
        disabled.validate_preflight()

    enabled, store, executor, _records, binding = _boundary(tmp_path)
    expected = _expected_actions(binding)
    preview = enabled.validate_preflight()
    repeated = enabled.validate_preflight()

    assert preview.to_dict() == repeated.to_dict()
    assert preview.plan_id == binding.plans[0].plan_id
    assert preview.total_request_units == len(expected)
    assert preview.current_context_revalidated is True
    assert preview.budget_reservation_allowed is True
    assert preview.durable_receipt_reserved is False
    assert preview.budget_reserved is False
    assert preview.claim_available is False
    assert preview.backend_dispatch_authority is False
    assert preview.finding_authority is False
    assert preview.target_requests_sent == 0
    assert preview.executable is False
    assert store.last_fingerprint is None
    assert not (tmp_path / "receipts").exists()
    assert executor.policy.budget.preview_reservation(expected) == (True, "ok")


def test_admission_reserves_exact_budget_and_redacted_durable_receipt(tmp_path):
    boundary, store, executor, _records, binding = _boundary(tmp_path)
    expected = _expected_actions(binding)

    lease = boundary.admit()
    public = lease.to_dict()
    encoded = json.dumps(public, sort_keys=True)

    assert lease.state == "active"
    assert lease.reserved_units == len(expected)
    assert public["durable_receipt_reserved"] is True
    assert public["budget_reserved"] is True
    assert public["single_use_claim_acquired"] is False
    assert public["backend_dispatch_authority"] is False
    assert public["target_requests_sent"] == 0
    assert public["executable"] is False
    assert store.last_fingerprint is not None
    assert store.load(store.last_fingerprint).state == "reserved"
    assert executor.policy.budget.reservation_matches(
        lease._resources.budget_reservation_id,
        expected,
    )
    assert ORIGIN not in encoded
    assert lease._resources.budget_reservation_id not in encoded
    assert "reservation_token" not in encoded
    for _action, endpoint in expected:
        assert endpoint not in encoded

    assert lease.abort() == len(expected)


def test_claim_is_one_use_and_abort_releases_budget_but_burns_replay(tmp_path):
    boundary, store, executor, _records, binding = _boundary(tmp_path)
    expected = _expected_actions(binding)
    lease = boundary.admit()

    claim = lease.claim()
    assert lease.state == claim.state == "claimed"
    assert claim.to_dict()["single_use_claim_acquired"] is True
    assert claim.to_dict()["backend_dispatch_authority"] is False
    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="claim_not_available",
    ):
        lease.claim()
    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="claim_state_mismatch",
    ):
        lease.abort()

    assert claim.abort() == len(expected)
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert store.load(store.last_fingerprint).state == "aborted"
    assert executor.policy.budget.preview_reservation(expected) == (True, "ok")

    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="claim_replay_denied",
    ):
        boundary.admit()
    assert executor.policy.budget.preview_reservation(expected) == (True, "ok")


def test_current_capture_authority_and_selected_plan_are_revalidated(tmp_path):
    boundary, _store, _executor_value, records, binding = _boundary(tmp_path)

    changed_records = list(records)
    changed_records[0] = {
        **changed_records[0],
        "response_body": '{"order_id":"changed"}',
    }
    changed_capture = GraphBoundExecutionClaimAdmission(
        changed_records,
        target_origin=boundary.target_origin,
        world_id="alice",
        actor_persona_id="alice",
        authorization=boundary.authorization,
        executor=boundary.executor,
        lifecycle=boundary.lifecycle,
        state_machine=boundary.state_machine,
        compilation=boundary.compilation,
        admission=boundary.admission,
        request_binding=boundary.request_binding,
        plan_id=boundary.plan_id,
        config=boundary.config,
        receipt_store=boundary.receipt_store,
    )
    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="request_binding_not_ready",
    ):
        changed_capture.validate_preflight()

    invalid_authorization = _authorization()
    invalid_authorization.authorization_basis = "changed after signing"
    changed_authority = GraphBoundExecutionClaimAdmission(
        records,
        target_origin=boundary.target_origin,
        world_id="alice",
        actor_persona_id="alice",
        authorization=invalid_authorization,
        executor=boundary.executor,
        lifecycle=boundary.lifecycle,
        state_machine=boundary.state_machine,
        compilation=boundary.compilation,
        admission=boundary.admission,
        request_binding=boundary.request_binding,
        plan_id=boundary.plan_id,
        config=boundary.config,
        receipt_store=boundary.receipt_store,
    )
    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="static_admission_not_ready",
    ):
        changed_authority.validate_preflight()

    unavailable_plan = GraphBoundExecutionClaimAdmission(
        records,
        target_origin=boundary.target_origin,
        world_id="alice",
        actor_persona_id="alice",
        authorization=boundary.authorization,
        executor=boundary.executor,
        lifecycle=boundary.lifecycle,
        state_machine=boundary.state_machine,
        compilation=boundary.compilation,
        admission=boundary.admission,
        request_binding=boundary.request_binding,
        plan_id=("graph_bound_prepared_request_plan:" + "0" * 64),
        config=boundary.config,
        receipt_store=boundary.receipt_store,
    )
    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="selected_plan_unavailable",
    ):
        unavailable_plan.validate_preflight()
    assert binding.plans
    assert boundary.receipt_store.last_fingerprint is None


def test_budget_race_aborts_new_receipt_without_partial_reservation(tmp_path):
    executor, calls, _scope_calls = _executor(max_total_requests=17)
    records, lifecycle, state, compilation, admission, binding = _context(
        executor=executor
    )
    expected = _expected_actions(binding)
    assert len(expected) == 17
    store = _RacingReceiptStore(
        tmp_path / "race-receipts",
        budget=executor.policy.budget,
        actions=expected,
    )
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

    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="budget_reservation_denied",
    ):
        boundary.admit()

    assert calls == []
    assert store.load(store.last_fingerprint).state == "aborted"
    assert store.competing_reservation_id is not None
    assert executor.policy.budget.reservation_remaining(
        store.competing_reservation_id
    ) == len(expected)
    assert executor.policy.budget.release_reservation(
        store.competing_reservation_id
    ) == len(expected)


def test_receipt_abort_failure_still_releases_budget_and_closes_lease(tmp_path):
    store = _FailingAbortReceiptStore(tmp_path / "failing-receipts")
    boundary, _store, executor, _records, binding = _boundary(
        tmp_path,
        receipt_store=store,
    )
    expected = _expected_actions(binding)
    lease = boundary.admit()

    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="budget_released_but_receipt_abort_failed",
    ):
        lease.abort()

    assert lease.state == "aborted"
    assert lease.reserved_units == 0
    assert executor.policy.budget.preview_reservation(expected) == (True, "ok")
    assert store.load(store.last_fingerprint).state == "reserved"


def test_abort_detects_unaccounted_budget_reservation_consumption(tmp_path):
    boundary, store, executor, _records, binding = _boundary(tmp_path)
    expected = _expected_actions(binding)
    claim = boundary.admit().claim()
    reservation_id = claim._resources.budget_reservation_id
    executor.policy.budget.record(
        *expected[0],
        reservation_id=reservation_id,
    )

    with pytest.raises(
        GraphBoundExecutionClaimDenied,
        match="budget_release_mismatch",
    ):
        claim.abort()

    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert store.load(store.last_fingerprint).state == "aborted"


def test_claim_contract_is_content_addressed_and_rejects_flag_tampering(tmp_path):
    boundary, _store, _executor_value, _records, _binding = _boundary(tmp_path)
    lease = boundary.admit()

    with pytest.raises(ValueError, match="claim contract is invalid"):
        replace(lease.contract, budget_reserved=False)

    lease.abort()


def test_claim_module_has_no_transport_or_finding_surface():
    source_path = (
        Path(__file__).parents[2]
        / "core"
        / "behavior"
        / "prerequisite_execution_claim.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert "raw_send" not in source
    assert ".execute(" not in source
    assert ".record(" not in source
    assert "PolicyExecutor(" not in source
    assert "Finding" not in source
    assert "SubmissionCandidate" not in source
    assert "finding_store" not in source
    assert "world_manager" not in source
