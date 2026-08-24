"""R5C4 atomic receipt/budget claim lifecycle; all traffic is forbidden."""

from __future__ import annotations

import ast
import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    ABORTED,
    RESERVED,
    BehavioralReceiptStore,
    ReceiptStoreError,
)
from core.behavior.role_execution_claim import (
    ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE,
    RoleMonotonicityExecutionClaimAdmission,
    RoleMonotonicityExecutionClaimConfig,
    RoleMonotonicityExecutionClaimContract,
    RoleMonotonicityExecutionClaimDenied,
)
from core.behavior.role_request_binding import RoleMembershipObservationBinding
from tests.unit.test_behavior_role_request_binding import (
    ACTIVE_LOW_SESSION,
    BODY_SECRET,
    HIGH_SESSION,
    ORIGIN,
    QUERY_SECRET,
    REVOKED_LOW_SESSION,
    TENANT_ID,
    _bind,
    _context,
    _mutated_runtime,
)


class _RecordingReceiptStore(BehavioralReceiptStore):
    def __init__(self, root):
        super().__init__(root)
        self.last_fingerprint = None

    def reserve(self, fingerprint, *, context):
        self.last_fingerprint = fingerprint
        return super().reserve(fingerprint, context=context)


class _FailingReserveReceiptStore(_RecordingReceiptStore):
    def reserve(self, fingerprint, *, context):
        self.last_fingerprint = fingerprint
        raise ReceiptStoreError("simulated receipt reservation failure")


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
        raise ReceiptStoreError("simulated receipt abort failure")


def _expected_actions(binding):
    return tuple(
        (
            item.request_binding.action_class.value,
            item.request_binding.endpoint_key,
        )
        for item in binding.action_bindings
    )


def _boundary(
    tmp_path,
    monkeypatch,
    *,
    config=None,
    receipt_store=None,
    runtime=None,
    authorization=None,
    request_binding=None,
):
    context = _context(tmp_path, monkeypatch)
    binding = request_binding or _bind(context)
    store = receipt_store or _RecordingReceiptStore(tmp_path / "receipts")
    boundary = RoleMonotonicityExecutionClaimAdmission(
        proof=context.proof,
        request_binding=binding,
        target_origin=ORIGIN,
        authorization=authorization or context.authorization,
        executor=context.executor,
        persona_vault=context.vault,
        runtime=runtime or context.runtime,
        authority_validator=context.validator,
        config=(
            config
            if config is not None
            else RoleMonotonicityExecutionClaimConfig(enabled=True)
        ),
        receipt_store=store,
    )
    return boundary, store, context, binding


def test_preflight_is_default_off_deterministic_and_side_effect_free(
    tmp_path,
    monkeypatch,
):
    disabled, store, context, _binding = _boundary(
        tmp_path,
        monkeypatch,
        config=RoleMonotonicityExecutionClaimConfig(enabled=False),
    )
    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="claim_is_disabled",
    ):
        disabled.validate_preflight()

    enabled, store, context, binding = _boundary(
        tmp_path / "enabled",
        monkeypatch,
    )
    before = context.executor.policy.budget.snapshot()
    first = enabled.validate_preflight()
    second = enabled.validate_preflight()

    assert first.to_dict() == second.to_dict()
    assert first.mode == ROLE_MONOTONICITY_EXECUTION_CLAIM_MODE
    assert first.request_binding.binding_id == binding.binding_id
    assert first.total_request_units == 8
    assert tuple(item.ordinal for item in first.reserved_request_units) == tuple(
        range(8)
    )
    assert first.resolved_execution_blockers == (
        "atomic_budget_reservation_required",
        "durable_execution_receipt_required",
    )
    assert first.remaining_execution_blockers == (
        "effect_evaluation_required",
    )
    assert first.current_context_revalidated is True
    assert first.budget_reservation_allowed is True
    assert first.atomic_resource_lifecycle is True
    assert first.durable_receipt_reserved is False
    assert first.budget_reserved is False
    assert first.claim_available is False
    assert first.target_requests_sent == 0
    assert first.executable is False
    assert store.last_fingerprint is None
    assert not (tmp_path / "enabled" / "receipts").exists()
    assert context.executor.policy.budget.snapshot() == before
    assert context.calls == []


def test_role_admission_production_seam_reserves_exact_atomic_claim(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    binding = _bind(context)
    store = _RecordingReceiptStore(tmp_path / "claim-receipts")
    expected = _expected_actions(binding)

    lease = context.coordinator.reserve_execution_claim(
        request_binding=binding,
        executor=context.executor,
        persona_vault=context.vault,
        runtime=context.runtime,
        authority_validator=context.validator,
        config=RoleMonotonicityExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )
    public = lease.to_dict()
    encoded = json.dumps(public, sort_keys=True)

    assert lease.state == "active"
    assert lease.reserved_units == len(expected) == 8
    assert lease.contract.preview.request_binding.binding_id == binding.binding_id
    assert lease.contract.remaining_execution_blockers == (
        "effect_evaluation_required",
    )
    assert lease.contract.atomic_resource_lifecycle is True
    assert public["durable_receipt_reserved"] is True
    assert public["budget_reserved"] is True
    assert public["single_use_claim_acquired"] is False
    assert public["world_provisioning_authority"] is False
    assert public["backend_dispatch_authority"] is False
    assert public["effect_evaluation_authority"] is False
    assert public["finding_authority"] is False
    assert public["target_requests_sent"] == 0
    assert public["executable"] is False
    assert store.last_fingerprint is not None
    assert store.load(store.last_fingerprint).state == RESERVED
    assert context.executor.policy.budget.reservation_matches(
        lease._resources.budget_reservation_id,
        expected,
    )
    assert lease._resources.budget_reservation_id not in encoded
    assert "reservation_token" not in encoded
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
        assert secret not in encoded
    for _action_class, endpoint in expected:
        assert endpoint not in encoded
    assert context.calls == []

    assert lease.abort() == len(expected)
    assert lease.terminal_receipt.state == ABORTED


def test_claim_is_one_use_and_terminal_replay_does_not_refresh_budget(
    tmp_path,
    monkeypatch,
):
    boundary, store, context, binding = _boundary(
        tmp_path,
        monkeypatch,
    )
    expected = _expected_actions(binding)
    lease = boundary.admit()

    claim = lease.claim()
    assert lease.state == claim.state == "claimed"
    assert claim.to_dict()["single_use_claim_acquired"] is True
    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="claim_is_not_available",
    ):
        lease.claim()
    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="claim_state_mismatch",
    ):
        lease.abort()

    assert claim.abort() == len(expected)
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert claim.terminal_receipt.state == ABORTED
    assert store.load(store.last_fingerprint).abort_reason == (
        "role_execution_claim_aborted"
    )
    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="claim_state_mismatch",
    ):
        claim.abort()

    def forbidden_budget_refresh(*_args, **_kwargs):
        raise AssertionError("terminal replay must not refresh the budget")

    monkeypatch.setattr(
        context.executor.policy.budget,
        "try_reserve",
        forbidden_budget_refresh,
    )
    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="claim_replay_denied",
    ) as denied:
        boundary.admit()

    assert denied.value.terminal_receipt.state == ABORTED
    assert context.executor.policy.budget.preview_reservation(expected) == (
        True,
        "ok",
    )
    assert context.calls == []


def test_receipt_reservation_failure_precedes_any_budget_mutation(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    binding = _bind(context)
    store = _FailingReserveReceiptStore(tmp_path / "failed-receipts")
    boundary = RoleMonotonicityExecutionClaimAdmission(
        proof=context.proof,
        request_binding=binding,
        target_origin=ORIGIN,
        authorization=context.authorization,
        executor=context.executor,
        persona_vault=context.vault,
        runtime=context.runtime,
        authority_validator=context.validator,
        config=RoleMonotonicityExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )
    before = context.executor.policy.budget.snapshot()

    def forbidden_budget_reservation(*_args, **_kwargs):
        raise AssertionError("budget reservation ran before durable receipt")

    monkeypatch.setattr(
        context.executor.policy.budget,
        "try_reserve",
        forbidden_budget_reservation,
    )
    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="receipt_reservation_failed",
    ):
        boundary.admit()

    assert context.executor.policy.budget.snapshot() == before
    assert context.calls == []


def test_budget_race_aborts_receipt_without_partial_claim(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    binding = _bind(context)
    expected = _expected_actions(binding)
    store = _RacingReceiptStore(
        tmp_path / "race-receipts",
        budget=context.executor.policy.budget,
        actions=expected,
    )
    boundary = RoleMonotonicityExecutionClaimAdmission(
        proof=context.proof,
        request_binding=binding,
        target_origin=ORIGIN,
        authorization=context.authorization,
        executor=context.executor,
        persona_vault=context.vault,
        runtime=context.runtime,
        authority_validator=context.validator,
        config=RoleMonotonicityExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )

    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="budget_reservation_denied",
    ) as denied:
        boundary.admit()

    assert denied.value.terminal_receipt.state == ABORTED
    assert denied.value.terminal_receipt.abort_reason == (
        "role_execution_budget_denied"
    )
    assert store.load(store.last_fingerprint).state == ABORTED
    assert store.competing_reservation_id is not None
    assert context.executor.policy.budget.reservation_remaining(
        store.competing_reservation_id
    ) == len(expected)
    assert context.executor.policy.budget.release_reservation(
        store.competing_reservation_id
    ) == len(expected)
    assert context.calls == []


def test_budget_identity_mismatch_releases_reservation_and_aborts_receipt(
    tmp_path,
    monkeypatch,
):
    boundary, store, context, binding = _boundary(
        tmp_path,
        monkeypatch,
    )
    expected = _expected_actions(binding)
    monkeypatch.setattr(
        context.executor.policy.budget,
        "reservation_matches",
        lambda *_args, **_kwargs: False,
    )

    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="budget_reservation_identity_mismatch",
    ) as denied:
        boundary.admit()

    assert denied.value.terminal_receipt.state == ABORTED
    assert denied.value.terminal_receipt.abort_reason == (
        "role_execution_budget_identity_mismatch"
    )
    assert context.executor.policy.budget.preview_reservation(expected) == (
        True,
        "ok",
    )
    assert store.load(store.last_fingerprint).state == ABORTED
    assert context.calls == []


def test_contract_failure_rolls_back_budget_and_receipt(
    tmp_path,
    monkeypatch,
):
    boundary, store, context, binding = _boundary(
        tmp_path,
        monkeypatch,
    )
    expected = _expected_actions(binding)

    def fail_contract(_cls, **_kwargs):
        raise ValueError("simulated contract construction failure")

    monkeypatch.setattr(
        RoleMonotonicityExecutionClaimContract,
        "build",
        classmethod(fail_contract),
    )
    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="contract_construction_failed",
    ) as denied:
        boundary.admit()

    assert denied.value.terminal_receipt.state == ABORTED
    assert denied.value.terminal_receipt.abort_reason == (
        "role_execution_contract_failed"
    )
    assert context.executor.policy.budget.preview_reservation(expected) == (
        True,
        "ok",
    )
    assert store.load(store.last_fingerprint).state == ABORTED
    assert context.calls == []


def test_receipt_abort_failure_still_releases_budget_and_closes_lease(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    binding = _bind(context)
    expected = _expected_actions(binding)
    store = _FailingAbortReceiptStore(tmp_path / "abort-failure-receipts")
    boundary = RoleMonotonicityExecutionClaimAdmission(
        proof=context.proof,
        request_binding=binding,
        target_origin=ORIGIN,
        authorization=context.authorization,
        executor=context.executor,
        persona_vault=context.vault,
        runtime=context.runtime,
        authority_validator=context.validator,
        config=RoleMonotonicityExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )
    lease = boundary.admit()

    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="budget_released_but_receipt_abort_failed",
    ):
        lease.abort()

    assert lease.state == "aborted"
    assert lease.reserved_units == 0
    assert store.load(store.last_fingerprint).state == RESERVED
    assert context.executor.policy.budget.preview_reservation(expected) == (
        True,
        "ok",
    )
    assert context.calls == []


@pytest.mark.parametrize(
    "case",
    (
        "policy",
        "request",
        "membership_generation",
        "observation",
        "cleanup",
        "run",
        "tenant",
        "authority",
    ),
)
def test_changed_bound_state_fails_closed_before_receipt_or_transport(
    tmp_path,
    monkeypatch,
    case,
):
    context = _context(tmp_path, monkeypatch)
    binding = _bind(context)
    runtime = context.runtime
    authorization = context.authorization
    if case == "policy":
        context.executor.policy.budget.max_total_requests = 7
    elif case == "request":
        runtime = _mutated_runtime(context, "query_substitution")
    elif case == "membership_generation":
        runtime = _mutated_runtime(context, "stale_revocation_generation")
    elif case == "observation":
        runtime = replace(
            runtime,
            membership_observation_binding=(
                RoleMembershipObservationBinding.build(
                    proof=context.proof,
                    tenant_pointer="/tenant",
                    subject_pointer="/subject",
                    role_pointer="/role",
                    state_pointer="/membership_state",
                    generation_pointer="/membership_generation",
                )
            ),
        )
    elif case == "cleanup":
        binding = copy.deepcopy(binding)
        object.__setattr__(
            binding,
            "cleanup_lineage_ref",
            stable_hash("role_membership_cleanup_lineage", "changed"),
        )
    elif case == "run":
        runtime = _mutated_runtime(context, "cross_run_splice")
    elif case == "tenant":
        runtime = _mutated_runtime(context, "cross_tenant_splice")
    elif case == "authority":
        authorization = copy.deepcopy(context.authorization)
        authorization.authorization_basis = "changed after R5C3 binding"
        authorization.sign()
    else:
        raise AssertionError(f"unknown case: {case}")
    store = _RecordingReceiptStore(tmp_path / f"{case}-receipts")
    boundary = RoleMonotonicityExecutionClaimAdmission(
        proof=context.proof,
        request_binding=binding,
        target_origin=ORIGIN,
        authorization=authorization,
        executor=context.executor,
        persona_vault=context.vault,
        runtime=runtime,
        authority_validator=context.validator,
        config=RoleMonotonicityExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )

    with pytest.raises(RoleMonotonicityExecutionClaimDenied):
        boundary.admit()

    assert store.last_fingerprint is None
    assert context.executor.policy.budget.snapshot()["total_requests"] == 0
    assert context.calls == []


def test_claim_contract_is_content_addressed_and_rejects_flag_tampering(
    tmp_path,
    monkeypatch,
):
    boundary, _store, context, _binding = _boundary(
        tmp_path,
        monkeypatch,
    )
    lease = boundary.admit()

    with pytest.raises(ValueError, match="claim contract is invalid"):
        replace(lease.contract, budget_reserved=False)
    with pytest.raises(ValueError, match="claim preview is invalid"):
        replace(
            lease.contract.preview,
            total_request_units=9,
        )

    assert lease.abort() == 8
    assert context.calls == []


def test_claim_module_has_no_transport_provisioning_or_effect_surface():
    source_path = (
        Path(__file__).parents[2]
        / "core"
        / "behavior"
        / "role_execution_claim.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    function_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert not function_names & {
        "execute",
        "dispatch",
        "provision",
        "evaluate_effect",
        "complete",
        "promote",
    }
    assert ".send(" not in source
    assert ".send_action(" not in source
    assert "raw_send" not in source
    assert ".try_reserve(" in source
