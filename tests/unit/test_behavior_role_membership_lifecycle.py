"""R5C5 exact-session membership setup, revocation, and cleanup proof tests."""

from __future__ import annotations

import asyncio
import json

import pytest

from core.behavior.receipts import ABORTED, BehavioralReceiptStore
from core.behavior.role_execution_claim import (
    RoleMonotonicityExecutionClaimConfig,
    RoleMonotonicityExecutionClaimDenied,
)
from core.behavior.role_membership_lifecycle import (
    ROLE_MEMBERSHIP_LIFECYCLE_MODE,
    RoleMembershipLifecycleConfig,
    RoleMembershipLifecycleDenied,
    RoleMembershipLifecycleExecutor,
    RoleSessionPolicyExecutor,
)
from core.wraith.bola_replay import (
    ReplayResponse,
    SessionBoundReplayResponse,
)
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
)


class _MembershipTransport:
    def __init__(
        self,
        context,
        *,
        active_generation: int = 41,
        revoked_state: str = "revoked",
        cancel_setup: bool = False,
    ) -> None:
        self.context = context
        self.active_generation = active_generation
        self.revoked_state = revoked_state
        self.cancel_setup = cancel_setup
        self.calls = []

    def _body(self, *, state: str, generation: int) -> str:
        return json.dumps(
            {
                "tenant_id": TENANT_ID,
                "member_id": self.context.lower.persona_id,
                "role_assignment": self.context.runtime.lower_role_ref,
                "state": state,
                "generation": generation,
            },
            sort_keys=True,
        )

    async def send_bound(self, persona, session_id, request):
        self.calls.append((persona, session_id, request))
        if self.cancel_setup and len(self.calls) == 1:
            raise asyncio.CancelledError()
        if request.method == "POST":
            body = self._body(
                state="active",
                generation=self.active_generation,
            )
        elif request.method == "PATCH":
            body = '{"accepted":true}'
        else:
            body = self._body(
                state=self.revoked_state,
                generation=42,
            )
        return SessionBoundReplayResponse(
            response=ReplayResponse(200, body),
            persona=persona,
            session_id=session_id,
        )


def _active_context(tmp_path, monkeypatch, **transport_kwargs):
    context = _context(tmp_path, monkeypatch)
    transport = _MembershipTransport(context, **transport_kwargs)
    context.executor = RoleSessionPolicyExecutor(
        transport,
        context.executor.policy,
        provenance=context.executor.provenance,
    )
    binding = _bind(context)
    store = BehavioralReceiptStore(tmp_path / "receipts")
    return context, transport, binding, store


def _run(context, binding, store, *, lifecycle_enabled=True):
    return asyncio.run(
        context.coordinator.run_membership_lifecycle_probe(
            request_binding=binding,
            executor=context.executor,
            persona_vault=context.vault,
            runtime=context.runtime,
            authority_validator=context.validator,
            claim_config=RoleMonotonicityExecutionClaimConfig(enabled=True),
            lifecycle_config=RoleMembershipLifecycleConfig(
                enabled=lifecycle_enabled
            ),
            receipt_store=store,
        )
    )


def test_production_seam_executes_only_session_attested_membership_lifecycle(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
    )

    result = _run(context, binding, store)
    public = result.to_dict()
    encoded = json.dumps(public, sort_keys=True)

    assert public["mode"] == ROLE_MEMBERSHIP_LIFECYCLE_MODE
    assert public["status"] == "cleaned"
    assert public["target_requests_sent"] == 3
    assert public["role_probes_sent"] == 0
    assert public["remaining_execution_blockers"] == [
        "effect_evaluation_required"
    ]
    assert public["effect_evaluation_authority"] is False
    assert public["finding_authority"] is False
    assert public["promotion_authority"] is False
    assert public["executable"] is False
    assert result.active_observation.state == "active"
    assert result.revoked_observation.state == "revoked"
    assert result.cleanup.status == "verified"
    assert result.cleanup.orphaned_owned_state_possible is False
    assert result.cleanup.target_requests_sent == 3
    assert [call[2].method for call in transport.calls] == [
        "POST",
        "PATCH",
        "GET",
    ]
    assert all(call[0] == context.higher.persona_id for call in transport.calls)
    assert all(call[1] == HIGH_SESSION for call in transport.calls)
    assert not any("admin-effect" in call[2].url for call in transport.calls)
    assert not any(
        "authoritative-effect" in call[2].url for call in transport.calls
    )
    assert context.executor.policy.budget.snapshot() == {
        "total_requests": 3,
        "cross_object_reads": 0,
        "privilege_mutations": 2,
        "creates": 0,
        "endpoints_touched": 2,
    }
    receipt = store.load(result.receipt_id.removeprefix("behavioral-"))
    assert receipt.state == ABORTED
    assert receipt.abort_reason == "role_membership_lifecycle_probe_completed"
    assert receipt.terminal_evidence["status"] == "cleaned"
    assert receipt.terminal_evidence["target_requests_sent"] == 3
    assert receipt.terminal_evidence["finding_confirmed"] is False
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
    ):
        assert secret not in encoded


def test_replay_refuses_without_refreshing_budget_or_transport(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
    )
    _run(context, binding, store)
    before = context.executor.policy.budget.snapshot()

    with pytest.raises(
        RoleMonotonicityExecutionClaimDenied,
        match="current_request_revalidation_denied",
    ):
        _run(context, binding, store)

    assert len(transport.calls) == 3
    assert context.executor.policy.budget.snapshot() == before


def test_default_off_refusal_precedes_receipt_budget_and_transport(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
    )

    with pytest.raises(
        RoleMembershipLifecycleDenied,
        match="lifecycle_is_disabled",
    ):
        _run(context, binding, store, lifecycle_enabled=False)

    assert transport.calls == []
    assert context.executor.policy.budget.snapshot()["total_requests"] == 0
    assert not (tmp_path / "receipts").exists()


def test_active_observation_mismatch_still_verifies_revocation_and_aborts(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        active_generation=99,
    )

    with pytest.raises(
        RoleMembershipLifecycleDenied,
        match="target_observation_mismatch",
    ) as denied:
        _run(context, binding, store)

    assert len(transport.calls) == 3
    assert denied.value.cleanup.status == "verified"
    assert denied.value.cleanup.orphaned_owned_state_possible is False
    assert denied.value.terminal_receipt.state == ABORTED
    evidence = denied.value.terminal_receipt.terminal_evidence
    assert evidence["status"] == "cleaned"
    assert evidence["active_observation_ref"] is None
    assert evidence["revoked_observation_ref"].startswith(
        "role_membership_state_observation:"
    )
    assert evidence["finding_confirmed"] is False


def test_unverified_revocation_is_terminal_and_marks_owned_state_possible(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        revoked_state="active",
    )

    with pytest.raises(
        RoleMembershipLifecycleDenied,
        match="cleanup_unverified",
    ) as denied:
        _run(context, binding, store)

    assert len(transport.calls) == 3
    assert denied.value.cleanup.status == "failed"
    assert denied.value.cleanup.orphaned_owned_state_possible is True
    assert denied.value.terminal_receipt.state == ABORTED
    evidence = denied.value.terminal_receipt.terminal_evidence
    assert evidence["status"] == "cleanup_failed"
    assert evidence["revoked_observation_ref"] is None
    assert evidence["retry_authority"] is False


def test_non_session_executor_is_denied_before_target_and_releases_claim(
    tmp_path,
    monkeypatch,
):
    context = _context(tmp_path, monkeypatch)
    binding = _bind(context)
    store = BehavioralReceiptStore(tmp_path / "receipts")
    lease = context.coordinator.reserve_execution_claim(
        request_binding=binding,
        executor=context.executor,
        persona_vault=context.vault,
        runtime=context.runtime,
        authority_validator=context.validator,
        config=RoleMonotonicityExecutionClaimConfig(enabled=True),
        receipt_store=store,
    )
    claim = lease.claim()

    with pytest.raises(
        RoleMembershipLifecycleDenied,
        match="runtime_authority_invalid",
    ) as denied:
        asyncio.run(
            RoleMembershipLifecycleExecutor(
                claim,
                config=RoleMembershipLifecycleConfig(enabled=True),
            ).execute()
        )

    assert context.calls == []
    assert claim.state == "aborted"
    assert claim.reserved_units == 0
    assert denied.value.target_request_possible is False
    assert denied.value.terminal_receipt.state == ABORTED


def test_replaced_policy_send_is_denied_before_target(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
    )
    forged_calls = []

    async def forged_send(*args, **kwargs):
        forged_calls.append((args, kwargs))
        return 200, "{}"

    context.executor.send_action = forged_send

    with pytest.raises(
        RoleMembershipLifecycleDenied,
        match="runtime_authority_invalid",
    ) as denied:
        _run(context, binding, store)

    assert forged_calls == []
    assert transport.calls == []
    assert denied.value.target_request_possible is False
    assert denied.value.terminal_receipt.state == ABORTED


def test_cancellation_still_runs_revocation_verification_and_terminalizes(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        cancel_setup=True,
    )

    with pytest.raises(asyncio.CancelledError):
        _run(context, binding, store)

    assert [call[2].method for call in transport.calls] == [
        "POST",
        "PATCH",
        "GET",
    ]
    receipts = list((tmp_path / "receipts").glob("*.json"))
    assert len(receipts) == 1
    stored = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert stored["state"] == ABORTED
    assert stored["terminal_evidence"]["status"] == "cleaned"
    assert stored["terminal_evidence"]["finding_confirmed"] is False
