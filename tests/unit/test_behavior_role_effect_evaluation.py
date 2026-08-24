"""R5C6 exact-session protected-effect execution and oracle proof tests."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from core.behavior.receipts import (
    ABORTED,
    COMPLETED,
    BehavioralReceiptStore,
    ReceiptStoreError,
)
from core.behavior.role_effect_evaluation import (
    ROLE_PROTECTED_EFFECT_EXECUTION_MODE,
    RoleProtectedEffectExecutionConfig,
    RoleProtectedEffectExecutionDenied,
    RoleProtectedEffectOracleVerdict,
)
from core.behavior.role_execution_claim import (
    RoleMonotonicityExecutionClaimConfig,
    RoleMonotonicityExecutionClaimDenied,
)
from core.behavior.role_membership_lifecycle import RoleSessionPolicyExecutor
from core.wraith.bola_replay import ReplayResponse, SessionBoundReplayResponse
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


EFFECT_VALUE = {"capability": "owned-admin-export", "visible": True}


class _FailingCompleteReceiptStore(BehavioralReceiptStore):
    def complete(self, fingerprint, *, reservation_token, outcome):
        raise ReceiptStoreError("simulated receipt completion failure")


class _EffectTransport:
    def __init__(
        self,
        context,
        *,
        active_outcome: str = "denied",
        revoked_outcome: str = "denied",
        active_witness_matches: bool = True,
        revoked_witness_matches: bool = True,
        revoked_membership_state: str = "revoked",
        cancel_at: int | None = None,
        fail_at: int | None = None,
        wrong_session_at: int | None = None,
    ) -> None:
        self.context = context
        self.active_outcome = active_outcome
        self.revoked_outcome = revoked_outcome
        self.active_witness_matches = active_witness_matches
        self.revoked_witness_matches = revoked_witness_matches
        self.revoked_membership_state = revoked_membership_state
        self.cancel_at = cancel_at
        self.fail_at = fail_at
        self.wrong_session_at = wrong_session_at
        self.calls = []

    def _membership(self, *, state: str, generation: int) -> str:
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

    @staticmethod
    def _probe(outcome: str) -> ReplayResponse:
        if outcome == "allowed":
            return ReplayResponse(
                200,
                json.dumps(
                    {"authorized": True, "effect": EFFECT_VALUE},
                    sort_keys=True,
                ),
            )
        if outcome == "denied":
            return ReplayResponse(
                403,
                json.dumps(
                    {"authorized": False, "effect": None},
                    sort_keys=True,
                ),
            )
        if outcome == "ambiguous":
            return ReplayResponse(
                200,
                json.dumps(
                    {
                        "authorized": True,
                        "effect": {"capability": "different-effect"},
                    },
                    sort_keys=True,
                ),
            )
        raise AssertionError(f"unknown probe outcome: {outcome}")

    async def send_bound(self, persona, session_id, request):
        self.calls.append((persona, session_id, request))
        call_number = len(self.calls)
        if self.cancel_at == call_number:
            raise asyncio.CancelledError()
        if self.fail_at == call_number:
            raise RuntimeError("simulated role transport failure")

        parsed = urlsplit(request.url)
        state = parse_qs(parsed.query).get("state", [None])[0]
        if request.method == "POST":
            response = ReplayResponse(
                200,
                self._membership(state="active", generation=41),
            )
        elif request.method == "PATCH":
            response = ReplayResponse(200, '{"accepted":true}')
        elif "/memberships/" in parsed.path:
            response = ReplayResponse(
                200,
                self._membership(
                    state=self.revoked_membership_state,
                    generation=42,
                ),
            )
        elif parsed.path.endswith("/admin-effect"):
            if state == "baseline":
                response = self._probe("allowed")
            elif state == "active":
                response = self._probe(self.active_outcome)
            elif state == "revoked":
                response = self._probe(self.revoked_outcome)
            else:
                raise AssertionError(f"unexpected admin-effect state: {state}")
        elif parsed.path.endswith("/authoritative-effect"):
            matches = (
                self.active_witness_matches
                if state == "active"
                else self.revoked_witness_matches
            )
            effect = EFFECT_VALUE if matches else {"capability": "stale-effect"}
            response = ReplayResponse(
                200,
                json.dumps({"effect": effect}, sort_keys=True),
            )
        else:
            raise AssertionError(f"unexpected request: {request.method} {request.url}")

        echoed_session = (
            f"{session_id}-forged"
            if self.wrong_session_at == call_number
            else session_id
        )
        return SessionBoundReplayResponse(
            response=response,
            persona=persona,
            session_id=echoed_session,
        )


def _active_context(tmp_path, monkeypatch, **transport_kwargs):
    context = _context(tmp_path, monkeypatch)
    transport = _EffectTransport(context, **transport_kwargs)
    context.executor = RoleSessionPolicyExecutor(
        transport,
        context.executor.policy,
        provenance=context.executor.provenance,
    )
    binding = _bind(context)
    store = BehavioralReceiptStore(tmp_path / "receipts")
    return context, transport, binding, store


def _run(context, binding, store, *, execution_enabled=True):
    return asyncio.run(
        context.coordinator.run_protected_effect_evaluation(
            request_binding=binding,
            executor=context.executor,
            persona_vault=context.vault,
            runtime=context.runtime,
            authority_validator=context.validator,
            claim_config=RoleMonotonicityExecutionClaimConfig(enabled=True),
            execution_config=RoleProtectedEffectExecutionConfig(
                enabled=execution_enabled
            ),
            receipt_store=store,
        )
    )


@pytest.mark.parametrize(
    ("active_outcome", "revoked_outcome", "expected_verdict"),
    (
        (
            "allowed",
            "denied",
            RoleProtectedEffectOracleVerdict.CONFIRMED_ACTIVE_ESCALATION,
        ),
        (
            "denied",
            "allowed",
            RoleProtectedEffectOracleVerdict.CONFIRMED_REVOCATION_SURVIVAL,
        ),
        (
            "denied",
            "denied",
            RoleProtectedEffectOracleVerdict.REFUTED,
        ),
    ),
)
def test_conclusive_oracle_executes_exact_bound_sequence_and_completes_receipt(
    tmp_path,
    monkeypatch,
    active_outcome,
    revoked_outcome,
    expected_verdict,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        active_outcome=active_outcome,
        revoked_outcome=revoked_outcome,
    )

    result = _run(context, binding, store)
    public = result.to_dict()
    encoded = json.dumps(public, sort_keys=True)

    assert result.oracle.verdict is expected_verdict
    assert public["mode"] == ROLE_PROTECTED_EFFECT_EXECUTION_MODE
    assert public["status"] == expected_verdict.value
    assert public["receipt_state"] == COMPLETED
    assert public["target_requests_sent"] == 8
    assert public["cleanup_status"] == "verified"
    assert public["orphaned_owned_state_possible"] is False
    assert public["promotion_authority"] is False
    assert public["finding_authority"] is False
    assert result.cleanup.target_requests_sent == 8
    assert result.cleanup.orphaned_owned_state_possible is False
    assert tuple(
        item.observation_kind for item in result.effect_observations
    ) == (
        "higher_baseline",
        "active_lower_probe",
        "active_effect_witness",
        "revoked_lower_probe",
        "revoked_effect_witness",
    )
    assert [call[2].method for call in transport.calls] == [
        "POST",
        "GET",
        "GET",
        "GET",
        "PATCH",
        "GET",
        "GET",
        "GET",
    ]
    assert [call[0] for call in transport.calls] == [
        context.higher.persona_id,
        context.higher.persona_id,
        context.lower.persona_id,
        context.higher.persona_id,
        context.higher.persona_id,
        context.higher.persona_id,
        context.lower.persona_id,
        context.higher.persona_id,
    ]
    assert [call[1] for call in transport.calls] == [
        HIGH_SESSION,
        HIGH_SESSION,
        ACTIVE_LOW_SESSION,
        HIGH_SESSION,
        HIGH_SESSION,
        HIGH_SESSION,
        REVOKED_LOW_SESSION,
        HIGH_SESSION,
    ]
    assert all(call[2].redirect_mode == "manual" for call in transport.calls)
    assert context.executor.policy.budget.snapshot()["total_requests"] == 8
    receipt = store.load(result.receipt_id.removeprefix("behavioral-"))
    assert receipt.state == COMPLETED
    assert receipt.outcome == result.execution_response()
    assert receipt.outcome["finding_confirmed"] is (
        expected_verdict is not RoleProtectedEffectOracleVerdict.REFUTED
    )
    assert (receipt.outcome["finding_candidate_ref"] is not None) is (
        expected_verdict is not RoleProtectedEffectOracleVerdict.REFUTED
    )
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
        "owned-admin-export",
    ):
        assert secret not in encoded
        assert secret not in json.dumps(receipt.to_dict(), sort_keys=True)


def test_mismatched_effect_is_inconclusive_and_aborts_after_verified_cleanup(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        active_outcome="denied",
        revoked_outcome="ambiguous",
    )

    with pytest.raises(
        RoleProtectedEffectExecutionDenied,
        match="oracle_inconclusive",
    ) as denied:
        _run(context, binding, store)

    assert len(transport.calls) == 8
    assert denied.value.oracle.verdict is (
        RoleProtectedEffectOracleVerdict.INCONCLUSIVE
    )
    assert denied.value.cleanup.status == "verified"
    assert denied.value.terminal_receipt.state == ABORTED
    evidence = denied.value.terminal_receipt.terminal_evidence
    assert evidence["status"] == "cleaned"
    assert evidence["oracle_verdict"] == "inconclusive"
    assert evidence["oracle_evaluation_id"].startswith(
        "role_protected_effect_oracle_evaluation:"
    )
    assert len(evidence["effect_observation_refs"]) == 5
    assert evidence["finding_candidate_ref"] is None
    assert evidence["retry_authority"] is False


def test_witness_mismatch_cannot_become_positive_or_negative_proof(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        active_outcome="allowed",
        revoked_outcome="denied",
        active_witness_matches=False,
    )

    with pytest.raises(
        RoleProtectedEffectExecutionDenied,
        match="oracle_inconclusive",
    ) as denied:
        _run(context, binding, store)

    assert len(transport.calls) == 8
    assert denied.value.oracle.active_independent_witness_observed is False
    assert (
        "active_independent_effect_witness_unavailable"
        in denied.value.oracle.uncertainty_reasons
    )
    assert denied.value.oracle.finding_candidate_ref is None
    assert denied.value.terminal_receipt.state == ABORTED


def test_cleanup_failure_aborts_and_never_runs_post_revocation_effect_units(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        active_outcome="allowed",
        revoked_membership_state="active",
    )

    with pytest.raises(
        RoleProtectedEffectExecutionDenied,
        match="cleanup_unverified",
    ) as denied:
        _run(context, binding, store)

    assert len(transport.calls) == 6
    assert not any(
        "state=revoked" in call[2].url for call in transport.calls
    )
    assert denied.value.cleanup.status == "failed"
    assert denied.value.cleanup.orphaned_owned_state_possible is True
    assert denied.value.terminal_receipt.state == ABORTED
    assert denied.value.terminal_receipt.terminal_evidence["status"] == (
        "cleanup_failed"
    )
    assert denied.value.terminal_receipt.terminal_evidence[
        "orphaned_owned_state_possible"
    ] is True


@pytest.mark.parametrize(
    ("failure_kind", "failure_at"),
    (("cancel", 3), ("transport", 4), ("session", 3)),
)
def test_failure_paths_still_revoke_verify_and_terminalize(
    tmp_path,
    monkeypatch,
    failure_kind,
    failure_at,
):
    kwargs = {
        "cancel_at": failure_at if failure_kind == "cancel" else None,
        "fail_at": failure_at if failure_kind == "transport" else None,
        "wrong_session_at": failure_at if failure_kind == "session" else None,
    }
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        **kwargs,
    )

    if failure_kind == "cancel":
        with pytest.raises(asyncio.CancelledError):
            _run(context, binding, store)
    else:
        with pytest.raises(RoleProtectedEffectExecutionDenied) as denied:
            _run(context, binding, store)
        assert denied.value.terminal_receipt.state == ABORTED
        assert denied.value.cleanup.status == "verified"

    assert [call[2].method for call in transport.calls[-2:]] == ["PATCH", "GET"]
    receipts = list((tmp_path / "receipts").glob("*.json"))
    assert len(receipts) == 1
    stored = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert stored["state"] == ABORTED
    assert stored["terminal_evidence"]["status"] == "cleaned"
    assert stored["terminal_evidence"]["finding_confirmed"] is False
    assert stored["terminal_evidence"]["retry_authority"] is False


def test_default_off_refusal_precedes_receipt_budget_and_transport(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(tmp_path, monkeypatch)

    with pytest.raises(
        RoleProtectedEffectExecutionDenied,
        match="execution_is_disabled",
    ):
        _run(context, binding, store, execution_enabled=False)

    assert transport.calls == []
    assert context.executor.policy.budget.snapshot()["total_requests"] == 0
    assert not (tmp_path / "receipts").exists()


def test_receipt_completion_failure_falls_back_to_durable_abort(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, _store = _active_context(
        tmp_path,
        monkeypatch,
        active_outcome="denied",
        revoked_outcome="denied",
    )
    store = _FailingCompleteReceiptStore(tmp_path / "failed-receipts")

    with pytest.raises(
        RoleProtectedEffectExecutionDenied,
        match="receipt_completion_failed",
    ) as denied:
        _run(context, binding, store)

    assert len(transport.calls) == 8
    assert denied.value.cleanup.status == "verified"
    assert denied.value.terminal_receipt.state == ABORTED
    assert denied.value.terminal_receipt.terminal_evidence["status"] == "cleaned"
    assert denied.value.terminal_receipt.terminal_evidence[
        "finding_confirmed"
    ] is False


def test_completed_replay_neither_refreshes_budget_nor_repeats_transport(
    tmp_path,
    monkeypatch,
):
    context, transport, binding, store = _active_context(
        tmp_path,
        monkeypatch,
        active_outcome="denied",
        revoked_outcome="denied",
    )
    first = _run(context, binding, store)
    before = context.executor.policy.budget.snapshot()

    with pytest.raises(RoleMonotonicityExecutionClaimDenied):
        _run(context, binding, store)

    assert first.oracle.verdict is RoleProtectedEffectOracleVerdict.REFUTED
    assert len(transport.calls) == 8
    assert context.executor.policy.budget.snapshot() == before
    receipt = store.load(first.receipt_id.removeprefix("behavioral-"))
    assert receipt.state == COMPLETED
