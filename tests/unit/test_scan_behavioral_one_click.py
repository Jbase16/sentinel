from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from core.behavior.omission_confirmation import OmissionCapabilityFinding
from core.errors import ErrorCode, SentinelError
from core.server.routers.scans import (
    BehavioralOneClickProfile,
    ScanRequest,
    _bounded_behavioral_phase_summary,
    begin_scan_logic,
    _run_behavioral_one_click_phase,
)
from core.server.state import ApplicationState


ENVELOPE_ID = "1" * 32
SOURCE_PERSONA_ID = "2" * 32
PEER_PERSONA_ID = "3" * 32


class _FindingStore:
    def __init__(self):
        self.added = []

    async def add_finding_async(self, finding, *, persist):
        self.added.append((finding, persist))
        return finding

    def get_all(self):
        return [finding for finding, _persist in self.added]


class _Session:
    def __init__(self):
        self.id = "behavioral-direct-session"
        self.findings = _FindingStore()
        self.logs = []

    def log(self, message):
        self.logs.append(message)


class _RunnerSession(_Session):
    def __init__(self, target):
        super().__init__()
        self.id = "behavioral-scan-session"
        self.target = target
        self.knowledge = {}
        self.status = "created"
        self.end_time = None
        self.issues = SimpleNamespace(get_all=lambda: [])

    def set_external_log_sink(self, _sink):
        return None

    def close_log_file(self):
        return None

    def close(self):
        return None

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
        }


class _RunnerEventBus:
    def __init__(self):
        self.events = []
        self.scan_starts = []

    def emit_scan_started(self, target, allowed_tools, session_id):
        self.scan_starts.append((target, list(allowed_tools), session_id))

    def subscribe_async(self, *_args, **_kwargs):
        return SimpleNamespace(unsubscribe=lambda: True)

    def emit(self, event):
        self.events.append(event)

    def emit_scan_completed(self, *_args, **_kwargs):
        return None


def _request(*, with_prior_capture: bool = False) -> ScanRequest:
    source_prior = (
        [
            {
                "method": "GET",
                "url": "https://example.test/app",
                "response_status": 200,
            }
        ]
        if with_prior_capture
        else None
    )
    peer_prior = (
        [
            {
                "method": "GET",
                "url": "https://example.test/app",
                "response_status": 403,
            }
        ]
        if with_prior_capture
        else None
    )
    return ScanRequest(
        target="https://example.test/app",
        mode="bug_bounty",
        behavioral_one_click=BehavioralOneClickProfile(
            envelope_id=ENVELOPE_ID,
            source_persona_id=SOURCE_PERSONA_ID,
            peer_persona_id=PEER_PERSONA_ID,
            prior_source_records=source_prior,
            prior_peer_records=peer_prior,
        ),
    )


def test_behavioral_one_click_requires_bug_bounty_mode():
    with pytest.raises(
        ValidationError,
        match="behavioral_one_click requires bug_bounty scan mode",
    ):
        ScanRequest(
            target="https://example.test/app",
            behavioral_one_click={
                "envelope_id": ENVELOPE_ID,
                "source_persona_id": SOURCE_PERSONA_ID,
                "peer_persona_id": PEER_PERSONA_ID,
            },
        )


def test_behavioral_one_click_requires_distinct_personas():
    with pytest.raises(
        ValidationError,
        match="behavioral one-click personas must be distinct",
    ):
        BehavioralOneClickProfile(
            envelope_id=ENVELOPE_ID,
            source_persona_id=SOURCE_PERSONA_ID,
            peer_persona_id=SOURCE_PERSONA_ID,
        )


def test_anonymous_passive_profile_forbids_persona_identities():
    profile = BehavioralOneClickProfile(
        mode="anonymous_passive",
        envelope_id=ENVELOPE_ID,
    )
    assert profile.is_anonymous_passive is True
    assert profile.source_persona_id is None
    assert profile.peer_persona_id is None

    with pytest.raises(
        ValidationError,
        match="anonymous passive one-click forbids persona identities",
    ):
        BehavioralOneClickProfile(
            mode="anonymous_passive",
            envelope_id=ENVELOPE_ID,
            source_persona_id=SOURCE_PERSONA_ID,
        )

    with pytest.raises(
        ValidationError,
        match="anonymous passive one-click forbids persona identities",
    ):
        BehavioralOneClickProfile(
            mode="anonymous_passive",
            envelope_id=ENVELOPE_ID,
            role_monotonicity={"schema_version": 1},
        )


def test_paired_persona_profile_still_requires_both_identities():
    with pytest.raises(
        ValidationError,
        match="paired-persona one-click requires both persona identities",
    ):
        BehavioralOneClickProfile(envelope_id=ENVELOPE_ID)


def test_paired_persona_prior_capture_requires_both_artifacts():
    with pytest.raises(
        ValidationError,
        match="prior behavioral capture requires both personas",
    ):
        BehavioralOneClickProfile(
            envelope_id=ENVELOPE_ID,
            source_persona_id=SOURCE_PERSONA_ID,
            peer_persona_id=PEER_PERSONA_ID,
            prior_source_records=[
                {
                    "method": "GET",
                    "url": "https://example.test/app",
                }
            ],
        )


def test_paired_persona_profile_can_stop_after_behavioral_phase():
    default = BehavioralOneClickProfile(
        envelope_id=ENVELOPE_ID,
        source_persona_id=SOURCE_PERSONA_ID,
        peer_persona_id=PEER_PERSONA_ID,
    )
    bounded = BehavioralOneClickProfile(
        completion="behavioral_phase_only",
        envelope_id=ENVELOPE_ID,
        source_persona_id=SOURCE_PERSONA_ID,
        peer_persona_id=PEER_PERSONA_ID,
    )

    assert default.completion == "continue_scan"
    assert default.is_behavioral_phase_only is False
    assert bounded.is_behavioral_phase_only is True


def test_behavioral_phase_summary_is_bounded_and_redacted():
    summary = _bounded_behavioral_phase_summary(
        phase_status="confirmed_finding",
        result={
            "status": "completed",
            "orchestration_receipt": {
                "receipt_id": "receipt:abc",
                "state": "completed",
                "reused": True,
                "reservation_token": "must-not-escape",
            },
            "execution": {
                "status": "completed",
                "cleanup_steps_completed": 2,
                "raw_response": "must-not-escape",
            },
            "capture_pair": {"raw": "must-not-escape"},
        },
        finding={
            "id": "finding-1",
            "type": "cross_principal_object_access",
            "metadata": {"secret": "must-not-escape"},
        },
    )

    assert summary == {
        "status": "confirmed_finding",
        "result_status": "completed",
        "finding_id": "finding-1",
        "finding_type": "cross_principal_object_access",
        "receipt_id": "receipt:abc",
        "receipt_state": "completed",
        "receipt_reused": True,
        "cleanup_status": "completed",
        "cleanup_steps_completed": 2,
        "profile_mode": None,
        "observation_classification": None,
        "observation_count": None,
        "adaptive_execution_status": None,
        "independent_proof_status": None,
        "reason": None,
    }
    assert "must-not-escape" not in str(summary)


@pytest.mark.asyncio
async def test_behavioral_one_click_runs_exact_profile_and_adds_finding(
    monkeypatch,
):
    from core.server.routers import foundry

    session = _Session()
    finding = {
        "id": "behavioral-finding",
        "type": "State-machine prerequisite enforcement failure",
    }

    async def execute(request, _):
        assert request.target_url == "https://example.test/app"
        assert request.envelope_id == ENVELOPE_ID
        assert request.source_persona_id == SOURCE_PERSONA_ID
        assert request.peer_persona_id == PEER_PERSONA_ID
        assert request.prior_source_records is not None
        assert request.prior_peer_records is not None
        assert _ is True
        return {"status": "completed", "finding": finding}

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )

    result = await _run_behavioral_one_click_phase(
        _request(with_prior_capture=True),
        session=session,
    )

    assert result == {"status": "completed", "finding": finding}
    assert session.findings.added == [(finding, True)]
    assert "before ordinary scan traffic" in session.logs[0]
    assert "behavioral-finding" in session.logs[1]


@pytest.mark.asyncio
async def test_behavioral_one_click_restores_cached_omission_finding(
    monkeypatch,
):
    from core.server.routers import foundry

    session = _Session()
    finding = OmissionCapabilityFinding.build(
        confirmation_id=f"fresh_omission_confirmation:{'4' * 64}",
        experiment_id=f"omission_experiment:{'5' * 64}",
        terminal_operation_id=f"action:{'6' * 64}",
        lifecycle_id=f"owned_lifecycle:{'7' * 64}",
        provenance_root="8" * 64,
    )

    async def execute(_request, _):
        return {
            "status": "already_executed",
            "kind": "fresh_omission_confirmation",
            "finding_authority": True,
            "finding_ref": finding.finding_id,
            "confirmation_id": finding.confirmation_id,
            "experiment_id": finding.experiment_id,
            "terminal_operation_id": finding.terminal_operation_id,
            "lifecycle_id": finding.lifecycle_id,
            "provenance_root": finding.provenance_root,
        }

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )

    await _run_behavioral_one_click_phase(_request(), session=session)

    restored, persist = session.findings.added[0]
    assert restored["id"] == finding.finding_id
    assert restored["metadata"]["finding_authority"] is True
    assert persist is True


@pytest.mark.asyncio
async def test_behavioral_one_click_restores_receipt_bound_graph_finding(
    monkeypatch,
):
    from core.behavior.normalize import stable_hash
    from core.server.routers import foundry, scans

    session = _Session()
    terminal_refs = [
        f"graph_bound_terminal_observation:{digit * 64}"
        for digit in ("1", "2", "3")
    ]
    cleanup_refs = [
        f"graph_bound_cleanup_evidence:{digit * 64}"
        for digit in ("4", "5", "6", "7", "8", "9")
    ]
    oracle_requirement_id = (
        f"prerequisite_effect_oracle_requirement:{'a' * 64}"
    )
    plan_id = f"graph_bound_prepared_request_plan:{'b' * 64}"
    effect_witness_ref = (
        f"graph_bound_independent_effect_witness:{'c' * 64}"
    )
    finding_candidate_ref = stable_hash(
        "graph_bound_prerequisite_candidate",
        {
            "oracle_requirement_id": oracle_requirement_id,
            "plan_id": plan_id,
            "family": "omission",
            "terminal_evidence_refs": terminal_refs,
            "effect_witness_ref": effect_witness_ref,
            "verdict": "confirmed",
        },
    )
    selection = {
        "payout_goal_plan_id": f"payout_goal_plan:{'d' * 64}",
        "payout_candidate_id": f"payout_goal_candidate:{'e' * 64}",
        "payout_goal_id": f"security_witness_goal:{'f' * 64}",
        "payout_terminal_operation_id": f"action:{'1' * 64}",
        "specification_id": (
            f"graph_bound_prerequisite_experiment:{'2' * 64}"
        ),
        "plan_id": plan_id,
        "graph_target_ref": f"security_obligation_target:{'3' * 64}",
        "graph_digest": f"security_obligation_graph:{'4' * 64}",
    }
    outcome = {
        "schema_version": 1,
        "kind": "graph_bound_prerequisite_execution",
        "mode": "behavioral_graph_bound_prerequisite_execution_v1",
        "status": "already_executed",
        "receipt_state": "completed",
        "claim_contract_id": (
            f"graph_bound_execution_claim_contract:{'5' * 64}"
        ),
        "capture_freshness_ref": (
            f"graph_bound_capture_freshness:{'0' * 64}"
        ),
        "plan_id": plan_id,
        "family": "omission",
        "provisioning_id": (
            f"graph_bound_fresh_world_provisioning:{'6' * 64}"
        ),
        "oracle_requirement_id": oracle_requirement_id,
        "reference_state_id": f"state:{'7' * 64}",
        "oracle_evaluation_id": (
            f"graph_bound_prerequisite_oracle_evaluation:{'8' * 64}"
        ),
        "oracle_verdict": "confirmed",
        "effect_witness_ref": effect_witness_ref,
        "runtime_value_inequality_ref": (
            "graph_bound_runtime_value_inequality_attestation:"
            f"{'9' * 64}"
        ),
        "terminal_evidence_refs": terminal_refs,
        "cleanup_evidence_refs": cleanup_refs,
        "cleanup_status": "verified",
        "cleanup_steps_attempted": 3,
        "cleanup_steps_completed": 3,
        "cleanup_verifications_attempted": 3,
        "cleanup_verifications_completed": 3,
        "ownership_grants_removed": 3,
        "target_requests_sent": 14,
        "orphaned_owned_state_possible": False,
        "provenance_root": "a" * 64,
        "finding_candidate_ref": finding_candidate_ref,
        "finding_confirmed": True,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
        **selection,
        "selection_ref": stable_hash(
            "graph_bound_one_click_selection",
            selection,
        ),
        "orchestration_receipt": {
            "receipt_id": f"behavioral-{'b' * 64}",
            "state": "completed",
            "reused": True,
        },
    }

    async def execute(_request, _):
        return dict(outcome)

    async def route(_req, *, session, result, finding):
        assert result["selection_ref"] == outcome["selection_ref"]
        return finding

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )
    monkeypatch.setattr(scans, "_route_completed_behavioral_finding", route)

    await _run_behavioral_one_click_phase(_request(), session=session)

    restored, persist = session.findings.added[0]
    assert restored["id"] == finding_candidate_ref
    assert restored["tool"] == "behavioral_graph_bound_prerequisite"
    assert restored["metadata"]["selection_ref"] == outcome["selection_ref"]
    assert persist is True


@pytest.mark.asyncio
async def test_behavioral_one_click_routes_receipt_bound_role_finding(
    monkeypatch,
    tmp_path,
):
    from core.base.task_router import TaskRouter
    from core.behavior.active import CONTROLLED_WORKFLOW
    from core.behavior.normalize import stable_hash
    from core.behavior.receipts import (
        BehavioralReceiptStore,
        redacted_receipt_context,
        redacted_role_protected_effect_execution_outcome,
        request_fingerprint,
    )
    from core.behavior.role_monotonicity import ROLE_MONOTONICITY_WORKFLOW
    from core.behavior.role_monotonicity_one_click import (
        RoleMonotonicityFindingCandidate,
    )
    from core.foundry.authorization import create_envelope
    from core.foundry.vault import PersonaVault
    from core.server.routers import foundry

    monkeypatch.setenv(
        "SENTINELFORGE_PERSONA_VAULT",
        str(tmp_path / "personas"),
    )
    monkeypatch.setenv(
        "SENTINELFORGE_AUTHZ_STORE",
        str(tmp_path / "authorizations"),
    )
    monkeypatch.setenv(
        "SENTINELFORGE_BEHAVIOR_RECEIPTS",
        str(tmp_path / "receipts"),
    )
    vault = PersonaVault()
    higher = vault.add_persona(
        label="role-higher",
        email="role-higher@research.example",
    )
    lower = vault.add_persona(
        label="role-lower",
        email="role-lower@research.example",
    )
    envelope = create_envelope(
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=["https://example.test"],
        authorization_basis="owned role monotonicity test",
        allowed_workflows=[CONTROLLED_WORKFLOW, ROLE_MONOTONICITY_WORKFLOW],
        disclosure_attestation=True,
    )
    role_specification = {"schema_version": 1, "test_ref": "exact-role-spec"}
    request = ScanRequest(
        target="https://example.test/app",
        mode="bug_bounty",
        behavioral_one_click=BehavioralOneClickProfile(
            envelope_id=envelope.envelope_id,
            source_persona_id=higher.persona_id,
            peer_persona_id=lower.persona_id,
            role_monotonicity=role_specification,
        ),
    )
    selection = {
        "payout_goal_plan_id": f"payout_goal_plan:{'0' * 64}",
        "payout_candidate_id": f"payout_goal_candidate:{'1' * 64}",
        "payout_goal_id": f"security_witness_goal:{'2' * 64}",
        "payout_terminal_operation_id": f"action:{'3' * 64}",
        "specification_id": (
            f"role_monotonicity_one_click_specification:{'4' * 64}"
        ),
        "proof_id": f"role_monotonicity_proof:{'5' * 64}",
        "request_binding_id": (
            f"role_monotonicity_request_binding:{'6' * 64}"
        ),
        "effect_observation_binding_id": (
            f"role_protected_effect_observation_binding:{'7' * 64}"
        ),
        "graph_target_ref": f"security_obligation_target:{'8' * 64}",
        "graph_digest": f"security_obligation_graph:{'9' * 64}",
        "role_receipt_id": f"behavioral-{'a' * 64}",
    }
    effect_refs = [
        f"role_protected_effect_observation:{digit * 64}"
        for digit in ("0", "1", "2", "3", "4")
    ]
    oracle_id = f"role_monotonicity_oracle:{'b' * 64}"
    active_witness = f"role_active_effect_witness:{'c' * 64}"
    revoked_witness = f"role_revoked_effect_witness:{'d' * 64}"
    candidate_payload = {
        "oracle_id": oracle_id,
        "observation_binding_id": selection[
            "effect_observation_binding_id"
        ],
        "verdict": "confirmed_active_escalation",
        "observation_refs": effect_refs,
        "active_effect_witness_ref": active_witness,
        "revoked_effect_witness_ref": revoked_witness,
    }
    outcome = redacted_role_protected_effect_execution_outcome(
        {
            "kind": "role_protected_effect_execution",
            "mode": "behavioral_role_protected_effect_execution_v1",
            "status": "confirmed_active_escalation",
            "receipt_state": "completed",
            "claim_contract_id": (
                "role_monotonicity_execution_claim_contract:"
                f"{'e' * 64}"
            ),
            "oracle_id": oracle_id,
            "oracle_evaluation_id": (
                "role_protected_effect_oracle_evaluation:"
                f"{'f' * 64}"
            ),
            "oracle_verdict": "confirmed_active_escalation",
            "active_membership_observation_ref": (
                f"role_membership_state_observation:{'a' * 64}"
            ),
            "revoked_membership_observation_ref": (
                f"role_membership_state_observation:{'b' * 64}"
            ),
            "effect_observation_refs": effect_refs,
            "active_effect_witness_ref": active_witness,
            "revoked_effect_witness_ref": revoked_witness,
            "cleanup_status": "verified",
            "target_requests_sent": 8,
            "target_request_may_have_been_sent": False,
            "orphaned_owned_state_possible": False,
            "provenance_root": "c" * 64,
            "finding_candidate_ref": stable_hash(
                "role_monotonicity_finding_candidate",
                candidate_payload,
            ),
            "finding_confirmed": True,
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
            **selection,
            "selection_ref": stable_hash(
                "role_monotonicity_one_click_selection",
                selection,
            ),
        }
    )
    store = BehavioralReceiptStore()
    fingerprint = request_fingerprint(
        {"test": "scan-role-receipt", "selection_ref": outcome["selection_ref"]}
    )
    reservation = store.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin="https://example.test",
            envelope_id=envelope.envelope_id,
            source_persona_id=higher.persona_id,
            peer_persona_id=lower.persona_id,
        ),
    )
    receipt = store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=outcome,
    )
    cached = {
        **outcome,
        "status": "already_executed",
        "orchestration_receipt": {
            "receipt_id": receipt.receipt_id,
            "state": receipt.state,
            "reused": True,
        },
    }
    expected_finding = (
        RoleMonotonicityFindingCandidate.from_completed_outcome(cached)
        .to_finding()
    )

    async def execute(foundry_request, _):
        assert foundry_request.role_monotonicity == role_specification
        assert _ is True
        return dict(cached)

    class RecordingRouter:
        async def handle_tool_output(self, **kwargs):
            proof = kwargs["completed_behavioral_proof"]
            assert proof.receipt_id == receipt.receipt_id
            assert proof.provenance_root == outcome["provenance_root"]
            assert kwargs["scanner_findings"] == (expected_finding,)
            canonical = dict(expected_finding)
            canonical["metadata"] = {
                **expected_finding["metadata"],
                "canonical_route": True,
            }
            return {"findings": [canonical]}

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )
    monkeypatch.setattr(
        TaskRouter,
        "instance",
        staticmethod(lambda: RecordingRouter()),
    )
    session = _Session()

    result = await _run_behavioral_one_click_phase(request, session=session)

    assert result["finding"]["metadata"]["canonical_route"] is True
    restored, persist = session.findings.added[0]
    assert restored == result["finding"]
    assert persist is True


@pytest.mark.asyncio
async def test_graph_finding_without_durable_receipt_is_not_persisted(
    monkeypatch,
):
    from core.server.routers import foundry

    session = _Session()

    async def execute(_request, _):
        return {
            "status": "confirmed",
            "kind": "graph_bound_prerequisite_execution",
            "finding": {
                "id": f"graph_bound_prerequisite_candidate:{'a' * 64}",
                "type": "State-machine prerequisite enforcement failure",
            },
        }

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )

    with pytest.raises(
        ValueError,
        match="specialized behavioral finding requires a durable orchestration receipt",
    ):
        await _run_behavioral_one_click_phase(_request(), session=session)

    assert session.findings.added == []


@pytest.mark.asyncio
async def test_behavioral_one_click_denial_fails_before_scan_traffic(
    monkeypatch,
):
    from core.server.routers import foundry

    state = ApplicationState()
    state.scan_state = {"session_id": "behavioral-direct-session"}
    monkeypatch.setattr(ApplicationState, "_instance", state)
    session = _Session()

    async def deny(_request, _):
        raise HTTPException(status_code=409, detail="signed workflow missing")

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        deny,
    )

    with pytest.raises(SentinelError) as raised:
        await _run_behavioral_one_click_phase(_request(), session=session)

    assert raised.value.code == ErrorCode.AUTH_PERMISSION_DENIED
    assert raised.value.details == {
        "phase": "behavioral_one_click",
        "status_code": 409,
        "reason": "signed workflow missing",
    }
    assert session.findings.added == []
    assert state.scan_state["behavioral_one_click"] == {
        "status": "refused",
        "result_status": None,
        "finding_id": None,
        "finding_type": None,
        "receipt_id": None,
        "receipt_state": None,
        "receipt_reused": None,
        "cleanup_status": None,
        "cleanup_steps_completed": None,
        "profile_mode": None,
        "observation_classification": None,
        "observation_count": None,
        "adaptive_execution_status": None,
        "independent_proof_status": None,
        "reason": "signed workflow missing",
    }


@pytest.mark.asyncio
async def test_scan_without_behavioral_profile_is_unchanged():
    session = SimpleNamespace()
    request = ScanRequest(target="https://example.test")

    assert (
        await _run_behavioral_one_click_phase(request, session=session)
        is None
    )


@pytest.mark.asyncio
async def test_anonymous_passive_profile_surfaces_observation_without_finding(
    monkeypatch,
):
    from core.server.routers import scans

    state = ApplicationState()
    state.scan_state = {"session_id": "behavioral-direct-session"}
    monkeypatch.setattr(ApplicationState, "_instance", state)
    session = _Session()
    result = {
        "kind": "passive_visibility_observation",
        "mode": "behavioral_anonymous_passive_visibility_v1",
        "status": "completed",
        "finding_authority": False,
        "finding_confirmed": False,
        "observation": {
            "classification": "preexisting_passive_visibility",
            "discovered_public_page_count": 1,
        },
        "execution": {"status": "completed", "mutations": 0},
        "adaptive_execution": {"status": "skipped"},
        "independent_proof": {"status": "skipped"},
        "orchestration_receipt": None,
    }

    async def execute(_request, *, session):
        assert session is not None
        return result

    monkeypatch.setattr(
        scans,
        "_run_anonymous_passive_one_click_phase",
        execute,
    )
    request = ScanRequest(
        target="https://example.test/",
        mode="bug_bounty",
        behavioral_one_click={
            "mode": "anonymous_passive",
            "envelope_id": ENVELOPE_ID,
        },
    )

    observed = await _run_behavioral_one_click_phase(request, session=session)

    assert observed == result
    assert session.findings.added == []
    summary = state.scan_state["behavioral_one_click"]
    assert summary["status"] == "passive_visibility_observed"
    assert summary["observation_classification"] == (
        "preexisting_passive_visibility"
    )
    assert summary["observation_count"] == 1
    assert summary["adaptive_execution_status"] == "skipped"
    assert summary["independent_proof_status"] == "skipped"
    assert summary["receipt_id"] is None


@pytest.mark.asyncio
async def test_anonymous_passive_scan_skips_reasoning_tools_and_verification(
    monkeypatch,
):
    state = ApplicationState()
    monkeypatch.setattr(ApplicationState, "_instance", state)

    database = MagicMock()
    database.init = AsyncMock()
    database.blackbox.enqueue = AsyncMock()
    database.blackbox.flush = AsyncMock()
    monkeypatch.setattr(
        "core.server.routers.scans.Database.instance",
        lambda: database,
    )
    monkeypatch.setattr("core.base.session.ScanSession", _RunnerSession)
    monkeypatch.setattr(
        "core.toolkit.tools.get_installed_tools",
        lambda: {"nuclei_safe": object()},
    )
    event_bus = _RunnerEventBus()
    monkeypatch.setattr("core.cortex.events.get_event_bus", lambda: event_bus)

    async def execute(_request, *, session):
        return {
            "kind": "passive_visibility_observation",
            "status": "completed",
            "finding_authority": False,
            "finding_confirmed": False,
            "execution": {"status": "completed", "mutations": 0},
        }

    monkeypatch.setattr(
        "core.server.routers.scans._run_behavioral_one_click_phase",
        execute,
    )
    reasoning_called = False

    async def forbidden_reasoning(**_kwargs):
        nonlocal reasoning_called
        reasoning_called = True
        raise AssertionError("passive-only scan must not start ordinary reasoning")

    monkeypatch.setattr(
        "core.cortex.reasoning.reasoning_engine.start_scan",
        forbidden_reasoning,
    )

    session_id = await begin_scan_logic(
        ScanRequest(
            target="https://example.test/",
            mode="bug_bounty",
            scope=["example.test"],
            scope_strict=True,
            behavioral_one_click={
                "mode": "anonymous_passive",
                "envelope_id": ENVELOPE_ID,
            },
        )
    )
    await state.active_scan_task

    session = await state.get_session(session_id)
    assert state.scan_state["status"] == "completed"
    assert session.status == "completed"
    assert reasoning_called is False


@pytest.mark.asyncio
async def test_paired_behavioral_phase_only_scan_skips_post_proof_authority(
    monkeypatch,
):
    state = ApplicationState()
    monkeypatch.setattr(ApplicationState, "_instance", state)

    database = MagicMock()
    database.init = AsyncMock()
    database.blackbox.enqueue = AsyncMock()
    database.blackbox.flush = AsyncMock()
    monkeypatch.setattr(
        "core.server.routers.scans.Database.instance",
        lambda: database,
    )
    monkeypatch.setattr("core.base.session.ScanSession", _RunnerSession)
    monkeypatch.setattr(
        "core.toolkit.tools.get_installed_tools",
        lambda: {"nuclei_safe": object()},
    )
    event_bus = _RunnerEventBus()
    monkeypatch.setattr("core.cortex.events.get_event_bus", lambda: event_bus)

    async def execute(_request, *, session):
        await session.findings.add_finding_async(
            {"id": "graph-finding", "type": "behavioral_graph"},
            persist=True,
        )
        return {
            "kind": "graph_bound_prerequisite_execution",
            "status": "completed",
        }

    monkeypatch.setattr(
        "core.server.routers.scans._run_behavioral_one_click_phase",
        execute,
    )

    async def forbidden_reasoning(**_kwargs):
        raise AssertionError("phase-only scan must not start ordinary reasoning")

    monkeypatch.setattr(
        "core.cortex.reasoning.reasoning_engine.start_scan",
        forbidden_reasoning,
    )

    def forbidden_connect(*_args):
        raise AssertionError("phase-only scan must not connect ActionDispatcher")

    dispatcher = SimpleNamespace(
        action_approved=SimpleNamespace(
            connect=forbidden_connect,
            disconnect=lambda *_args: None,
        )
    )
    monkeypatch.setattr(
        "core.base.action_dispatcher.ActionDispatcher.instance",
        lambda: dispatcher,
    )

    session_id = await begin_scan_logic(
        ScanRequest(
            target="https://example.test/",
            mode="bug_bounty",
            scope=["example.test"],
            scope_strict=True,
            behavioral_one_click={
                "completion": "behavioral_phase_only",
                "envelope_id": ENVELOPE_ID,
                "source_persona_id": SOURCE_PERSONA_ID,
                "peer_persona_id": PEER_PERSONA_ID,
            },
        )
    )
    await state.active_scan_task

    session = await state.get_session(session_id)
    assert state.scan_state["status"] == "completed"
    assert session.status == "completed"
    assert session.findings.added == [
        ({"id": "graph-finding", "type": "behavioral_graph"}, True)
    ]
    assert event_bus.scan_starts == [
        ("https://example.test/", [], "behavioral-scan-session")
    ]
    assert any(
        "Behavioral phase-only profile completed" in message
        for message in session.logs
    )


@pytest.mark.asyncio
async def test_behavioral_refusal_precedes_reasoning_and_tool_dispatch(
    monkeypatch,
):
    state = ApplicationState()
    monkeypatch.setattr(ApplicationState, "_instance", state)

    database = MagicMock()
    database.init = AsyncMock()
    database.blackbox.enqueue = AsyncMock()
    database.blackbox.flush = AsyncMock()
    monkeypatch.setattr(
        "core.server.routers.scans.Database.instance",
        lambda: database,
    )
    monkeypatch.setattr(
        "core.base.session.ScanSession",
        _RunnerSession,
    )
    monkeypatch.setattr(
        "core.toolkit.tools.get_installed_tools",
        lambda: {},
    )

    event_bus = _RunnerEventBus()
    monkeypatch.setattr(
        "core.cortex.events.get_event_bus",
        lambda: event_bus,
    )

    async def refuse(_request, *, session):
        assert session.id == "behavioral-scan-session"
        raise SentinelError(
            ErrorCode.AUTH_PERMISSION_DENIED,
            "behavioral admission refused",
        )

    reasoning_called = False

    async def forbidden_reasoning(**_kwargs):
        nonlocal reasoning_called
        reasoning_called = True
        raise AssertionError("ordinary reasoning must not start")

    monkeypatch.setattr(
        "core.server.routers.scans._run_behavioral_one_click_phase",
        refuse,
    )
    monkeypatch.setattr(
        "core.cortex.reasoning.reasoning_engine.start_scan",
        forbidden_reasoning,
    )

    session_id = await begin_scan_logic(
        ScanRequest(
            target="https://example.test/app",
            mode="bug_bounty",
            scope=["example.test"],
            scope_strict=True,
            behavioral_one_click={
                "envelope_id": ENVELOPE_ID,
                "source_persona_id": SOURCE_PERSONA_ID,
                "peer_persona_id": PEER_PERSONA_ID,
            },
        )
    )
    await state.active_scan_task

    session = await state.get_session(session_id)
    assert state.scan_state["status"] == "error"
    assert session.status == "error"
    assert reasoning_called is False
    assert event_bus.events[-1].payload["error_code"] == (
        ErrorCode.AUTH_PERMISSION_DENIED.value
    )
