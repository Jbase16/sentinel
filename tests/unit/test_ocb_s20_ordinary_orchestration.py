"""OCB-S20 suite proof for default-off ordinary-click orchestration."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

from fastapi import HTTPException
import pytest

from core.behavior.capability_effect_evidence import evaluate_replay_leak
from core.server.ordinary_orchestration import (
    BOUNDED_ORCHESTRATION_STATES,
    CandidateHandoff,
    OrdinaryClickFamily,
    OrdinaryClickOrchestrationConfig,
    resolve_submission_candidate_handoff,
    run_ordinary_click_orchestration,
)
from core.server.routers.foundry import RunBehavioralAuthorizationFromURLRequest
from core.server.routers.scans import (
    ScanRequest,
    _run_behavioral_one_click_phase,
)
from core.server.state import ApplicationState
from tests.unit.test_ocb_s19_candidate_assembly import (
    _deny_target_requests,
    _family_d,
)
from tests.unit import test_behavior_capability_effect_evaluation as r5d8_fixtures
from tests.unit.test_behavior_capability_effect_evidence import (
    _evidence_from_result,
)
from tests.unit.test_scan_behavioral_one_click import (
    CAPABILITY_EFFECT_SPECIFICATION,
    ENVELOPE_ID,
    PEER_PERSONA_ID,
    SOURCE_PERSONA_ID,
    _Session,
)


ROLE_SPECIFICATION = {"schema_version": 1, "test_ref": "role-specification"}
SOURCE_RECORDS = [
    {
        "method": "GET",
        "url": "https://example.test/app",
        "response_status": 200,
    }
]
PEER_RECORDS = [
    {
        "method": "GET",
        "url": "https://example.test/app",
        "response_status": 403,
    }
]


def _foundry_request(
    *,
    prior: bool = False,
    role: bool = False,
    capability: bool = False,
) -> RunBehavioralAuthorizationFromURLRequest:
    return RunBehavioralAuthorizationFromURLRequest(
        target_url="https://example.test/app",
        envelope_id=ENVELOPE_ID,
        source_persona_id=SOURCE_PERSONA_ID,
        peer_persona_id=PEER_PERSONA_ID,
        prior_source_records=SOURCE_RECORDS if prior else None,
        prior_peer_records=PEER_RECORDS if prior else None,
        role_monotonicity=ROLE_SPECIFICATION if role else None,
        capability_effect=(CAPABILITY_EFFECT_SPECIFICATION if capability else None),
    )


def _completed_result(family: OrdinaryClickFamily) -> dict:
    if family is OrdinaryClickFamily.A:
        return {
            "kind": "proof_experiment_generalized_authorization",
            "status": "completed",
            "oracle_verdict": "refuted",
            "finding": None,
        }
    if family is OrdinaryClickFamily.B:
        return {
            "kind": "graph_bound_prerequisite_execution",
            "status": "refuted",
            "oracle_verdict": "refuted",
            "finding": None,
            "finding_confirmed": False,
            "cleanup_status": "verified",
            "orphaned_owned_state_possible": False,
        }
    if family is OrdinaryClickFamily.C:
        return {
            "kind": "role_protected_effect_execution",
            "status": "refuted",
            "oracle_verdict": "refuted",
            "finding": None,
            "finding_confirmed": False,
            "cleanup_status": "verified",
            "orphaned_owned_state_possible": False,
        }
    return {
        "kind": "capability_effect_one_click",
        "status": "refuted",
        "oracle_verdict": "refuted",
        "finding": None,
        "finding_confirmed": False,
        "execution": {
            "status": "completed",
            "cleanup": {
                "status": "verified",
                "orphaned_owned_state_possible": False,
            },
        },
    }


def _family_for_request(
    request: RunBehavioralAuthorizationFromURLRequest,
) -> OrdinaryClickFamily:
    if request.prior_source_records is not None:
        return OrdinaryClickFamily.B
    if request.role_monotonicity is not None:
        return OrdinaryClickFamily.C
    if request.capability_effect is not None:
        return OrdinaryClickFamily.D
    return OrdinaryClickFamily.A


def _assert_no_coverage_claim(value: object) -> None:
    serialized = json.dumps(value, sort_keys=True).lower()
    assert "coverage" not in serialized
    assert "marginal" not in serialized


def test_ocb_s20_bounded_state_contract_and_default_off(monkeypatch):
    monkeypatch.delenv(
        "SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION",
        raising=False,
    )

    assert {state.value for state in BOUNDED_ORCHESTRATION_STATES} == {
        "observing",
        "acquiring",
        "blocked",
        "proving",
        "cleaning",
        "confirmed",
        "exhausted",
        "incomplete",
    }
    assert OrdinaryClickOrchestrationConfig.from_environment().enabled is False


@pytest.mark.asyncio
async def test_ocb_s20_sequences_only_a_and_selected_b_c_families():
    calls: list[RunBehavioralAuthorizationFromURLRequest] = []

    async def execute(request):
        calls.append(request)
        return _completed_result(_family_for_request(request))

    result = await run_ordinary_click_orchestration(
        _foundry_request(prior=True, role=True),
        assessment_session_id="ocb-s20-session",
        execute_family=execute,
        config=OrdinaryClickOrchestrationConfig(enabled=True),
    )
    payload = result.to_dict()

    assert [_family_for_request(request) for request in calls] == [
        OrdinaryClickFamily.A,
        OrdinaryClickFamily.B,
        OrdinaryClickFamily.C,
    ]
    assert all(request._assessment_session_id == "ocb-s20-session" for request in calls)
    assert calls[0].prior_source_records is None
    assert calls[0].role_monotonicity is None
    assert calls[0].capability_effect is None
    assert calls[1].prior_source_records == SOURCE_RECORDS
    assert calls[1].prior_peer_records == PEER_RECORDS
    assert calls[1].role_monotonicity is None
    assert calls[1].capability_effect is None
    assert calls[2].prior_source_records is None
    assert calls[2].prior_peer_records is None
    assert calls[2].role_monotonicity == ROLE_SPECIFICATION
    assert calls[2].capability_effect is None
    assert payload["status"] == "exhausted"
    assert payload["exhaustion_kind"] == "sequence_exhausted"
    assert payload["families"][3] == {
        "family": "D",
        "applicable": False,
        "attempted": False,
        "native_status": None,
        "receipt_kind": None,
        "oracle_verdict": None,
        "cleanup": None,
        "terminal": False,
        "finding_confirmed": False,
        "failure_code": None,
        "candidate": None,
    }
    _assert_no_coverage_claim(payload)


@pytest.mark.asyncio
async def test_ocb_s20_orphan_risk_is_incomplete_and_stops_later_family():
    calls: list[OrdinaryClickFamily] = []
    handler = AsyncMock()

    async def execute(request):
        family = _family_for_request(request)
        calls.append(family)
        if family is OrdinaryClickFamily.B:
            return {
                **_completed_result(family),
                "finding_confirmed": True,
                "cleanup_status": "uncertain",
                "orphaned_owned_state_possible": True,
            }
        return _completed_result(family)

    result = await run_ordinary_click_orchestration(
        _foundry_request(prior=True, role=True),
        assessment_session_id="ocb-s20-session",
        execute_family=execute,
        handle_result=handler,
        config=OrdinaryClickOrchestrationConfig(enabled=True),
    )
    payload = result.to_dict()

    assert calls == [OrdinaryClickFamily.A, OrdinaryClickFamily.B]
    assert payload["status"] == "incomplete"
    assert "cleaning" in payload["state_trace"]
    assert payload["families"][1]["cleanup"] == {
        "status": "uncertain",
        "orphaned_owned_state_possible": True,
        "attention_required": True,
    }
    assert payload["families"][2]["applicable"] is True
    assert payload["families"][2]["attempted"] is False
    assert payload["families"][2]["failure_code"] == "sequence_stopped"
    assert payload["families"][1]["failure_code"] == ("cleanup_attention_required")
    assert payload["submission_candidates"] == []
    handler.assert_not_awaited()
    assert "exhaustion_kind" not in payload


@pytest.mark.asyncio
async def test_ocb_s20_refusal_is_blocked_without_inventing_a_finding():
    async def execute(request):
        family = _family_for_request(request)
        if family is OrdinaryClickFamily.B:
            raise HTTPException(status_code=409, detail="family refused")
        return _completed_result(family)

    result = await run_ordinary_click_orchestration(
        _foundry_request(prior=True),
        assessment_session_id="ocb-s20-session",
        execute_family=execute,
        config=OrdinaryClickOrchestrationConfig(enabled=True),
    )
    payload = result.to_dict()

    assert payload["status"] == "blocked"
    assert payload["submission_candidates"] == []
    assert payload["families"][1]["failure_code"] == "http_409"
    assert "exhaustion_kind" not in payload


@pytest.mark.asyncio
async def test_ocb_s20_unknown_applicable_terminal_is_incomplete():
    async def execute(_request):
        return {"kind": "native_result", "status": "still_running"}

    result = await run_ordinary_click_orchestration(
        _foundry_request(),
        assessment_session_id="ocb-s20-session",
        execute_family=execute,
        config=OrdinaryClickOrchestrationConfig(enabled=True),
    )
    payload = result.to_dict()

    assert payload["status"] == "incomplete"
    assert payload["families"][0]["terminal"] is False
    assert payload["families"][0]["failure_code"] == "native_terminal_unknown"
    assert "exhaustion_kind" not in payload


@pytest.mark.asyncio
async def test_ocb_s20_confirmed_result_requires_candidate_handoff():
    handler = AsyncMock(
        return_value=CandidateHandoff(
            finding_id=f"finding:{'a' * 64}",
            candidate_digest=f"submission_candidate:{'b' * 64}",
            reproduction_kind="replayable_recipe",
        )
    )

    async def execute(request):
        family = _family_for_request(request)
        result = _completed_result(family)
        if family is OrdinaryClickFamily.B:
            result["finding_confirmed"] = True
        return result

    result = await run_ordinary_click_orchestration(
        _foundry_request(prior=True),
        assessment_session_id="ocb-s20-session",
        execute_family=execute,
        handle_result=handler,
        config=OrdinaryClickOrchestrationConfig(enabled=True),
    )
    payload = result.to_dict()

    assert payload["status"] == "confirmed"
    assert len(payload["submission_candidates"]) == 1
    handler.assert_awaited_once()


def test_ocb_s20_family_d_refuted_eligible_routes_to_shape_a(
    tmp_path,
    monkeypatch,
):
    from core.server import ordinary_orchestration
    from core.server.routers import foundry

    proof = _family_d(tmp_path, monkeypatch)
    _deny_target_requests(monkeypatch)
    monkeypatch.setenv("SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION", "1")
    assert proof.evidence.oracle["verdict"] == "refuted"
    assert evaluate_replay_leak(proof.evidence).eligible is True
    calls_before = (len(proof.twin.calls), len(proof.twin.cleanup_calls))
    observation_id = proof.read_model().observations[0].id
    requests = []

    async def execute(request, _):
        assert _ is True
        requests.append(request)
        family = _family_for_request(request)
        if family is OrdinaryClickFamily.A:
            return _completed_result(family)
        return {
            **_completed_result(OrdinaryClickFamily.D),
            "capability_effect_promotion": {
                "schema_version": 1,
                "slice": "R5D10",
                "execution_id": proof.evidence.source_receipt_id,
                "assessment_session_id": proof.session_id,
                "source_receipt_id": proof.evidence.source_receipt_id,
                "execution_state": "completed",
                "evidence_classification": "eligible_replay_leak",
                "promotion_state": "promoted",
                "reason_code": "eligible_replay_leak",
                "canonical_observation_id": observation_id,
                "canonical_finding_id": proof.finding_id,
                "permitted_next_local_action": None,
            },
        }

    def resolve_candidate(*, session_id, finding_id):
        assert session_id == proof.session_id
        assert finding_id == proof.finding_id
        return resolve_submission_candidate_handoff(
            session_id=proof.session_id,
            finding_id=proof.finding_id,
            workbench_store=proof.store(),
            read_model_loader=lambda _session_id: proof.read_model(),
        )

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )
    monkeypatch.setattr(
        ordinary_orchestration,
        "resolve_submission_candidate_handoff",
        resolve_candidate,
    )
    request = ScanRequest(
        target="https://example.test/app",
        mode="bug_bounty",
        behavioral_one_click={
            "mode": "capability_effect",
            "completion": "behavioral_phase_only",
            "envelope_id": ENVELOPE_ID,
            "source_persona_id": SOURCE_PERSONA_ID,
            "peer_persona_id": PEER_PERSONA_ID,
            "capability_effect": CAPABILITY_EFFECT_SPECIFICATION,
        },
    )
    result = asyncio.run(_run_behavioral_one_click_phase(request, session=_Session()))

    assert [_family_for_request(item) for item in requests] == [
        OrdinaryClickFamily.A,
        OrdinaryClickFamily.D,
    ]
    assert result["status"] == "confirmed"
    assert result["families"][3]["oracle_verdict"] == "refuted"
    assert result["submission_candidates"][0]["reproduction_kind"] == (
        "evidence_attestation"
    )
    assert (len(proof.twin.calls), len(proof.twin.cleanup_calls)) == calls_before


def test_ocb_s20_family_d_refuted_ineligible_stays_exhausted():
    receipts = r5d8_fixtures._receipts("ocb-s20-refuted-ineligible")
    twin = r5d8_fixtures._TwinTransport(
        receipts,
        leak_kind="no_capability_baseline",
        missing_projection_kind="replayed_capability_probe",
    )
    evidence = _evidence_from_result(
        r5d8_fixtures._run(twin, receipts),
        persona_id="r5d6-ocb-s20-refuted-ineligible",
    )
    assert evidence.oracle["verdict"] == "refuted"
    assert evaluate_replay_leak(evidence).eligible is False
    handler = AsyncMock()

    async def execute(request):
        family = _family_for_request(request)
        if family is OrdinaryClickFamily.A:
            return _completed_result(family)
        return {
            **_completed_result(OrdinaryClickFamily.D),
            "capability_effect_promotion": {
                "promotion_state": "not_eligible",
            },
        }

    result = asyncio.run(
        run_ordinary_click_orchestration(
            _foundry_request(capability=True),
            assessment_session_id="ocb-s20-session",
            execute_family=execute,
            handle_result=handler,
            config=OrdinaryClickOrchestrationConfig(enabled=True),
        )
    )
    payload = result.to_dict()

    assert payload["status"] == "exhausted"
    assert payload["submission_candidates"] == []
    handler.assert_not_awaited()
    _assert_no_coverage_claim(payload)


@pytest.mark.asyncio
async def test_ocb_s20_scan_gate_off_preserves_the_single_native_call(
    monkeypatch,
):
    from core.server.routers import foundry

    monkeypatch.delenv(
        "SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION",
        raising=False,
    )
    calls = []
    native_result = _completed_result(OrdinaryClickFamily.D)

    async def execute(request, _):
        calls.append(request)
        assert _ is True
        return dict(native_result)

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )
    request = ScanRequest(
        target="https://example.test/app",
        mode="bug_bounty",
        behavioral_one_click={
            "mode": "capability_effect",
            "completion": "behavioral_phase_only",
            "envelope_id": ENVELOPE_ID,
            "source_persona_id": SOURCE_PERSONA_ID,
            "peer_persona_id": PEER_PERSONA_ID,
            "capability_effect": CAPABILITY_EFFECT_SPECIFICATION,
        },
    )

    result = await _run_behavioral_one_click_phase(request, session=_Session())

    assert result == native_result
    assert len(calls) == 1
    assert calls[0].capability_effect == CAPABILITY_EFFECT_SPECIFICATION


@pytest.mark.asyncio
async def test_ocb_s20_scan_gate_on_runs_always_a_plus_selected_d(
    monkeypatch,
):
    from core.server.routers import foundry

    monkeypatch.setenv("SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION", "1")
    state = ApplicationState()
    session = _Session()
    state.scan_state = {"session_id": session.id}
    monkeypatch.setattr(ApplicationState, "_instance", state)
    calls = []

    async def execute(request, _):
        calls.append(request)
        assert _ is True
        return _completed_result(_family_for_request(request))

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )
    request = ScanRequest(
        target="https://example.test/app",
        mode="bug_bounty",
        behavioral_one_click={
            "mode": "capability_effect",
            "completion": "behavioral_phase_only",
            "envelope_id": ENVELOPE_ID,
            "source_persona_id": SOURCE_PERSONA_ID,
            "peer_persona_id": PEER_PERSONA_ID,
            "capability_effect": CAPABILITY_EFFECT_SPECIFICATION,
        },
    )

    result = await _run_behavioral_one_click_phase(request, session=session)

    assert [_family_for_request(item) for item in calls] == [
        OrdinaryClickFamily.A,
        OrdinaryClickFamily.D,
    ]
    assert result["status"] == "exhausted"
    assert result["families"][1]["applicable"] is False
    assert result["families"][2]["applicable"] is False
    assert state.scan_state["behavioral_one_click"]["status"] == "exhausted"
    _assert_no_coverage_claim(result)
