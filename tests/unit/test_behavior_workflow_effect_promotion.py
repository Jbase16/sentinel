"""Candidate-scoped R5E9f inner-route capture and gated local promotion."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    ABORTED,
    BehavioralReceiptStore,
    redacted_workflow_effect_evidence_outcome,
)
from core.behavior.workflow_effect_evidence import WorkflowEffectEvidence
from core.behavior.workflow_effect_promotion import (
    WORKFLOW_FINDING_PROMOTION_ENV,
    WorkflowEffectPromotionService,
)
from core.epistemic.ledger import EvidenceLedger
from core.server.routers.foundry import (
    RunBehavioralAuthorizationRequest,
    run_behavioral_authorization_endpoint,
)
from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport
from tests.unit.test_behavior_workflow_invariant_effect_one_click import (
    ORIGIN,
    _case,
)


def _setup(tmp_path, monkeypatch, *, secure=False, amounts=(6, 6)):
    from core.behavior import workflow_effect_promotion as promotion_module

    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_RECEIPTS", str(tmp_path / "receipts"))
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_WORKFLOW_EFFECT_EXECUTION", "1")
    monkeypatch.setenv(
        "SENTINELFORGE_BEHAVIOR_WORKFLOW_EVIDENCE_CLASSIFICATION",
        "controlled_in_memory_twin",
    )
    monkeypatch.delenv(WORKFLOW_FINDING_PROMOTION_ENV, raising=False)
    config = SentinelConfig(
        storage=StorageConfig(base_dir=tmp_path / "canonical-evidence")
    )
    monkeypatch.setattr(promotion_module, "get_config", lambda: config)
    case = _case(tmp_path, monkeypatch, secure=secure, amounts=amounts)
    module, _, mapping, target, _, vault, envelope, persona, records = case
    peer = vault.add_persona(label="peer", email="peer@research.example")
    request = RunBehavioralAuthorizationRequest(
        target_origin=ORIGIN,
        envelope_id=envelope.envelope_id,
        source_persona_id=persona.persona_id,
        peer_persona_id=peer.persona_id,
        source_records=list(records),
        peer_records=[
            {"id": "peer-capture", "url": f"{ORIGIN}/peer", "method": "GET"}
        ],
        workflow_effect=mapping,
    )

    async def fake_send(_transport, persona_id, replay_request):
        assert persona_id == persona.persona_id
        status, payload = await target.send(
            replay_request.method,
            replay_request.url,
            json.loads(replay_request.body),
            _redirect_mode=replay_request.redirect_mode,
        )
        return ReplayResponse(status, json.dumps(payload))

    monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
    return request, case, config


def _service(config):
    return WorkflowEffectPromotionService(
        config, receipt_store=BehavioralReceiptStore()
    )


def test_inner_candidate_capture_is_retained_and_gate_off_admits_nothing(
    tmp_path, monkeypatch
):
    from core.behavior.workflow_invariant_effect_one_click import (
        WorkflowEffectOneClickDispatcher,
    )

    request, case, config = _setup(tmp_path, monkeypatch)
    observed_contexts = []
    original_run = WorkflowEffectOneClickDispatcher.run

    async def tracked_run(dispatcher):
        run = await original_run(dispatcher)
        observed_contexts.append(dispatcher.run_context)
        return run

    monkeypatch.setattr(WorkflowEffectOneClickDispatcher, "run", tracked_run)
    response = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    evidence = WorkflowEffectEvidence.from_mapping(response["workflow_effect_evidence"])
    assert evidence.to_dict() == response["workflow_effect_evidence"]
    assert evidence.evidence_root == response["workflow_effect_evidence"]["evidence_root"]
    assert evidence.candidate_id == response["workflow_invariant_effect_one_click"][
        "candidate"
    ]["candidate_id"]
    context = observed_contexts[0]
    assert context is not None
    assert context.experiment_world_ref == stable_hash("world", case[7].persona_id)
    for name in (
        "experiment_world_ref",
        "authority_ref",
        "tenant_ref",
        "source_evidence_ref",
    ):
        assert getattr(context, name) == getattr(evidence, name)
        assert isinstance(getattr(context, name), str)
        assert len(getattr(context, name).rsplit(":", 1)[-1]) == 64
    assert evidence.observed_at_epoch == context.observed_at_epoch
    for name in (
        "finding_authority",
        "promotion_authority",
        "real_workflow_effect_observed",
        "wired_into_production",
    ):
        assert response["workflow_invariant_effect_one_click"][name] is False

    receipt_id = response["receipt"]["receipt_id"]
    receipt = BehavioralReceiptStore().load(receipt_id.removeprefix("behavioral-"))
    assert receipt is not None and receipt.state == "completed"
    assert receipt.outcome == redacted_workflow_effect_evidence_outcome(response)
    assert WorkflowEffectEvidence.from_mapping(
        receipt.outcome["workflow_effect_evidence"]
    ).evidence_root == evidence.evidence_root
    status = response["workflow_effect_promotion"]
    assert status["promotion_state"] == "blocked_by_policy"
    assert status["canonical_observation_id"] is None
    assert status["canonical_finding_id"] is None
    service = _service(config)
    journal = service.repository.load_workflow_effect_admission(receipt_id)
    assert journal is not None and journal["state"] == "blocked_by_policy"
    assert journal["admission_id"] == evidence.execution_admission_ref
    assert journal["admission_id"].startswith("workflow_effect_promotion_admission:")
    assert not EvidenceLedger(config).session_read_model(
        status["assessment_session_id"]
    ).findings

    duplicate = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    assert duplicate["status"] == "already_executed"
    assert duplicate["workflow_effect_promotion"] == status
    assert len(observed_contexts) == 1


@pytest.mark.parametrize(
    "secure,amounts",
    [(True, (6, 6)), (False, (4, 6))],
)
def test_inner_candidate_less_twins_have_no_capture_reserve_or_status(
    tmp_path, monkeypatch, secure, amounts
):
    request, _, config = _setup(
        tmp_path, monkeypatch, secure=secure, amounts=amounts
    )
    response = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    assert response["workflow_invariant_effect_one_click"]["candidate"] is None
    assert "workflow_effect_evidence" not in response
    assert "workflow_effect_promotion" not in response
    assert _service(config).repository.list_workflow_effect_admissions() == ()


def test_inner_gate_on_promotes_exactly_once_and_repromotion_is_idempotent(
    tmp_path, monkeypatch
):
    request, _, config = _setup(tmp_path, monkeypatch)
    monkeypatch.setenv(WORKFLOW_FINDING_PROMOTION_ENV, "1")
    try:
        response = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
        status = response["workflow_effect_promotion"]
        assert status["promotion_state"] == "promoted"
        assert status["canonical_observation_id"]
        assert status["canonical_finding_id"]
        service = _service(config)
        receipt_id = response["receipt"]["receipt_id"]
        journal = service.repository.load_workflow_effect_admission(receipt_id)
        assert journal is not None and journal["state"] == "promoted"
        read_model = EvidenceLedger(config).session_read_model(status["assessment_session_id"])
        assert [item.id for item in read_model.observations] == [
            status["canonical_observation_id"]
        ]
        assert [item.id for item in read_model.findings] == [
            status["canonical_finding_id"]
        ]
        assert read_model.findings[0].metadata["finding_class"] == (
            "workflow_invariant_violation_v1"
        )
        assert service.promote(receipt_id).to_dict() == status
        assert service.repository.load_workflow_effect_admission(receipt_id)[
            "attempt_count"
        ] == 1
    finally:
        monkeypatch.delenv(WORKFLOW_FINDING_PROMOTION_ENV, raising=False)


def test_inner_non_workflow_profile_has_no_workflow_promotion(
    tmp_path, monkeypatch
):
    request, _, config = _setup(tmp_path, monkeypatch)
    request = request.model_copy(update={"workflow_effect": None})
    monkeypatch.delenv("SENTINELFORGE_BEHAVIOR_PRIMARY", raising=False)
    response = asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    assert "workflow_effect_evidence" not in response
    assert "workflow_effect_promotion" not in response
    assert _service(config).repository.list_workflow_effect_admissions() == ()


def test_inner_missing_runtime_context_aborts_reserved_receipt(
    tmp_path, monkeypatch
):
    from core.behavior.workflow_invariant_effect_one_click import (
        WorkflowEffectOneClickDispatcher,
    )

    request, _, config = _setup(tmp_path, monkeypatch)
    original_context = WorkflowEffectOneClickDispatcher.run_context

    def invalid_context(dispatcher):
        context = original_context.fget(dispatcher)
        if context is None:
            return None
        return SimpleNamespace(
            observed_at_epoch=0.0,
            experiment_world_ref=context.experiment_world_ref,
            authority_ref=context.authority_ref,
            tenant_ref=context.tenant_ref,
            source_evidence_ref=context.source_evidence_ref,
        )

    monkeypatch.setattr(
        WorkflowEffectOneClickDispatcher, "run_context", property(invalid_context)
    )
    with pytest.raises(HTTPException) as error:
        asyncio.run(run_behavioral_authorization_endpoint(request, _=True))
    assert error.value.status_code == 500
    service = _service(config)
    admissions = service.repository.list_workflow_effect_admissions()
    assert len(admissions) == 1
    admission = admissions[0]
    receipt = BehavioralReceiptStore().load(admission["source_fingerprint"])
    assert receipt is not None and receipt.state == ABORTED
    assert not receipt.outcome
    assert admission["state"] != "promoted"


def test_gate_and_journal_wiring_stays_inside_the_inner_route():
    root = Path(__file__).resolve().parents[2]
    foundry = (root / "core/server/routers/foundry.py").read_text()
    inner = foundry.split("async def run_behavioral_authorization_endpoint(", 1)[1].split(
        "async def run_behavioral_authorization_from_url_endpoint(", 1
    )[0]
    outer = foundry.split("async def run_behavioral_authorization_from_url_endpoint(", 1)[1]
    service = (root / "core/behavior/workflow_effect_promotion.py").read_text()
    assert "workflow_effect_one_click_run.candidate is not None" in inner
    assert "workflow_effect_promotion_service.reserve_execution(" in inner
    assert "WorkflowEffectEvidence.build(" in inner
    assert "workflow_effect_promotion_service.promote(" in inner
    assert "workflow_effect_promotion_service" not in outer
    assert service.index("if not gate_enabled:") < service.index(
        "ledger.admit_workflow_invariant_finding("
    )
