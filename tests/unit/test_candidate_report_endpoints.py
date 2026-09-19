from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.errors import SentinelError
from core.reporting.submission_candidate import build_submission_candidate
from tests.unit.test_ocb_s19_candidate_assembly import _family_r, _select_captures


def _candidate_state(tmp_path: Path, monkeypatch):
    proof = _family_r(tmp_path, monkeypatch)
    selected = _select_captures(proof)
    read_model = proof.read_model()
    store = proof.store()
    candidate = build_submission_candidate(
        read_model,
        workbench_id=selected.workbench_id,
        workbench_store=store,
    )
    return read_model, store, candidate


def test_cortex_and_ai_reports_share_candidate_and_ai_cannot_add_claims(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from core.data import db as db_module
    from core.reporting import submission_candidate as candidate_module
    from core.server.routers import ai, cortex

    read_model, store, expected = _candidate_state(tmp_path, monkeypatch)
    origin = read_model.observations[0].identity.target_origin

    class _DB:
        async def init(self):
            return None

        async def get_session(self, session_id):
            return {"target": origin}

    monkeypatch.setattr(
        db_module.Database,
        "instance",
        staticmethod(lambda: _DB()),
    )
    monkeypatch.setattr(
        candidate_module,
        "CandidateWorkbenchStore",
        lambda: store,
    )
    monkeypatch.setattr(
        cortex,
        "load_canonical_session_read_model",
        lambda session_id: read_model,
    )
    monkeypatch.setattr(
        ai,
        "load_canonical_session_read_model",
        lambda session_id: read_model,
    )
    monkeypatch.setattr(
        ai.AIEngine,
        "instance",
        staticmethod(lambda: (_ for _ in ()).throw(
            AssertionError("AI model must not own candidate claims")
        )),
    )

    cortex_response = asyncio.run(cortex.generate_report(
        cortex.ReportGenerateRequest(
            target=origin,
            session_id=read_model.session_id,
            finding_id=read_model.findings[0].id,
        ),
        graph_analyzer=SimpleNamespace(),
    ))
    ai_response = asyncio.run(ai.generate_report(
        session_id=read_model.session_id,
        finding_id=read_model.findings[0].id,
        report_type="technical",
        format="markdown",
    ))

    assert cortex_response.candidate_digest == expected.candidate_digest
    assert ai_response["candidate_digest"] == expected.candidate_digest
    assert cortex_response.claims == ai_response["claims"]
    assert cortex_response.claims == expected.to_dict()["claims"]
    assert "ocb-operator-token" not in cortex_response.content
    assert "ocb-response-secret" not in ai_response["content"]

    with pytest.raises(SentinelError, match="caller-provided claims"):
        asyncio.run(ai.generate_section(
            session_id=read_model.session_id,
            finding_id=read_model.findings[0].id,
            section="executive_summary",
            context={"claim": "Remote code execution"},
        ))

    section = asyncio.run(ai.generate_section(
        session_id=read_model.session_id,
        finding_id=read_model.findings[0].id,
        section="executive_summary",
        context=None,
    ))
    assert section["candidate_digest"] == expected.candidate_digest
    assert section["claims"] == expected.to_dict()["claims"]
    assert "Remote code execution" not in section["content"]


def test_response_only_verify_evidence_cannot_be_relabelled_as_a_request_recipe(
    tmp_path: Path, monkeypatch,
) -> None:
    """Response equality does not bind a caller-selected request body/header."""
    from fastapi import HTTPException

    from core.base.config import SentinelConfig, StorageConfig
    from core.behavior.receipts import (
        BehavioralReceiptStore, redacted_receipt_context, request_fingerprint,
    )
    from core.epistemic.ledger import ActiveProofCitation, Citation, EvidenceLedger
    from core.ghost.flow import FlowStep
    from core.identity.http_observation import record_http_observation
    from core.server.routers import verify
    from tests.unit.test_active_finding_promotion_seam import (
        ORIGIN, PROVENANCE_ROOT, _confirmed_outcome, _identity,
    )
    from tests.unit.test_ocb_s19_candidate_assembly import (
        _RetainedProof, _assert_four_refuse, _deny_target_requests,
        _verify_shell, _wire_surfaces,
    )

    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    receipts = BehavioralReceiptStore(tmp_path / "receipts")
    session_id = "candidate-response-only-proof"
    identity = _identity(session_id)
    fingerprint = request_fingerprint({"test": "response-only-proof"})
    reservation = receipts.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=identity.authorization_envelope_id,
            source_persona_id=identity.persona_id,
            peer_persona_id="persona-bob",
        ),
    )
    receipt = receipts.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=_confirmed_outcome(),
    )
    ledger = EvidenceLedger(config, receipt_store=receipts)
    step = FlowStep(
        "POST", f"{ORIGIN}/api/action",
        headers={"X-Action": "caller-selected-action"},
        request_body='{"action":"caller-selected-action"}',
    )
    step.set_response(status=200, body='{"ok":true}', content_type="application/json")
    observation = record_http_observation(
        ledger,
        source="verify_console",
        identity=identity,
        method=step.method,
        url=step.url,
        response_status=step.response_status,
        raw_evidence={
            "response_status": step.response_status,
            "response_body": step.response_body,
            "response_body_truncated": False,
            "response_content_type": step.response_content_type,
            "elapsed_ms": step.response_elapsed_ms,
            "principal_ref": "principal:response-only",
        },
    )
    finding = ledger.promote_canonical_finding(
        title="Receipt-backed response observation",
        severity="HIGH",
        citations=[Citation(observation_id=observation.id)],
        description="Canonical response evidence contains no committed request body.",
        confirmation_level="confirmed",
        active_proof=[ActiveProofCitation(
            observation_id=observation.id,
            receipt_id=receipt.receipt_id,
            provenance_root=PROVENANCE_ROOT,
        )],
    )
    proof = _RetainedProof(
        config=config,
        receipts=receipts,
        session_id=session_id,
        finding_id=finding.id,
        workbench_root=tmp_path / "workbenches",
        captured=(step,),
        observation_ids=(observation.id,),
    )
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    session.append_exchange(step)
    # Even matching an authentic session observation ID cannot add the missing
    # request commitment to the already-recorded response-only source.
    session.canonical_observation_ids.append(observation.id)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(verify.promote_to_repro(
            session.session_id,
            verify.PromoteRequest(evidence_bindings=[verify.EvidenceBindingRequest(
                exchange_index=0,
                observation_id=observation.id,
                receipt_id=receipt.receipt_id,
            )]),
            _=True,
        ))
    assert refused.value.status_code == 400
    assert "caller-selected-action" not in str(refused.value.detail)
    assert proof.store().load(
        session.workbench_id, read_model=proof.read_model(),
    ).selections == ()
    asyncio.run(_assert_four_refuse(proof, session, origin))


def test_verify_candidate_teardown_removes_only_owned_draft_and_reports_failure(
    tmp_path: Path, monkeypatch,
) -> None:
    from core.server.routers import verify
    from core.verify.console import get_session
    from tests.unit.test_ocb_s19_candidate_assembly import (
        _deny_target_requests, _verify_shell, _wire_surfaces,
    )

    proof = _family_r(tmp_path, monkeypatch)
    _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    store = session.candidate_workbench_store
    draft_path = store._path(session.workbench_id)
    finding_before = proof.read_model().findings[0].to_dict()
    receipts_before = {
        item.name: item.read_bytes()
        for item in proof.receipts.root.iterdir() if item.is_file()
    }

    removed = asyncio.run(verify.discard_submission_candidate(session.session_id, _=True))
    assert removed.model_dump() == {
        "status": "removed", "orphaned_owned_state_possible": False,
    }
    assert not draft_path.exists()
    assert get_session(session.session_id) is session
    absent = asyncio.run(verify.discard_submission_candidate(session.session_id, _=True))
    assert absent.model_dump() == {
        "status": "absent", "orphaned_owned_state_possible": False,
    }

    # Teardown refuses an unsafe file instead of claiming it cleaned up.
    store.open(proof.read_model(), finding_id=proof.finding_id)
    draft_path.chmod(0o644)
    failed = asyncio.run(verify.discard_submission_candidate(session.session_id, _=True))
    assert failed.model_dump() == {
        "status": "failed", "orphaned_owned_state_possible": True,
    }
    assert draft_path.exists()
    assert proof.read_model().findings[0].to_dict() == finding_before
    assert {
        item.name: item.read_bytes()
        for item in proof.receipts.root.iterdir() if item.is_file()
    } == receipts_before


@pytest.mark.parametrize("malformed", [TypeError, KeyError])
def test_all_candidate_routes_refuse_malformed_artifact_data(
    tmp_path: Path, monkeypatch, malformed,
) -> None:
    from core.reporting import submission_candidate as candidate_module
    from tests.unit.test_ocb_s19_candidate_assembly import (
        _assert_four_refuse, _deny_target_requests, _verify_shell, _wire_surfaces,
    )

    proof = _family_r(tmp_path, monkeypatch)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)

    def malformed_payload(*_args, **_kwargs):
        raise malformed("malformed secret-bearing artifact field")

    monkeypatch.setattr(candidate_module, "candidate_report_payload", malformed_payload)
    asyncio.run(_assert_four_refuse(proof, session, origin))
