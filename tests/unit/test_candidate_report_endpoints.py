from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.behavior.receipts import COMPLETED
from core.epistemic.ledger import (
    ActiveProofCitation,
    CanonicalSessionReadModel,
    Citation,
    Finding,
)
from core.errors import SentinelError
from core.ghost.flow import FlowStep
from core.reporting.submission_candidate import build_submission_candidate
from core.verify.workbench import CandidateWorkbenchStore


class _Receipts:
    def __init__(self, fingerprint: str) -> None:
        self.fingerprint = fingerprint

    def load(self, fingerprint: str):
        if fingerprint != self.fingerprint:
            return None
        return SimpleNamespace(state=COMPLETED)


def _candidate_state(tmp_path: Path):
    fingerprint = "a" * 64
    receipt_id = f"behavioral-{fingerprint}"
    observation = SimpleNamespace(
        id="obs-" + "1" * 64,
        target="https://reports.example.test/private/123",
    )
    finding = Finding(
        id="find-" + "2" * 64,
        title="Cross-account record read",
        severity="HIGH",
        citations=[Citation(observation_id=observation.id)],
        description="A peer can read another account's private record.",
        remediation="Enforce record ownership.",
        confirmation_level="confirmed",
        session_id="candidate-report-session",
        commitment="evidence_finding:" + "3" * 64,
        active_proof=[
            ActiveProofCitation(
                observation_id=observation.id,
                receipt_id=receipt_id,
                provenance_root="4" * 64,
            )
        ],
    )
    read_model = CanonicalSessionReadModel(
        session_id="candidate-report-session",
        revision="canonical_session_read_model:" + "5" * 64,
        observations=(observation,),
        findings=(finding,),
    )
    store = CandidateWorkbenchStore(
        tmp_path / "workbenches",
        receipt_store=_Receipts(fingerprint),
    )
    workbench = store.open(read_model, finding_id=finding.id)
    step = FlowStep(
        "GET",
        "https://reports.example.test/private/987",
        headers={"Authorization": "Bearer endpoint-secret"},
    )
    step.set_response(
        status=200,
        headers={"Content-Type": "application/json"},
        body='{"private":"response-secret"}',
        content_type="application/json",
    )
    selected = store.select_exchange(
        workbench,
        exchange_index=0,
        step=step,
        observation_id=observation.id,
        receipt_id=receipt_id,
        read_model=read_model,
    )
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

    read_model, store, expected = _candidate_state(tmp_path)

    class _DB:
        async def init(self):
            return None

        async def get_session(self, session_id):
            return {"target": "https://reports.example.test"}

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
            target="https://reports.example.test",
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
    assert "endpoint-secret" not in cortex_response.content
    assert "response-secret" not in ai_response["content"]

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
