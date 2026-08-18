from __future__ import annotations

import asyncio
import json
from dataclasses import replace
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
from core.ghost.flow import FlowStep
from core.reporting.submission_candidate import (
    build_submission_candidate,
    render_submission_candidate,
)
from core.verify.workbench import CandidateWorkbenchStore


class _Receipts:
    def __init__(self, *fingerprints: str) -> None:
        self.fingerprints = frozenset(fingerprints)

    def load(self, fingerprint: str):
        if fingerprint not in self.fingerprints:
            return None
        return SimpleNamespace(state=COMPLETED)


def _read_model(receipt_ids: tuple[str, ...]) -> CanonicalSessionReadModel:
    observation = SimpleNamespace(
        id="obs-" + "1" * 64,
        target="https://candidate.example.test/private/123?token=target-secret",
    )
    finding = Finding(
        id="find-" + "2" * 64,
        title="Cross-account private record read",
        severity="HIGH",
        citations=[Citation(observation_id=observation.id)],
        description="A peer account can read another account's private record.",
        remediation="Enforce record ownership before returning the record.",
        confirmation_level="confirmed",
        session_id="candidate-session-14",
        commitment="evidence_finding:" + "3" * 64,
        active_proof=[
            ActiveProofCitation(
                observation_id=observation.id,
                receipt_id=receipt_id,
                provenance_root=str(index) * 64,
            )
            for index, receipt_id in enumerate(receipt_ids, start=4)
        ],
    )
    return CanonicalSessionReadModel(
        session_id="candidate-session-14",
        revision="canonical_session_read_model:" + "6" * 64,
        observations=(observation,),
        findings=(finding,),
    )


def test_submission_candidate_is_receipt_gated_and_deterministic(
    tmp_path: Path,
    monkeypatch,
) -> None:
    fingerprints = ("a" * 64, "b" * 64)
    receipt_ids = tuple(f"behavioral-{item}" for item in fingerprints)
    read_model = _read_model(receipt_ids)
    root = tmp_path / "workbenches"
    store = CandidateWorkbenchStore(
        root,
        receipt_store=_Receipts(*fingerprints),
    )
    workbench = store.open(read_model, finding_id=read_model.findings[0].id)
    step = FlowStep(
        "GET",
        "https://candidate.example.test/private/987?token=request-secret",
        headers={
            "Authorization": "Bearer header-secret",
            "X-Private": "private-header",
        },
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
        observation_id=read_model.observations[0].id,
        receipt_id=receipt_ids[0],
        read_model=read_model,
    )

    restarted_store = CandidateWorkbenchStore(
        root,
        receipt_store=_Receipts(*fingerprints),
    )
    first = build_submission_candidate(
        read_model,
        workbench_id=selected.workbench_id,
        workbench_store=restarted_store,
    )
    second = build_submission_candidate(
        read_model,
        workbench_id=selected.workbench_id,
        workbench_store=restarted_store,
    )
    first_render = render_submission_candidate(first)
    second_render = render_submission_candidate(second)

    assert first.to_dict() == second.to_dict()
    assert first.candidate_digest == second.candidate_digest
    assert first_render.to_dict() == second_render.to_dict()
    assert first_render.render_digest == second_render.render_digest
    assert first.steps[0].proof.receipt_id == receipt_ids[0]
    assert len(first.active_proof) == 2
    serialized = json.dumps(
        {"candidate": first.to_dict(), "render": first_render.to_dict()},
        sort_keys=True,
    )
    for secret in (
        "target-secret",
        "request-secret",
        "header-secret",
        "private-header",
        "response-secret",
    ):
        assert secret not in serialized

    with pytest.raises(ValueError, match="digest mismatch"):
        replace(first, summary="AI-added unsupported claim")

    from core.data import db as db_module
    from core.epistemic import ledger as ledger_module
    from core.server.routers import scans
    from core.verify import workbench as workbench_module

    class _DB:
        async def get_session(self, session_id):
            return {"target": "https://candidate.example.test"}

    monkeypatch.setattr(
        db_module.Database,
        "instance",
        staticmethod(lambda: _DB()),
    )
    monkeypatch.setattr(
        ledger_module,
        "load_canonical_session_read_model",
        lambda session_id: read_model,
    )
    monkeypatch.setattr(
        workbench_module,
        "CandidateWorkbenchStore",
        lambda: restarted_store,
    )
    bounty = asyncio.run(
        scans.get_session_bounty_report(read_model.session_id)
    )
    assert bounty["candidate_digests"] == [first.candidate_digest]
    assert bounty["reports"][0]["candidate_digest"] == first.candidate_digest
    assert bounty["reports"][0]["claims"] == first.to_dict()["claims"]
    assert bounty["reports"][0]["impact"] is None

    missing_active_receipt_store = CandidateWorkbenchStore(
        root,
        receipt_store=_Receipts(fingerprints[0]),
    )
    with pytest.raises(ValueError, match="active proof receipt is not completed"):
        build_submission_candidate(
            read_model,
            workbench_id=selected.workbench_id,
            workbench_store=missing_active_receipt_store,
        )

    empty_store = CandidateWorkbenchStore(
        tmp_path / "empty-workbench",
        receipt_store=_Receipts(*fingerprints),
    )
    empty = empty_store.open(read_model, finding_id=read_model.findings[0].id)
    with pytest.raises(ValueError, match="requires receipt-bound workbench steps"):
        build_submission_candidate(
            read_model,
            workbench_id=empty.workbench_id,
            workbench_store=empty_store,
        )
