from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.behavior.receipts import BehavioralReceiptStore, request_fingerprint
from core.epistemic.ledger import ActiveProofCitation
from core.reporting.submission_candidate import (
    build_submission_candidate,
    render_submission_candidate,
)
from core.verify.workbench import CandidateWorkbenchStore
from tests.unit.test_ocb_s19_candidate_assembly import (
    _confirmed_outcome,
    _family_r,
    _select_captures,
)


def test_submission_candidate_is_receipt_gated_and_deterministic(
    tmp_path: Path,
    monkeypatch,
) -> None:
    proof = _family_r(tmp_path, monkeypatch)
    selected = _select_captures(proof)
    read_model = proof.read_model()
    receipt_id = read_model.findings[0].active_proof[0].receipt_id
    restarted_store = proof.store()
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
    assert first.steps[0].proof.receipt_id == receipt_id
    assert len(first.active_proof) == 1
    serialized = json.dumps(
        {"candidate": first.to_dict(), "render": first_render.to_dict()},
        sort_keys=True,
    )
    for secret in (
        "ocb-query-secret",
        "ocb-operator-token",
        "ocb-cookie-secret",
        "ocb-csrf-secret",
        "ocb-persona-session-value",
        "ocb-response-secret",
    ):
        assert secret not in serialized

    with pytest.raises(ValueError, match="digest mismatch"):
        replace(first, summary="AI-added unsupported claim")

    from core.epistemic import ledger as ledger_module
    from core.server.routers import scans
    from core.verify import workbench as workbench_module

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
    assert bounty["reports"][0]["impact"] == first.to_dict()["impact"]

    missing_active_receipt_store = CandidateWorkbenchStore(
        proof.workbench_root,
        receipt_store=BehavioralReceiptStore(tmp_path / "missing-receipts"),
    )
    with pytest.raises(ValueError, match="receipt"):
        build_submission_candidate(
            read_model,
            workbench_id=selected.workbench_id,
            workbench_store=missing_active_receipt_store,
        )

    empty_store = CandidateWorkbenchStore(
        tmp_path / "empty-workbench",
        receipt_store=proof.receipts,
    )
    empty = empty_store.open(read_model, finding_id=read_model.findings[0].id)
    reconstructed = build_submission_candidate(
        read_model,
        workbench_id=empty.workbench_id,
        workbench_store=empty_store,
    )
    assert reconstructed.candidate_digest == first.candidate_digest
    assert len(empty_store.load(empty.workbench_id, read_model=read_model).selections) == 1


def test_submission_candidate_refuses_multiple_active_receipt_lineages(
    tmp_path: Path, monkeypatch,
) -> None:
    proof = _family_r(tmp_path, monkeypatch)
    ledger = proof.ledger()
    finding = proof.read_model().findings[0]
    first_binding = finding.active_proof[0]
    first_receipt = proof.receipts.load(first_binding.receipt_id.removeprefix("behavioral-"))
    fingerprint = request_fingerprint({"scenario": "OCB-S19", "lineage": "additional"})
    reservation = proof.receipts.reserve(fingerprint, context=first_receipt.context)
    additional = proof.receipts.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=_confirmed_outcome(),
    )
    finding = ledger.promote_canonical_finding(
        title=finding.title,
        severity=finding.severity,
        citations=finding.citations,
        description=finding.description,
        remediation=finding.remediation,
        confirmation_level=finding.confirmation_level,
        active_proof=[
            first_binding,
            ActiveProofCitation(
                observation_id=first_binding.observation_id,
                receipt_id=additional.receipt_id,
                provenance_root=first_binding.provenance_root,
            ),
        ],
    )
    read_model = ledger.session_read_model(proof.session_id)
    store = proof.store()
    workbench = store.open(read_model, finding_id=finding.id)
    selected = store.select_exchange(
        workbench,
        exchange_index=0,
        step=proof.captured[0],
        observation_id=proof.observation_ids[0],
        receipt_id=first_binding.receipt_id,
        read_model=read_model,
    )
    with pytest.raises(ValueError, match="lineage"):
        build_submission_candidate(
            read_model, workbench_id=selected.workbench_id, workbench_store=store,
        )
