from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.epistemic.ledger import (
    ActiveProofCitation,
    CanonicalSessionReadModel,
    Citation,
    Finding,
)
from core.ghost.flow import FlowStep
from core.verify.workbench import CandidateWorkbenchStore


class _CompletedReceipts:
    def __init__(self, fingerprint: str) -> None:
        self.fingerprint = fingerprint

    def load(self, fingerprint: str):
        if fingerprint != self.fingerprint:
            return None
        return SimpleNamespace(state="completed")


def _read_model(receipt_id: str) -> CanonicalSessionReadModel:
    observation = SimpleNamespace(
        id="obs-" + "1" * 64,
        target="https://verify.example.test/api/documents/12345?token=raw-query-secret",
    )
    finding = Finding(
        id="find-" + "2" * 64,
        title="Cross-object document read",
        severity="HIGH",
        citations=[Citation(observation_id=observation.id)],
        description="Receipt-bound fixture",
        confirmation_level="confirmed",
        session_id="assessment-session-13",
        commitment="evidence_finding:" + "3" * 64,
        active_proof=[
            ActiveProofCitation(
                observation_id=observation.id,
                receipt_id=receipt_id,
                provenance_root="4" * 64,
            )
        ],
    )
    return CanonicalSessionReadModel(
        session_id="assessment-session-13",
        revision="canonical_session_read_model:" + "5" * 64,
        observations=(observation,),
        findings=(finding,),
    )


def test_verify_workbench_is_session_finding_receipt_bound_and_restart_safe(
    tmp_path: Path,
) -> None:
    fingerprint = "a" * 64
    receipt_id = f"behavioral-{fingerprint}"
    receipts = _CompletedReceipts(fingerprint)
    read_model = _read_model(receipt_id)
    store = CandidateWorkbenchStore(tmp_path / "workbenches", receipt_store=receipts)
    workbench = store.open(read_model, finding_id=read_model.findings[0].id)

    step = FlowStep(
        "POST",
        "https://verify.example.test/api/documents/12345?token=raw-query-secret",
        headers={
            "Authorization": "Bearer raw-header-secret",
            "X-Custom-Secret": "custom-secret-value",
            "Content-Type": "application/json",
        },
        request_body='{"documentId":"raw-body-secret","include":"owner"}',
        request_content_type="application/json",
    )
    step.set_response(
        status=200,
        headers={"Content-Type": "application/json"},
        body='{"privateNote":"raw-response-secret"}',
        content_type="application/json",
    )
    selected = store.select_exchange(
        workbench,
        exchange_index=0,
        step=step,
        observation_id=read_model.observations[0].id,
        receipt_id=receipt_id,
        read_model=read_model,
    )

    restarted = CandidateWorkbenchStore(
        tmp_path / "workbenches",
        receipt_store=receipts,
    ).load(selected.workbench_id, read_model=read_model)
    assert restarted.to_dict() == selected.to_dict()
    assert restarted.canonical_session_id == "assessment-session-13"
    assert restarted.finding_id == read_model.findings[0].id
    assert len(restarted.selections) == 1
    selection = restarted.selections[0]
    assert selection.observation_id == read_model.observations[0].id
    assert selection.receipt_id == receipt_id
    assert selection.provenance_root == "4" * 64
    assert "$VALUE" in selection.sanitized_url
    assert dict(selection.sanitized_headers)["authorization"] == "Bearer $TOKEN"
    assert dict(selection.sanitized_headers)["x-custom-secret"] == "$REDACTED"
    assert dict(selection.sanitized_headers)["content-type"] == "application/json"

    persisted = next((tmp_path / "workbenches").glob("*.json")).read_text()
    for secret in (
        "raw-query-secret",
        "raw-header-secret",
        "custom-secret-value",
        "raw-body-secret",
        "raw-response-secret",
    ):
        assert secret not in persisted

    with pytest.raises(ValueError, match="finding/receipt bound"):
        store.select_exchange(
            workbench,
            exchange_index=1,
            step=step,
            observation_id=read_model.observations[0].id,
            receipt_id="behavioral-" + "b" * 64,
            read_model=read_model,
        )

    with pytest.raises(ValueError, match="finding/receipt bound"):
        store.select_exchanges(
            selected,
            exchanges=(
                (1, step, read_model.observations[0].id, receipt_id),
                (
                    2,
                    step,
                    read_model.observations[0].id,
                    "behavioral-" + "b" * 64,
                ),
            ),
            read_model=read_model,
        )
    after_failed_batch = store.load(selected.workbench_id, read_model=read_model)
    assert tuple(item.exchange_index for item in after_failed_batch.selections) == (0,)

    global_model = CanonicalSessionReadModel(
        session_id="global_scan",
        revision="canonical_session_read_model:" + "6" * 64,
        observations=read_model.observations,
        findings=read_model.findings,
    )
    with pytest.raises(ValueError, match="global_scan"):
        store.open(global_model, finding_id=read_model.findings[0].id)

    invalidated_model = CanonicalSessionReadModel(
        session_id=read_model.session_id,
        revision="canonical_session_read_model:" + "7" * 64,
        observations=read_model.observations,
        findings=(replace(read_model.findings[0], active_proof=[]),),
    )
    with pytest.raises(ValueError, match="proof binding became invalid"):
        store.load(selected.workbench_id, read_model=invalidated_model)

    persisted_path = next((tmp_path / "workbenches").glob("*.json"))
    backing_path = persisted_path.with_suffix(".backing")
    persisted_path.rename(backing_path)
    persisted_path.symlink_to(backing_path)
    with pytest.raises(ValueError, match="cannot be opened safely"):
        store.load(selected.workbench_id, read_model=read_model)
