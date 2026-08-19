from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.ai.scan_briefing import build_scan_briefing
from core.base.config import SentinelConfig, StorageConfig
from core.behavior.compiler import operation_atoms_from_records
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    BehavioralReceiptStore,
    redacted_receipt_context,
    request_fingerprint,
)
from core.cortex.canonical_graph import build_causal_graph_snapshot
from core.cortex.triage_adversary import BOUNTY, route_findings
from core.data.pressure_graph.projection import project_pressure_graph
from core.epistemic.ledger import (
    ActiveProofCitation,
    Citation,
    ConfirmationLevel,
    EvidenceLedger,
    LifecycleState,
)
from core.ghost.flow import FlowStep
from core.identity import AssessmentIdentityContext, CredentialFreshness
from core.reporting.submission_candidate import (
    build_submission_candidate,
    render_submission_candidate,
)
from core.verify.workbench import CandidateWorkbenchStore


ORIGIN = "https://owned.example.test"
SESSION_ID = "session-wo09"
PROVENANCE_ROOT = "d" * 64
TITLE = "Cross-persona owned note disclosure"


def _identity() -> AssessmentIdentityContext:
    return AssessmentIdentityContext(
        session_id=SESSION_ID,
        authorization_envelope_id="envelope-wo09",
        authorization_envelope_ref=f"authorization_envelope:{'a' * 64}",
        target_origin=ORIGIN,
        target_reset_epoch=1,
        world_id="alice",
        persona_id="persona-alice",
        target_actor_id="actor-alice",
        tenant_id="tenant-owned",
        credential_source_ref="credential:alice",
        credential_epoch=1,
        credential_freshness=CredentialFreshness.FRESH,
        resource_id="resource:owned-note",
        representation_id="representation:http-json-v1",
    )


def _receipt_response() -> dict:
    empty_resolution = {
        "resolved_operations": 0,
        "unresolved_operations": 0,
        "ambiguous_operations": 0,
    }
    return {
        "status": "completed",
        "plan": {
            "selected_proposal_id": f"authorization_proposal:{'b' * 64}",
        },
        "execution": {
            "status": "completed",
            "legacy_verdict": "BOLA_CONFIRMED",
            "finding_confirmed": True,
            "requests_attempted": 1,
            "requests_sent": 1,
            "policy_denials": 0,
            "provenance_root": PROVENANCE_ROOT,
        },
        "finding_confirmed": True,
        "finding": {"redacted": True},
        "graphql_resolution": {
            "catalog": {
                "artifacts": 0,
                "artifact_bytes": 0,
                "documents": 0,
                "operation_names": 0,
                "dropped": {
                    "artifacts": 0,
                    "artifact_bytes": 0,
                    "documents": 0,
                },
            },
            "assets": {
                "attempted": 0,
                "fetched": 0,
                "failed": 0,
                "documents_added": 0,
            },
            "source": empty_resolution,
            "peer": empty_resolution,
        },
    }


def _triage_count(findings: list[dict]) -> int:
    buckets = route_findings(
        findings,
        route=BOUNTY,
        scope=object(),
        program_rules=object(),
    )
    return sum(len(items) for items in buckets.values())


def test_invalidating_one_observation_changes_every_canonical_reader(
    tmp_path: Path,
) -> None:
    families, instances = operation_atoms_from_records(
        (
            {
                "id": "owned-cross-read",
                "persona_id": "alice",
                "method": "GET",
                "url": f"{ORIGIN}/notes/peer-owned",
                "response_status": 200,
                "response_body": '{"marker":"peer-owned"}',
            },
        )
    )
    instance = next(
        item for item in instances if item.world_ref == stable_hash("world", "alice")
    )
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path))
    receipt_store = BehavioralReceiptStore(tmp_path / "receipts")

    with patch("core.base.sequence.GlobalSequenceAuthority") as sequence:
        sequence.instance.return_value.run_id = "run-wo09"
        ledger = EvidenceLedger(config, receipt_store=receipt_store)
        observation = ledger.record_canonical_observation(
            tool_name="owned-lab-http",
            tool_args=["GET", "/notes/peer-owned"],
            target=f"{ORIGIN}/notes/peer-owned",
            raw_output=b'{"marker":"peer-owned"}',
            identity=_identity(),
            operation_family=families[0],
            operation_instance=instance,
        )
        fingerprint = request_fingerprint(
            {"session_id": SESSION_ID, "observation_id": observation.id}
        )
        reservation = receipt_store.reserve(
            fingerprint,
            context=redacted_receipt_context(
                target_origin=ORIGIN,
                envelope_id=_identity().authorization_envelope_id,
                source_persona_id=_identity().persona_id,
                peer_persona_id="persona-peer",
            ),
        )
        receipt_store.complete(
            fingerprint,
            reservation_token=reservation.reservation_token or "",
            outcome=_receipt_response(),
        )
        finding = ledger.promote_canonical_finding(
            title=TITLE,
            severity="high",
            citations=[Citation(observation_id=observation.id, snippet="peer-owned")],
            description="The peer-owned marker was returned to the source persona.",
            confirmation_level=ConfirmationLevel.CONFIRMED.value,
            metadata={
                "type": "cross_principal_object_access",
                "finding_class": "cross_principal_object_access",
                "poc": "GET the owned peer fixture with the source test persona.",
                "impact": "Minimal owned-lab cross-persona read was observed.",
                "sentinel_provenance": {
                    "root": PROVENANCE_ROOT,
                    "events": 1,
                },
            },
            active_proof=[
                ActiveProofCitation(
                    observation_id=observation.id,
                    receipt_id=reservation.receipt.receipt_id,
                    provenance_root=PROVENANCE_ROOT,
                )
            ],
        )

        before = ledger.session_read_model(SESSION_ID)
        before_graph = build_causal_graph_snapshot(before)
        before_pressure = project_pressure_graph(before_graph)
        tampered_graph_view = before_graph.graph_dto
        tampered_graph_view["nodes"].clear()
        assert before_graph.graph_dto["count"]["nodes"] == 1
        before_findings = before.finding_views()
        before_chat = build_scan_briefing(
            before_findings,
            [],
            target=ORIGIN,
            session_id=SESSION_ID,
            graph_dto=before_graph.graph_dto,
        )
        workbench_store = CandidateWorkbenchStore(
            tmp_path / "workbenches",
            receipt_store=receipt_store,
        )
        workbench = workbench_store.open(before, finding_id=finding.id)
        step = FlowStep("GET", f"{ORIGIN}/notes/peer-owned")
        step.set_response(
            status=200,
            headers={"Content-Type": "application/json"},
            body='{"marker":"peer-owned"}',
            content_type="application/json",
        )
        workbench = workbench_store.select_exchange(
            workbench,
            exchange_index=0,
            step=step,
            observation_id=observation.id,
            receipt_id=reservation.receipt.receipt_id,
            read_model=before,
        )
        before_candidate = build_submission_candidate(
            before,
            workbench_id=workbench.workbench_id,
            workbench_store=workbench_store,
        )
        before_report = render_submission_candidate(before_candidate).markdown
        before_triage_count = _triage_count(before_findings)

        ledger.invalidate_observation(
            observation.id,
            "owned fixture reset invalidated the cited representation",
        )

        restored = EvidenceLedger(config, receipt_store=receipt_store)
        after = restored.session_read_model(SESSION_ID)
        after_graph = build_causal_graph_snapshot(after)
        after_pressure = project_pressure_graph(after_graph)
        after_findings = after.finding_views()
        after_chat = build_scan_briefing(
            after_findings,
            [],
            target=ORIGIN,
            session_id=SESSION_ID,
            graph_dto=after_graph.graph_dto,
        )
        with pytest.raises(
            ValueError,
            match="requires a finding in the exact session",
        ):
            build_submission_candidate(
                after,
                workbench_id=workbench.workbench_id,
                workbench_store=workbench_store,
            )
        after_triage_count = _triage_count(after_findings)

    assert ledger.get_state(observation.id).state is LifecycleState.INVALIDATED
    assert ledger.get_state(finding.id).state is LifecycleState.INVALIDATED
    assert restored.get_state(observation.id).state is LifecycleState.INVALIDATED
    assert restored.get_state(finding.id).state is LifecycleState.INVALIDATED
    assert before.revision != after.revision
    assert before_graph.graph_hash != after_graph.graph_hash
    assert before_pressure.graph_hash != after_pressure.graph_hash
    assert before_pressure.projection_hash != after_pressure.projection_hash
    assert before_graph.graph_dto["count"]["nodes"] == 1
    assert after_graph.graph_dto["count"]["nodes"] == 0
    assert before_chat != after_chat
    assert "Findings (total): 1" in before_chat
    assert "0 finding(s) / 0 issue(s)" in after_chat
    assert TITLE in before_report
    assert before_triage_count == 1
    assert after_triage_count == 0
