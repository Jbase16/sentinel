"""Receipt-to-disposition feedback tests; the adapter must stay transport-free."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.feedback as feedback_module
from core.behavior.closure import BLOCKED, UPHELD, VIOLATED
from core.behavior.feedback import ReceiptDispositionAdapter, ReceiptFeedbackDenied
from core.behavior.obligations import SecurityObligationGraphBuilder
from core.behavior.orchestrator import BehavioralShadowOrchestrator
from core.behavior.proposals import compile_authorization_proposals
from core.behavior.receipts import (
    BehavioralReceiptStore,
    redacted_compiled_outcome,
    redacted_outcome,
    redacted_receipt_context,
    request_fingerprint,
)

ORIGIN = "https://api.example.test"
SOURCE_ID = "doc_source_7fa9f13a2b4c"
PEER_ID = "doc_peer_4a5b6c7d8e9f0"
SOURCE_WORLD = "alice"
PEER_WORLD = "bob"
ENVELOPE_ID = "feedback-envelope"


def _records():
    source = ({
        "persona_id": SOURCE_WORLD,
        "method": "GET",
        "url": f"{ORIGIN}/api/documents/{SOURCE_ID}",
        "response_status": 200,
        "response_body": '{"owner":"alice-private"}',
    },)
    peer = ({
        "persona_id": PEER_WORLD,
        "method": "GET",
        "url": f"{ORIGIN}/api/documents/{PEER_ID}",
        "response_status": 200,
        "response_body": '{"owner":"bob-private"}',
    },)
    return source, peer


def _graph():
    source, peer = _records()
    proposals = compile_authorization_proposals(
        source,
        peer,
        source_world=SOURCE_WORLD,
        peer_world=PEER_WORLD,
    )
    graph = SecurityObligationGraphBuilder().build(
        target_origin=ORIGIN,
        proposals=proposals,
    )
    assert len(proposals.proposals) == 1
    return graph, proposals.proposals[0]


def _context():
    return redacted_receipt_context(
        target_origin=ORIGIN,
        envelope_id=ENVELOPE_ID,
        source_persona_id=SOURCE_WORLD,
        peer_persona_id=PEER_WORLD,
    )


def _graphql_diagnostics():
    empty = {
        "resolved_operations": 0,
        "unresolved_operations": 0,
        "ambiguous_operations": 0,
    }
    return {
        "catalog": {
            "artifacts": 0,
            "artifact_bytes": 0,
            "documents": 0,
            "operation_names": 0,
            "dropped": {"artifacts": 0, "artifact_bytes": 0, "documents": 0},
        },
        "assets": {
            "attempted": 0,
            "fetched": 0,
            "failed": 0,
            "documents_added": 0,
        },
        "source": dict(empty),
        "peer": dict(empty),
    }


def _completed_receipt(tmp_path, proposal_id, verdict, *, status="completed"):
    response = {
        "status": status,
        "plan": {"selected_proposal_id": proposal_id},
        "execution": {
            "status": status,
            "legacy_verdict": verdict,
            "finding_confirmed": verdict == "BOLA_CONFIRMED",
            "requests_attempted": 3,
            "requests_sent": 3,
            "policy_denials": 0,
        },
        "finding": ({"redacted": True} if verdict == "BOLA_CONFIRMED" else None),
        "finding_confirmed": verdict == "BOLA_CONFIRMED",
        "graphql_resolution": _graphql_diagnostics(),
    }
    fingerprint = request_fingerprint(
        {"proposal_id": proposal_id, "verdict": verdict, "status": status}
    )
    store = BehavioralReceiptStore(tmp_path / fingerprint)
    reservation = store.reserve(fingerprint, context=_context())
    assert reservation.reservation_token is not None
    return store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=redacted_outcome(response),
    )


def test_confirmed_receipt_becomes_exact_violated_disposition(tmp_path):
    graph, proposal = _graph()
    receipt = _completed_receipt(
        tmp_path,
        proposal.proposal_id,
        "BOLA_CONFIRMED",
    )

    first = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=_context(),
    )
    second = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=_context(),
    )

    assert first.to_dict() == second.to_dict()
    assert first.status == "ready"
    assert len(first.dispositions) == 1
    disposition = first.dispositions[0]
    obligation = next(
        item for item in graph.obligations if proposal.proposal_id in item.evidence_refs
    )
    assert disposition.obligation_id == obligation.obligation_id
    assert disposition.status == VIOLATED
    assert disposition.reason_code == "bola_cross_read_confirmed"
    assert disposition.evidence_refs == (
        f"behavioral_receipt:{receipt.fingerprint}",
    )
    encoded = json.dumps(first.to_dict(), sort_keys=True)
    assert ORIGIN not in encoded
    assert SOURCE_ID not in encoded
    assert PEER_ID not in encoded


@pytest.mark.parametrize(
    ("verdict", "expected_status", "expected_reason"),
    (
        ("DENIED", UPHELD, "authorization_boundary_denied"),
        ("NO_CROSS_READ", UPHELD, "victim_private_marker_absent"),
        ("AMBIGUOUS", BLOCKED, "authorization_evidence_ambiguous"),
        ("ERROR", BLOCKED, "authorization_execution_error"),
    ),
)
def test_terminal_verdict_mapping_is_fail_closed(
    tmp_path,
    verdict,
    expected_status,
    expected_reason,
):
    graph, proposal = _graph()
    receipt = _completed_receipt(tmp_path, proposal.proposal_id, verdict)

    batch = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=_context(),
    )

    assert batch.dispositions[0].status == expected_status
    assert batch.dispositions[0].reason_code == expected_reason


def test_aborted_execution_outcome_is_blocked_not_upheld(tmp_path):
    graph, proposal = _graph()
    receipt = _completed_receipt(
        tmp_path,
        proposal.proposal_id,
        "DENIED",
        status="aborted",
    )

    batch = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=_context(),
    )

    assert batch.dispositions[0].status == BLOCKED
    assert batch.dispositions[0].reason_code == "authorization_execution_aborted"


def test_no_candidate_receipt_cannot_close_an_obligation(tmp_path):
    graph, _proposal = _graph()
    response = {
        "status": "no_executable_candidate",
        "plan": {"selected_proposal_id": None},
        "execution": None,
        "finding": None,
        "finding_confirmed": False,
        "graphql_resolution": _graphql_diagnostics(),
    }
    fingerprint = request_fingerprint({"no_candidate": True})
    store = BehavioralReceiptStore(tmp_path)
    reservation = store.reserve(fingerprint, context=_context())
    assert reservation.reservation_token is not None
    receipt = store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=redacted_outcome(response),
    )

    batch = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=_context(),
    )

    assert batch.status == "no_dispositions"
    assert batch.dispositions == ()
    assert batch.diagnostics.unbound_receipts == 1


def test_compiled_setup_receipt_is_not_authorization_evidence(tmp_path):
    graph, _proposal = _graph()
    fingerprint = request_fingerprint({"compiled": True})
    store = BehavioralReceiptStore(tmp_path)
    reservation = store.reserve(fingerprint, context=_context())
    assert reservation.reservation_token is not None
    receipt = store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=redacted_compiled_outcome({
            "sequence_id": "controlled_runtime_sequence:" + "b" * 64,
            "status": "completed",
            "main_steps_attempted": 2,
            "main_steps_completed": 2,
            "cleanup_steps_attempted": 1,
            "cleanup_steps_completed": 1,
            "policy_denials": 0,
            "runtime_values_bound": 2,
            "orphaned_owned_state_possible": False,
            "provenance_root": "c" * 64,
            "budget_snapshot": {
                "total_requests": 3,
                "cross_object_reads": 0,
                "privilege_mutations": 0,
                "creates": 1,
                "endpoints_touched": 2,
            },
            "error_code": None,
        }),
    )

    batch = ReceiptDispositionAdapter().adapt(
        graph,
        (receipt,),
        expected_context=_context(),
    )

    assert batch.status == "no_dispositions"
    assert batch.dispositions == ()
    assert batch.diagnostics.unsupported_receipts == 1


def test_context_or_proposal_mismatch_fails_closed(tmp_path):
    graph, proposal = _graph()
    receipt = _completed_receipt(tmp_path, proposal.proposal_id, "DENIED")
    wrong_context = redacted_receipt_context(
        target_origin="https://other.example.test",
        envelope_id=ENVELOPE_ID,
        source_persona_id=SOURCE_WORLD,
        peer_persona_id=PEER_WORLD,
    )

    with pytest.raises(ReceiptFeedbackDenied, match="context_mismatch"):
        ReceiptDispositionAdapter().adapt(
            graph,
            (receipt,),
            expected_context=wrong_context,
        )

    other_receipt = _completed_receipt(
        tmp_path,
        "authorization_proposal:" + "f" * 64,
        "DENIED",
    )
    with pytest.raises(ReceiptFeedbackDenied, match="no_exact_open_obligation"):
        ReceiptDispositionAdapter().adapt(
            graph,
            (other_receipt,),
            expected_context=_context(),
        )


def test_feedback_disposition_drives_next_shadow_round_without_traffic(tmp_path):
    source, peer = _records()
    orchestrator = BehavioralShadowOrchestrator()
    first = orchestrator.run(
        source,
        target_origin=ORIGIN,
        world_id=SOURCE_WORLD,
        peer_records=peer,
        peer_world_id=PEER_WORLD,
    )
    assert first.proposals is not None
    proposal = first.proposals.proposals[0]
    receipt = _completed_receipt(
        tmp_path,
        proposal.proposal_id,
        "BOLA_CONFIRMED",
    )
    feedback = ReceiptDispositionAdapter().adapt(
        first.graph,
        (receipt,),
        expected_context=_context(),
    )

    second = orchestrator.run(
        source,
        target_origin=ORIGIN,
        world_id=SOURCE_WORLD,
        peer_records=peer,
        peer_world_id=PEER_WORLD,
        dispositions=feedback.dispositions,
        previous_graph=first.graph,
        derivation_round=2,
    )

    assert second.status == "finding"
    assert second.closure.finding_ids == (
        feedback.dispositions[0].obligation_id,
    )
    assert second.closure.fixed_point is True


def test_feedback_module_has_no_transport_or_execution_surface():
    tree = ast.parse(Path(feedback_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert not hasattr(behavior_package, "ReceiptDispositionAdapter")
