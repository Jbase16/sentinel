"""Passive fixed-point closure tests; no execution is available."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.closure as closure_module

from core.behavior.affordances import ClientArtifact, LatentAffordanceMiner
from core.behavior.closure import (
    CONDITIONALLY_CLOSED,
    FINDING,
    MAX_DISPOSITION_EVIDENCE_REFS,
    ObligationDisposition,
    SecurityClosureEvaluator,
)
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.normalize import stable_hash
from core.behavior.obligations import (
    BLOCKED,
    OPEN,
    SUBSUMED,
    UNREACHABLE,
    UPHELD,
    VIOLATED,
    SecurityObligation,
    SecurityObligationGraph,
    SecurityObligationGraphBuilder,
    SecurityObligationLimits,
)
from core.behavior.proposals import compile_authorization_proposals

ORIGIN = "https://api.example.test"
NOTE_ID = "note_7fa9f13a2b4c5d6e"
JOB_ID = "job_4a5b6c7d8e9f0123"
ALICE_DOCUMENT_ID = "doc_alice_7fa9f13a2b4c"
BOB_DOCUMENT_ID = "doc_bob_4a5b6c7d8e9f0"


def _lifecycle():
    return LifecycleContractMiner().mine(
        (
            {
                "id": "create-note",
                "persona_id": "alice",
                "method": "POST",
                "url": f"{ORIGIN}/api/notes",
                "request_body": '{"title":"controlled"}',
                "response_status": 201,
                "response_body": json.dumps({"noteId": NOTE_ID}),
            },
            {
                "id": "read-note",
                "persona_id": "alice",
                "method": "GET",
                "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
                "response_status": 200,
                "response_body": '{"title":"controlled"}',
            },
            {
                "id": "cleanup-note",
                "persona_id": "alice",
                "method": "PATCH",
                "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
                "request_body": '{"archived":true}',
                "response_status": 200,
                "response_body": '{"archived":true}',
            },
        )
    )


def _proposals():
    return compile_authorization_proposals(
        (
            {
                "id": "bob-document",
                "method": "GET",
                "url": f"{ORIGIN}/api/documents/{BOB_DOCUMENT_ID}",
                "response_status": 200,
            },
        ),
        (
            {
                "id": "alice-document",
                "method": "GET",
                "url": f"{ORIGIN}/api/documents/{ALICE_DOCUMENT_ID}",
                "response_status": 200,
            },
        ),
        source_world="bob",
        peer_world="alice",
    )


def _affordances():
    records = (
        {
            "id": "start-export",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/documents/{ALICE_DOCUMENT_ID}/export",
            "request_body": "{}",
            "response_status": 202,
            "response_body": json.dumps({"jobId": JOB_ID}),
        },
    )
    artifacts = (
        ClientArtifact(
            f"{ORIGIN}/assets/app.js",
            "const poll = jobId => fetch(`/api/export-jobs/${jobId}`);",
        ),
    )
    return LatentAffordanceMiner().mine(records, artifacts, target_origin=ORIGIN)


def _graph(*, limits=None):
    return SecurityObligationGraphBuilder(limits).build(
        target_origin=ORIGIN,
        lifecycle=_lifecycle(),
        proposals=_proposals(),
        affordances=_affordances(),
    )


def _proof(label: str) -> str:
    return stable_hash("closure_test_evidence", label)


def _disposition(obligation_id: str, status: str, *, covered_by=None):
    return ObligationDisposition.create(
        obligation_id=obligation_id,
        status=status,
        evidence_refs=(_proof(f"{status}:{obligation_id}"),),
        reason_code=f"test_{status}",
        covered_by_obligation_id=covered_by,
    )


def _all_upheld(graph):
    return tuple(
        _disposition(item.obligation_id, UPHELD)
        for item in graph.obligations
        if item.status == OPEN
    )


def _graph_with_equivalent_boundary():
    graph = _graph()
    boundary = next(
        item for item in graph.obligations if item.kind == "ownership_boundary"
    )
    identity = {
        "target_ref": boundary.target_ref,
        "kind": "equivalent_ownership_boundary",
        "property_kind": boundary.property_kind,
        "subject_ref": boundary.subject_ref,
        "prerequisite_ids": list(boundary.prerequisite_ids),
        "risk_class": boundary.risk_class,
        "requires_execution": boundary.requires_execution,
    }
    sibling = SecurityObligation(
        obligation_id=stable_hash("security_obligation", identity),
        target_ref=boundary.target_ref,
        kind=identity["kind"],
        property_kind=boundary.property_kind,
        subject_ref=boundary.subject_ref,
        status=OPEN,
        prerequisite_ids=boundary.prerequisite_ids,
        evidence_refs=boundary.evidence_refs,
        evidence_digest=stable_hash(
            "security_obligation_evidence",
            {
                "source_kind": "equivalent_test",
                "evidence_refs": boundary.evidence_refs,
            },
        ),
        source_kind="equivalent_test",
        risk_class=boundary.risk_class,
        requires_execution=boundary.requires_execution,
    )
    obligations = tuple(
        sorted((*graph.obligations, sibling), key=lambda item: item.obligation_id)
    )
    diagnostics = replace(
        graph.diagnostics,
        ownership_boundaries=graph.diagnostics.ownership_boundaries + 1,
    )
    payload = {
        "target_ref": graph.target_ref,
        "input_digest": graph.input_digest,
        "obligations": [item.to_dict() for item in obligations],
        "diagnostics": diagnostics.to_dict(),
    }
    return SecurityObligationGraph(
        status="ready",
        target_ref=graph.target_ref,
        input_digest=graph.input_digest,
        graph_digest=stable_hash("security_obligation_graph", payload),
        obligations=obligations,
        diagnostics=diagnostics,
    )


def test_open_frontier_preserves_every_unresolved_obligation():
    graph = _graph()
    certificate = SecurityClosureEvaluator().evaluate(graph)

    assert certificate.status == OPEN
    assert certificate.open_count == 4
    assert certificate.unresolved_ids == tuple(
        sorted(item.obligation_id for item in graph.obligations if item.status == OPEN)
    )
    assert certificate.fixed_point is False
    assert certificate.blockers == ()


def test_resolved_frontier_remains_open_until_an_unchanged_second_round():
    graph = _graph()
    certificate = SecurityClosureEvaluator().evaluate(
        graph,
        dispositions=_all_upheld(graph),
    )

    assert certificate.status == OPEN
    assert certificate.open_count == 0
    assert certificate.fixed_point is False
    assert certificate.blockers == ("fixed_point_not_reached",)


def test_unchanged_resolved_frontier_is_conditionally_closed_and_deterministic():
    graph = _graph()
    dispositions = _all_upheld(graph)
    evaluator = SecurityClosureEvaluator()

    first = evaluator.evaluate(
        graph,
        dispositions=dispositions,
        previous_graph=_graph(),
        derivation_round=2,
    )
    second = evaluator.evaluate(
        graph,
        dispositions=reversed(dispositions),
        previous_graph=_graph(),
        derivation_round=2,
    )

    assert first.status == CONDITIONALLY_CLOSED
    assert first.fixed_point is True
    assert first.open_count == 0
    assert first.upheld_count == 5
    assert first.blockers == ()
    assert first.to_dict() == second.to_dict()


def test_violated_obligation_takes_precedence_and_preserves_remaining_frontier():
    graph = _graph()
    candidate = next(
        item
        for item in graph.obligations
        if item.kind == "authorization_counterexample"
    )
    certificate = SecurityClosureEvaluator().evaluate(
        graph,
        dispositions=(_disposition(candidate.obligation_id, VIOLATED),),
    )

    assert certificate.status == FINDING
    assert certificate.finding_ids == (candidate.obligation_id,)
    assert certificate.violated_count == 1
    assert certificate.open_count == 3


@pytest.mark.parametrize(
    ("disposition_status", "expected_blocker"),
    (
        (BLOCKED, "evidence_blocked"),
        (UNREACHABLE, "obligation_unreachable"),
    ),
)
def test_non_resolutions_are_honest_blocked_outcomes(
    disposition_status,
    expected_blocker,
):
    graph = _graph()
    candidate = next(item for item in graph.obligations if item.status == OPEN)
    certificate = SecurityClosureEvaluator().evaluate(
        graph,
        dispositions=(_disposition(candidate.obligation_id, disposition_status),),
    )

    assert certificate.status == BLOCKED
    assert expected_blocker in certificate.blockers
    assert candidate.obligation_id in certificate.blocked_ids


def test_truncated_and_empty_graphs_can_never_claim_closure():
    limits = SecurityObligationLimits(max_obligations=1)
    truncated = _graph(limits=limits)
    truncated_certificate = SecurityClosureEvaluator().evaluate(
        truncated,
        previous_graph=_graph(limits=limits),
        derivation_round=2,
    )
    empty = SecurityObligationGraphBuilder().build(target_origin=ORIGIN)
    empty_certificate = SecurityClosureEvaluator().evaluate(
        empty,
        previous_graph=SecurityObligationGraphBuilder().build(target_origin=ORIGIN),
        derivation_round=2,
    )

    assert truncated_certificate.status == BLOCKED
    assert "obligation_limit_truncated" in truncated_certificate.blockers
    assert empty_certificate.status == BLOCKED
    assert empty_certificate.blockers == ("no_security_obligations",)


def test_terminal_disposition_requires_resolved_prerequisites():
    graph = _graph()
    confinement = next(
        item for item in graph.obligations if item.kind == "capability_confinement"
    )

    with pytest.raises(
        ValueError,
        match="terminal disposition has unresolved prerequisite obligations",
    ):
        SecurityClosureEvaluator().evaluate(
            graph,
            dispositions=(_disposition(confinement.obligation_id, UPHELD),),
        )


def test_dispositions_require_evidence_and_cannot_be_duplicated():
    graph = _graph()
    candidate = next(item for item in graph.obligations if item.status == OPEN)

    with pytest.raises(
        ValueError,
        match="security obligation disposition contract is invalid",
    ):
        ObligationDisposition.create(
            obligation_id=candidate.obligation_id,
            status=UPHELD,
            evidence_refs=(),
            reason_code="missing_evidence",
        )

    with pytest.raises(
        ValueError,
        match="security obligation disposition evidence limit exceeded",
    ):
        ObligationDisposition.create(
            obligation_id=candidate.obligation_id,
            status=UPHELD,
            evidence_refs=(
                _proof(f"overflow:{index}")
                for index in range(MAX_DISPOSITION_EVIDENCE_REFS + 1)
            ),
            reason_code="excess_evidence",
        )

    disposition = _disposition(candidate.obligation_id, BLOCKED)
    with pytest.raises(
        ValueError,
        match="an obligation cannot receive multiple dispositions",
    ):
        SecurityClosureEvaluator().evaluate(
            graph,
            dispositions=(disposition, disposition),
        )


def test_subsumption_cannot_hide_a_different_security_question():
    graph = _graph()
    boundary = next(
        item for item in graph.obligations if item.kind == "ownership_boundary"
    )
    control = next(item for item in graph.obligations if item.kind == "owned_control")

    with pytest.raises(
        ValueError,
        match="subsumed obligation coverage is not semantically equivalent",
    ):
        SecurityClosureEvaluator().evaluate(
            graph,
            dispositions=(
                _disposition(
                    boundary.obligation_id,
                    SUBSUMED,
                    covered_by=control.obligation_id,
                ),
            ),
        )


def test_subsumption_requires_an_upheld_equivalent_and_rejects_cycles():
    graph = _graph_with_equivalent_boundary()
    boundaries = tuple(
        item
        for item in graph.obligations
        if item.kind in {"ownership_boundary", "equivalent_ownership_boundary"}
    )
    first, second = boundaries
    certificate = SecurityClosureEvaluator().evaluate(
        graph,
        dispositions=(
            _disposition(first.obligation_id, UPHELD),
            _disposition(
                second.obligation_id,
                SUBSUMED,
                covered_by=first.obligation_id,
            ),
        ),
    )

    assert certificate.status == OPEN
    assert certificate.subsumed_count == 1
    assert certificate.upheld_count == 2

    with pytest.raises(
        ValueError,
        match="subsumed obligation coverage contains a cycle",
    ):
        SecurityClosureEvaluator().evaluate(
            graph,
            dispositions=(
                _disposition(
                    first.obligation_id,
                    SUBSUMED,
                    covered_by=second.obligation_id,
                ),
                _disposition(
                    second.obligation_id,
                    SUBSUMED,
                    covered_by=first.obligation_id,
                ),
            ),
        )


def test_previous_graph_must_share_the_target_and_digest_to_reach_fixed_point():
    graph = _graph()
    different_target = SecurityObligationGraphBuilder().build(
        target_origin="https://different.example.test"
    )
    different_frontier = SecurityObligationGraphBuilder().build(
        target_origin=ORIGIN,
        proposals=_proposals(),
    )

    with pytest.raises(
        ValueError,
        match="previous graph target does not match current graph",
    ):
        SecurityClosureEvaluator().evaluate(
            graph,
            previous_graph=different_target,
            derivation_round=2,
        )

    certificate = SecurityClosureEvaluator().evaluate(
        graph,
        dispositions=_all_upheld(graph),
        previous_graph=different_frontier,
        derivation_round=2,
    )
    assert certificate.status == OPEN
    assert certificate.fixed_point is False
    assert certificate.blockers == ("fixed_point_not_reached",)


def test_certificate_and_dispositions_are_strictly_redacted():
    graph = _graph()
    dispositions = _all_upheld(graph)
    certificate = SecurityClosureEvaluator().evaluate(
        graph,
        dispositions=dispositions,
        previous_graph=_graph(),
        derivation_round=2,
    )
    serialized = json.dumps(
        {
            "certificate": certificate.to_dict(),
            "dispositions": [item.to_dict() for item in dispositions],
        },
        sort_keys=True,
    )

    for raw_value in (
        ORIGIN,
        NOTE_ID,
        JOB_ID,
        ALICE_DOCUMENT_ID,
        BOB_DOCUMENT_ID,
        "alice",
        "bob",
        "app.js",
    ):
        assert raw_value not in serialized


def test_closure_module_has_no_transport_or_async_execution_surface():
    tree = ast.parse(Path(closure_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert not hasattr(behavior_package, "SecurityClosureEvaluator")
