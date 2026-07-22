"""Bounded continuation controller tests; this layer must remain transport-free."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.continuation as continuation_module
from core.behavior.closure import ObligationDisposition
from core.behavior.continuation import (
    CONTINUATION_WORKFLOW,
    BoundedContinuationConfig,
    BoundedContinuationController,
    BoundedContinuationDenied,
    ContinuationRound,
)
from core.behavior.obligations import UPHELD
from core.behavior.orchestrator import BehavioralShadowOrchestrator
from core.behavior.resolver import ClosedLoopResolverConfig, SingleStepObligationResolver
from core.foundry.authorization import AuthorizationEnvelope

ORIGIN = "https://api.example.test"


def _records():
    def record(persona, noun, object_id, marker):
        return {
            "persona_id": persona,
            "method": "GET",
            "url": f"{ORIGIN}/api/{noun}/{object_id}",
            "response_status": 200,
            "response_body": json.dumps({"owner": marker}),
        }

    source = (
        record("alice", "documents", "doc_source_7fa9f13a2b4c", "alice-private"),
        record("alice", "invoices", "invoice_source_7fa9f13a2b4c", "alice-private"),
    )
    peer = (
        record("bob", "documents", "doc_peer_4a5b6c7d8e9f0", "bob-private"),
        record("bob", "invoices", "invoice_peer_4a5b6c7d8e9f0", "bob-private"),
    )
    return source, peer


def _shadow_pair():
    source, peer = _records()
    orchestrator = BehavioralShadowOrchestrator()
    before = orchestrator.run(
        source,
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=peer,
        peer_world_id="bob",
    )
    selected = before.ranked_frontier[0]
    disposition = ObligationDisposition.create(
        obligation_id=selected.obligation_id,
        status=UPHELD,
        evidence_refs=("behavioral_receipt:" + "a" * 64,),
        reason_code="authorization_boundary_denied",
    )
    after = orchestrator.run(
        source,
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=peer,
        peer_world_id="bob",
        dispositions=(disposition,),
        previous_graph=before.graph,
        derivation_round=2,
    )
    round_summary = ContinuationRound(
        round_index=1,
        receipt_ref="behavioral_receipt:" + "a" * 64,
        obligation_id=selected.obligation_id,
        resolution_kind=selected.resolution_kind,
        resolution_ref=selected.resolution_ref,
        plan_id="closed_loop_resolver_plan:" + "b" * 64,
        shadow_before_id=before.run_id,
        shadow_after_id=after.run_id,
        closure_before_id=before.closure.certificate_id,
        closure_after_id=after.closure.certificate_id,
        status="completed",
        legacy_verdict="DENIED",
        finding_confirmed=False,
        requests_attempted=3,
        requests_sent=3,
        cleanup_uncertain=False,
    )
    return before, after, round_summary


def _envelope(workflows):
    envelope = AuthorizationEnvelope(
        envelope_id="continuation-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized bounded continuation test",
        disclosure_attestation=True,
        allowed_workflows=list(workflows),
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    return envelope


def test_config_requires_both_flags_and_separate_workflow(monkeypatch):
    monkeypatch.delenv("SENTINELFORGE_BEHAVIOR_PRIMARY", raising=False)
    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_CONTINUATION", "1")
    assert BoundedContinuationConfig.from_environment().enabled is False

    monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
    config = BoundedContinuationConfig.from_environment()
    assert config.enabled is True
    with pytest.raises(BoundedContinuationDenied, match="authorization_denied"):
        config.authorize(_envelope(()), target_origin=ORIGIN)
    config.authorize(_envelope((CONTINUATION_WORKFLOW,)), target_origin=ORIGIN)


def test_receipt_backed_frontier_progress_admits_one_next_plan():
    before, after, round_summary = _shadow_pair()
    controller = BoundedContinuationController(
        BoundedContinuationConfig(enabled=True)
    )

    progress = controller.after_round(
        (round_summary,),
        before=before,
        after=after,
    )
    next_plan = SingleStepObligationResolver(
        ClosedLoopResolverConfig(enabled=False)
    ).plan(after)
    admission = controller.admit_plan((round_summary,), next_plan)

    assert progress.continue_execution is True
    assert admission.continue_execution is True
    assert next_plan.selected is not None
    assert next_plan.selected.obligation_id != round_summary.obligation_id


def test_unchanged_unresolved_frontier_cannot_continue():
    before, _after, round_summary = _shadow_pair()
    round_summary = replace(
        round_summary,
        shadow_after_id=before.run_id,
        closure_after_id=before.closure.certificate_id,
    )
    controller = BoundedContinuationController(
        BoundedContinuationConfig(enabled=True)
    )

    decision = controller.after_round(
        (round_summary,),
        before=before,
        after=before,
    )

    assert decision.continue_execution is False
    assert decision.reason == "frontier_progress_missing"


def test_cleanup_uncertainty_stops_even_when_the_round_confirmed_a_finding():
    before, after, round_summary = _shadow_pair()
    round_summary = replace(
        round_summary,
        status="cleanup_failed",
        legacy_verdict="BOLA_CONFIRMED",
        finding_confirmed=True,
        cleanup_uncertain=True,
    )
    controller = BoundedContinuationController(
        BoundedContinuationConfig(enabled=True)
    )

    decision = controller.after_round(
        (round_summary,),
        before=before,
        after=after,
    )

    assert decision.continue_execution is False
    assert decision.reason == "cleanup_uncertain"


def test_continuation_session_is_deterministic_and_redacted():
    before, after, round_summary = _shadow_pair()
    controller = BoundedContinuationController(
        BoundedContinuationConfig(enabled=True)
    )
    first = controller.finish(
        root_fingerprint="c" * 64,
        initial=before,
        final=after,
        rounds=(round_summary,),
        stop_reason="no_executable_candidate",
    )
    second = controller.finish(
        root_fingerprint="c" * 64,
        initial=before,
        final=after,
        rounds=(round_summary,),
        stop_reason="no_executable_candidate",
    )

    assert first.to_dict() == second.to_dict()
    encoded = json.dumps(first.to_dict(), sort_keys=True)
    assert ORIGIN not in encoded
    assert "doc_source" not in encoded
    assert "alice-private" not in encoded


def test_continuation_layer_has_no_transport_or_package_level_surface():
    tree = ast.parse(Path(continuation_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert not hasattr(behavior_package, "BoundedContinuationController")
