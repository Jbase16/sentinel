"""Single-step obligation resolver tests; the frontier owns selection."""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.resolver as resolver_module
from core.behavior.active import CONTROLLED_WORKFLOW
from core.behavior.orchestrator import (
    BehavioralShadowOrchestrator,
    OwnedExperimentShadowContext,
    ShadowOrchestratorConfig,
)
from core.behavior.resolver import (
    ClosedLoopResolverConfig,
    ClosedLoopResolverDenied,
    SingleStepObligationResolver,
)
from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://api.example.test"
NOTE_ID = "note_7fa9f13a2b4c5d6e"
SOURCE_DOCUMENT_ID = "doc_source_7fa9f13a2b4c"
PEER_DOCUMENT_ID = "doc_peer_4a5b6c7d8e9f0"


def _source_records():
    return (
        {
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/notes",
            "request_body": '{"title":"controlled marker"}',
            "response_status": 201,
            "response_body": json.dumps({"noteId": NOTE_ID}),
        },
        {
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
            "response_status": 200,
            "response_body": '{"title":"controlled marker"}',
        },
        {
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/notes/{NOTE_ID}",
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        },
        {
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{SOURCE_DOCUMENT_ID}",
            "response_status": 200,
            "response_body": '{"owner":"alice-private"}',
        },
    )


def _peer_records():
    return (
        {
            "persona_id": "bob",
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{PEER_DOCUMENT_ID}",
            "response_status": 200,
            "response_body": '{"owner":"bob-private"}',
        },
    )


def _context():
    calls = []

    async def forbidden_transport(method, url, body=None, **kwargs):
        calls.append((method, url, body, kwargs))
        raise AssertionError("planning must not invoke target transport")

    envelope = AuthorizationEnvelope(
        envelope_id="closed-loop-resolver-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized resolver test",
        disclosure_attestation=True,
        allowed_workflows=[CONTROLLED_WORKFLOW, CONTROLLED_SEQUENCE_WORKFLOW],
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=3,
            max_requests_per_endpoint=3,
            max_creates=1,
            allow_real_user_data_access=False,
        ),
        ownership_registry=OwnershipRegistry(),
    )
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    executor = PolicyExecutor(forbidden_transport, policy, provenance=provenance)
    return (
        OwnedExperimentShadowContext(
            authorization=envelope,
            actor_persona_id="alice",
            executor=executor,
        ),
        calls,
    )


def _shadow(*, peer=True):
    context, calls = _context()
    result = BehavioralShadowOrchestrator().run(
        _source_records(),
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=_peer_records() if peer else (),
        peer_world_id="bob",
        experiment_context=context,
    )
    return result, calls


def test_plan_defers_preparatory_setup_and_selects_next_outcome_bearing_obligation():
    shadow, calls = _shadow()
    assert shadow.ranked_frontier[0].resolution_kind == "owned_experiment"

    resolver = SingleStepObligationResolver(ClosedLoopResolverConfig(enabled=False))
    first = resolver.plan(shadow)
    second = resolver.plan(shadow)

    assert first.to_dict() == second.to_dict()
    assert first.selected is not None
    assert first.selected.frontier_index == 1
    assert first.selected.obligation_id == shadow.ranked_frontier[1].obligation_id
    assert first.selected.proposal_id == shadow.ranked_frontier[1].resolution_ref
    assert first.diagnostics.actionable_items == 2
    assert first.diagnostics.outcome_bearing_items == 1
    assert first.diagnostics.deferred_preparatory_items == 1
    assert calls == []
    encoded = json.dumps(first.to_dict(), sort_keys=True)
    for raw in (ORIGIN, NOTE_ID, SOURCE_DOCUMENT_ID, PEER_DOCUMENT_ID, "alice", "bob"):
        assert raw not in encoded


def test_enabled_resolver_with_only_preparatory_work_sends_no_traffic():
    shadow, calls = _shadow(peer=False)
    resolver = SingleStepObligationResolver(ClosedLoopResolverConfig(enabled=True))

    result = asyncio.run(
        resolver.run(shadow, _source_records(), (), controlled_executor=None)
    )

    assert result.status == "no_executable_candidate"
    assert result.plan.selected is None
    assert result.plan.diagnostics.deferred_preparatory_items == 1
    assert result.execution is None
    assert calls == []


def test_disabled_resolver_plans_exact_proposal_without_requiring_executor():
    shadow, calls = _shadow()
    resolver = SingleStepObligationResolver(ClosedLoopResolverConfig(enabled=False))

    result = asyncio.run(
        resolver.run(
            shadow,
            _source_records(),
            _peer_records(),
            controlled_executor=None,
        )
    )

    assert result.status == "disabled"
    assert result.plan.selected is not None
    assert result.execution is None
    assert calls == []


def test_unbound_frontier_reference_fails_closed():
    shadow, _calls = _shadow()
    assert shadow.proposals is not None
    object.__setattr__(shadow.proposals, "proposals", ())

    with pytest.raises(ClosedLoopResolverDenied, match="resolution_ref_is_unbound"):
        SingleStepObligationResolver().plan(shadow)


def test_rank_bound_cannot_be_misreported_as_no_outcome_bearing_candidate():
    context, calls = _context()
    shadow = BehavioralShadowOrchestrator(
        config=ShadowOrchestratorConfig(max_ranked_obligations=1)
    ).run(
        _source_records(),
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=_peer_records(),
        peer_world_id="bob",
        experiment_context=context,
    )
    assert shadow.ranked_dropped > 0
    assert shadow.ranked_frontier[0].resolution_kind == "owned_experiment"

    with pytest.raises(ClosedLoopResolverDenied, match="blocked_by_rank_bound"):
        SingleStepObligationResolver().plan(shadow)

    assert calls == []


def test_resolver_stays_explicit_only_and_has_no_direct_transport_dependency():
    tree = ast.parse(Path(resolver_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not hasattr(behavior_package, "SingleStepObligationResolver")
