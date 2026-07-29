"""Adaptive safe-read to independent-proof handoff tests."""

from __future__ import annotations

import copy
import json

import pytest

from core.behavior.adaptive_proof import (
    AdaptiveProofHandoff,
    AdaptiveProofHandoffDenied,
)
from core.behavior.interaction_adaptive import InteractionAdaptiveDerivation
from core.behavior.feedback import (
    ReceiptDispositionAdapter,
    ReceiptFeedbackDenied,
)
from core.behavior.orchestrator import BehavioralShadowOrchestrator
from core.behavior.receipts import (
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_adaptive_proof_handoff,
    redacted_outcome,
    redacted_receipt_context,
    request_fingerprint,
)
from core.behavior.resolver import (
    ClosedLoopResolverConfig,
    ClosedLoopResolverDenied,
    SingleStepObligationResolver,
)
from tests.unit.test_behavior_interaction_adaptive import _adaptive_context
from tests.unit.test_behavior_interaction_second_transition import (
    SECOND_URL,
)

ORIGIN = "https://api.example.test"
SOURCE_ID = "doc_source_7fa9f13a2b4c"
PEER_ID = "doc_peer_4a5b6c7d8e9f0"


def _shadow_pair():
    orchestrator = BehavioralShadowOrchestrator()
    initial = orchestrator.run(
        (),
        target_origin=ORIGIN,
        world_id="alice",
    )
    source = (
        {
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{SOURCE_ID}",
            "response_status": 200,
            "response_body": json.dumps({"owner": "alice-private"}),
        },
    )
    peer = (
        {
            "persona_id": "bob",
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{PEER_ID}",
            "response_status": 200,
            "response_body": json.dumps({"owner": "bob-private"}),
        },
    )
    final = orchestrator.run(
        source,
        target_origin=ORIGIN,
        world_id="alice",
        peer_records=peer,
        peer_world_id="bob",
    )
    assert not any(item.actionable for item in initial.ranked_frontier)
    assert any(item.actionable for item in final.ranked_frontier)
    return initial, final, source, peer


async def _handoff_context(tmp_path):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append((method, url, body, kwargs))
        return 200, '<a href="/next">Next</a>'

    controller, boundary, _resolver_calls, parent, frontier = (
        await _adaptive_context(
            raw_send,
            tmp_path,
            destinations=[SECOND_URL, SECOND_URL],
        )
    )
    initial, final, source, peer = _shadow_pair()

    async def derive(_record, _observation, _state, _depth):
        return InteractionAdaptiveDerivation(
            after_frontier=tuple(
                item.to_dict() for item in final.ranked_frontier
            ),
            next_admission=None,
            state=final,
        )

    adaptive = await controller.run(
        initial_parent=parent,
        initial_source_boundary=boundary.source_boundary,
        initial_observation=boundary.observation,
        initial_admission=boundary.admission,
        initial_frontier=frontier,
        initial_state=initial,
        derive=derive,
    )
    resolver = SingleStepObligationResolver(
        ClosedLoopResolverConfig(enabled=False)
    )
    plan = resolver.plan(final)
    handoff = AdaptiveProofHandoff.create(
        initial_shadow=initial,
        adaptive=adaptive,
        final_shadow=final,
        plan=plan,
    )
    return handoff, adaptive, initial, final, plan, resolver, source, peer, sent


@pytest.mark.asyncio
async def test_handoff_binds_completed_chain_to_exact_final_proof_plan(
    tmp_path,
):
    (
        handoff,
        adaptive,
        initial,
        final,
        plan,
        _resolver,
        _source,
        _peer,
        sent,
    ) = await _handoff_context(tmp_path)

    serialized = handoff.to_dict()
    assert sent and len(sent) == 1
    assert serialized["target_requests_sent"] == 0
    assert serialized["executable"] is False
    assert serialized["initial_shadow_id"] == initial.run_id
    assert serialized["final_shadow_id"] == final.run_id
    assert serialized["adaptive_final_chain_ref"] == adaptive.chain_ref
    assert serialized["plan_id"] == plan.plan_id
    assert serialized["obligation_id"] == plan.selected.obligation_id
    assert serialized["resolution_ref"] == plan.selected.resolution_ref
    assert handoff.validates_plan(plan)
    assert AdaptiveProofHandoff.from_dict(serialized) == handoff
    assert redacted_adaptive_proof_handoff(serialized) == serialized


@pytest.mark.asyncio
async def test_handoff_tampering_and_preexisting_authority_fail_closed(
    tmp_path,
):
    (
        handoff,
        adaptive,
        _initial,
        final,
        plan,
        _resolver,
        _source,
        _peer,
        _sent,
    ) = await _handoff_context(tmp_path)

    tampered = copy.deepcopy(handoff.to_dict())
    tampered["resolution_ref"] = "authorization_proposal:" + "f" * 64
    with pytest.raises(ReceiptStoreError):
        redacted_adaptive_proof_handoff(tampered)

    with pytest.raises(
        AdaptiveProofHandoffDenied,
        match="already_actionable",
    ):
        AdaptiveProofHandoff.create(
            initial_shadow=final,
            adaptive=adaptive,
            final_shadow=final,
            plan=plan,
        )


@pytest.mark.asyncio
async def test_resolver_rederives_sealed_plan_before_any_execution(
    tmp_path,
):
    (
        _handoff,
        _adaptive,
        _initial,
        final,
        plan,
        resolver,
        source,
        peer,
        _sent,
    ) = await _handoff_context(tmp_path)
    changed = BehavioralShadowOrchestrator().run(
        (),
        target_origin=ORIGIN,
        world_id="alice",
    )

    with pytest.raises(
        ClosedLoopResolverDenied,
        match="sealed_resolver_plan_changed",
    ):
        await resolver.run(
            changed,
            source,
            peer,
            expected_plan=plan,
        )

    unchanged = await resolver.run(
        final,
        source,
        peer,
        expected_plan=plan,
    )
    assert unchanged.status == "disabled"


@pytest.mark.asyncio
async def test_receipt_feedback_requires_and_carries_exact_handoff_binding(
    tmp_path,
):
    (
        handoff,
        _adaptive,
        initial,
        final,
        plan,
        _resolver,
        _source,
        _peer,
        _sent,
    ) = await _handoff_context(tmp_path / "adaptive")
    selected = plan.selected
    assert selected is not None
    response = {
        "status": "completed",
        "plan": {"selected_proposal_id": selected.resolution_ref},
        "execution": {
            "status": "completed",
            "legacy_verdict": "DENIED",
            "finding_confirmed": False,
            "requests_attempted": 3,
            "requests_sent": 3,
            "policy_denials": 0,
        },
        "finding": None,
        "finding_confirmed": False,
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
            "source": {
                "resolved_operations": 0,
                "unresolved_operations": 0,
                "ambiguous_operations": 0,
            },
            "peer": {
                "resolved_operations": 0,
                "unresolved_operations": 0,
                "ambiguous_operations": 0,
            },
        },
        "adaptive_proof_handoff": handoff.to_dict(),
    }
    transplanted = copy.deepcopy(response)
    transplanted["plan"]["selected_proposal_id"] = (
        "authorization_proposal:" + "f" * 64
    )
    with pytest.raises(
        ReceiptStoreError,
        match="selection binding",
    ):
        redacted_outcome(transplanted)

    fingerprint = request_fingerprint(
        {
            "handoff_id": handoff.handoff_id,
            "resolution_ref": selected.resolution_ref,
        }
    )
    context = redacted_receipt_context(
        target_origin=ORIGIN,
        envelope_id="adaptive-proof-envelope",
        source_persona_id="alice",
        peer_persona_id="bob",
    )
    store = BehavioralReceiptStore(tmp_path / "proof")
    reservation = store.reserve(fingerprint, context=context)
    assert reservation.reservation_token is not None
    receipt = store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=redacted_outcome(response),
    )

    batch = ReceiptDispositionAdapter().adapt(
        final.graph,
        (receipt,),
        expected_context=context,
    )

    assert handoff.handoff_id in batch.dispositions[0].evidence_refs
    assert (
        "behavioral_receipt:" + receipt.fingerprint
        in batch.dispositions[0].evidence_refs
    )
    with pytest.raises(
        ReceiptFeedbackDenied,
        match="graph_binding_changed",
    ):
        ReceiptDispositionAdapter().adapt(
            initial.graph,
            (receipt,),
            expected_context=context,
        )
