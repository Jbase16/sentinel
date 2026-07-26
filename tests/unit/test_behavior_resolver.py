"""Single-step obligation resolver tests; the frontier owns selection."""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

import core.behavior as behavior_package
import core.behavior.resolver as resolver_module
from core.behavior.active import CONTROLLED_WORKFLOW
from core.behavior.orchestrator import (
    BehavioralShadowOrchestrator,
    OwnedExperimentShadowContext,
    ShadowOrchestratorConfig,
)
from core.behavior.omission_confirmation import (
    FRESH_OMISSION_CONFIRMATION_WORKFLOW,
    FreshOmissionConfirmationAdmission,
    FreshOmissionConfirmationAdmissionResult,
    FreshOmissionConfirmationConfig,
    FreshOmissionConfirmationExecutor,
)
from core.behavior.omission_boundary import FRESH_OMISSION_WORKFLOW
from core.behavior.receipts import BehavioralReceiptStore
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
CAPTURED_WORKFLOW_ID = "workflow_7fa9f13a2b4c5d6e"
CAPTURED_TOKEN = "token_4a5b6c7d8e9f0123"
BASELINE_WORKFLOW_ID = "workflow_fresh_baseline_8b9c0d1e2f3a"
OMISSION_WORKFLOW_ID = "workflow_fresh_omission_5b6c7d8e9f0a"
CONTROL_WORKFLOW_ID = "workflow_fresh_control_2c3d4e5f6a7b"
BASELINE_TOKEN = "token_fresh_baseline_12345678"
REFERENCE_BODY = {"status": "ready", "artifact": "controlled"}


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


def _omission_records():
    return (
        {
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows",
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "request_body": '{"label":"controlled"}',
            "response_status": 201,
            "response_body": json.dumps({"workflowId": CAPTURED_WORKFLOW_ID}),
        },
        {
            "persona_id": "alice",
            "method": "GET",
            "url": (f"{ORIGIN}/api/workflows/{CAPTURED_WORKFLOW_ID}/export-token"),
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "response_status": 200,
            "response_body": json.dumps({"exportToken": CAPTURED_TOKEN}),
        },
        {
            "persona_id": "alice",
            "method": "GET",
            "url": (
                f"{ORIGIN}/api/workflows/{CAPTURED_WORKFLOW_ID}/export"
                f"?format=json&exportToken={CAPTURED_TOKEN}"
            ),
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "response_status": 200,
            "response_body": json.dumps(REFERENCE_BODY),
        },
        {
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/workflows/{CAPTURED_WORKFLOW_ID}",
            "request_headers": {"x-csrf-token": "csrf-alice"},
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        },
    )


def _omission_shadow():
    return BehavioralShadowOrchestrator().run(
        _omission_records(),
        target_origin=ORIGIN,
        world_id="alice",
    )


def _confirmation_admission(shadow, tmp_path, *, enabled=True):
    calls = []
    creates = iter(
        (
            BASELINE_WORKFLOW_ID,
            OMISSION_WORKFLOW_ID,
            CONTROL_WORKFLOW_ID,
        )
    )

    async def raw(method, url, body=None, **kwargs):
        calls.append((method, url, body, kwargs))
        path = urlsplit(url).path
        if method == "POST":
            return 201, {"workflowId": next(creates)}
        if method == "PATCH":
            return 200, {"archived": True}
        if path.endswith("/export-token"):
            return 200, {"exportToken": BASELINE_TOKEN}
        if CONTROL_WORKFLOW_ID in url:
            return 403, {"error": "wrong workflow"}
        return 200, dict(REFERENCE_BODY)

    envelope = AuthorizationEnvelope(
        envelope_id="resolver-omission-confirmation-envelope",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="authorized resolver omission test",
        disclosure_attestation=True,
        allowed_workflows=[
            CONTROLLED_SEQUENCE_WORKFLOW,
            FRESH_OMISSION_WORKFLOW,
            FRESH_OMISSION_CONFIRMATION_WORKFLOW,
        ],
        created_at=1_780_000_000.0,
        expires_at=1_900_000_000.0,
    )
    envelope.sign()
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=10,
            max_requests_per_endpoint=3,
            max_cross_object_reads=0,
            max_privilege_mutations=0,
            max_creates=3,
            allow_delete=False,
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
    experiment = shadow.omissions.experiments[0]
    boundary = FreshOmissionConfirmationExecutor(
        _omission_records(),
        world_id="alice",
        target_origin=ORIGIN,
        authorization=envelope,
        actor_persona_id="alice",
        executor=PolicyExecutor(raw, policy, provenance=provenance),
        experiment=experiment,
        config=FreshOmissionConfirmationConfig(enabled=enabled),
    )
    return (
        FreshOmissionConfirmationAdmission(
            boundary,
            receipt_store=BehavioralReceiptStore(tmp_path),
        ),
        calls,
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


def test_omission_confirmation_is_deferred_without_exact_admission():
    shadow = _omission_shadow()
    ranked = next(
        item
        for item in shadow.ranked_frontier
        if item.resolution_kind == "omission_experiment"
    )
    assert ranked.actionable is True

    plan = SingleStepObligationResolver().plan(shadow)

    assert plan.selected is None
    assert plan.diagnostics.actionable_items == 1
    assert plan.diagnostics.outcome_bearing_items == 0
    assert plan.diagnostics.deferred_preparatory_items == 1
    assert plan.dispatchable_resolution_refs == ()


@pytest.mark.asyncio
async def test_disabled_resolver_selects_bound_omission_without_traffic(
    tmp_path,
):
    shadow = _omission_shadow()
    admission, calls = _confirmation_admission(shadow, tmp_path)
    resolver = SingleStepObligationResolver(ClosedLoopResolverConfig(enabled=False))

    result = await resolver.run(
        shadow,
        _omission_records(),
        (),
        omission_confirmation_admission=admission,
    )

    assert result.status == "disabled"
    assert result.execution is None
    assert result.plan.selected is not None
    assert result.plan.selected.resolution_kind == "omission_experiment"
    assert result.plan.selected.resolution_ref == (
        shadow.omissions.experiments[0].experiment_id
    )
    assert result.plan.selected.confirmation_id is not None
    assert result.plan.selected.admission_fingerprint is not None
    assert result.plan.dispatchable_resolution_refs == (
        shadow.omissions.experiments[0].experiment_id,
    )
    assert calls == []


@pytest.mark.asyncio
async def test_enabled_resolver_dispatches_omission_through_durable_admission(
    tmp_path,
):
    shadow = _omission_shadow()
    admission, calls = _confirmation_admission(shadow, tmp_path)
    resolver = SingleStepObligationResolver(ClosedLoopResolverConfig(enabled=True))

    result = await resolver.run(
        shadow,
        _omission_records(),
        (),
        omission_confirmation_admission=admission,
    )

    assert result.status == "completed"
    assert result.plan.selected is not None
    assert result.plan.selected.resolution_kind == "omission_experiment"
    assert isinstance(
        result.execution,
        FreshOmissionConfirmationAdmissionResult,
    )
    assert result.execution is not None
    assert result.execution.execution["kind"] == ("fresh_omission_confirmation")
    assert result.execution.execution["confirmation_status"] == ("confirmed_fail_open")
    assert result.execution.execution["finding_authority"] is True
    assert len(calls) == 10

    duplicate_admission, duplicate_calls = _confirmation_admission(
        shadow,
        tmp_path,
    )
    duplicate = await resolver.run(
        shadow,
        _omission_records(),
        (),
        omission_confirmation_admission=duplicate_admission,
    )

    assert duplicate.status == "already_executed"
    assert duplicate.execution is not None
    assert duplicate.execution.reused is True
    assert duplicate_calls == []


def test_invalid_omission_admission_fails_before_traffic(tmp_path):
    shadow = _omission_shadow()
    admission, calls = _confirmation_admission(
        shadow,
        tmp_path,
        enabled=False,
    )

    with pytest.raises(
        ClosedLoopResolverDenied,
        match="omission_confirmation_preflight_denied",
    ):
        SingleStepObligationResolver().plan(
            shadow,
            omission_confirmation_admission=admission,
        )

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
