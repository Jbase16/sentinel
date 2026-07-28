"""Receipt-chained second interaction transition tests."""

from __future__ import annotations

import json

import pytest

from core.behavior.interaction_admission import InteractionIntentSelector
from core.behavior.interaction_boundary import (
    INTERACTION_ACQUISITION_WORKFLOW,
)
from core.behavior.interaction_render import (
    INTERACTION_RENDER_WORKFLOW,
    InteractionRenderConfig,
    InteractionRenderObservationBoundary,
)
from core.behavior.interaction_second_transition import (
    INTERACTION_SECOND_TRANSITION_WORKFLOW,
    InteractionSecondReadAdmission,
    InteractionSecondReadBoundary,
    InteractionSecondTransitionConfig,
    InteractionSecondTransitionDenied,
)
from core.behavior.interaction_state import (
    BrowserStateLimits,
    build_acquisition_transition,
    build_chained_acquisition_transition,
)
from core.behavior.interactions import InteractionIntentMiner
from core.behavior.normalize import normalize_exchange, stable_hash
from core.behavior.receipts import (
    BehavioralReceiptStore,
    ReceiptStoreError,
    _redacted_interaction_acquisition_summary,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.action_classifier import SAFE_READ
from core.safety.proof_budget import ProofBudget, endpoint_key
from core.safety.provenance import ProvenanceSink, body_hash, response_shape

ORIGIN = "https://example.test"
ALICE = "a" * 32
BOB = "b" * 32
FIRST_URL = f"{ORIGIN}/first"
SECOND_URL = f"{ORIGIN}/second"
FIRST_BODY = '<html><body><a href="/second">Second</a></body></html>'


def _control(index: int = 1):
    return {
        "tag": "a",
        "role": "link",
        "input_type": "",
        "form_method": "none",
        "destination": "same_origin",
        "locator": [
            {"tag": "html", "sibling_index": 1},
            {"tag": "body", "sibling_index": 1},
            {"tag": "a", "sibling_index": index},
        ],
        "locator_truncated": False,
        "visible": True,
        "disabled": False,
        "content_editable": False,
        "aria_expanded": False,
        "aria_haspopup": False,
        "sensitive_form": False,
        "download": False,
        "scripted_handler": False,
        "submitter": False,
    }


def _frontier(index: int):
    return [{
        "obligation_id": stable_hash("security_obligation", {"index": index}),
        "kind": "ownership_boundary",
        "risk_class": "read",
        "score": 500,
        "actionable": False,
        "resolution_kind": "unavailable",
        "resolution_ref": None,
        "signals": ["unresolved_frontier"],
    }]


def _envelope(*, second_workflow: bool = True):
    workflows = [
        INTERACTION_ACQUISITION_WORKFLOW,
        INTERACTION_RENDER_WORKFLOW,
    ]
    if second_workflow:
        workflows.append(INTERACTION_SECOND_TRANSITION_WORKFLOW)
    envelope = AuthorizationEnvelope(
        envelope_id="c" * 32,
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="public bounty authorization",
        disclosure_attestation=True,
        allowed_workflows=workflows,
    )
    envelope.sign()
    return envelope


def _policy():
    return ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=7,
            max_requests_per_endpoint=5,
            max_cross_object_reads=1,
            max_privilege_mutations=0,
            max_creates=2,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
    )


def _select(
    controls,
    *,
    page_url: str,
    frontier,
    policy: ExecutionPolicy,
):
    catalog = InteractionIntentMiner().mine(
        controls,
        target_origin=ORIGIN,
        world_id=ALICE,
        page_url=page_url,
    )
    selected = InteractionIntentSelector().select(
        catalog,
        frontier,
        world_id=ALICE,
        policy_digest=policy.digest(),
        budget_snapshot=policy.budget.snapshot(),
        max_total_requests=policy.budget.max_total_requests,
    )
    assert selected.admission is not None
    return catalog, selected.admission


def _acquisition(admission, record):
    request_ref = stable_hash(
        "interaction_acquisition_request",
        {
            "method": "GET",
            "url": record["url"],
            "redirect_mode": "manual",
        },
    )
    response_ref = stable_hash(
        "interaction_acquisition_response",
        {
            "request_ref": request_ref,
            "status": record["response_status"],
            "body_hash": body_hash(record["response_body"]),
            "shape": response_shape(record["response_body"]),
            "truncated": False,
        },
    )
    normalized = normalize_exchange(record, world_id=ALICE)
    return {
        "kind": "interaction_read_acquisition",
        "mode": "behavioral_interaction_read_acquisition_v1",
        "status": "completed",
        "acquisition_id": stable_hash(
            "interaction_read_acquisition",
            {
                "admission_id": admission.admission_id,
                "response_ref": response_ref,
            },
        ),
        "admission_id": admission.admission_id,
        "obligation_id": admission.obligation_id,
        "destination_page_ref": stable_hash(
            "interaction_page",
            {
                "origin": ORIGIN,
                "path_template": normalized.path_template,
            },
        ),
        "operation_ref": normalized.action_id,
        "request_ref": request_ref,
        "response_ref": response_ref,
        "response_status": record["response_status"],
        "response_truncated": False,
        "requests_attempted": 1,
        "requests_sent": 1,
        "policy_denials": 0,
        "provenance_root": "1" * 64,
        "budget_snapshot": {
            "total_requests": 1,
            "cross_object_reads": 0,
            "privilege_mutations": 0,
            "creates": 0,
            "endpoints_touched": 1,
        },
    }


async def _context(
    raw_send,
    *,
    destinations=None,
    second_workflow: bool = True,
):
    policy = _policy()
    first_frontier = _frontier(1)
    _initial_catalog, first_admission = _select(
        [_control()],
        page_url=f"{ORIGIN}/app",
        frontier=first_frontier,
        policy=policy,
    )
    first_record = {
        "persona_id": ALICE,
        "url": FIRST_URL,
        "method": "GET",
        "response_status": 200,
        "response_body": FIRST_BODY,
        "response_truncated": False,
    }
    first_acquisition = _acquisition(first_admission, first_record)
    envelope = _envelope(second_workflow=second_workflow)

    async def observe(_persona_id, *, base_url, html):
        return {
            "base_url": base_url,
            "controls": [_control()],
            "scanned_nodes": 1,
            "controls_truncated": False,
            "bytes_inspected": len(html.encode()),
            "target_requests_sent": 0,
        }

    source_boundary = InteractionRenderObservationBoundary(
        admission=first_admission,
        acquisition=first_acquisition,
        acquisition_receipt_id="behavioral-" + ("f" * 64),
        record=first_record,
        target_origin=ORIGIN,
        authorization=envelope,
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        observer=observe,
        config=InteractionRenderConfig(enabled=True),
    )
    observation = await source_boundary.execute()
    policy.budget.record(SAFE_READ, endpoint_key(FIRST_URL), 200)
    next_frontier = _frontier(2)
    _next_catalog, next_admission = _select(
        observation.controls,
        page_url=FIRST_URL,
        frontier=next_frontier,
        policy=policy,
    )
    parent = build_acquisition_transition(
        target_origin=ORIGIN,
        world_id=ALICE,
        before_records=[{"url": f"{ORIGIN}/app", "method": "GET"}],
        admission=first_admission,
        acquisition=first_acquisition,
        receipt_id=source_boundary.acquisition_receipt_id,
        policy_digest=policy.digest(),
        max_total_requests=policy.budget.max_total_requests,
        before_frontier=first_frontier,
        after_frontier=next_frontier,
        next_admission=next_admission,
        after_control_surface="observed",
        after_catalog_id=observation.catalog_id,
    )
    destination_values = iter(destinations or [SECOND_URL] * 10)
    resolver_calls = []

    async def resolver(persona_id, locator, *, base_url, html):
        resolver_calls.append((persona_id, locator, base_url, html))
        return {
            "current_url": base_url,
            "destination_url": next(destination_values),
            "control": _control(),
            "catalog_controls": observation.controls,
            "peer_catalog_controls": (),
        }

    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=policy.digest(),
    )
    boundary = InteractionSecondReadBoundary(
        admission=next_admission,
        parent_transition=parent,
        source_boundary=source_boundary,
        observation=observation,
        target_origin=ORIGIN,
        authorization=envelope,
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(raw_send, policy, provenance=provenance),
        resolver=resolver,
        config=InteractionSecondTransitionConfig(enabled=True),
    )
    return boundary, resolver_calls, parent, next_frontier


@pytest.mark.asyncio
async def test_second_transition_resolves_twice_sends_one_get_and_seals_child(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append((method, url, body, kwargs))
        return 200, '<a href="/third">Third</a>'

    boundary, resolver_calls, parent, frontier = await _context(raw_send)
    result = await InteractionSecondReadAdmission(
        boundary,
        receipt_store=BehavioralReceiptStore(tmp_path),
    ).execute()

    assert result.status == "completed"
    assert result.reused is False
    assert result.receipt_id != parent.transition.receipt_id
    assert len(resolver_calls) == 2
    assert [(method, url, body) for method, url, body, _ in sent] == [
        ("GET", SECOND_URL, None)
    ]
    assert sent[0][3]["_redirect_mode"] == "manual"
    assert result.record is not None
    chained = build_chained_acquisition_transition(
        parent=parent,
        world_id=ALICE,
        admission=boundary.admission,
        acquisition=result.execution,
        receipt_id=result.receipt_id,
        policy_digest=boundary.executor.policy.digest(),
        max_total_requests=boundary.executor.policy.budget.max_total_requests,
        before_frontier=frontier,
        after_frontier=frontier,
        after_control_surface="unobserved",
        after_catalog_id=None,
        limits=BrowserStateLimits(max_transitions=2),
    )
    assert chained.transition.depth == 2
    assert chained.transition.decision == "stop"
    assert "transition_limit" in chained.transition.stop_reasons
    stored = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert stored["outcome"]["kind"] == "interaction_read_acquisition"
    assert FIRST_BODY not in json.dumps(stored)

    second_summary = result.to_dict()
    second_summary.update(
        {
            "schema_version": 1,
            "mode": "behavioral_interaction_second_read_transition_v1",
            "parent_receipt_id": parent.transition.receipt_id,
            "parent_transition_id": parent.transition.transition_id,
            "parent_after_state_id": parent.after_state.state_id,
            "observation_id": boundary.observation.observation_id,
            "target_requests_sent": 1,
            "render_observation": {
                "schema_version": 1,
                "mode": "behavioral_interaction_render_observation_v1",
                "status": "unavailable",
                "reason_code": (
                    "acquisition_response_not_available_for_observation"
                ),
                "target_requests_sent": 0,
                "executable": False,
            },
            "state_transition": {
                "status": "completed",
                "result": chained.to_dict(),
            },
            "executable": False,
        }
    )
    root_summary = {
        "schema_version": 1,
        "mode": "behavioral_interaction_read_acquisition_v1",
        "status": "completed",
        "receipt": {
            "receipt_id": parent.transition.receipt_id,
            "state": "completed",
            "reused": False,
        },
        "execution": boundary.source_boundary.acquisition,
        "target_requests_sent": 1,
        "render_observation": boundary.observation.to_dict(),
        "state_transition": {
            "status": "completed",
            "result": parent.to_dict(),
        },
        "second_transition": second_summary,
    }
    redacted = _redacted_interaction_acquisition_summary(root_summary)
    assert redacted["second_transition"]["parent_transition_id"] == (
        parent.transition.transition_id
    )
    second_summary["parent_transition_id"] = stable_hash(
        "browser_state_transition",
        {"tampered": True},
    )
    with pytest.raises(ReceiptStoreError):
        _redacted_interaction_acquisition_summary(root_summary)


@pytest.mark.asyncio
async def test_changed_resolution_aborts_child_receipt_before_target_send(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append(url)
        return 200, "unexpected"

    boundary, resolver_calls, _parent, _frontier = await _context(
        raw_send,
        destinations=[SECOND_URL, f"{ORIGIN}/changed"],
    )
    with pytest.raises(
        InteractionSecondTransitionDenied,
        match="resolution_changed_before_send",
    ):
        await InteractionSecondReadAdmission(
            boundary,
            receipt_store=BehavioralReceiptStore(tmp_path),
        ).execute()

    assert len(resolver_calls) == 2
    assert sent == []
    stored = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert stored["state"] == "aborted"
    assert stored["abort_reason"] == "interaction_second_transition_error"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("enabled", "second_workflow", "reason"),
    [
        (False, True, "is_disabled"),
        (True, False, "authorization_denied"),
    ],
)
async def test_disabled_or_unauthorized_second_transition_is_zero_traffic(
    enabled,
    second_workflow,
    reason,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append(url)
        return 200, "unexpected"

    boundary, resolver_calls, _parent, _frontier = await _context(
        raw_send,
        second_workflow=second_workflow,
    )
    boundary.config = InteractionSecondTransitionConfig(enabled=enabled)
    with pytest.raises(InteractionSecondTransitionDenied, match=reason):
        await boundary.validate_preflight()

    assert resolver_calls == []
    assert sent == []
