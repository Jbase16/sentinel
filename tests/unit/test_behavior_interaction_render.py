"""Receipt-bound inert interaction-response observation tests."""

from __future__ import annotations

import copy

import pytest

from core.behavior.interaction_admission import (
    InteractionAdmissionPolicy,
    InteractionIntentSelector,
)
from core.behavior.interaction_render import (
    INTERACTION_RENDER_WORKFLOW,
    InteractionRenderConfig,
    InteractionRenderDenied,
    InteractionRenderObservationBoundary,
)
from core.behavior.interaction_state import build_acquisition_transition
from core.behavior.interactions import InteractionIntentMiner
from core.behavior.normalize import normalize_exchange, stable_hash
from core.behavior.receipts import (
    ReceiptStoreError,
    _redacted_interaction_acquisition_summary,
    _redacted_interaction_render_summary,
)
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.provenance import body_hash, response_shape

ORIGIN = "https://example.test"
ALICE = "a" * 32
BOB = "b" * 32
DESTINATION = f"{ORIGIN}/details/123?view=full"
BODY = '<html><body><a href="/next">Next</a></body></html>'


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


def _frontier():
    return [{
        "obligation_id": stable_hash("security_obligation", {"index": 1}),
        "kind": "ownership_boundary",
        "risk_class": "read",
        "score": 500,
        "actionable": False,
        "resolution_kind": "unavailable",
        "resolution_ref": None,
        "signals": ["unresolved_frontier"],
    }]


def _admission():
    catalog = InteractionIntentMiner().mine(
        [_control()],
        target_origin=ORIGIN,
        world_id=ALICE,
        page_url=f"{ORIGIN}/app",
    )
    policy = InteractionAdmissionPolicy.create(
        policy_digest="sha256:" + ("1" * 64),
        budget_snapshot={
            "total_requests": 0,
            "cross_object_reads": 0,
            "privilege_mutations": 0,
            "creates": 0,
            "endpoints_touched": 0,
        },
        max_total_requests=7,
        world_id=ALICE,
    )
    result = InteractionIntentSelector().select(
        catalog,
        _frontier(),
        world_id=ALICE,
        policy_digest="sha256:" + ("1" * 64),
        budget_snapshot={
            "total_requests": 0,
            "cross_object_reads": 0,
            "privilege_mutations": 0,
            "creates": 0,
            "endpoints_touched": 0,
        },
        max_total_requests=7,
    )
    assert result.admission is not None
    assert result.admission.policy_ref == policy.policy_ref
    return result.admission


def _envelope(*, signed: bool = True):
    envelope = AuthorizationEnvelope(
        envelope_id="c" * 32,
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="public bounty authorization",
        disclosure_attestation=True,
        allowed_workflows=[INTERACTION_RENDER_WORKFLOW],
    )
    if signed:
        envelope.sign()
    return envelope


def _record(*, body: str = BODY):
    return {
        "persona_id": ALICE,
        "url": DESTINATION,
        "method": "GET",
        "response_status": 200,
        "response_body": body,
        "response_truncated": False,
    }


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
        "status": "completed",
        "acquisition_id": stable_hash(
            "interaction_read_acquisition",
            {"admission_id": admission.admission_id},
        ),
        "admission_id": admission.admission_id,
        "obligation_id": admission.obligation_id,
        "request_ref": request_ref,
        "response_ref": response_ref,
        "response_status": 200,
        "response_truncated": False,
        "destination_page_ref": stable_hash(
            "interaction_page",
            {
                "origin": ORIGIN,
                "path_template": normalized.path_template,
            },
        ),
        "operation_ref": normalized.action_id,
    }


def _boundary(observer, *, enabled: bool = True, signed: bool = True):
    admission = _admission()
    record = _record()
    return InteractionRenderObservationBoundary(
        admission=admission,
        acquisition=_acquisition(admission, record),
        acquisition_receipt_id="behavioral-" + ("f" * 64),
        record=record,
        target_origin=ORIGIN,
        authorization=_envelope(signed=signed),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        observer=observer,
        config=InteractionRenderConfig(enabled=enabled),
    )


@pytest.mark.asyncio
async def test_exact_acquired_response_becomes_redacted_zero_traffic_catalog():
    calls = []

    async def observer(persona_id, *, base_url, html):
        calls.append((persona_id, base_url, html))
        return {
            "base_url": base_url,
            "controls": [_control(2)],
            "scanned_nodes": 1,
            "controls_truncated": False,
            "bytes_inspected": len(html.encode()),
            "target_requests_sent": 0,
        }

    observation = await _boundary(observer).execute()

    assert calls == [(ALICE, DESTINATION, BODY)]
    assert observation.complete is True
    assert observation.target_requests_sent == 0
    assert observation.controls_observed == 1
    assert observation.catalog.catalog_id == observation.catalog_id
    serialized = observation.to_dict()
    assert "controls" not in serialized
    assert BODY not in repr(serialized)
    assert _redacted_interaction_render_summary(serialized) == serialized


@pytest.mark.asyncio
async def test_completed_observation_is_receipt_bound_to_acquisition_and_state():
    async def observer(_persona_id, *, base_url, html):
        return {
            "base_url": base_url,
            "controls": [_control(2)],
            "scanned_nodes": 1,
            "controls_truncated": False,
            "bytes_inspected": len(html.encode()),
            "target_requests_sent": 0,
        }

    boundary = _boundary(observer)
    observation = await boundary.execute()
    execution = dict(boundary.acquisition)
    execution.update(
        {
            "kind": "interaction_read_acquisition",
            "mode": "behavioral_interaction_read_acquisition_v1",
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
    )
    transition = build_acquisition_transition(
        target_origin=ORIGIN,
        world_id=ALICE,
        before_records=[{"url": f"{ORIGIN}/app", "method": "GET"}],
        admission=boundary.admission,
        acquisition=execution,
        receipt_id=boundary.acquisition_receipt_id,
        policy_digest="sha256:" + ("1" * 64),
        max_total_requests=7,
        before_frontier=_frontier(),
        after_frontier=_frontier(),
        after_control_surface="observed",
        after_catalog_id=observation.catalog_id,
    )
    summary = {
        "schema_version": 1,
        "mode": "behavioral_interaction_read_acquisition_v1",
        "status": "completed",
        "receipt": {
            "receipt_id": boundary.acquisition_receipt_id,
            "state": "completed",
            "reused": False,
        },
        "execution": execution,
        "target_requests_sent": 1,
        "state_transition": {
            "status": "completed",
            "result": transition.to_dict(),
        },
        "render_observation": observation.to_dict(),
    }

    redacted = _redacted_interaction_acquisition_summary(summary)
    assert redacted["render_observation"] == observation.to_dict()

    tampered = copy.deepcopy(summary)
    tampered["render_observation"]["catalog_id"] = stable_hash(
        "interaction_intent_catalog",
        {"tampered": True},
    )
    with pytest.raises(ReceiptStoreError):
        _redacted_interaction_acquisition_summary(tampered)


@pytest.mark.asyncio
async def test_changed_response_binding_is_denied_before_observer():
    called = False

    async def observer(*_args, **_kwargs):
        nonlocal called
        called = True
        return {}

    boundary = _boundary(observer)
    boundary.record["response_body"] = "changed"

    with pytest.raises(
        InteractionRenderDenied,
        match="response_binding_changed",
    ):
        await boundary.execute()
    assert called is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("enabled", "signed", "reason"),
    [
        (False, True, "is_disabled"),
        (True, False, "authorization_is_unsigned"),
    ],
)
async def test_disabled_or_unsigned_observation_never_reaches_driver(
    enabled,
    signed,
    reason,
):
    called = False

    async def observer(*_args, **_kwargs):
        nonlocal called
        called = True
        return {}

    with pytest.raises(InteractionRenderDenied, match=reason):
        await _boundary(observer, enabled=enabled, signed=signed).execute()
    assert called is False


@pytest.mark.asyncio
async def test_observer_must_prove_zero_target_traffic():
    async def observer(_persona_id, *, base_url, html):
        return {
            "base_url": base_url,
            "controls": [],
            "scanned_nodes": 0,
            "controls_truncated": False,
            "bytes_inspected": len(html.encode()),
            "target_requests_sent": 1,
        }

    with pytest.raises(
        InteractionRenderDenied,
        match="observation_is_invalid",
    ):
        await _boundary(observer).execute()


def test_render_receipt_rejects_private_or_tampered_fields():
    value = {
        "schema_version": 1,
        "mode": "behavioral_interaction_render_observation_v1",
        "status": "denied",
        "error_code": "interaction_render_observer_failed",
        "target_requests_sent": 0,
        "executable": False,
    }
    assert _redacted_interaction_render_summary(value) == value

    tampered = copy.deepcopy(value)
    tampered["response_body"] = BODY
    with pytest.raises(ReceiptStoreError):
        _redacted_interaction_render_summary(tampered)
