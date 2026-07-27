"""Bounded browser-state explorer contract tests."""

from __future__ import annotations

import copy

import pytest

from core.behavior.interaction_admission import (
    InteractionAdmissionPolicy,
    InteractionIntentSelector,
)
from core.behavior.interaction_state import (
    BoundedBrowserStateExplorer,
    BrowserState,
    build_acquisition_transition,
    operation_refs_from_records,
)
from core.behavior.interactions import InteractionIntentMiner
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    ReceiptStoreError,
    _redacted_browser_transition_summary,
)

ORIGIN = "https://example.test"
ALICE = "a" * 32


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


def _frontier(obligation_id: str, *, actionable: bool = False):
    return [
        {
            "obligation_id": obligation_id,
            "kind": "ownership_boundary",
            "risk_class": "read",
            "score": 500,
            "actionable": actionable,
            "resolution_kind": (
                "authorization_proposal" if actionable else "unavailable"
            ),
            "resolution_ref": (
                stable_hash("authorization_proposal", {"ready": True})
                if actionable
                else None
            ),
            "signals": ["unresolved_frontier"],
        }
    ]


def _policy(total_requests: int = 0):
    return InteractionAdmissionPolicy.create(
        policy_digest="sha256:" + ("1" * 64),
        budget_snapshot={
            "total_requests": total_requests,
            "cross_object_reads": 0,
            "privilege_mutations": 0,
            "creates": 0,
            "endpoints_touched": min(total_requests, 1),
        },
        max_total_requests=7,
        world_id=ALICE,
    )


def _admission(
    *,
    page_url: str,
    obligation_id: str,
    policy: InteractionAdmissionPolicy,
    control_index: int = 1,
    total_requests: int = 0,
):
    catalog = InteractionIntentMiner().mine(
        [_control(control_index)],
        target_origin=ORIGIN,
        world_id=ALICE,
        page_url=page_url,
    )
    result = InteractionIntentSelector().select(
        catalog,
        _frontier(obligation_id),
        world_id=ALICE,
        policy_digest="sha256:" + ("1" * 64),
        budget_snapshot={
            "total_requests": total_requests,
            "cross_object_reads": 0,
            "privilege_mutations": 0,
            "creates": 0,
            "endpoints_touched": min(total_requests, 1),
        },
        max_total_requests=7,
    )
    assert result.admission is not None
    assert result.admission.policy_ref == policy.policy_ref
    assert result.admission.budget_ref == policy.budget_ref
    return catalog, result.admission


def _acquisition(admission, *, page_ref: str, operation_ref: str):
    return {
        "acquisition_id": stable_hash(
            "interaction_read_acquisition",
            {"admission_id": admission.admission_id},
        ),
        "admission_id": admission.admission_id,
        "obligation_id": admission.obligation_id,
        "destination_page_ref": page_ref,
        "operation_ref": operation_ref,
        "request_ref": stable_hash(
            "interaction_acquisition_request",
            {"admission_id": admission.admission_id},
        ),
        "response_ref": stable_hash(
            "interaction_acquisition_response",
            {"admission_id": admission.admission_id},
        ),
        "budget_snapshot": {
            "total_requests": 1,
            "cross_object_reads": 0,
            "privilege_mutations": 0,
            "creates": 0,
            "endpoints_touched": 1,
        },
    }


def test_operation_coverage_is_redacted_deduplicated_and_route_templated():
    refs = operation_refs_from_records(
        [
            {"url": f"{ORIGIN}/documents/12345", "method": "GET"},
            {"url": f"{ORIGIN}/documents/67890", "method": "GET"},
            {"url": "https://outside.test/private", "method": "GET"},
        ],
        target_origin=ORIGIN,
        world_id=ALICE,
    )

    assert len(refs) == 1
    assert refs[0].startswith("action:")
    assert "12345" not in refs[0]
    assert "67890" not in refs[0]


def test_unrendered_destination_records_progress_but_cannot_continue():
    obligation_id = stable_hash("security_obligation", {"index": 1})
    before_policy = _policy(0)
    catalog, admission = _admission(
        page_url=f"{ORIGIN}/app",
        obligation_id=obligation_id,
        policy=before_policy,
    )
    existing_operation = stable_hash("action", {"route": "/app"})
    acquired_operation = stable_hash("action", {"route": "/details"})
    before = BrowserState.create(
        target_ref=admission.target_ref,
        world_ref=admission.world_ref,
        page_ref=admission.page_ref,
        control_surface="observed",
        interaction_catalog_id=catalog.catalog_id,
        operation_refs=(existing_operation,),
        policy_ref=before_policy.policy_ref,
        budget_ref=before_policy.budget_ref,
        depth=0,
    )
    destination_page_ref = stable_hash(
        "interaction_page",
        {"origin": ORIGIN, "path_template": "/details"},
    )
    after_policy = _policy(1)
    after = BrowserState.create(
        target_ref=admission.target_ref,
        world_ref=admission.world_ref,
        page_ref=destination_page_ref,
        control_surface="unobserved",
        interaction_catalog_id=None,
        operation_refs=(acquired_operation, existing_operation),
        policy_ref=after_policy.policy_ref,
        budget_ref=after_policy.budget_ref,
        depth=1,
    )

    result = BoundedBrowserStateExplorer().observe_transition(
        before_state=before,
        after_state=after,
        admission=admission,
        acquisition=_acquisition(
            admission,
            page_ref=destination_page_ref,
            operation_ref=acquired_operation,
        ),
        receipt_id="behavioral-" + ("f" * 64),
        before_frontier=_frontier(obligation_id),
        after_frontier=_frontier(obligation_id),
    )

    assert result.transition.new_operation_refs == (acquired_operation,)
    assert result.transition.decision == "stop"
    assert result.transition.stop_reasons == ("control_surface_unobserved",)
    assert "new_operation" in result.transition.signals
    serialized = result.to_dict()
    assert serialized["executable"] is False
    assert serialized["transition"]["receipt_id"].startswith("behavioral-")
    assert (
        _redacted_browser_transition_summary(
            {"status": "completed", "result": serialized}
        )["result"]
        == serialized
    )
    tampered = copy.deepcopy(serialized)
    tampered["transition"]["response_ref"] = stable_hash(
        "interaction_acquisition_response",
        {"tampered": True},
    )
    with pytest.raises(ReceiptStoreError):
        _redacted_browser_transition_summary(
            {"status": "completed", "result": tampered}
        )
    unavailable = {
        "schema_version": 1,
        "mode": "behavioral_browser_state_explorer_v1",
        "status": "unavailable",
        "reason_code": "legacy_acquisition_receipt_missing_state_refs",
        "executable": False,
    }
    assert _redacted_browser_transition_summary(unavailable) == unavailable


def test_observed_novel_state_can_present_only_its_state_bound_next_admission():
    first_obligation = stable_hash("security_obligation", {"index": 1})
    next_obligation = stable_hash("security_obligation", {"index": 2})
    before_policy = _policy(0)
    before_catalog, admission = _admission(
        page_url=f"{ORIGIN}/app",
        obligation_id=first_obligation,
        policy=before_policy,
    )
    after_policy = _policy(1)
    after_catalog, next_admission = _admission(
        page_url=f"{ORIGIN}/details",
        obligation_id=next_obligation,
        policy=after_policy,
        control_index=2,
        total_requests=1,
    )
    existing_operation = stable_hash("action", {"route": "/app"})
    acquired_operation = stable_hash("action", {"route": "/details"})
    before = BrowserState.create(
        target_ref=admission.target_ref,
        world_ref=admission.world_ref,
        page_ref=admission.page_ref,
        control_surface="observed",
        interaction_catalog_id=before_catalog.catalog_id,
        operation_refs=(existing_operation,),
        policy_ref=before_policy.policy_ref,
        budget_ref=before_policy.budget_ref,
        depth=0,
    )
    after = BrowserState.create(
        target_ref=next_admission.target_ref,
        world_ref=next_admission.world_ref,
        page_ref=next_admission.page_ref,
        control_surface="observed",
        interaction_catalog_id=after_catalog.catalog_id,
        operation_refs=(acquired_operation, existing_operation),
        policy_ref=after_policy.policy_ref,
        budget_ref=after_policy.budget_ref,
        depth=1,
    )

    result = BoundedBrowserStateExplorer().observe_transition(
        before_state=before,
        after_state=after,
        admission=admission,
        acquisition=_acquisition(
            admission,
            page_ref=after.page_ref,
            operation_ref=acquired_operation,
        ),
        receipt_id="behavioral-" + ("e" * 64),
        before_frontier=_frontier(first_obligation),
        after_frontier=_frontier(next_obligation),
        next_admission=next_admission,
    )

    assert result.transition.decision == "eligible_for_next_transition"
    assert result.transition.stop_reasons == ()
    assert result.transition.next_admission_id == next_admission.admission_id
    assert result.transition.next_intent_id == next_admission.intent_id


def test_one_click_builder_uses_only_pre_acquisition_records_for_before_state():
    obligation_id = stable_hash("security_obligation", {"index": 1})
    policy = _policy(0)
    _catalog, admission = _admission(
        page_url=f"{ORIGIN}/app",
        obligation_id=obligation_id,
        policy=policy,
    )
    acquired_operation = operation_refs_from_records(
        [{"url": f"{ORIGIN}/details/12345", "method": "GET"}],
        target_origin=ORIGIN,
        world_id=ALICE,
    )[0]
    destination_page_ref = stable_hash(
        "interaction_page",
        {"origin": ORIGIN, "path_template": "/details/{id}"},
    )
    acquisition = _acquisition(
        admission,
        page_ref=destination_page_ref,
        operation_ref=acquired_operation,
    )

    result = build_acquisition_transition(
        target_origin=ORIGIN,
        world_id=ALICE,
        before_records=[{"url": f"{ORIGIN}/app", "method": "GET"}],
        admission=admission,
        acquisition=acquisition,
        receipt_id="behavioral-" + ("c" * 64),
        policy_digest="sha256:" + ("1" * 64),
        max_total_requests=7,
        before_frontier=_frontier(obligation_id),
        after_frontier=_frontier(obligation_id),
    )

    assert acquired_operation not in result.before_state.operation_refs
    assert acquired_operation in result.after_state.operation_refs
    assert result.transition.new_operation_refs == (acquired_operation,)
    assert result.transition.stop_reasons == ("control_surface_unobserved",)


def test_duplicate_state_and_no_progress_stop_deterministically():
    obligation_id = stable_hash("security_obligation", {"index": 1})
    policy = _policy(0)
    catalog, admission = _admission(
        page_url=f"{ORIGIN}/app",
        obligation_id=obligation_id,
        policy=policy,
    )
    operation_ref = stable_hash("action", {"route": "/app"})
    before = BrowserState.create(
        target_ref=admission.target_ref,
        world_ref=admission.world_ref,
        page_ref=admission.page_ref,
        control_surface="observed",
        interaction_catalog_id=catalog.catalog_id,
        operation_refs=(operation_ref,),
        policy_ref=policy.policy_ref,
        budget_ref=policy.budget_ref,
        depth=0,
    )
    after = BrowserState.create(
        target_ref=admission.target_ref,
        world_ref=admission.world_ref,
        page_ref=admission.page_ref,
        control_surface="observed",
        interaction_catalog_id=catalog.catalog_id,
        operation_refs=(operation_ref,),
        policy_ref=policy.policy_ref,
        budget_ref=policy.budget_ref,
        depth=1,
    )

    result = BoundedBrowserStateExplorer().observe_transition(
        before_state=before,
        after_state=after,
        admission=admission,
        acquisition=_acquisition(
            admission,
            page_ref=after.page_ref,
            operation_ref=operation_ref,
        ),
        receipt_id="behavioral-" + ("d" * 64),
        before_frontier=_frontier(obligation_id),
        after_frontier=_frontier(obligation_id),
    )

    assert result.transition.decision == "stop"
    assert result.transition.stop_reasons == (
        "duplicate_state",
        "no_progress",
    )
    assert result.state_count == 1
