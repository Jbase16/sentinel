"""Passive interaction admission tests; driver and transport use is forbidden."""

from __future__ import annotations

import inspect
from dataclasses import replace

import pytest

import core.behavior.interaction_admission as admission_module
from core.behavior.interaction_admission import InteractionIntentSelector
from core.behavior.interactions import InteractionIntentMiner
from core.behavior.normalize import stable_hash

ORIGIN = "https://api.example.test"
POLICY_DIGEST = "sha256:" + "a" * 64


def _control(index: int, **overrides):
    value = {
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
    value.update(overrides)
    return value


def _budget(total_requests: int = 0):
    return {
        "total_requests": total_requests,
        "cross_object_reads": 0,
        "privilege_mutations": 0,
        "creates": 0,
        "endpoints_touched": 0,
    }


def _obligation(index: int, *, score: int, actionable: bool = False):
    return {
        "obligation_id": stable_hash("security_obligation", {"index": index}),
        "kind": "ownership_boundary",
        "risk_class": "read",
        "score": score,
        "actionable": actionable,
        "resolution_kind": (
            "authorization_proposal" if actionable else "unavailable"
        ),
        "resolution_ref": (
            stable_hash("authorization_proposal", {"index": index})
            if actionable
            else None
        ),
        "signals": sorted([
            (
                "paired_world_proposal_ready"
                if actionable
                else "no_safe_resolution_path"
            ),
            "unresolved_frontier",
        ]),
    }


def _catalog(*controls, page="/app", peer_controls=()):
    return InteractionIntentMiner().mine(
        controls,
        target_origin=ORIGIN,
        world_id="alice",
        peer_controls=peer_controls,
        peer_world_id="bob",
        page_url=f"{ORIGIN}{page}",
    )


def _select(catalog, frontier, **overrides):
    values = {
        "world_id": "alice",
        "policy_digest": POLICY_DIGEST,
        "budget_snapshot": _budget(),
        "max_total_requests": 7,
    }
    values.update(overrides)
    return InteractionIntentSelector().select(catalog, frontier, **values)


def test_selector_deterministically_seals_one_safe_intent_for_top_unresolved_need():
    catalog = _catalog(
        _control(2),
        _control(
            1,
            tag="summary",
            role="",
            destination="none",
            aria_expanded=True,
        ),
        peer_controls=(_control(3),),
    )
    frontier = [
        _obligation(1, score=900, actionable=True),
        _obligation(2, score=400),
        _obligation(3, score=300),
    ]

    first = _select(catalog, frontier)
    second = _select(catalog, list(reversed(frontier)))

    assert first == second
    assert first.status == "ready_for_active_boundary"
    assert first.executable is False
    assert first.admission is not None
    assert first.admission.intent_kind == "navigate"
    assert first.admission.obligation_id == frontier[1]["obligation_id"]
    assert first.admission.action_limit == 1
    assert first.admission.executable is False
    assert first.admission.to_dict()["requires_active_boundary"] is True
    assert first.diagnostics.eligible_intents == 2
    assert first.diagnostics.wrong_world == 1


def test_selector_rejects_scripted_dangerous_ambiguous_and_wrong_world_intents():
    shared_locator = [{"tag": "html", "sibling_index": 1}, {"tag": "a", "sibling_index": 1}]
    catalog = _catalog(
        _control(1, locator=shared_locator),
        _control(
            2,
            tag="summary",
            role="",
            destination="none",
            aria_expanded=True,
            locator=shared_locator,
        ),
        _control(3, scripted_handler=True),
        _control(4, disabled=True),
        _control(5, locator_truncated=True),
        _control(6, form_method="post", submitter=True),
        _control(7, destination="external_origin"),
        peer_controls=(_control(8),),
    )

    result = _select(catalog, [_obligation(1, score=400)])

    assert result.status == "no_eligible_intents"
    assert result.admission is None
    assert result.diagnostics.ambiguous == 2
    assert result.diagnostics.blocked == 3
    assert result.diagnostics.non_read == 2
    assert result.diagnostics.wrong_world == 1


def test_selector_fail_closed_states_are_explicit_and_non_executable():
    catalog = _catalog(_control(1))
    frontier = [_obligation(1, score=400)]
    selector = InteractionIntentSelector()

    no_policy = selector.select(catalog, frontier, world_id="alice")
    no_budget = _select(
        catalog,
        frontier,
        budget_snapshot=_budget(total_requests=7),
    )
    no_need = _select(catalog, [_obligation(1, score=400, actionable=True)])

    assert no_policy.status == "policy_unavailable"
    assert no_policy.policy_ref is None
    assert no_budget.status == "budget_unavailable"
    assert no_need.status == "no_open_acquisition_obligation"
    assert all(
        result.admission is None and result.executable is False
        for result in (no_policy, no_budget, no_need)
    )
    with pytest.raises(ValueError, match="duplicate obligations"):
        _select(catalog, [frontier[0], frontier[0]])


def test_every_catalog_frontier_world_policy_and_budget_change_invalidates_binding():
    frontier = [_obligation(1, score=400)]
    baseline = _select(_catalog(_control(1)), frontier)
    other_page = _select(_catalog(_control(1), page="/admin"), frontier)
    other_frontier = _select(
        _catalog(_control(1)),
        [_obligation(2, score=400)],
    )
    other_policy = _select(
        _catalog(_control(1)),
        frontier,
        policy_digest="sha256:" + "b" * 64,
    )
    other_budget = _select(
        _catalog(_control(1)),
        frontier,
        budget_snapshot={
            **_budget(),
            "endpoints_touched": 1,
        },
    )
    other_world = _select(
        _catalog(_control(1), peer_controls=(_control(2),)),
        frontier,
        world_id="bob",
    )

    assert baseline.admission is not None
    assert other_page.admission is not None
    assert other_frontier.admission is not None
    assert other_policy.admission is not None
    assert other_budget.admission is not None
    assert other_world.admission is not None
    assert len({
        baseline.result_id,
        other_page.result_id,
        other_frontier.result_id,
        other_policy.result_id,
        other_budget.result_id,
        other_world.result_id,
    }) == 6
    with pytest.raises(ValueError, match="admission contract"):
        replace(
            baseline.admission,
            obligation_id=other_frontier.admission.obligation_id,
        )
    with pytest.raises(ValueError, match="admission contract"):
        replace(
            baseline.admission,
            scope_ref=stable_hash("interaction_scope", {"other": True}),
        )


def test_selector_has_no_driver_transport_receipt_or_execution_dependency():
    source = inspect.getsource(admission_module)

    assert "core.server" not in source
    assert "DriverBridge" not in source
    assert "PolicyExecutor" not in source
    assert "SNDReplayTransport" not in source
    assert "BehavioralReceiptStore" not in source
