"""Passive interaction-intent catalog tests; browser execution is forbidden."""

from __future__ import annotations

import inspect

import pytest

import core.behavior.interactions as interactions_module
from core.behavior.interactions import (
    InteractionIntentLimits,
    InteractionIntentMiner,
)

ORIGIN = "https://api.example.test"


def _control(index: int, **overrides):
    value = {
        "tag": "button",
        "role": "button",
        "input_type": "",
        "form_method": "none",
        "destination": "none",
        "locator": [
            {"tag": "html", "sibling_index": 1},
            {"tag": "body", "sibling_index": 1},
            {"tag": "button", "sibling_index": index},
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


def test_catalog_is_deterministic_redacted_and_analysis_only():
    secret = "never-retain-this-control-value"
    controls = [
        _control(
            1,
            tag="a",
            role="link",
            destination="same_origin",
            text=secret,
            id=secret,
            name=secret,
            value=secret,
        ),
        _control(2, form_method="post", submitter=True),
        _control(3, form_method="destructive_override", submitter=True),
        _control(
            4,
            tag="a",
            role="link",
            destination="external_origin",
        ),
        _control(5, tag="summary", role="", aria_expanded=True),
        _control(6, tag="select", role="combobox"),
        _control(7, tag="other", role="button", scripted_handler=True),
    ]
    miner = InteractionIntentMiner()

    first = miner.mine(
        controls,
        target_origin=ORIGIN,
        world_id="alice",
        page_url=f"{ORIGIN}/projects/1234/settings?token={secret}",
    )
    second = miner.mine(
        list(reversed(controls)),
        target_origin=ORIGIN,
        world_id="alice",
        page_url=f"{ORIGIN}/projects/5678/settings?token=other",
    )

    assert first == second
    assert first.executable is False
    assert first.status == "ready"
    assert first.diagnostics.read_interactions == 2
    assert first.diagnostics.state_mutations == 1
    assert first.diagnostics.externally_consequential == 1
    assert first.diagnostics.destructive == 1
    assert first.diagnostics.unknown == 2
    assert {item.risk_class for item in first.intents} == {
        "read_interaction",
        "state_mutation",
        "externally_consequential",
        "destructive",
        "unknown",
    }
    assert all(item.executable is False for item in first.intents)
    assert all(
        "passive_catalog_only" in item.safety_blockers
        for item in first.intents
    )
    assert secret not in str(first.to_dict())
    assert "token" not in str(first.to_dict())


def test_page_identity_rejects_cross_origin_and_distinguishes_static_paths():
    miner = InteractionIntentMiner()
    controls = [_control(1)]

    account = miner.mine(
        controls,
        target_origin=ORIGIN,
        world_id="alice",
        page_url=f"{ORIGIN}/account/settings",
    )
    admin = miner.mine(
        controls,
        target_origin=ORIGIN,
        world_id="alice",
        page_url=f"{ORIGIN}/admin/settings",
    )

    assert account.catalog_id != admin.catalog_id
    with pytest.raises(ValueError, match="must match"):
        miner.mine(
            controls,
            target_origin=ORIGIN,
            world_id="alice",
            page_url="https://other.example.test/account/settings",
        )


def test_catalog_bounds_exactly_and_rejects_invalid_or_hidden_controls():
    miner = InteractionIntentMiner(
        InteractionIntentLimits(
            max_controls_per_world=2,
            max_total_controls=3,
        )
    )
    result = miner.mine(
        [_control(index) for index in range(1, 6)],
        target_origin=ORIGIN,
        world_id="alice",
        peer_controls=[_control(10), _control(11)],
        peer_world_id="bob",
    )

    assert result.diagnostics.controls_seen == 3
    assert result.diagnostics.accepted_controls == 3
    assert result.diagnostics.dropped_controls == 4

    rejected = InteractionIntentMiner().mine(
        [
            _control(1, visible=False),
            _control(2, locator=[]),
            "not-a-control",
        ],
        target_origin=ORIGIN,
        world_id="alice",
    )
    assert rejected.status == "no_interaction_intents"
    assert rejected.diagnostics.hidden_controls == 1
    assert rejected.diagnostics.invalid_controls == 2
    with pytest.raises(ValueError, match="limits are invalid"):
        InteractionIntentLimits(max_total_controls=513)


def test_interaction_miner_has_no_driver_transport_or_execution_dependency():
    source = inspect.getsource(interactions_module)

    assert "core.server" not in source
    assert "DriverBridge" not in source
    assert "PolicyExecutor" not in source
    assert "SNDReplayTransport" not in source
