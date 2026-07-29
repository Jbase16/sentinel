"""Bounded adaptive safe-read controller tests."""

from __future__ import annotations

import copy
import json

import pytest

from core.behavior.interaction_adaptive import (
    INTERACTION_ADAPTIVE_WORKFLOW,
    InteractionAdaptiveConfig,
    InteractionAdaptiveController,
    InteractionAdaptiveDenied,
    InteractionAdaptiveDerivation,
)
from core.behavior.interaction_render import InteractionRenderConfig
from core.behavior.receipts import (
    BehavioralReceiptStore,
    ReceiptStoreError,
    _redacted_interaction_acquisition_summary,
)
from tests.unit.test_behavior_interaction_second_transition import (
    ALICE,
    FIRST_URL,
    ORIGIN,
    SECOND_URL,
    _context,
    _control,
    _frontier,
    _select,
)

THIRD_URL = f"{ORIGIN}/third"
FOURTH_URL = f"{ORIGIN}/fourth"


async def _adaptive_context(
    raw_send,
    tmp_path,
    *,
    destinations,
    authorize: bool = True,
    authorization=None,
):
    boundary, resolver_calls, parent, frontier = await _context(
        raw_send,
        destinations=destinations,
    )
    if authorization is not None:
        boundary.authorization = authorization
        boundary.source_boundary.authorization = authorization
    elif authorize:
        boundary.authorization.allowed_workflows.append(
            INTERACTION_ADAPTIVE_WORKFLOW
        )
        boundary.authorization.sign()

    async def observer(_persona_id, *, base_url, html):
        return {
            "base_url": base_url,
            "controls": [_control()],
            "scanned_nodes": 1,
            "controls_truncated": False,
            "bytes_inspected": len(html.encode()),
            "target_requests_sent": 0,
        }

    controller = InteractionAdaptiveController(
        target_origin=ORIGIN,
        authorization=boundary.authorization,
        actor_persona_id=ALICE,
        peer_persona_id=boundary.peer_persona_id,
        executor=boundary.executor,
        resolver=boundary.resolver,
        observer=observer,
        render_config=InteractionRenderConfig(enabled=True),
        receipt_store=BehavioralReceiptStore(tmp_path),
        config=InteractionAdaptiveConfig(enabled=True),
    )
    return controller, boundary, resolver_calls, parent, frontier


async def _run_to_limit(
    raw_send,
    tmp_path,
    *,
    destinations,
    authorize: bool = True,
    authorization=None,
):
    (
        controller,
        boundary,
        resolver_calls,
        parent,
        frontier,
    ) = await _adaptive_context(
        raw_send,
        tmp_path,
        destinations=destinations,
        authorize=authorize,
        authorization=authorization,
    )
    records = []

    async def derive(record, observation, state, depth):
        next_frontier = tuple(_frontier(depth + 1))
        _catalog, next_admission = _select(
            observation.controls,
            page_url=record["url"],
            frontier=next_frontier,
            policy=boundary.executor.policy,
        )
        return InteractionAdaptiveDerivation(
            after_frontier=tuple(dict(item) for item in next_frontier),
            next_admission=next_admission,
            state=state + 1,
        )

    result = await controller.run(
        initial_parent=parent,
        initial_source_boundary=boundary.source_boundary,
        initial_observation=boundary.observation,
        initial_admission=boundary.admission,
        initial_frontier=frontier,
        initial_state=1,
        derive=derive,
        record_sink=lambda record: records.append(dict(record)),
    )
    return (
        result,
        resolver_calls,
        records,
        controller.authorization,
        boundary,
        parent,
    )


@pytest.mark.asyncio
async def test_adaptive_controller_progresses_to_fixed_transition_ceiling(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append((method, url, body, kwargs))
        return 200, '<a href="/next">Next</a>'

    (
        result,
        resolver_calls,
        records,
        _authorization,
        boundary,
        parent,
    ) = await _run_to_limit(
        raw_send,
        tmp_path,
        destinations=[
            SECOND_URL,
            SECOND_URL,
            THIRD_URL,
            THIRD_URL,
            FOURTH_URL,
            FOURTH_URL,
        ],
    )
    serialized = result.to_dict()

    assert [item.step_index for item in result.steps] == [2, 3, 4]
    assert [url for _method, url, _body, _kwargs in sent] == [
        SECOND_URL,
        THIRD_URL,
        FOURTH_URL,
    ]
    assert len(resolver_calls) == 6
    assert len(records) == 3
    assert serialized["target_requests_sent"] == 3
    assert serialized["transition_count"] == 4
    assert serialized["final_state_id"] == (
        result.final_transition.after_state.state_id
    )
    assert "transition_limit" in serialized["stop_reasons"]
    assert "depth_limit" in serialized["stop_reasons"]
    assert len({item.acquisition.receipt_id for item in result.steps}) == 3
    assert all(
        item.parent_receipt_id
        == (
            result.root_receipt_id
            if index == 0
            else result.steps[index - 1].acquisition.receipt_id
        )
        for index, item in enumerate(result.steps)
    )
    assert len(list(tmp_path.glob("behavioral-*.json"))) == 3

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
        "adaptive_chain": serialized,
    }
    redacted = _redacted_interaction_acquisition_summary(root_summary)
    assert redacted["adaptive_chain"]["chain_ref"] == serialized["chain_ref"]
    tampered = copy.deepcopy(root_summary)
    tampered["adaptive_chain"]["steps"][1]["parent_chain_ref"] = (
        tampered["adaptive_chain"]["root_chain_ref"]
    )
    with pytest.raises(ReceiptStoreError):
        _redacted_interaction_acquisition_summary(tampered)


@pytest.mark.asyncio
async def test_adaptive_controller_stops_on_duplicate_no_progress_state(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append(url)
        return 200, '<a href="/first">Again</a>'

    (
        result,
        resolver_calls,
        records,
        _authorization,
        _boundary,
        _parent,
    ) = await _run_to_limit(
        raw_send,
        tmp_path,
        destinations=[FIRST_URL, FIRST_URL],
    )

    assert sent == [FIRST_URL]
    assert len(resolver_calls) == 2
    assert len(records) == 1
    assert len(result.steps) == 1
    assert set(result.final_transition.transition.stop_reasons) >= {
        "duplicate_state",
        "no_progress",
    }


@pytest.mark.asyncio
async def test_adaptive_controller_changed_resolution_aborts_before_send(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append(url)
        return 200, "unexpected"

    controller, boundary, resolver_calls, parent, frontier = (
        await _adaptive_context(
            raw_send,
            tmp_path,
            destinations=[SECOND_URL, THIRD_URL],
        )
    )

    async def derive(*_args):
        raise AssertionError("changed resolution must not be derived")

    with pytest.raises(
        InteractionAdaptiveDenied,
        match="resolution_changed_before_send",
    ):
        await controller.run(
            initial_parent=parent,
            initial_source_boundary=boundary.source_boundary,
            initial_observation=boundary.observation,
            initial_admission=boundary.admission,
            initial_frontier=frontier,
            initial_state=None,
            derive=derive,
        )

    assert len(resolver_calls) == 2
    assert sent == []
    stored = json.loads(next(tmp_path.glob("behavioral-*.json")).read_text())
    assert stored["state"] == "aborted"
    assert stored["abort_reason"] == "interaction_adaptive_step_error"


@pytest.mark.asyncio
async def test_adaptive_failure_preserves_prior_completed_request_count(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append(url)
        return 200, '<a href="/next">Next</a>'

    controller, boundary, resolver_calls, parent, frontier = (
        await _adaptive_context(
            raw_send,
            tmp_path,
            destinations=[
                SECOND_URL,
                SECOND_URL,
                THIRD_URL,
                FOURTH_URL,
            ],
        )
    )

    async def derive(record, observation, state, depth):
        next_frontier = tuple(_frontier(depth + 1))
        _catalog, next_admission = _select(
            observation.controls,
            page_url=record["url"],
            frontier=next_frontier,
            policy=boundary.executor.policy,
        )
        return InteractionAdaptiveDerivation(
            after_frontier=tuple(dict(item) for item in next_frontier),
            next_admission=next_admission,
            state=state,
        )

    with pytest.raises(
        InteractionAdaptiveDenied,
        match="resolution_changed_before_send",
    ) as error:
        await controller.run(
            initial_parent=parent,
            initial_source_boundary=boundary.source_boundary,
            initial_observation=boundary.observation,
            initial_admission=boundary.admission,
            initial_frontier=frontier,
            initial_state=None,
            derive=derive,
        )

    assert sent == [SECOND_URL]
    assert len(resolver_calls) == 4
    assert error.value.target_requests_sent == 1
    assert error.value.target_request_possible is False


@pytest.mark.asyncio
async def test_adaptive_controller_requires_separate_workflow_before_traffic(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append(url)
        return 200, "unexpected"

    controller, boundary, resolver_calls, parent, frontier = (
        await _adaptive_context(
            raw_send,
            tmp_path,
            destinations=[SECOND_URL, SECOND_URL],
            authorize=False,
        )
    )

    async def derive(*_args):
        raise AssertionError("unauthorized controller must not derive")

    with pytest.raises(
        InteractionAdaptiveDenied,
        match="authorization_denied",
    ):
        await controller.run(
            initial_parent=parent,
            initial_source_boundary=boundary.source_boundary,
            initial_observation=boundary.observation,
            initial_admission=boundary.admission,
            initial_frontier=frontier,
            initial_state=None,
            derive=derive,
        )

    assert resolver_calls == []
    assert sent == []
    assert not list(tmp_path.glob("behavioral-*.json"))


@pytest.mark.asyncio
async def test_adaptive_replay_uses_child_receipt_without_repeating_get(
    tmp_path,
):
    first_sent = []

    async def first_send(method, url, body=None, **kwargs):
        first_sent.append(url)
        return 200, '<a href="/next">Next</a>'

    (
        first,
        _resolver_calls,
        _records,
        authorization,
        _boundary,
        _parent,
    ) = await _run_to_limit(
        first_send,
        tmp_path,
        destinations=[
            SECOND_URL,
            SECOND_URL,
            THIRD_URL,
            THIRD_URL,
            FOURTH_URL,
            FOURTH_URL,
        ],
    )
    assert len(first_sent) == 3

    second_sent = []

    async def second_send(method, url, body=None, **kwargs):
        second_sent.append(url)
        return 200, "unexpected"

    (
        second,
        resolver_calls,
        records,
        _authorization,
        _boundary,
        _parent,
    ) = await _run_to_limit(
        second_send,
        tmp_path,
        destinations=[SECOND_URL, SECOND_URL],
        authorization=authorization,
    )

    assert second_sent == []
    assert len(resolver_calls) == 1
    assert records == []
    assert len(second.steps) == 1
    assert second.steps[0].acquisition.status == "already_executed"
    assert second.to_dict()["target_requests_sent"] == 0
    assert "control_surface_unobserved" in (
        second.final_transition.transition.stop_reasons
    )
    assert first.steps[0].acquisition.receipt_id == (
        second.steps[0].acquisition.receipt_id
    )
