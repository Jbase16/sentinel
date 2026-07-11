"""Compatibility and safety tests for the passive behavioral kernel."""

from __future__ import annotations

import json

import pytest

from core.behavior.graph import BehaviorGraph, GraphLimits
from core.behavior.normalize import normalize_exchange
from core.behavior.shadow import (
    SHADOW_ENV,
    ShadowBehaviorRegistry,
    get_shadow_registry,
    reset_shadow_registry_for_tests,
)
from core.ghost.flow import FlowMapper


@pytest.fixture(autouse=True)
def _reset_singletons(monkeypatch):
    monkeypatch.delenv(SHADOW_ENV, raising=False)
    reset_shadow_registry_for_tests()
    FlowMapper._instance = None
    yield
    FlowMapper._instance = None
    reset_shadow_registry_for_tests()


def _record(*, url="https://Example.test/api/users/123456?token=secret&q=alice", status=200,
            response='{"id":"123456","email":"alice@example.test"}'):
    return {
        "id": "exchange-1",
        "method": "POST",
        "url": url,
        "headers": {
            "Authorization": "Bearer super-secret",
            "Content-Type": "application/json",
            "X-CSRF-Token": "csrf-secret",
        },
        "request_body": '{"email":"alice@example.test","password":"hunter2"}',
        "response_status": status,
        "response_headers": {"Content-Type": "application/json", "Set-Cookie": "sid=secret"},
        "response_body": response,
        "cookies_after_step": {"sid": "cookie-secret"},
    }


def test_normalization_redacts_all_raw_values():
    exchange = normalize_exchange(_record(), world_id="persona:alice")
    encoded = json.dumps(exchange.to_dict(), sort_keys=True)

    for secret in (
        "super-secret", "csrf-secret", "hunter2", "cookie-secret", "alice@example.test",
        "token=secret", "q=alice", "persona:alice", "exchange-1",
    ):
        assert secret not in encoded

    assert exchange.origin == "https://example.test"
    assert exchange.path_template == "/api/users/{id}"
    assert exchange.query_keys == ("q", "token")
    assert exchange.cookie_names == ("sid",)
    assert exchange.request_body_hash.startswith("sha256:")
    assert exchange.response_body_hash.startswith("sha256:")


def test_structural_ids_ignore_secret_and_object_values():
    first = normalize_exchange(_record(), world_id="persona:a")
    second_record = _record(
        url="https://example.test/api/users/999999?token=other&q=bob",
        response='{"id":"999999","email":"bob@example.test"}',
    )
    second_record["request_body"] = '{"email":"bob@example.test","password":"different"}'
    second = normalize_exchange(
        second_record,
        world_id="persona:b",
    )

    assert first.action_id == second.action_id
    assert first.state_id == second.state_id
    assert first.request_body_hash != second.request_body_hash
    assert first.response_body_hash != second.response_body_hash


def test_graph_tracks_cross_world_relational_coverage_without_claiming_a_finding():
    graph = BehaviorGraph()
    alice = normalize_exchange(_record(), world_id="persona:alice")
    bob = normalize_exchange(
        _record(response='{"id":"999999","email":"bob@example.test"}'),
        source_id="exchange-2",
        world_id="persona:bob",
    )

    assert graph.observe(alice).accepted is True
    assert graph.observe(bob).accepted is True
    coverage = graph.coverage()

    assert coverage["worlds"] == 2
    assert coverage["actions"] == 1
    assert coverage["cross_world_actions"] == 1
    assert coverage["cross_world_structural_divergences"] == 0
    assert coverage["cross_world_content_variants"] == 1
    assert "finding" not in json.dumps(graph.snapshot()).lower()


def test_graph_limits_fail_closed_and_remain_bounded():
    graph = BehaviorGraph(GraphLimits(max_worlds=1, max_actions=1, max_states=1, max_transitions=1))
    assert graph.observe(normalize_exchange(_record(), world_id="one")).accepted is True

    rejected = graph.observe(normalize_exchange(_record(), world_id="two"))
    assert rejected.accepted is False
    assert rejected.reason == "world_limit"
    assert graph.coverage()["worlds"] == 1
    assert graph.coverage()["dropped"]["worlds"] == 1


def test_concrete_content_variants_are_bounded():
    graph = BehaviorGraph(GraphLimits(max_content_variants_per_action=2))
    for index in range(5):
        graph.observe(normalize_exchange(
            _record(response=json.dumps({"id": "123456", "value": f"variant-{index}"})),
            source_id=f"exchange-{index}",
            world_id="one",
        ))

    coverage = graph.coverage()
    assert coverage["actions"] == 1
    assert coverage["dropped"]["content_variants"] == 3


def test_json_body_hash_is_canonical_across_whitespace():
    compact = normalize_exchange(_record(response='{"id":123456,"ok":true}'))
    spaced = normalize_exchange(_record(response='{ "ok": true, "id": 123456 }'))
    assert compact.response_body_hash == spaced.response_body_hash


def test_registry_rejects_malformed_observation_without_raising():
    registry = ShadowBehaviorRegistry()
    result = registry.observe("scan-1", {"response_status": object()})
    assert result.accepted is False
    assert result.reason == "normalization_error"
    assert registry.errors == 1


def test_shadow_disabled_preserves_existing_flow_behavior(monkeypatch):
    monkeypatch.delenv(SHADOW_ENV, raising=False)
    mapper = FlowMapper.instance()
    flow_id = mapper.start_recording("existing-contract")
    step_id = mapper.record_request(flow_id, "GET", "https://example.test/")

    assert mapper.finalize_step(step_id, status=200, body="ok") is True
    assert get_shadow_registry().context_ids() == []
    assert mapper.active_flows[flow_id].steps[0].response_body == "ok"


def test_shadow_enabled_observes_finalized_flow_without_mutating_it(monkeypatch):
    monkeypatch.setenv(SHADOW_ENV, "1")
    mapper = FlowMapper.instance()
    flow_id = mapper.start_recording("shadow-contract")
    step_id = mapper.record_request(
        flow_id, "POST", "https://example.test/api/items/123456",
        request_body='{"name":"private marker"}',
        request_content_type="application/json",
    )

    assert mapper.finalize_step(
        step_id,
        status=201,
        headers={"content-type": "application/json"},
        body='{"id":"654321","name":"private marker"}',
        content_type="application/json",
    ) is True

    snapshot = get_shadow_registry().snapshot(f"ghost:{flow_id}")
    assert snapshot is not None
    assert snapshot["mode"] == "passive_shadow"
    assert snapshot["coverage"]["observations"] == 1
    assert "private marker" not in json.dumps(snapshot)
    step = mapper.active_flows[flow_id].steps[0]
    assert step.response_status == 201
    assert step.response_body == '{"id":"654321","name":"private marker"}'


def test_shadow_observer_failure_cannot_break_finalize(monkeypatch):
    monkeypatch.setenv(SHADOW_ENV, "1")
    mapper = FlowMapper.instance()
    flow_id = mapper.start_recording("failure-isolation")
    step_id = mapper.record_request(flow_id, "GET", "https://example.test/")

    def explode(*_args, **_kwargs):
        raise RuntimeError("observer failed")

    monkeypatch.setattr("core.behavior.shadow.observe_flow_step_if_enabled", explode)
    assert mapper.finalize_step(step_id, status=204) is True
    assert mapper.active_flows[flow_id].steps[0].response_status == 204
