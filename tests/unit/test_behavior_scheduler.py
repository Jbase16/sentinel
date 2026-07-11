"""Autonomous primary-planner tests; no target network is used."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from core.behavior.active import ControlledExecutionResult
from core.behavior.scheduler import (
    BehavioralPrimaryScheduler,
    PrimaryPlannerConfig,
    PrimaryPlannerError,
)
import core.behavior.scheduler as scheduler_module
from core.foundry.vault import ResearchPersona
from core.wraith.bola_replay import BolaFinding, OpVerdict

SOURCE_ID = "RlLB9Tjpk7YfkTaBB0SpzA"
PEER_ID = "9QsBs4y23m6HH4aB38ffkA"


def _persona(persona_id):
    return ResearchPersona(persona_id, persona_id, f"{persona_id}@research.example")


def _record(operation, resource_id, *, response, status=200, query=True):
    item = {"operationName": operation, "variables": {"BizEncId": resource_id}}
    if query:
        item["query"] = (
            f"query {operation}($BizEncId: ID!) "
            "{ privateObject(id: $BizEncId) { id } }"
        )
    return {
        "method": "POST",
        "url": "https://api.example.test/gql/batch",
        "request_body": json.dumps([item]),
        "response_status": status,
        "response_body": response,
    }


def _captures():
    source = [
        _record("GetSame", SOURCE_ID, response='{"value":"shared"}'),
        _record("GetPrivate", SOURCE_ID, response='{"owner":"source-private"}'),
    ]
    peer = [
        _record("GetSame", PEER_ID, response='{"value":"shared"}'),
        _record("GetPrivate", PEER_ID, response='{"owner":"peer-private"}'),
    ]
    return source, peer


def _execution(proposal_id):
    finding = BolaFinding(
        object_ref="GET /objects/{id}",
        method="GET",
        leaked=["peer-private"],
        victim="peer-object",
        evidence="legacy three-way diff confirmed",
    )
    return ControlledExecutionResult(
        proposal_id=proposal_id,
        legacy_verdict=OpVerdict("GetPrivate", "BOLA_CONFIRMED", "confirmed", finding),
        requests_attempted=3,
        requests_sent=3,
        policy_denials=0,
        provenance_root="root123",
        restraint={"requests_sent": 3, "stopped_after_first_proof": True},
        provenance={"root": "root123", "events": 3},
    )


class _FakeControlledExecutor:
    def __init__(self):
        self.calls = []

    async def execute(self, proposal, source_records, peer_records):
        self.calls.append((proposal, source_records, peer_records))
        return _execution(proposal.proposal_id)


def test_primary_scheduler_has_no_network_client_or_legacy_hunt_call():
    tree = ast.parse(Path(scheduler_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "hunt"
        for node in ast.walk(tree)
    )


def test_primary_planner_deterministically_selects_best_proof_candidate():
    source, peer = _captures()
    scheduler = BehavioralPrimaryScheduler(PrimaryPlannerConfig(enabled=False))

    first = scheduler.plan(
        source, peer, source_persona=_persona("source"), peer_persona=_persona("peer")
    )
    second = scheduler.plan(
        source, peer, source_persona=_persona("source"), peer_persona=_persona("peer")
    )

    assert first.to_dict() == second.to_dict()
    assert first.selected is not None
    assert first.selected.proposal.operation_label == "GetPrivate"
    assert "cross_world_response_difference" in first.selected.signals


@pytest.mark.asyncio
async def test_disabled_primary_planner_never_calls_controlled_executor():
    source, peer = _captures()
    executor = _FakeControlledExecutor()
    scheduler = BehavioralPrimaryScheduler(PrimaryPlannerConfig(enabled=False))

    result = await scheduler.run(
        source,
        peer,
        source_persona=_persona("source"),
        peer_persona=_persona("peer"),
        controlled_executor=executor,
    )

    assert result.status == "disabled"
    assert executor.calls == []


@pytest.mark.asyncio
async def test_enabled_primary_planner_executes_exactly_one_selected_proposal():
    source, peer = _captures()
    executor = _FakeControlledExecutor()
    scheduler = BehavioralPrimaryScheduler(PrimaryPlannerConfig(enabled=True))

    result = await scheduler.run(
        source,
        peer,
        source_persona=_persona("source"),
        peer_persona=_persona("peer"),
        controlled_executor=executor,
    )

    assert result.status == "completed"
    assert len(executor.calls) == 1
    assert executor.calls[0][0].operation_label == "GetPrivate"
    assert result.finding["metadata"]["behavioral_primary_planner"]["rank_score"] > 0
    assert result.finding["metadata"]["sentinel_provenance_root"] == "root123"


@pytest.mark.asyncio
async def test_enabled_planner_requires_controlled_execution_seam():
    source, peer = _captures()
    scheduler = BehavioralPrimaryScheduler(PrimaryPlannerConfig(enabled=True))

    with pytest.raises(PrimaryPlannerError, match="requires_controlled_executor"):
        await scheduler.run(
            source,
            peer,
            source_persona=_persona("source"),
            peer_persona=_persona("peer"),
        )


def test_unproven_persisted_graphql_operation_is_not_ranked():
    source = [_record("GetPrivate", SOURCE_ID, response="source", query=False)]
    peer = [_record("GetPrivate", PEER_ID, response="peer", query=False)]
    scheduler = BehavioralPrimaryScheduler(PrimaryPlannerConfig(enabled=True))

    plan = scheduler.plan(
        source, peer, source_persona=_persona("source"), peer_persona=_persona("peer")
    )

    assert plan.selected is None
    assert plan.diagnostics["rejected"]["unproven_read_semantics"] == 1


def test_ranked_candidate_count_is_bounded():
    source = [
        _record(f"GetObject{index}", SOURCE_ID, response=f"source-{index}")
        for index in range(5)
    ]
    peer = [
        _record(f"GetObject{index}", PEER_ID, response=f"peer-{index}")
        for index in range(5)
    ]
    scheduler = BehavioralPrimaryScheduler(
        PrimaryPlannerConfig(enabled=False, max_ranked_candidates=2)
    )

    plan = scheduler.plan(
        source, peer, source_persona=_persona("source"), peer_persona=_persona("peer")
    )

    assert len(plan.ranked) == 2
    assert plan.diagnostics["dropped_for_rank_bound"] == 3
