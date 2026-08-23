"""State-machine legality mining tests; this relation is analysis-only."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.prerequisite_graph as prerequisite_graph_module
import core.behavior.state_machine as state_machine_module
from core.behavior.state_machine import (
    STATE_MACHINE_LEGALITY_MODE,
    StateMachineLegalityLimits,
    StateMachineLegalityMiner,
)
from core.behavior.normalize import normalize_exchange

ORIGIN = "https://api.example.test"
WORKFLOW_ID = "workflow_7fa9f13a2b4c5d6e"
EXPORT_TOKEN = "token_4a5b6c7d8e9f0123"
ORDER_ID = "order_6e7f8a9b0c1d2e3f"
ADDRESS_ID = "address_6e7f8a9b0c1d2e3f"


def _records(*, persona: str = "alice"):
    return (
        {
            "id": "create-workflow",
            "persona_id": persona,
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows",
            "request_body": '{"label":"controlled"}',
            "response_status": 201,
            "response_body": json.dumps({"workflowId": WORKFLOW_ID}),
        },
        {
            "id": "approve-workflow",
            "persona_id": persona,
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/approve",
            "request_body": "{}",
            "response_status": 200,
            "response_body": json.dumps({"exportToken": EXPORT_TOKEN}),
        },
        {
            "id": "export-workflow",
            "persona_id": persona,
            "method": "GET",
            "url": (
                f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/export"
                f"?exportToken={EXPORT_TOKEN}"
            ),
            "response_status": 200,
            "response_body": '{"status":"ready"}',
        },
    )


def _joining_records():
    prerequisites = (
        {
            "id": "create-order",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/orders",
            "request_body": "{}",
            "response_status": 201,
            "response_body": json.dumps({"orderId": ORDER_ID}),
        },
        {
            "id": "create-address",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/addresses",
            "request_body": "{}",
            "response_status": 201,
            "response_body": json.dumps({"addressId": ADDRESS_ID}),
        },
    )
    observed = tuple(
        sorted(
            prerequisites,
            key=lambda record: normalize_exchange(
                record,
                source_id=record["id"],
                world_id="alice",
            ).action_id,
            reverse=True,
        )
    )
    return (
        *observed,
        {
            "id": "export-order",
            "persona_id": "alice",
            "method": "GET",
            "url": (
                f"{ORIGIN}/api/export?orderId={ORDER_ID}"
                f"&addressId={ADDRESS_ID}"
            ),
            "response_status": 200,
            "response_body": '{"status":"ready"}',
        },
    )


def test_miner_derives_exact_same_world_ordered_prerequisite_relation():
    records = _records()
    result = StateMachineLegalityMiner().mine(records, world_id="alice")

    assert result.status == "ready"
    assert result.mode == STATE_MACHINE_LEGALITY_MODE
    assert result.executable is False
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert len(candidate.prerequisite_operation_ids) == 2
    assert len(candidate.source_refs) == 3
    assert len(candidate.lineage_binding_ids) == 3
    assert candidate.risk_class == "read"
    assert candidate.prerequisite_graph.shape == "branching_joining"
    assert candidate.prerequisite_graph.is_multi_prerequisite
    assert candidate.prerequisite_graph.is_non_linear
    assert len(candidate.prerequisite_graph.relations) == 3
    assert len(candidate.prerequisite_graph.branch_operation_ids) == 1
    assert candidate.prerequisite_graph.join_operation_ids == (
        candidate.terminal_operation_id,
    )
    assert candidate.prerequisite_graph.max_depth == 3
    assert all(
        not relation.necessity_proven
        and not relation.enforcement_proven
        and not relation.finding_authority
        and not relation.executable
        for relation in candidate.prerequisite_graph.relations
    )
    assert result.diagnostics.ordered_chains == 1
    assert result.diagnostics.observed_relations == 3
    assert result.diagnostics.multi_prerequisite_candidates == 1
    assert result.diagnostics.non_linear_candidates == 1
    assert result.diagnostics.incomplete_work == 0
    assert result.to_dict()["schema_version"] == 2


def test_independent_prerequisites_are_preserved_as_one_joining_topology():
    records = _joining_records()
    result = StateMachineLegalityMiner().mine(
        records,
        world_id="alice",
    )

    assert result.status == "ready"
    candidate = next(
        item
        for item in result.candidates
        if len(item.prerequisite_operation_ids) == 2
    )
    graph = candidate.prerequisite_graph
    assert candidate.prerequisite_operation_ids == tuple(
        normalize_exchange(
            record,
            source_id=record["id"],
            world_id="alice",
        ).action_id
        for record in records[:-1]
    )
    assert graph.shape == "joining"
    assert len(graph.root_operation_ids) == 2
    assert len(graph.direct_terminal_prerequisite_operation_ids) == 2
    assert graph.branch_operation_ids == ()
    assert graph.join_operation_ids == (candidate.terminal_operation_id,)
    assert graph.max_depth == 2
    assert len(graph.relations) == 2
    encoded = json.dumps(graph.to_dict(), sort_keys=True)
    assert ORDER_ID not in encoded
    assert ADDRESS_ID not in encoded


def test_prerequisite_topology_cannot_be_relabelled_without_readdressing():
    candidate = StateMachineLegalityMiner().mine(
        _records(),
        world_id="alice",
    ).candidates[0]

    with pytest.raises(
        ValueError,
        match="observed prerequisite graph contract is invalid",
    ):
        replace(candidate.prerequisite_graph, shape="linear")


def test_result_is_deterministic_and_contains_no_raw_target_values():
    first = StateMachineLegalityMiner().mine(_records(), world_id="alice")
    second = StateMachineLegalityMiner().mine(_records(), world_id="alice")

    assert first.to_dict() == second.to_dict()
    encoded = json.dumps(first.to_dict(), sort_keys=True)
    for raw in (
        ORIGIN,
        WORKFLOW_ID,
        EXPORT_TOKEN,
        "alice",
        "controlled",
    ):
        assert raw not in encoded


def test_out_of_order_observations_do_not_manufacture_a_legal_chain():
    records = _records()
    result = StateMachineLegalityMiner().mine(
        (records[2], records[0], records[1]),
        world_id="alice",
    )

    assert result.status == "no_candidates"
    assert result.candidates == ()
    assert result.diagnostics.ambiguous_chains == 1


def test_repeated_step_is_rejected_as_ambiguous_instead_of_chosen_arbitrarily():
    records = _records()
    repeated = {**records[1], "id": "approve-workflow-again"}
    result = StateMachineLegalityMiner().mine(
        (records[0], records[1], repeated, records[2]),
        world_id="alice",
    )

    assert result.status == "no_candidates"
    assert result.diagnostics.ambiguous_chains == 1
    assert result.diagnostics.ordered_chains == 0


def test_semantic_name_match_without_exact_value_lineage_is_rejected():
    create, approve, export = _records()
    mismatched_create = {
        **create,
        "response_body": json.dumps(
            {"workflowId": "workflow_different_8c9d0e1f2a3b4c5d"}
        ),
    }

    result = StateMachineLegalityMiner().mine(
        (mismatched_create, approve, export),
        world_id="alice",
    )

    assert result.status == "no_candidates"
    assert result.diagnostics.ordered_chains == 1
    assert result.diagnostics.lineage_rejections == 1


def test_cross_world_steps_cannot_form_one_state_machine_relation():
    create, approve, export = _records()
    result = StateMachineLegalityMiner().mine(
        (
            create,
            {**approve, "persona_id": "bob"},
            export,
        ),
        world_id="alice",
    )

    assert result.status == "no_candidates"
    assert result.diagnostics.cross_world_rejections == 1


def test_high_value_terminal_without_prerequisites_is_not_a_legality_claim():
    result = StateMachineLegalityMiner().mine(
        (
            {
                "id": "public-export",
                "persona_id": "alice",
                "method": "GET",
                "url": f"{ORIGIN}/api/export",
                "response_status": 200,
                "response_body": "{}",
            },
        ),
        world_id="alice",
    )

    assert result.status == "no_candidates"
    assert result.diagnostics.terminal_only_goals == 1


def test_record_limit_returns_content_addressed_blocker_without_partial_work():
    miner = StateMachineLegalityMiner(
        StateMachineLegalityLimits(max_records=2)
    )

    result = miner.mine(_records(), world_id="alice")

    assert result.status == "blocked"
    assert result.blocker == "record_limit_exceeded"
    assert result.candidates == ()
    assert result.executable is False


def test_fixed_safety_ceilings_cannot_be_raised_by_a_caller():
    with pytest.raises(ValueError, match="exceeds the state-machine contract"):
        StateMachineLegalityLimits(max_candidates=65)


def test_input_contract_rejects_non_mapping_records():
    with pytest.raises(TypeError, match="sequence of mappings"):
        StateMachineLegalityMiner().mine(("not-a-record",))


def test_state_machine_analysis_modules_have_no_transport_or_execution_surface():
    for module in (state_machine_module, prerequisite_graph_module):
        tree = ast.parse(Path(module.__file__).read_text())
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        assert not imported_roots & {
            "aiohttp",
            "httpx",
            "requests",
            "socket",
            "urllib3",
            "websockets",
        }
        assert not any(
            isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree)
        )
    assert not hasattr(behavior_package, "StateMachineLegalityMiner")
    assert not hasattr(behavior_package, "ObservedPrerequisiteGraph")
