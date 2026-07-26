"""Minimized prerequisite-omission compiler tests; execution is forbidden."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import core.behavior as behavior_package
import core.behavior.omission as omission_module
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.omission import (
    MINIMIZED_OMISSION_MODE,
    MinimizedOmissionCompiler,
)
from core.behavior.orchestrator import BehavioralShadowOrchestrator
from core.behavior.state_machine import StateMachineLegalityMiner

ORIGIN = "https://api.example.test"
WORKFLOW_ID = "workflow_7fa9f13a2b4c5d6e"
EXPORT_TOKEN = "token_4a5b6c7d8e9f0123"
SESSION_KEY = "session_1234567890abcdef"


def _records(
    *,
    terminal_query: str = f"exportToken={EXPORT_TOKEN}",
    approval_response=None,
    truncated: bool = False,
):
    return (
        {
            "id": "create-workflow",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows",
            "request_body": '{"label":"controlled"}',
            "response_status": 201,
            "response_body": json.dumps({"workflowId": WORKFLOW_ID}),
        },
        {
            "id": "approve-workflow",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/approve",
            "request_body": "{}",
            "response_status": 200,
            "response_body": json.dumps(
                approval_response or {"exportToken": EXPORT_TOKEN}
            ),
        },
        {
            "id": "export-workflow",
            "persona_id": "alice",
            "method": "GET",
            "url": (f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/export?{terminal_query}"),
            "response_status": 200,
            "response_body": '{"status":"ready","artifact":"controlled"}',
            "response_body_truncated": truncated,
        },
        {
            "id": "cleanup-workflow",
            "persona_id": "alice",
            "method": "PATCH",
            "url": f"{ORIGIN}/api/workflows/{WORKFLOW_ID}",
            "request_body": '{"archived":true}',
            "response_status": 200,
            "response_body": '{"archived":true}',
        },
    )


def _compile(records):
    lifecycle = LifecycleContractMiner().mine(records, world_id="alice")
    state_machine = StateMachineLegalityMiner().mine(records, world_id="alice")
    return MinimizedOmissionCompiler().compile(
        records,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
    )


def test_compiler_seals_one_exact_query_omission_without_authority():
    result = _compile(_records())

    assert result.status == "ready"
    assert result.mode == MINIMIZED_OMISSION_MODE
    assert result.executable is False
    assert result.finding_authority is False
    assert len(result.experiments) == 1
    experiment = result.experiments[0]
    assert experiment.mutation_kind == "remove_request_query_binding"
    assert experiment.consumer_locator_kind == "request_query"
    assert experiment.consumer_locator_pointer == "/exportToken/0"
    assert experiment.capability_key == "value:export_token"
    assert (
        experiment.omitted_prerequisite_operation_id
        in experiment.prerequisite_operation_ids
    )
    assert experiment.baseline_operation_ids == (
        *experiment.prerequisite_operation_ids,
        experiment.terminal_operation_id,
    )
    assert experiment.omission_operation_ids == tuple(
        item
        for item in experiment.baseline_operation_ids
        if item != experiment.omitted_prerequisite_operation_id
    )
    assert experiment.executable is False
    assert experiment.finding_authority is False
    assert experiment.oracle.comparison_kind == "exact_success_body_match"
    assert experiment.oracle.baseline_requirement == "captured_state_match"
    assert experiment.oracle.finding_authority is False
    assert set(experiment.execution_blockers) >= {
        "analysis_only_no_execution_authority",
        "prerequisite_execution_safety_unproven",
        "requires_two_fresh_owned_states",
    }


def test_compilation_is_deterministic_and_serialization_excludes_raw_values():
    first = _compile(_records())
    second = _compile(_records())

    assert first.to_dict() == second.to_dict()
    serialized = json.dumps(first.to_dict(), sort_keys=True)
    for raw in (
        ORIGIN,
        WORKFLOW_ID,
        EXPORT_TOKEN,
        "alice",
        "controlled",
    ):
        assert raw not in serialized


def test_multiple_sensitive_query_omissions_are_rejected_as_ambiguous():
    records = _records(
        terminal_query=(f"exportToken={EXPORT_TOKEN}&sessionKey={SESSION_KEY}"),
        approval_response={
            "exportToken": EXPORT_TOKEN,
            "sessionKey": SESSION_KEY,
        },
    )

    result = _compile(records)

    assert result.status == "no_experiments"
    assert result.experiments == ()
    assert result.diagnostics.ambiguous_omissions == 1


def test_skipped_prerequisite_cannot_feed_any_retained_operation():
    artifact_id = "artifact_1234567890abcdef"
    records = (
        _records()[0],
        {
            "id": "approve-workflow",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/approve",
            "request_body": "{}",
            "response_status": 200,
            "response_body": json.dumps(
                {"exportToken": EXPORT_TOKEN, "artifactId": artifact_id}
            ),
        },
        {
            "id": "export-workflow",
            "persona_id": "alice",
            "method": "GET",
            "url": (
                f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/artifacts/"
                f"{artifact_id}/export?exportToken={EXPORT_TOKEN}"
            ),
            "response_status": 200,
            "response_body": '{"status":"ready","artifact":"controlled"}',
        },
        _records()[-1],
    )

    result = _compile(records)

    assert result.status == "no_experiments"
    assert result.diagnostics.no_eligible_omission == 1


def test_compiler_requires_owned_create_read_cleanup_provenance():
    records = _records()[:-1]

    result = _compile(records)

    assert result.status == "no_experiments"
    assert result.diagnostics.no_owned_lifecycle == 1


def test_truncated_baseline_cannot_define_the_comparison_oracle():
    result = _compile(_records(truncated=True))

    assert result.status == "no_experiments"
    assert result.diagnostics.invalid_baselines == 1


def test_orchestrator_attaches_compiled_omission_as_non_actionable_resolution():
    result = BehavioralShadowOrchestrator().run(
        _records(),
        target_origin=ORIGIN,
        world_id="alice",
    )

    assert result.omissions.status == "ready"
    assert result.graph.diagnostics.omission_experiments == 1
    ranked = next(
        item for item in result.ranked_frontier if item.kind == "state_machine_legality"
    )
    assert ranked.resolution_kind == "omission_experiment"
    assert ranked.resolution_ref == result.omissions.experiments[0].experiment_id
    assert ranked.actionable is False
    assert "omission_proof_compiled" in ranked.signals
    assert result.selected is None


def test_omission_module_has_no_transport_or_execution_surface():
    tree = ast.parse(Path(omission_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
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
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert not hasattr(behavior_package, "MinimizedOmissionCompiler")
