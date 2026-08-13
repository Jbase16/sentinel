"""R5B2 graph-bound experiment specifications remain passive and fail closed."""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

import core.behavior as behavior_package
import core.behavior.prerequisite_experiments as experiment_module
from core.behavior.lifecycle import LifecycleContractMiner
from core.behavior.normalize import normalize_exchange
from core.behavior.orchestrator import BehavioralShadowOrchestrator
from core.behavior.prerequisite_experiments import (
    GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE,
    GraphBoundPrerequisiteExperimentCompiler,
    GraphBoundPrerequisiteExperimentSpec,
    PrerequisiteCounterfactualFamily,
    prerequisite_topology_support_matrix,
)
from core.behavior.state_machine import StateMachineLegalityMiner

ORIGIN = "https://api.example.test"
WORKFLOW_ID = "workflow_7fa9f13a2b4c5d6e"
EXPORT_TOKEN = "token_4a5b6c7d8e9f0123"
FIRST_TOKEN = "first_4a5b6c7d8e9f0123"
SECOND_TOKEN = "second_4a5b6c7d8e9f0123"
ARTIFACT_ID = "artifact_4a5b6c7d8e9f0123"
PRIVATE_MARKER = "private_marker_6e7f8a9b0c1d2e3f"


def _omission_records(*, truncated: bool = False, token_in_path: bool = False):
    export_location = (
        (
            f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/artifacts/"
            f"{ARTIFACT_ID}/export"
        )
        if token_in_path
        else (
            f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/export"
            f"?exportToken={EXPORT_TOKEN}"
        )
    )
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
                {"artifactId": ARTIFACT_ID}
                if token_in_path
                else {"exportToken": EXPORT_TOKEN}
            ),
        },
        {
            "id": "export-workflow",
            "persona_id": "alice",
            "method": "GET",
            "url": export_location,
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


def _branch_join_records():
    create = {
        "id": "create-workflow",
        "persona_id": "alice",
        "method": "POST",
        "url": f"{ORIGIN}/api/workflows",
        "request_body": json.dumps({"label": PRIVATE_MARKER}),
        "response_status": 201,
        "response_body": json.dumps({"workflowId": WORKFLOW_ID}),
    }
    independent = [
        {
            "id": "first-prerequisite",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/first",
            "response_status": 200,
            "response_body": json.dumps({"firstToken": FIRST_TOKEN}),
        },
        {
            "id": "second-prerequisite",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/second",
            "response_status": 200,
            "response_body": json.dumps({"secondToken": SECOND_TOKEN}),
        },
    ]
    independent.sort(
        key=lambda record: normalize_exchange(
            record,
            source_id=record["id"],
            world_id="alice",
        ).action_id
    )
    return (
        create,
        *independent,
        {
            "id": "export-workflow",
            "persona_id": "alice",
            "method": "GET",
            "url": (
                f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/export"
                f"?firstToken={FIRST_TOKEN}&secondToken={SECOND_TOKEN}"
            ),
            "response_status": 200,
            "response_body": json.dumps(
                {"status": "ready", "artifact": PRIVATE_MARKER}
            ),
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


def _compile(records, *, compiler=None):
    lifecycle = LifecycleContractMiner().mine(records, world_id="alice")
    state_machine = StateMachineLegalityMiner().mine(records, world_id="alice")
    result = (compiler or GraphBoundPrerequisiteExperimentCompiler()).compile(
        records,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
    )
    return lifecycle, state_machine, result


def test_support_matrix_is_complete_explicit_and_non_executable():
    matrix = prerequisite_topology_support_matrix()

    assert len(matrix) == 16
    assert {
        (item.graph_shape, item.family) for item in matrix
    } == {
        (shape, family)
        for shape in ("branching", "branching_joining", "joining", "linear")
        for family in PrerequisiteCounterfactualFamily
    }
    supported = {
        (item.graph_shape, item.family)
        for item in matrix
        if item.status == "supported"
    }
    assert supported == {
        ("linear", PrerequisiteCounterfactualFamily.OMISSION),
        ("joining", PrerequisiteCounterfactualFamily.OMISSION),
        ("branching_joining", PrerequisiteCounterfactualFamily.OMISSION),
        ("joining", PrerequisiteCounterfactualFamily.REORDERING),
        ("branching_joining", PrerequisiteCounterfactualFamily.REORDERING),
    }
    assert all(
        item.status == "deferred"
        for item in matrix
        if item.family
        in {
            PrerequisiteCounterfactualFamily.REPLAY,
            PrerequisiteCounterfactualFamily.STALE_STATE,
        }
    )
    assert all(not item.executable for item in matrix)


def test_compiler_seals_one_graph_bound_omission_with_fresh_cleanup_requirements():
    lifecycle, state_machine, result = _compile(_omission_records())

    assert result.status == "ready"
    assert result.mode == GRAPH_BOUND_PREREQUISITE_EXPERIMENT_MODE
    assert result.executable is False
    assert result.finding_authority is False
    assert len(result.specifications) == 1
    specification = result.specifications[0]
    candidate = state_machine.candidates[0]
    assert specification.state_machine_candidate_id == candidate.candidate_id
    assert specification.prerequisite_graph_id == candidate.prerequisite_graph.graph_id
    assert specification.graph_shape == "branching_joining"
    assert specification.delta.family is PrerequisiteCounterfactualFamily.OMISSION
    assert specification.delta.mutation_kind == "omit_isolated_prerequisite"
    assert specification.delta.consumer_locator_kind == "request_query"
    assert specification.delta.consumer_locator_pointer == "/exportToken/0"
    assert specification.delta.capability_key == "value:export_token"
    assert len(specification.delta.target_relation_ids) == 1
    assert len(specification.delta.target_binding_ids) == 1
    assert specification.delta.treatment_operation_ids == tuple(
        item
        for item in specification.delta.baseline_operation_ids
        if item not in specification.delta.target_operation_ids
    )

    fresh = specification.fresh_state
    assert fresh.fresh_instance_count == 3
    assert fresh.instance_roles == (
        "counterfactual_treatment",
        "independent_control",
        "valid_baseline",
    )
    assert fresh.distinct_owned_instances_required
    assert fresh.recreate_full_prerequisite_graph
    assert fresh.reference_state_match_required
    assert fresh.lifecycle_ids == tuple(
        item.lifecycle_id for item in lifecycle.candidates
    )

    cleanup = specification.cleanup
    assert cleanup.instances_per_lifecycle == 3
    assert cleanup.cleanup_each_fresh_instance
    assert cleanup.independent_verification_required
    assert cleanup.stop_on_uncertain_cleanup
    assert cleanup.bindings[0].cleanup_operation_id == (
        lifecycle.candidates[0].cleanup_operation_id
    )

    oracle = specification.oracle
    assert oracle.valid_baseline_required
    assert oracle.independent_control_required
    assert oracle.independent_effect_witness_required
    assert oracle.response_difference_sufficient is False
    assert oracle.finding_authority is False
    assert oracle.executable is False
    assert set(specification.execution_blockers) >= {
        "analysis_only_no_execution_authority",
        "experiment_admission_required",
        "fresh_controlled_state_required",
        "graph_bound_manifest_required",
        "graph_omission_backend_required",
        "independent_effect_oracle_required",
    }
    assert specification.admission_ready is False
    assert specification.finding_authority is False
    assert specification.executable is False


def test_non_linear_graph_compiles_two_omissions_and_one_independent_reordering():
    _, _, result = _compile(_branch_join_records())

    assert result.status == "ready"
    assert result.diagnostics.omission_specifications == 2
    assert result.diagnostics.reordering_specifications == 1
    assert len(result.specifications) == 3
    reordering = next(
        item
        for item in result.specifications
        if item.delta.family is PrerequisiteCounterfactualFamily.REORDERING
    )
    first, second = reordering.delta.target_operation_ids
    baseline = reordering.delta.baseline_operation_ids
    treatment = reordering.delta.treatment_operation_ids
    index = baseline.index(first)
    assert baseline[index + 1] == second
    assert treatment[index : index + 2] == (second, first)
    assert treatment[-1] == baseline[-1] == reordering.terminal_operation_id
    assert set(treatment) == set(baseline)
    assert len(reordering.delta.target_relation_ids) >= 2
    assert reordering.delta.capability_key is None
    assert "graph_reordering_backend_required" in reordering.execution_blockers


def test_compilation_is_deterministic_and_public_artifact_is_redacted():
    first = _compile(_branch_join_records())[2]
    second = _compile(_branch_join_records())[2]

    assert first.to_dict() == second.to_dict()
    encoded = json.dumps(first.to_dict(), sort_keys=True)
    for raw in (
        ORIGIN,
        WORKFLOW_ID,
        EXPORT_TOKEN,
        FIRST_TOKEN,
        SECOND_TOKEN,
        ARTIFACT_ID,
        "alice",
        PRIVATE_MARKER,
    ):
        assert raw not in encoded


def test_missing_cleanup_or_truncated_baseline_cannot_produce_a_specification():
    without_cleanup = _compile(_omission_records()[:-1])[2]
    truncated = _compile(_omission_records(truncated=True))[2]

    assert without_cleanup.status == "no_specifications"
    assert without_cleanup.diagnostics.no_owned_lifecycle == 1
    assert truncated.status == "no_specifications"
    assert truncated.diagnostics.invalid_baselines == 1


def test_path_bound_prerequisite_is_not_treated_as_safely_removable():
    _, _, result = _compile(_omission_records(token_in_path=True))

    assert result.status == "no_specifications"
    assert result.diagnostics.unsupported_locator_relations == 1


@pytest.mark.parametrize(
    ("request_body", "headers", "locator_kind", "locator_pointer"),
    (
        (
            json.dumps({"exportToken": EXPORT_TOKEN}),
            {"content-type": "application/json"},
            "request_json",
            "/exportToken",
        ),
        (
            f"exportToken={EXPORT_TOKEN}",
            {"content-type": "application/x-www-form-urlencoded"},
            "request_form",
            "/exportToken/0",
        ),
    ),
)
def test_json_and_form_bindings_produce_exact_passive_omission_deltas(
    request_body,
    headers,
    locator_kind,
    locator_pointer,
):
    records = list(_omission_records())
    records[2] = {
        **records[2],
        "url": f"{ORIGIN}/api/workflows/{WORKFLOW_ID}/export",
        "request_body": request_body,
        "headers": headers,
    }

    result = _compile(tuple(records))[2]

    assert result.status == "ready"
    assert len(result.specifications) == 1
    delta = result.specifications[0].delta
    assert delta.consumer_locator_kind == locator_kind
    assert delta.consumer_locator_pointer == locator_pointer


def test_deferred_matrix_rule_cannot_be_used_to_build_a_specification():
    lifecycle, state_machine, result = _compile(_omission_records())
    specification = result.specifications[0]
    deferred = next(
        item
        for item in result.support_matrix
        if item.graph_shape == specification.graph_shape
        and item.family is PrerequisiteCounterfactualFamily.REPLAY
    )

    with pytest.raises(ValueError, match="does not admit"):
        GraphBoundPrerequisiteExperimentSpec.build(
            candidate=state_machine.candidates[0],
            support_rule=deferred,
            delta=specification.delta,
            fresh_state=specification.fresh_state,
            cleanup=specification.cleanup,
            execution_blockers=specification.execution_blockers,
        )
    assert lifecycle.status == "ready"


def test_content_addressing_rejects_a_relabelled_delta():
    specification = _compile(_omission_records())[2].specifications[0]

    with pytest.raises(ValueError, match="counterfactual delta is invalid"):
        replace(
            specification.delta,
            mutation_kind="swap_adjacent_independent_prerequisites",
        )


def test_specification_limit_is_fixed_and_truncation_stays_visible():
    compiler = GraphBoundPrerequisiteExperimentCompiler(max_specifications=1)
    result = _compile(_branch_join_records(), compiler=compiler)[2]

    assert result.status == "ready"
    assert len(result.specifications) == 1
    assert result.diagnostics.dropped_specifications == 2
    assert result.diagnostics.incomplete_work == 2
    with pytest.raises(ValueError, match="exceeds the R5B2 contract"):
        GraphBoundPrerequisiteExperimentCompiler(max_specifications=65)


def test_ordinary_shadow_run_carries_passive_specs_without_new_resolution_authority():
    first = BehavioralShadowOrchestrator().run(
        _omission_records(),
        target_origin=ORIGIN,
        world_id="alice",
    )
    second = BehavioralShadowOrchestrator().run(
        _omission_records(),
        target_origin=ORIGIN,
        world_id="alice",
    )

    assert first.prerequisite_experiments.status == "ready"
    assert len(first.prerequisite_experiments.specifications) == 1
    assert first.run_id == second.run_id
    assert first.to_dict() == second.to_dict()
    assert first.prerequisite_experiments.executable is False
    assert first.prerequisite_experiments.finding_authority is False
    assert first.selected is not None
    assert first.selected.resolution_kind == "omission_experiment"


def test_analysis_module_has_no_transport_or_execution_surface():
    tree = ast.parse(Path(experiment_module.__file__).read_text())
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
    assert not hasattr(
        behavior_package,
        "GraphBoundPrerequisiteExperimentCompiler",
    )
