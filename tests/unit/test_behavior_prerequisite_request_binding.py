import ast
import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from core.behavior.normalize import stable_hash
from core.behavior.orchestrator import (
    BehavioralShadowOrchestrator,
    OwnedExperimentShadowContext,
)
from core.behavior.prerequisite_admission import (
    GraphBoundManifestAdmissionPlanner,
)
from core.behavior.prerequisite_request_binding import GraphBoundRequestBinder
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink
from tests.unit.test_behavior_prerequisite_admission import _authorization
from tests.unit.test_behavior_prerequisite_experiments import (
    FIRST_TOKEN,
    ORIGIN,
    SECOND_TOKEN,
    _branch_join_records,
    _compile,
)


def _executor(
    *,
    scope=True,
    max_total_requests=96,
    max_requests_per_endpoint=20,
):
    calls = []
    scope_calls = []

    async def forbidden_transport(method, url, body=None, **kwargs):
        calls.append((method, url, body, kwargs))
        raise AssertionError("request binding must never invoke transport")

    def scope_filter(url):
        scope_calls.append(url)
        return scope and url.startswith(ORIGIN)

    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=scope_filter,
        budget=ProofBudget(
            max_total_requests=max_total_requests,
            max_requests_per_endpoint=max_requests_per_endpoint,
            max_creates=20,
            allow_real_user_data_access=False,
        ),
        ownership_registry=OwnershipRegistry(),
    )
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe",
        policy_digest=policy.digest(),
    )
    return (
        PolicyExecutor(forbidden_transport, policy, provenance=provenance),
        calls,
        scope_calls,
    )


def _context(records=None, *, executor=None):
    records = tuple(records or _branch_join_records())
    lifecycle, state_machine, compilation = _compile(records)
    executor = executor or _executor()[0]
    admission = GraphBoundManifestAdmissionPlanner().plan(
        compilation=compilation,
        target_origin=ORIGIN,
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        world_id="alice",
        authorization=_authorization(),
        executor=executor,
        actor_persona_id="alice",
    )
    assert admission.status == "ready_for_explicit_execution_boundary"
    result = GraphBoundRequestBinder().bind(
        records,
        target_origin=ORIGIN,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
        compilation=compilation,
        admission=admission,
        executor=executor,
    )
    return records, lifecycle, state_machine, compilation, admission, result


def test_omission_plan_seals_cross_world_effect_witness_override():
    *_context_values, result = _context()
    plan = next(item for item in result.plans if item.family == "omission")
    terminal_operation_id = plan.baseline_operation_ids[-1]
    terminal = {
        phase: next(
            item
            for item in plan.request_bindings
            if item.phase == phase
            and item.operation_id == terminal_operation_id
        )
        for phase in ("baseline", "treatment", "control")
    }
    baseline_ids = set(terminal["baseline"].input_binding_ids)
    treatment_ids = set(terminal["treatment"].input_binding_ids)
    witness = terminal["control"]

    assert baseline_ids - treatment_ids == {
        witness.runtime_override_binding_id
    }
    assert witness.input_binding_ids == terminal["baseline"].input_binding_ids
    assert witness.runtime_override_source_world_slot_id == (
        terminal["baseline"].world_slot_id
    )
    assert witness.runtime_override_source_world_slot_id != witness.world_slot_id
    assert witness.runtime_override_source_create_operation_id is not None
    assert witness.request_mutation_ref is None
    assert sum(
        item.runtime_override_binding_id is not None
        for item in plan.request_bindings
    ) == 1


def test_binder_reconstructs_exact_sequences_and_endpoint_budget_entries():
    executor, calls, scope_calls = _executor()
    _records, _lifecycle, _state, compilation, admission, result = _context(
        executor=executor
    )

    assert result.status == "ready_for_single_use_execution_claim"
    assert len(result.plans) == len(admission.manifests) == 3
    assert result.compilation_result_id == compilation.result_id
    assert result.request_bindings_complete is True
    assert result.policy_preflight_complete is True
    assert result.budget_preview_only is True
    assert result.budget_reserved is False
    assert result.dispatch_authority is False
    assert result.finding_authority is False
    assert result.target_requests_sent == 0
    assert result.executable is False
    assert calls == []
    assert scope_calls

    for plan in result.plans:
        expected_units = next(
            item.budget.total_request_units
            for item in admission.manifests
            if item.manifest_id == plan.manifest_id
        )
        assert len(plan.request_bindings) == expected_units
        assert len(plan.budget_bindings) == expected_units
        assert tuple(item.ordinal for item in plan.request_bindings) == tuple(
            range(expected_units)
        )
        assert all(item.policy_allowed for item in plan.request_bindings)
        assert all(not item.reserved for item in plan.budget_bindings)
        terminal_operation_id = plan.baseline_operation_ids[-1]
        stages = tuple(
            (
                item.phase
                if item.phase in {"cleanup", "cleanup_verification"}
                else (
                    "dispatch"
                    if item.operation_id == terminal_operation_id
                    else "provision"
                )
            )
            for item in plan.request_bindings
        )
        assert stages == tuple(
            sorted(
                stages,
                key={
                    "provision": 0,
                    "dispatch": 1,
                    "cleanup": 2,
                    "cleanup_verification": 3,
                }.__getitem__,
            )
        )
        expected_terminal_roles = (
            (
                "independent_control",
                "valid_baseline",
                "counterfactual_treatment",
            )
            if plan.family == "omission"
            else (
                "valid_baseline",
                "counterfactual_treatment",
                "independent_control",
            )
        )
        assert tuple(
            item.world_role
            for item in plan.request_bindings
            if item.phase in {"baseline", "treatment", "control"}
            and item.operation_id == terminal_operation_id
        ) == expected_terminal_roles
        assert "endpoint_budget_bindings_not_compiled" not in (
            plan.remaining_execution_blockers
        )
        assert "per_action_policy_preflight_not_completed" not in (
            plan.remaining_execution_blockers
        )
        assert "atomic_budget_not_reserved" in plan.remaining_execution_blockers
        assert "single_use_receipt_not_acquired" in (
            plan.remaining_execution_blockers
        )


def test_omission_removes_only_the_bound_query_and_reordering_changes_only_order():
    _records, _lifecycle, _state, _compilation, _admission, result = _context()
    omissions = [item for item in result.plans if item.family == "omission"]
    reordering = next(item for item in result.plans if item.family == "reordering")

    assert len(omissions) == 2
    for plan in omissions:
        mutations = [
            item
            for item in plan.request_bindings
            if item.request_mutation_ref is not None
        ]
        assert len(mutations) == 2
        mutation = next(item for item in mutations if item.phase == "treatment")
        assert mutation.phase == "treatment"
        assert mutation.operation_id == plan.treatment_operation_ids[-1]
        raw = next(
            item.request
            for item in plan.ephemeral_requests
            if item.binding_id == mutation.binding_id
        )
        query = dict(parse_qsl(urlsplit(raw.url).query, keep_blank_values=True))
        assert len(query) == 1
        assert set(query.values()) in ({FIRST_TOKEN}, {SECOND_TOKEN})
        verification = next(
            item
            for item in mutations
            if item.phase == "cleanup_verification"
        )
        assert verification.world_role == "counterfactual_treatment"
        assert verification.request_template_ref == mutation.request_template_ref
        assert tuple(
            item.operation_id
            for item in plan.request_bindings
            if item.phase == "treatment"
        ) == plan.treatment_operation_ids

    assert all(
        item.request_mutation_ref is None for item in reordering.request_bindings
    )
    assert reordering.treatment_operation_ids != reordering.baseline_operation_ids
    assert set(reordering.treatment_operation_ids) == set(
        reordering.baseline_operation_ids
    )


@pytest.mark.parametrize("content_type", ("json", "form"))
def test_omission_mutates_the_exact_json_or_form_locator(content_type):
    records = list(_branch_join_records())
    terminal = dict(records[3])
    terminal["url"] = terminal["url"].split("?", 1)[0]
    if content_type == "json":
        terminal["headers"] = {"content-type": "application/json"}
        terminal["request_body"] = json.dumps(
            {"firstToken": FIRST_TOKEN, "secondToken": SECOND_TOKEN}
        )
    else:
        terminal["headers"] = {
            "content-type": "application/x-www-form-urlencoded"
        }
        terminal["request_body"] = (
            f"firstToken={FIRST_TOKEN}&secondToken={SECOND_TOKEN}"
        )
    records[3] = terminal

    _records, _lifecycle, _state, _compilation, _admission, result = _context(
        tuple(records)
    )

    omissions = [item for item in result.plans if item.family == "omission"]
    assert len(omissions) == 2
    for plan in omissions:
        mutation = next(
            item
            for item in plan.request_bindings
            if item.request_mutation_ref is not None
        )
        raw = next(
            item.request
            for item in plan.ephemeral_requests
            if item.binding_id == mutation.binding_id
        )
        if content_type == "json":
            remaining = json.loads(raw.body)
        else:
            remaining = dict(parse_qsl(raw.body, keep_blank_values=True))
        assert len(remaining) == 1
        assert set(remaining.values()) in ({FIRST_TOKEN}, {SECOND_TOKEN})


def test_raw_requests_and_endpoint_keys_are_redacted_from_public_artifact():
    records, _lifecycle, _state, _compilation, admission, result = _context()

    public = json.dumps(result.to_dict(), sort_keys=True)
    assert FIRST_TOKEN not in public
    assert SECOND_TOKEN not in public
    assert records[0]["url"] not in public
    assert admission.authorization_ref not in public
    assert "ephemeral_requests" not in public
    assert "endpoint_key_value" not in public
    assert repr(result.plans[0].ephemeral_requests[0]).endswith(
        "raw_request=REDACTED)"
    )


def test_binding_is_deterministic_and_content_addressed():
    executor, calls, _scope_calls = _executor()
    context = _context(executor=executor)
    records, lifecycle, state_machine, compilation, admission, first = context

    second = GraphBoundRequestBinder().bind(
        records,
        target_origin=ORIGIN,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
        compilation=compilation,
        admission=admission,
        executor=executor,
    )

    assert first.to_dict() == second.to_dict()
    assert calls == []
    with pytest.raises(ValueError, match="prepared request plan is invalid"):
        replace(first.plans[0], target_requests_sent=1)
    with pytest.raises(ValueError, match="binding result is invalid"):
        replace(first, dispatch_authority=True)


def test_policy_denial_fails_closed_without_touching_transport_or_budget():
    executor, calls, scope_calls = _executor(scope=False)
    _records, _lifecycle, _state, _compilation, _admission, result = _context(
        executor=executor
    )

    assert result.status == "no_bindable_manifests"
    assert result.plans == ()
    assert result.diagnostics.policy_denials == 3
    assert result.diagnostics.budget_denials == 0
    assert executor.policy.budget.snapshot()["total_requests"] == 0
    assert scope_calls
    assert calls == []


def test_exact_budget_preview_fails_per_endpoint_without_reserving():
    executor, calls, _scope_calls = _executor(max_requests_per_endpoint=2)
    _records, _lifecycle, _state, _compilation, _admission, result = _context(
        executor=executor
    )

    assert result.status == "no_bindable_manifests"
    assert result.plans == ()
    assert result.diagnostics.budget_denials == 3
    assert executor.policy.budget.snapshot()["total_requests"] == 0
    assert calls == []


def test_binding_preview_does_not_steal_the_later_atomic_reservation():
    executor, calls, _scope_calls = _executor()
    _records, _lifecycle, _state, _compilation, _admission, result = _context(
        executor=executor
    )
    plan = result.plans[0]
    sequence = tuple(
        (binding.action_class, raw.endpoint_key_value)
        for binding, raw in zip(plan.request_bindings, plan.ephemeral_requests)
    )

    reservation_id, reason = executor.policy.budget.try_reserve(sequence)

    assert reason == "ok" and reservation_id is not None
    assert executor.policy.budget.reservation_remaining(reservation_id) == len(
        sequence
    )
    assert executor.policy.budget.release_reservation(reservation_id) == len(
        sequence
    )
    assert calls == []


def test_changed_capture_cannot_reuse_the_old_admission_manifest():
    records, lifecycle, state_machine, compilation, admission, _result = _context()
    changed = list(records)
    changed[3] = {**changed[3], "response_status": 204}
    executor, calls, _scope_calls = _executor()

    result = GraphBoundRequestBinder().bind(
        tuple(changed),
        target_origin=ORIGIN,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
        compilation=compilation,
        admission=admission,
        executor=executor,
    )

    assert result.status == "capture_mismatch"
    assert result.plans == ()
    assert result.blocker == "graph_bound_request_capture_changed"
    assert calls == []

    cleanup_changed = list(records)
    cleanup_changed[4] = {
        **cleanup_changed[4],
        "request_body": '{"archived":false}',
    }
    cleanup_result = GraphBoundRequestBinder().bind(
        tuple(cleanup_changed),
        target_origin=ORIGIN,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
        compilation=compilation,
        admission=admission,
        executor=executor,
    )
    assert cleanup_result.status == "capture_mismatch"
    assert cleanup_result.plans == ()
    assert cleanup_result.blocker == "graph_bound_request_capture_changed"
    assert calls == []


def test_non_ready_static_admission_does_not_require_or_invoke_policy():
    records = _branch_join_records()
    lifecycle, state_machine, compilation = _compile(records)
    admission = GraphBoundManifestAdmissionPlanner().plan(
        compilation=compilation,
        target_origin=ORIGIN,
        target_ref=stable_hash("security_obligation_target", ORIGIN),
        world_id="alice",
    )

    result = GraphBoundRequestBinder().bind(
        records,
        target_origin=ORIGIN,
        world_id="alice",
        lifecycle=lifecycle,
        state_machine=state_machine,
        compilation=compilation,
        admission=admission,
    )

    assert result.status == "admission_not_ready"
    assert result.plans == ()
    assert result.policy_ref is None


def test_ordinary_shadow_run_carries_bound_requests_without_dispatching_them():
    executor, calls, scope_calls = _executor()
    orchestrator = BehavioralShadowOrchestrator()

    passive = orchestrator.run(
        _branch_join_records(),
        target_origin=ORIGIN,
        world_id="alice",
    )
    prepared = orchestrator.run(
        _branch_join_records(),
        target_origin=ORIGIN,
        world_id="alice",
        experiment_context=OwnedExperimentShadowContext(
            authorization=_authorization(),
            actor_persona_id="alice",
            executor=executor,
        ),
    )

    assert passive.prerequisite_requests.status == "admission_not_ready"
    assert prepared.prerequisite_requests.status == (
        "ready_for_single_use_execution_claim"
    )
    assert len(prepared.prerequisite_requests.plans) == 3
    assert prepared.to_dict()["prerequisite_requests"] == (
        prepared.prerequisite_requests.to_dict()
    )
    assert "ephemeral_requests" not in json.dumps(prepared.to_dict())
    assert prepared.prerequisite_requests.budget_reserved is False
    assert prepared.prerequisite_requests.dispatch_authority is False
    assert prepared.prerequisite_requests.target_requests_sent == 0
    assert scope_calls
    assert calls == []


def test_request_binding_module_has_no_execution_or_transport_surface():
    source_path = (
        Path(__file__).parents[2]
        / "core"
        / "behavior"
        / "prerequisite_request_binding.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
    assert "raw_send" not in source
    assert ".execute(" not in source
    assert ".try_reserve(" not in source
    assert "PolicyExecutor(" not in source
