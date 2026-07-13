"""Backward exploit compiler tests; the compiler has no transport by design."""

from __future__ import annotations

import json

import pytest

from core.behavior.compiler import (
    ANALYSIS_ONLY_MODE,
    BackwardExploitCompiler,
    BackwardGoal,
    Capability,
    CapabilityKind,
    CompilerLimits,
    CompilerPolicy,
    OperationCatalogLimits,
    OperationContract,
    OperationSafety,
    high_value_goals,
    operation_contracts_from_records,
)


def _cap(name: str, kind: CapabilityKind = CapabilityKind.RESOURCE) -> Capability:
    return Capability(kind, name)


def _operation(
    operation_id: str,
    *,
    requires=(),
    produces=(),
    safety=OperationSafety.READ_ONLY,
    cost=1,
    cleanup_operation_id=None,
):
    return OperationContract(
        operation_id=operation_id,
        label=operation_id,
        requires=tuple(requires),
        produces=tuple(produces),
        safety=safety,
        cost=cost,
        observed_success=True,
        cleanup_operation_id=cleanup_operation_id,
    )


def test_compiler_builds_minimum_prerequisite_chain_and_never_executes():
    account = _cap("account", CapabilityKind.CONTEXT)
    product = _cap("product")
    address = _cap("address")
    cart = _cap("cart")
    order = _cap("order")
    invoice = _cap("invoice")
    document = _cap("document")
    operations = (
        _operation(
            "create_cart",
            requires=(account, product),
            produces=(cart,),
            safety=OperationSafety.OWNED_REVERSIBLE_WRITE,
            cleanup_operation_id="delete_cart",
        ),
        _operation(
            "create_order",
            requires=(account, cart, address),
            produces=(order,),
            safety=OperationSafety.OWNED_REVERSIBLE_WRITE,
            cleanup_operation_id="cancel_order",
        ),
        _operation(
            "complete_order",
            requires=(account, order),
            produces=(invoice,),
            safety=OperationSafety.OWNED_REVERSIBLE_WRITE,
            cleanup_operation_id="void_test_order",
        ),
        _operation(
            "export_invoice",
            requires=(account, invoice),
            produces=(document,),
        ),
    )
    compiler = BackwardExploitCompiler(operations)

    plan = compiler.compile(
        BackwardGoal("prove_invoice_export", "export_invoice", (document,)),
        initial_capabilities=(account, product, address),
    )

    assert plan.status == "planned"
    assert plan.step_ids == (
        "create_cart",
        "create_order",
        "complete_order",
        "export_invoice",
    )
    assert plan.missing_capabilities == ()
    assert plan.execution_blockers == ("analysis_only_no_execution_authority",)
    assert plan.mode == ANALYSIS_ONLY_MODE
    assert plan.executable is False


def test_compiler_reports_an_exact_missing_capability():
    secret = _cap("download_token", CapabilityKind.VALUE)
    terminal = _operation("download_backup", requires=(secret,), produces=(_cap("backup"),))

    plan = BackwardExploitCompiler((terminal,)).compile(
        BackwardGoal("download", "download_backup")
    )

    assert plan.status == "blocked"
    assert plan.missing_capabilities == (secret,)
    assert f"no_producer:{secret.key}" in plan.execution_blockers
    assert plan.executable is False


def test_compiler_rejects_a_dependency_cycle_without_a_bootstrap_capability():
    capability_a = _cap("a")
    capability_b = _cap("b")
    operations = (
        _operation("make_a", requires=(capability_b,), produces=(capability_a,)),
        _operation("make_b", requires=(capability_a,), produces=(capability_b,)),
        _operation("terminal", requires=(capability_a,), produces=(_cap("result"),)),
    )

    plan = BackwardExploitCompiler(operations).compile(
        BackwardGoal("cycle", "terminal")
    )

    assert plan.status == "blocked"
    assert any(item.startswith("cyclic_or_unreachable:") for item in plan.execution_blockers)
    assert plan.executable is False


def test_compiler_prefers_a_safe_observed_producer_over_a_shorter_unknown_one():
    token = _cap("job_token", CapabilityKind.VALUE)
    operations = (
        _operation(
            "unknown_shortcut",
            produces=(token,),
            safety=OperationSafety.UNKNOWN,
            cost=1,
        ),
        _operation("safe_observed_path", produces=(token,), cost=9),
        _operation("download_result", requires=(token,), produces=(_cap("result"),)),
    )
    compiler = BackwardExploitCompiler(tuple(reversed(operations)))

    plan = compiler.compile(BackwardGoal("safe_path", "download_result"))

    assert plan.step_ids == ("safe_observed_path", "download_result")
    assert not any("unknown_shortcut" in blocker for blocker in plan.execution_blockers)


def test_compiler_plan_is_deterministic_across_catalog_order():
    project = _cap("project")
    artifact = _cap("artifact")
    operations = (
        _operation("create_project", produces=(project,)),
        _operation("export_project", requires=(project,), produces=(artifact,)),
    )
    goal = BackwardGoal("export", "export_project", (artifact,))

    first = BackwardExploitCompiler(operations).compile(goal)
    second = BackwardExploitCompiler(tuple(reversed(operations))).compile(goal)

    assert first.step_ids == second.step_ids
    assert first.plan_id == second.plan_id
    assert first.to_dict() == second.to_dict()


def test_capture_adapter_connects_observed_producer_to_sink_without_raw_values():
    invoice_id = "inv_7fa9f13a2b4c5d6e"
    private_url = "https://api.example.test/private/export/result-91"
    records = (
        {
            "id": "create-capture",
            "method": "POST",
            "url": "https://api.example.test/api/invoices",
            "request_body": '{"memo":"controlled test"}',
            "response_status": 201,
            "response_body": json.dumps({"invoiceId": invoice_id}),
        },
        {
            "id": "export-capture",
            "method": "GET",
            "url": f"https://api.example.test/api/invoices/{invoice_id}/export",
            "response_status": 200,
            "response_body": json.dumps({"downloadUrl": private_url}),
        },
    )

    operations = operation_contracts_from_records(records)
    goals = high_value_goals(operations)

    assert len(operations) == 2
    assert len(goals) == 1
    plan = BackwardExploitCompiler(operations).compile(goals[0])
    serialized = json.dumps(
        {
            "operations": [operation.to_dict() for operation in operations],
            "plan": plan.to_dict(),
        },
        sort_keys=True,
    )
    assert plan.status == "planned"
    assert len(plan.step_ids) == 2
    assert plan.step_ids[-1] == goals[0].terminal_operation_id
    assert any(blocker.endswith(":unknown") for blocker in plan.execution_blockers)
    assert invoice_id not in serialized
    assert private_url not in serialized
    assert "controlled test" not in serialized


def test_capture_adapter_links_graphql_camel_case_fields_by_semantic_capability():
    invoice_id = "inv_3fd818292f61408a"
    records = (
        {
            "method": "POST",
            "url": "https://api.example.test/graphql",
            "request_body": json.dumps(
                {"operationName": "CreateInvoice", "variables": {"memo": "test"}}
            ),
            "response_status": 200,
            "response_body": json.dumps(
                {"data": {"createInvoice": {"invoice": {"id": invoice_id}}}}
            ),
        },
        {
            "method": "POST",
            "url": "https://api.example.test/graphql",
            "request_body": json.dumps(
                {
                    "operationName": "ExportInvoice",
                    "variables": {"invoiceId": invoice_id},
                }
            ),
            "response_status": 200,
            "response_body": json.dumps({"data": {"exportInvoice": {"url": "/owned"}}}),
        },
    )

    operations = operation_contracts_from_records(records)
    goal = high_value_goals(operations)[0]
    plan = BackwardExploitCompiler(operations).compile(goal)

    assert sorted(operation.label for operation in operations) == [
        "CreateInvoice",
        "ExportInvoice",
    ]
    assert plan.status == "planned"
    assert len(plan.step_ids) == 2
    assert any(blocker.endswith(":unknown") for blocker in plan.execution_blockers)


def test_capture_adapter_redacts_short_unknown_path_segments():
    operations = operation_contracts_from_records(
        (
            {
                "method": "GET",
                "url": "https://api.example.test/api/users/alice/export",
                "response_status": 200,
                "response_body": "{}",
            },
        )
    )

    assert operations[0].label == "GET /api/users/{value}/export"
    assert "alice" not in json.dumps(operations[0].to_dict())


def test_capture_adapter_rejects_oversized_input_before_normalization():
    limits = OperationCatalogLimits(max_body_chars=8)
    records = (
        {
            "method": "GET",
            "url": "https://api.example.test/status",
            "response_status": 200,
            "response_body": "123456789",
        },
    )

    with pytest.raises(ValueError, match="response_body exceeds max_body_chars"):
        operation_contracts_from_records(records, limits=limits)


def test_plan_identity_commits_to_catalog_and_policy():
    token = _cap("token", CapabilityKind.VALUE)
    terminal = _operation("use_token", requires=(token,), produces=(_cap("result"),))
    observed = _operation("mint_token", produces=(token,), cost=1)
    changed_cost = _operation("mint_token", produces=(token,), cost=2)

    first = BackwardExploitCompiler((observed, terminal)).compile(
        BackwardGoal("identity", "use_token")
    )
    catalog_changed = BackwardExploitCompiler((changed_cost, terminal)).compile(
        BackwardGoal("identity", "use_token")
    )
    policy_changed = BackwardExploitCompiler(
        (observed, terminal),
        policy=CompilerPolicy(require_observed_success=False),
    ).compile(BackwardGoal("identity", "use_token"))

    assert first.catalog_digest != catalog_changed.catalog_digest
    assert first.plan_id != catalog_changed.plan_id
    assert first.policy_digest != policy_changed.policy_digest
    assert first.plan_id != policy_changed.plan_id


def test_owned_write_without_cleanup_is_explicitly_blocked_for_execution():
    job = _cap("job")
    operations = (
        _operation(
            "create_job",
            produces=(job,),
            safety=OperationSafety.OWNED_REVERSIBLE_WRITE,
        ),
        _operation("read_job", requires=(job,), produces=(_cap("result"),)),
    )

    plan = BackwardExploitCompiler(operations).compile(
        BackwardGoal("cleanup", "read_job")
    )

    assert "cleanup_required:create_job" in plan.execution_blockers
    assert plan.executable is False


def test_search_budget_exhaustion_is_reported_instead_of_returning_partial_success():
    target = _cap("target")
    operations = (
        _operation("producer_a", requires=(_cap("missing_a"),), produces=(target,)),
        _operation("producer_b", requires=(_cap("missing_b"),), produces=(target,)),
        _operation("terminal", requires=(target,), produces=(_cap("result"),)),
    )
    compiler = BackwardExploitCompiler(
        operations,
        limits=CompilerLimits(max_search_states=1),
    )

    plan = compiler.compile(BackwardGoal("bounded", "terminal"))

    assert plan.status == "blocked"
    assert plan.search_exhausted is True
    assert "max_search_states_reached" in plan.execution_blockers


def test_goal_output_must_be_produced_by_the_terminal_operation():
    terminal = _operation("export", produces=(_cap("document"),))
    impossible = _cap("admin_session", CapabilityKind.CONTEXT)

    plan = BackwardExploitCompiler((terminal,)).compile(
        BackwardGoal("invalid_goal", "export", (impossible,))
    )

    assert plan.status == "blocked"
    assert plan.missing_capabilities == (impossible,)
    assert "terminal_does_not_produce_required_output" in plan.execution_blockers


def test_unknown_terminal_is_a_deterministic_blocked_result():
    goal = BackwardGoal("missing", "not_in_catalog")

    first = BackwardExploitCompiler(()).compile(goal)
    second = BackwardExploitCompiler(()).compile(goal)

    assert first.status == "blocked"
    assert first.execution_blockers == (
        "analysis_only_no_execution_authority",
        "terminal_operation_not_found",
    )
    assert first.plan_id == second.plan_id
