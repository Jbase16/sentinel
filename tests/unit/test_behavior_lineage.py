"""Exact value-lineage and transport-free rehydration tests."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from core.behavior.compiler import BackwardExploitCompiler, high_value_goals
from core.behavior.lineage import (
    LocatorKind,
    PlanRehydrator,
    RehydrationDenied,
    ValueLineageLedger,
    ValueLocator,
)

ORIGIN = "https://api.example.test"
INVOICE_ID = "inv_7fa9f13a2b4c5d6e"


def _rest_records(*, persona_id="alice", invoice_id=INVOICE_ID):
    return (
        {
            "id": "create-invoice",
            "persona_id": persona_id,
            "method": "POST",
            "url": f"{ORIGIN}/api/invoices",
            "request_body": '{"memo":"private controlled marker"}',
            "response_status": 201,
            "response_body": json.dumps({"invoiceId": invoice_id}),
        },
        {
            "id": "export-invoice",
            "persona_id": persona_id,
            "method": "GET",
            "url": f"{ORIGIN}/api/invoices/{invoice_id}/export",
            "request_headers": {"Authorization": "Bearer private-session-secret"},
            "response_status": 200,
            "response_body": json.dumps({"downloadUrl": "/owned/result"}),
        },
    )


def _plan(ledger: ValueLineageLedger):
    goal = high_value_goals(ledger.operations)[0]
    return BackwardExploitCompiler(ledger.operations).compile(goal)


def test_ledger_builds_exact_same_world_producer_to_consumer_binding():
    ledger = ValueLineageLedger(_rest_records())

    assert len(ledger.bindings) == 1
    binding = ledger.bindings[0]
    assert binding.capability.name == "invoice_id"
    assert binding.producer_locator == ValueLocator(
        LocatorKind.RESPONSE_JSON,
        "/invoiceId",
    )
    assert binding.consumer_locator == ValueLocator(
        LocatorKind.REQUEST_PATH,
        "/segments/2",
    )
    assert binding.sensitive is False


def test_recipe_rehydrates_exact_captured_request_but_has_no_execution_authority():
    ledger = ValueLineageLedger(_rest_records())
    plan = _plan(ledger)
    rehydrator = PlanRehydrator(ledger)
    recipe = rehydrator.build_recipe(plan, world_id="alice")

    assert recipe.status == "ready"
    assert recipe.executable is False
    assert recipe.mode == "analysis_only"
    assert len(recipe.bindings) == 1
    assert "analysis_only_no_execution_authority" in recipe.execution_blockers

    terminal = rehydrator.rehydrate_step(recipe, plan.terminal_operation_id)

    assert terminal.url.endswith(f"/{INVOICE_ID}/export")
    assert terminal.headers["Authorization"] == "Bearer private-session-secret"
    assert INVOICE_ID not in repr(terminal)
    assert "private-session-secret" not in repr(terminal)
    assert terminal.redacted_summary()["mode"] == "analysis_only"


def test_public_snapshots_and_recipes_never_serialize_raw_values_or_secrets():
    ledger = ValueLineageLedger(_rest_records())
    recipe = PlanRehydrator(ledger).build_recipe(_plan(ledger), world_id="alice")

    serialized = json.dumps(
        {"ledger": ledger.snapshot(), "recipe": recipe.to_dict()},
        sort_keys=True,
    )

    assert INVOICE_ID not in serialized
    assert "private controlled marker" not in serialized
    assert "private-session-secret" not in serialized
    assert ORIGIN not in serialized


def test_value_hashes_are_capture_salted_and_not_cross_run_correlators():
    first = ValueLineageLedger(_rest_records())
    changed = list(_rest_records())
    changed[0] = {
        **changed[0],
        "request_body": '{"memo":"a different controlled marker"}',
    }
    second = ValueLineageLedger(tuple(changed))

    assert first.bindings[0].capability == second.bindings[0].capability
    assert first.capture_digest != second.capture_digest
    assert first.bindings[0].value_hash != second.bindings[0].value_hash


def test_multiple_exact_producer_locations_are_ambiguous_and_fail_closed():
    records = list(_rest_records())
    records[0] = {
        **records[0],
        "response_body": json.dumps(
            {"invoiceId": INVOICE_ID, "invoice": {"id": INVOICE_ID}}
        ),
    }
    ledger = ValueLineageLedger(tuple(records))
    recipe = PlanRehydrator(ledger).build_recipe(_plan(ledger), world_id="alice")

    assert ledger.bindings == ()
    assert ledger.ambiguous_consumers == 1
    assert recipe.status == "blocked"
    assert any(error.startswith("missing_lineage:") for error in recipe.validation_errors)
    with pytest.raises(RehydrationDenied, match="not analysis-ready"):
        PlanRehydrator(ledger).rehydrate_step(recipe, recipe.steps[-1].operation_id)


def test_equal_values_in_different_worlds_never_create_lineage():
    alice_create = _rest_records(persona_id="alice")[0]
    bob_consumer = _rest_records(persona_id="bob")[1]
    ledger = ValueLineageLedger((alice_create, bob_consumer))
    recipe = PlanRehydrator(ledger).build_recipe(_plan(ledger), world_id="bob")

    assert ledger.bindings == ()
    assert recipe.status == "blocked"
    assert any(error.startswith("missing_step_capture:") for error in recipe.validation_errors)
    assert any(error.startswith("missing_lineage:") for error in recipe.validation_errors)


def test_recipe_from_changed_capture_is_rejected_as_stale():
    first = ValueLineageLedger(_rest_records())
    recipe = PlanRehydrator(first).build_recipe(_plan(first), world_id="alice")
    second = ValueLineageLedger(
        _rest_records(invoice_id="inv_91c8a20b3d4e5f6a")
    )

    with pytest.raises(RehydrationDenied, match="capture digest mismatch"):
        PlanRehydrator(second).rehydrate_step(
            recipe,
            recipe.steps[-1].operation_id,
        )


def test_forged_recipe_identity_is_rejected_before_raw_material_is_returned():
    ledger = ValueLineageLedger(_rest_records())
    rehydrator = PlanRehydrator(ledger)
    recipe = rehydrator.build_recipe(_plan(ledger), world_id="alice")
    forged = replace(recipe, recipe_id="rehydration_recipe:" + "0" * 64)

    with pytest.raises(RehydrationDenied, match="identity mismatch"):
        rehydrator.rehydrate_step(forged, recipe.steps[-1].operation_id)


def test_secret_capability_is_hash_linked_but_requires_vault_before_execution():
    secret = "tok_7fa9f13a2b4c5d6e"
    records = (
        {
            "id": "mint-token",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/tokens",
            "response_status": 201,
            "response_body": json.dumps({"downloadToken": secret}),
        },
        {
            "id": "download",
            "persona_id": "alice",
            "method": "GET",
            "url": f"{ORIGIN}/api/download?downloadToken={secret}",
            "response_status": 200,
            "response_body": "result",
        },
    )
    ledger = ValueLineageLedger(records)
    recipe = PlanRehydrator(ledger).build_recipe(_plan(ledger), world_id="alice")
    serialized = json.dumps(recipe.to_dict(), sort_keys=True)

    assert recipe.status == "ready"
    assert ledger.bindings[0].sensitive is True
    assert any(
        blocker.startswith("sensitive_capability_requires_vault:")
        for blocker in recipe.execution_blockers
    )
    assert secret not in serialized


def test_graphql_response_id_links_to_later_variable_exactly():
    records = (
        {
            "id": "create",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/graphql",
            "request_body": json.dumps(
                {"operationName": "CreateInvoice", "variables": {"memo": "test"}}
            ),
            "response_status": 200,
            "response_body": json.dumps(
                {"data": {"createInvoice": {"invoice": {"id": INVOICE_ID}}}}
            ),
        },
        {
            "id": "export",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/graphql",
            "request_body": json.dumps(
                {
                    "operationName": "ExportInvoice",
                    "variables": {"invoiceId": INVOICE_ID},
                }
            ),
            "response_status": 200,
            "response_body": json.dumps({"data": {"exportInvoice": {"url": "/owned"}}}),
        },
    )
    ledger = ValueLineageLedger(records)
    recipe = PlanRehydrator(ledger).build_recipe(_plan(ledger), world_id="alice")

    assert recipe.status == "ready"
    assert recipe.bindings[0].consumer_locator == ValueLocator(
        LocatorKind.REQUEST_JSON,
        "/variables/invoiceId",
    )


def test_locator_contract_rejects_unsupported_or_relative_locations():
    with pytest.raises(ValueError, match="LocatorKind"):
        ValueLocator("request_header", "/Authorization")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="absolute pointer"):
        ValueLocator(LocatorKind.REQUEST_JSON, "variables/id")


def test_duplicate_step_capture_is_not_selected_arbitrarily():
    records = (*_rest_records(), {**_rest_records()[1], "id": "export-again"})
    ledger = ValueLineageLedger(records)
    recipe = PlanRehydrator(ledger).build_recipe(_plan(ledger), world_id="alice")

    assert recipe.status == "blocked"
    assert any(
        error.startswith("ambiguous_step_capture:")
        for error in recipe.validation_errors
    )
