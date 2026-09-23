"""OCB-S20 Option-A Family-A coverage activation over one real local run."""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from core.behavior.experiment_sdk import ProofExperimentManifest
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import (
    PayoutSink,
    SecurityProperty,
    SecurityWitnessGoal,
)
from core.behavior.search_stopping import HighValueSinkLedger, RecordedSearchExecution
from core.behavior.semantic_catalog import TargetSemanticCatalogBuilder
from core.server.routers import foundry
from tests.unit import test_behavior_generalized_authorization_one_click as fixtures


_GENERALIZED_KINDS = frozenset(
    {
        "proof_experiment_authorization",
        "proof_experiment_generalized_authorization",
    }
)


async def _real_generalized_run(tmp_path, monkeypatch):
    context = fixtures._context(tmp_path, monkeypatch)
    dispatcher = context["dispatcher"]
    shadow = context["shadow"]
    selections = []
    compile_selection = dispatcher._compile_selection

    def capture_selection(*args, **kwargs):
        selection = compile_selection(*args, **kwargs)
        selections.append(selection)
        return selection

    monkeypatch.setattr(dispatcher, "_compile_selection", capture_selection)
    run = await dispatcher.run(
        actor_records=context["actor_records"],
        owner_records=context["owner_records"],
        payout_goal_plan=shadow.payout_goal_plan,
        operations=shadow.semantic_catalog.planner_operations(),
    )
    assert len(selections) == 1
    return context, shadow, run, selections[0]


@pytest.mark.asyncio
async def test_dispatched_run_exposes_only_its_typed_manifest(
    tmp_path,
    monkeypatch,
):
    context, shadow, run, selection = await _real_generalized_run(
        tmp_path / "completed",
        monkeypatch,
    )

    assert run.dispatched is True
    assert type(run.manifest) is ProofExperimentManifest
    assert run.manifest is selection.manifest
    assert run.manifest_id == selection.manifest.manifest_id
    assert run.execution_response() == replace(run, manifest=None).execution_response()
    assert "manifest" not in run.to_dict()
    assert "manifest" not in run.execution_response()
    assert "manifest" not in run.execution_response()["one_click_selection"]

    disabled = fixtures._context(
        tmp_path / "disabled",
        monkeypatch,
        admission_enabled=False,
    )
    disabled_run = await disabled["dispatcher"].run(
        actor_records=disabled["actor_records"],
        owner_records=disabled["owner_records"],
        payout_goal_plan=disabled["shadow"].payout_goal_plan,
        operations=disabled["shadow"].semantic_catalog.planner_operations(),
    )
    assert disabled_run.status == "selected_execution_disabled"
    assert disabled_run.manifest is None

    no_selection = fixtures._context(tmp_path / "no-selection", monkeypatch)
    no_selection_run = await no_selection["dispatcher"].run(
        actor_records=no_selection["actor_records"],
        owner_records=no_selection["owner_records"],
        payout_goal_plan=no_selection["shadow"].payout_goal_plan,
        operations=(),
    )
    assert no_selection_run.status == "no_eligible_candidate"
    assert no_selection_run.manifest is None
    assert len(context["target"].calls) == 4
    assert shadow.payout_goal_plan.target_ref == run.manifest.target_ref


@pytest.mark.asyncio
async def test_generalized_receipt_adapter_is_kind_only_and_content_neutral(
    tmp_path,
    monkeypatch,
):
    context, _, run, _ = await _real_generalized_run(tmp_path, monkeypatch)
    assert run.manifest is not None and run.execution is not None
    receipt_json = foundry._read_exact_behavioral_receipt_json(
        context["dispatcher"].receipt_store,
        run.execution.receipt_id,
    )
    receipt = context["dispatcher"].receipt_store.load(
        run.execution.receipt_id.removeprefix("behavioral-")
    )
    assert receipt is not None
    assert receipt_json == json.dumps(
        receipt.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    with pytest.raises(ValueError, match="does not bind the manifest"):
        RecordedSearchExecution(run.manifest, receipt_json)
    with pytest.raises(ValueError, match="does not bind the manifest"):
        RecordedSearchExecution(
            run.manifest,
            receipt_json + " ",
            accepted_kinds=_GENERALIZED_KINDS,
        )

    generalized_only = RecordedSearchExecution(
        run.manifest,
        receipt_json,
        accepted_kinds=frozenset(
            {"proof_experiment_generalized_authorization"}
        ),
    )
    two_kind = RecordedSearchExecution(
        run.manifest,
        receipt_json,
        accepted_kinds=_GENERALIZED_KINDS,
    )
    assert generalized_only == two_kind
    assert generalized_only.to_dict() == two_kind.to_dict()
    assert generalized_only.record_id == two_kind.record_id

    tampered = json.loads(receipt_json)
    tampered["outcome"]["oracle_id"] = stable_hash(
        "proof_experiment_oracle",
        "outside-the-manifest",
    )
    with pytest.raises(ValueError, match="does not bind the manifest"):
        RecordedSearchExecution(
            run.manifest,
            json.dumps(
                tampered,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
            accepted_kinds=_GENERALIZED_KINDS,
        )


@pytest.mark.asyncio
async def test_real_family_a_run_yields_an_observational_r6_certificate(
    tmp_path,
    monkeypatch,
):
    context, shadow, run, selection = await _real_generalized_run(
        tmp_path,
        monkeypatch,
    )
    assert run.manifest is not None and run.execution is not None
    store = context["dispatcher"].receipt_store
    receipt_json = foundry._read_exact_behavioral_receipt_json(
        store,
        run.execution.receipt_id,
    )
    calls_before = list(context["target"].calls)

    certificate = foundry._family_a_coverage_certificate(
        payout_plan=shadow.payout_goal_plan,
        catalog=shadow.semantic_catalog,
        manifest=run.manifest,
        receipt_json=receipt_json,
        derivation_binding=True,
    )
    payload = certificate.to_dict()
    projection = foundry._family_a_coverage_projection(
        payout_plan=shadow.payout_goal_plan,
        catalog=shadow.semantic_catalog,
        manifest=run.manifest,
        receipt_json=receipt_json,
        derivation_binding=True,
    )

    frontier_candidate = selection.pair.payout_candidate
    ledger = HighValueSinkLedger(shadow.payout_goal_plan, shadow.semantic_catalog)
    assert run.manifest.candidate_id != frontier_candidate.candidate_id
    assert run.manifest.goal_id != frontier_candidate.goal.goal_id
    assert (
        SecurityWitnessGoal.derived_goal_id(
            base=frontier_candidate.goal,
            evidence_refs=run.manifest.backend.source_evidence_refs,
        )
        == run.manifest.goal_id
    )
    assert ledger._derive_frontier_candidate(run.manifest) == frontier_candidate
    assert run.manifest.backend.source_evidence_refs == tuple(
        sorted(set(run.manifest.backend.source_evidence_refs))
    )
    assert frontier_candidate.candidate_id in payload["admitted_candidate_ids"]
    assert run.manifest.candidate_id not in payload["admitted_candidate_ids"]
    assert payload["phase_id"] == "OCB-R6"
    assert payload["exit_gate"] == "OCB-S18"
    assert payload["stop_reason"] == "proof_budget_unavailable"
    assert payload["families"]["A"]["proved"] == [
        frontier_candidate.candidate_id
    ]
    never_explored = payload["families"]["A"]["never_explored"]
    assert len(never_explored) == len(ledger.candidates) - 1
    assert frontier_candidate.candidate_id not in never_explored
    assert all(
        not any(statuses.values())
        for family, statuses in payload["families"].items()
        if family != "A"
    )
    assert payload["budget_consumed_requests"] == run.execution.requests_sent
    assert payload["planner_requests_sent"] == 0
    assert payload["execution_authority"] is False
    assert payload["finding_authority"] is False
    assert certificate.verify(certificate._plan)
    assert projection == {
        "certificate_id": certificate.certificate_id,
        "stop_reason": payload["stop_reason"],
        "admitted_candidate_count": len(payload["admitted_candidate_ids"]),
        "explored_candidate_count": 1,
        "execution_authority": False,
        "finding_authority": False,
    }
    assert context["target"].calls == calls_before
    assert (
        foundry._read_exact_behavioral_receipt_json(
            store,
            run.execution.receipt_id,
        )
        == receipt_json
    )


@pytest.mark.asyncio
async def test_nested_gate_is_default_off_and_glue_failure_degrades_to_absence(
    tmp_path,
    monkeypatch,
    caplog,
):
    context, shadow, run, _ = await _real_generalized_run(tmp_path, monkeypatch)
    native = run.execution_response()
    native_bytes = json.dumps(native, sort_keys=True, separators=(",", ":"))
    calls_before = list(context["target"].calls)

    assert foundry._family_a_coverage_enabled({}) is False
    assert (
        foundry._family_a_coverage_enabled(
            {"SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION": "1"}
        )
        is False
    )
    assert (
        foundry._family_a_coverage_enabled(
            {"SENTINELFORGE_FAMILY_A_COVERAGE": "true"}
        )
        is False
    )
    assert foundry._family_a_coverage_enabled(
        {
            "SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION": "yes",
            "SENTINELFORGE_FAMILY_A_COVERAGE": "on",
        }
    )
    assert (
        foundry._r6_derivation_binding_enabled(
            {
                "SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION": "yes",
                "SENTINELFORGE_FAMILY_A_COVERAGE": "on",
            }
        )
        is False
    )
    assert (
        foundry._r6_derivation_binding_enabled(
            {"SENTINELFORGE_R6_DERIVATION_BINDING": "true"}
        )
        is False
    )
    assert foundry._r6_derivation_binding_enabled(
        {
            "SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION": "yes",
            "SENTINELFORGE_FAMILY_A_COVERAGE": "on",
            "SENTINELFORGE_R6_DERIVATION_BINDING": "1",
        }
    )

    foundry._maybe_add_family_a_coverage(
        response=native,
        shadow_run=shadow,
        one_click_run=run,
        receipt_store=context["dispatcher"].receipt_store,
        enabled=False,
    )
    assert json.dumps(native, sort_keys=True, separators=(",", ":")) == native_bytes
    assert "family_a_coverage" not in native

    flag_off = run.execution_response()
    foundry._maybe_add_family_a_coverage(
        response=flag_off,
        shadow_run=shadow,
        one_click_run=run,
        receipt_store=context["dispatcher"].receipt_store,
        enabled=True,
    )
    assert json.dumps(flag_off, sort_keys=True, separators=(",", ":")) == native_bytes
    assert "family_a_coverage" not in flag_off
    assert "non-admitted candidate refused" in caplog.text

    caplog.clear()
    enabled = run.execution_response()
    foundry._maybe_add_family_a_coverage(
        response=enabled,
        shadow_run=shadow,
        one_click_run=run,
        receipt_store=context["dispatcher"].receipt_store,
        enabled=True,
        derivation_binding=True,
    )
    assert enabled["family_a_coverage"]["explored_candidate_count"] == 1

    def broken_load(_fingerprint):
        raise OSError("deliberate coverage-only receipt fetch failure")

    monkeypatch.setattr(context["dispatcher"].receipt_store, "load", broken_load)
    degraded = run.execution_response()
    foundry._maybe_add_family_a_coverage(
        response=degraded,
        shadow_run=shadow,
        one_click_run=run,
        receipt_store=context["dispatcher"].receipt_store,
        enabled=True,
        derivation_binding=True,
    )
    assert "family_a_coverage" not in degraded
    assert degraded["status"] == native["status"]
    assert "Family-A coverage measurement was unavailable" in caplog.text
    assert context["target"].calls == calls_before


@pytest.mark.asyncio
async def test_zero_derivation_match_degrades_without_changing_native_result(
    tmp_path,
    monkeypatch,
    caplog,
):
    context, shadow, run, _ = await _real_generalized_run(tmp_path, monkeypatch)
    native = run.execution_response()
    native_bytes = json.dumps(native, sort_keys=True, separators=(",", ":"))
    calls_before = list(context["target"].calls)
    dispatcher = context["dispatcher"]
    empty_catalog = TargetSemanticCatalogBuilder().build(
        (),
        target_ref=shadow.payout_goal_plan.target_ref,
        target_origin=dispatcher.target_origin,
        world_id=dispatcher.backend.source_persona.persona_id,
    )

    foundry._maybe_add_family_a_coverage(
        response=native,
        shadow_run=SimpleNamespace(
            payout_goal_plan=shadow.payout_goal_plan,
            semantic_catalog=empty_catalog,
        ),
        one_click_run=run,
        receipt_store=dispatcher.receipt_store,
        enabled=True,
        derivation_binding=True,
    )

    assert json.dumps(native, sort_keys=True, separators=(",", ":")) == native_bytes
    assert "family_a_coverage" not in native
    assert "manifest does not derive from exactly one admitted candidate" in caplog.text
    assert context["target"].calls == calls_before


@pytest.mark.asyncio
@pytest.mark.parametrize("mismatch", ["sink", "property"])
async def test_derivation_refuses_a_different_security_question(
    tmp_path,
    monkeypatch,
    mismatch,
):
    _, shadow, run, selection = await _real_generalized_run(tmp_path, monkeypatch)
    assert run.manifest is not None
    frontier = selection.pair.payout_candidate
    sink = frontier.goal.sink
    security_property = frontier.goal.security_property
    if mismatch == "sink":
        sink = (
            PayoutSink.PRIVATE_DATA
            if sink is not PayoutSink.PRIVATE_DATA
            else PayoutSink.FILE_ACCESS
        )
    else:
        security_property = SecurityProperty.AUTHORITY_MONOTONICITY
    different_goal = SecurityWitnessGoal.build(
        operation=selection.pair.operation,
        sink=sink,
        security_property=security_property,
        evidence_refs=frontier.goal.evidence_refs,
    )
    different_manifest = SimpleNamespace(
        goal_id=SecurityWitnessGoal.derived_goal_id(
            base=different_goal,
            evidence_refs=run.manifest.backend.source_evidence_refs,
        ),
        backend=run.manifest.backend,
    )
    ledger = HighValueSinkLedger(shadow.payout_goal_plan, shadow.semantic_catalog)

    with pytest.raises(
        ValueError,
        match="does not derive from exactly one admitted candidate",
    ):
        ledger._derive_frontier_candidate(different_manifest)
