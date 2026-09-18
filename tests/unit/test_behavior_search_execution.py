"""OCB-R6 receipt integration using the existing admitted in-memory R4 runner.

These are focused local tests, not an external-target run or acceptance evidence.
The certificates written below come from the scheduler and genuine stored local
execution outcomes; the scheduler never writes or completes execution receipts.
"""

from __future__ import annotations

import importlib.util
import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.behavior.compiler import OperationContract, OperationSafety
from core.behavior.constraints import ConstraintLedgerBuilder
from core.behavior.experiment_admission import GeneralizedExperimentAdmission
from core.behavior.experiment_sdk import ExistingBackendAdapter
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import (
    GoalPlanningContext,
    PayoutGoalCandidate,
    PayoutGoalDiagnostics,
    PayoutGoalPlan,
    PayoutSink,
    ProofTopology,
    SecurityProperty,
    SecurityWitnessGoal,
    WorldRequirement,
)
from core.behavior.receipts import COMPLETED
from core.behavior.search_stopping import (
    HighValueSinkLedger,
    MarginalValueScheduler,
    RecordedSearchExecution,
    SearchBudget,
    SearchProof,
)
from core.behavior.semantic_catalog import TargetSemanticCatalogBuilder
from core.safety.proof_budget import ProofBudget


# Reuse the actual R4 test runner without modifying that completed work order.
# Its module contains no import-time execution and all sends use an injected fake.
_SPEC = importlib.util.spec_from_file_location(
    "_search_execution_r4_fixture",
    Path(__file__).with_name("test_behavior_experiment_authorization.py"),
)
assert _SPEC is not None and _SPEC.loader is not None
_R4 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_R4)


class _ObservedTarget(_R4._Target):
    """Retain actual fake responses for the passive R2 input projection."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.observations = []

    async def send(self, persona_id, method, url, body=None, **kwargs):
        status, response = await super().send(persona_id, method, url, body, **kwargs)
        self.observations.append(
            {
                "persona_id": persona_id,
                "method": method,
                "url": url,
                "response_status": status,
                "response_body": json.dumps(response),
            }
        )
        return status, response


def _ledger(context, *, candidate_score=100, peer_world_id=None, target_origin=None):
    """Wrap the exact R4 candidate in the existing R1 immutable plan contract."""
    proposal = context["proposal"]
    backend = context["adapter"].backend
    origin = target_origin or _R4.ORIGIN
    target_ref = stable_hash("security_obligation_target", origin)
    source_id = backend.source_persona.persona_id
    peer_id = peer_world_id or backend.peer_persona.persona_id
    envelope = backend.authorization
    if origin != _R4.ORIGIN:
        envelope = replace(envelope, authorized_origins=[origin])
        envelope.sign()
    planning_context = GoalPlanningContext.build(
        target_ref=target_ref,
        target_origin=origin,
        authorization=envelope,
        selected_world_id=source_id,
        owned_world_ids=(source_id, peer_id),
        available_backends=("object_authorization",),
    )
    operation = OperationContract(
        operation_id=proposal.action_id,
        label=proposal.operation_label,
        requires=(),
        produces=(),
        safety=OperationSafety.READ_ONLY,
        observed_success=True,
    )
    goal = SecurityWitnessGoal.build(
        operation=operation,
        sink=PayoutSink.FILE_ACCESS,
        security_property=SecurityProperty.OBJECT_AUTHORIZATION,
        evidence_refs=ExistingBackendAdapter.authorization(
            proposal
        ).source_evidence_refs,
    )
    candidate = PayoutGoalCandidate.build(
        goal=goal,
        world_requirement=WorldRequirement(
            ProofTopology.PAIRED_OWNED_ACCOUNTS,
            2,
            required_workflows=(_R4.WORKFLOW,),
        ),
        backend="object_authorization",
        score=candidate_score,
        blockers=(),
    )
    diagnostics = PayoutGoalDiagnostics(
        operations=1,
        high_value_operations=1,
        candidates=1,
        admissible=1,
        blocked=0,
        obligations=0,
        dropped_candidates=0,
        dropped_evidence_refs=0,
    )
    plan_values = {
        "status": "ready",
        "target_ref": target_ref,
        "graph_digest": stable_hash("security_obligation_graph", proposal.proposal_id),
        "context": planning_context,
        "selected_goal_id": goal.goal_id,
        "candidates": (candidate,),
        "input_blockers": (),
        "diagnostics": diagnostics,
    }
    plan_payload = {
        **plan_values,
        "context": planning_context.to_dict(),
        "candidates": [candidate.to_dict()],
        "input_blockers": [],
        "diagnostics": diagnostics.to_dict(),
    }
    payout_plan = PayoutGoalPlan(
        plan_id=stable_hash("payout_goal_plan", plan_payload),
        **plan_values,
    )
    # R4's owner baseline is the second real response. Response data does not
    # change the request action identity used by its existing compiled manifest.
    source_record = dict(context["target"].observations[1])
    source_record["url"] = source_record["url"].replace(_R4.ORIGIN, origin, 1)
    catalog = TargetSemanticCatalogBuilder().build(
        (source_record,),
        target_ref=target_ref,
        target_origin=origin,
        world_id=source_id,
    )
    return HighValueSinkLedger(payout_plan, catalog)


async def _execute(tmp_path, monkeypatch, **target_options):
    target = _ObservedTarget(**target_options)
    before_admission = []
    admitted_bindings = []

    class ObservedAdmission(GeneralizedExperimentAdmission):
        def _preflight(self):
            preflight = super()._preflight()
            admitted_bindings.append(preflight.action_bindings)
            return preflight

    def bounded_budget(**kwargs):
        budget = ProofBudget(**{**kwargs, "max_total_requests": 4})
        before_admission.append(SearchBudget.capture(budget))
        return budget

    # Bind the limit before admission creates its policy digest. Changing a
    # budget after admission would correctly invalidate the existing R4 claim.
    monkeypatch.setattr(_R4, "ProofBudget", bounded_budget)
    monkeypatch.setattr(_R4, "GeneralizedExperimentAdmission", ObservedAdmission)
    context = _R4._context(tmp_path, monkeypatch, target=target)
    context["budget_before_admission"] = before_admission[0]
    context["search_proof"] = SearchProof(context["manifest"], admitted_bindings[0])
    result = await context["adapter"].execute(
        context["proposal"],
        context["source_records"],
        context["peer_records"],
    )
    receipt = context["store"].load(context["claim"].contract.receipt_fingerprint)
    assert receipt is not None and receipt.state == COMPLETED
    assert result.requests_sent == len(target.calls) == 4
    return context, result, receipt


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target_options", "verdict", "coverage"),
    [
        ({}, "confirmed", "proved"),
        ({"attack_denied": True}, "refuted", "blocked"),
        ({"witness_status": 500}, "inconclusive", "blocked"),
    ],
    ids=("confirmed", "target_denied", "witness_unavailable"),
)
async def test_ocb_s18_recorded_outcomes_without_dispatch(
    tmp_path,
    monkeypatch,
    target_options,
    verdict,
    coverage,
):
    context, result, receipt = await _execute(tmp_path, monkeypatch, **target_options)
    ledger = _ledger(context)
    candidate_id = context["manifest"].candidate_id
    assert ledger.candidate_ids == (candidate_id,)
    assert result.oracle_evaluation.verdict.value == verdict
    record = RecordedSearchExecution.capture(context["manifest"], receipt)
    budget = SearchBudget.capture(context["budget"])
    assert budget.limits[0] == budget.consumed[0] == 4
    assert budget.reserved == (0, 0, 0, 0)
    assert budget.remaining == 0
    calls_before = list(context["target"].calls)
    receipt_before = receipt.to_dict()
    scheduler = MarginalValueScheduler()
    # Replay immutable snapshots after the controlled run. The genuine R2
    # document path retains its document_id prerequisite; this passive adapter
    # has no initial-capability input, so it cannot order this proof itself.
    # The existing admitted R4 execution still supplies a real recorded outcome.
    previous = scheduler.plan(
        ledger=ledger,
        constraints=ConstraintLedgerBuilder().build(),
        budget=context["budget_before_admission"],
        enabled=True,
        proofs=(context["search_proof"],),
    )
    assert previous.entries[0].status == "blocked"
    assert previous.entries[0].reason == "r3_constraints_blocked"
    assert previous.ordering == ()
    assert previous.entries[0].signals.proof_cost == 4
    plan = scheduler.plan(
        ledger=ledger,
        constraints=previous.constraints,
        budget=budget,
        enabled=True,
        proofs=(context["search_proof"],),
        executions=(record,),
        previous=previous,
    )
    assert len(plan.entries) == 1
    entry = plan.entries[0]
    assert entry.status == coverage
    assert entry.oracle_verdict == verdict
    assert entry.reason == f"recorded_oracle_{verdict}"
    assert record.record_id in entry.evidence_refs
    assert result.oracle_evaluation.evaluation_id in entry.evidence_refs
    assert plan.ordering == ()
    certificate = plan.certificate()
    assert certificate.verify(plan)
    value = certificate.to_dict()
    assert value["families"]["A"][coverage] == [candidate_id]
    assert value["budget_consumed_requests"] == 4
    assert value["planner_requests_sent"] == 0
    assert value["execution_authority"] is value["finding_authority"] is False
    assert context["target"].calls == calls_before
    assert SearchBudget.capture(context["budget"]) == budget
    assert context["store"].load(receipt.fingerprint).to_dict() == receipt_before
    # Test artifacts are generated from retained inputs; no certificate is
    # authored separately from the implementation under test.
    (tmp_path / "search-inputs.json").write_text(
        json.dumps(plan.input_dict(), sort_keys=True, indent=2) + "\n",
    )
    (tmp_path / "search-stop-certificate.json").write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ledger_options",
    [
        {"candidate_score": 99},
        {"peer_world_id": "a-different-owned-world"},
        {"target_origin": "https://other.example.test"},
    ],
    ids=("candidate", "world", "target"),
)
async def test_genuine_receipt_cannot_cover_a_different_frontier(
    tmp_path,
    monkeypatch,
    ledger_options,
):
    context, _, receipt = await _execute(tmp_path, monkeypatch)
    record = RecordedSearchExecution.capture(context["manifest"], receipt)
    before = SearchBudget.capture(context["budget"])
    different_ledger = _ledger(context, **ledger_options)
    with pytest.raises(ValueError):
        MarginalValueScheduler().plan(
            ledger=different_ledger,
            constraints=ConstraintLedgerBuilder().build(),
            budget=before,
            enabled=True,
            executions=(record,),
        )
    assert len(context["target"].calls) == 4
    assert SearchBudget.capture(context["budget"]) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("manifest_id", stable_hash("proof_experiment_manifest", "different")),
        ("oracle_id", stable_hash("proof_experiment_oracle", "different")),
        ("backend_receipt_ref", stable_hash("behavioral_receipt", "different")),
    ],
)
async def test_receipt_identity_tampering_is_rejected_before_coverage(
    tmp_path,
    monkeypatch,
    field,
    replacement,
):
    context, _, receipt = await _execute(tmp_path, monkeypatch)
    tampered = replace(receipt, outcome={**receipt.outcome, field: replacement})
    with pytest.raises(ValueError, match="does not bind the manifest"):
        RecordedSearchExecution.capture(context["manifest"], tampered)
    assert len(context["target"].calls) == 4
    assert context["store"].load(receipt.fingerprint).to_dict() == receipt.to_dict()


@pytest.mark.asyncio
async def test_coordinated_refuted_verdict_tampering_cannot_become_proved(
    tmp_path,
    monkeypatch,
):
    context, _, receipt = await _execute(tmp_path, monkeypatch, attack_denied=True)
    original_outcome = receipt.outcome
    assert original_outcome["oracle_verdict"] == "refuted"
    tampered = replace(
        receipt,
        outcome={
            **original_outcome,
            "oracle_verdict": "confirmed",
            "legacy_verdict": "BOLA_CONFIRMED",
            "finding_candidate_ref": stable_hash(
                "proof_experiment_finding_candidate", "forged"
            ),
        },
    )
    assert tampered.outcome["evaluation_id"] == original_outcome["evaluation_id"]
    with pytest.raises(ValueError):
        RecordedSearchExecution.capture(context["manifest"], tampered)
    assert len(context["target"].calls) == 4
    assert context["store"].load(receipt.fingerprint).to_dict() == receipt.to_dict()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,prefix",
    [
        ("target_ref", "behavioral_receipt_target"),
        ("source_persona_ref", "behavioral_receipt_persona"),
        ("peer_persona_ref", "behavioral_receipt_persona"),
    ],
)
async def test_root_receipt_context_cannot_be_substituted(
    tmp_path, monkeypatch, field, prefix
):
    context, _, receipt = await _execute(tmp_path, monkeypatch)
    tampered_context = replace(
        receipt.context, **{field: stable_hash(prefix, "outside")}
    )
    tampered = replace(receipt, context=tampered_context)
    assert tampered.outcome["evaluation_id"] == receipt.outcome["evaluation_id"]
    with pytest.raises(ValueError, match="does not bind the manifest"):
        RecordedSearchExecution.capture(context["manifest"], tampered)
    assert context["store"].load(receipt.fingerprint).to_dict() == receipt.to_dict()
