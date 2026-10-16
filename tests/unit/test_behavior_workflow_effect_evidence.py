"""R5E9b-r2 authority-free workflow effect evidence and run-binding contracts.

Recast of the R5E9b provenance contract into a faithful mirror of the
capability promotion substrate (``CapabilityEffectEvidence``). Two load-bearing
deltas are exercised explicitly: the bare ``behavioral-<hash>`` source receipt
id (DELTA-1) and the typed ``workflow_effect_promotion_admission`` execution
admission reference (DELTA-2). The companion eligibility predicate is a pure,
authority-free truth table.
"""

from __future__ import annotations

import asyncio
import ast
import json
import re
from pathlib import Path

import pytest

from core.behavior.experiment_admission import experiment_authority_context_ref
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_outcome,
    redacted_receipt_context,
    redacted_workflow_effect_evidence_outcome,
)
from core.behavior.workflow_effect_evidence import (
    WORKFLOW_EFFECT_EVIDENCE_MAX_BYTES,
    WorkflowEffectEligibility,
    WorkflowEffectEvidence,
    WorkflowEffectEvidenceError,
    bind_to_run,
    evaluate_workflow_effect_eligibility,
    workflow_effect_producer_build_identity,
    workflow_runtime_evidence_classification,
)
from core.identity.context import AssessmentIdentityContext, CredentialFreshness
from tests.import_contract import find_module_consumers
from tests.unit.test_behavior_workflow_invariant_effect_one_click import (
    ORIGIN,
    WORKFLOW,
    _case,
    _dispatcher,
)


_BEHAVIORAL_RECEIPT = re.compile(r"^behavioral-[0-9a-f]{64}$")
_SAMPLE_RECEIPT_ID = f"behavioral-{'9' * 64}"
_SAMPLE_ADMISSION_REF = f"workflow_effect_promotion_admission:{'a' * 64}"


def _sample(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    run = asyncio.run(_dispatcher(case, enabled=True).run())
    assert run.candidate is not None and run.result is not None
    assert run.result.evidence is not None
    specification = case[1]
    envelope = case[6]
    persona = case[7]
    world = specification.binding.fixture.world
    identity = AssessmentIdentityContext(
        session_id="owned-workflow-session",
        authorization_envelope_id=envelope.envelope_id,
        authorization_envelope_ref=stable_hash(
            "authorization_envelope", envelope.envelope_id
        ),
        target_origin=ORIGIN,
        target_reset_epoch=0,
        world_id=persona.persona_id,
        persona_id=persona.persona_id,
        target_actor_id=world.persona_ref,
        tenant_id=specification.binding.fixture.contract.tenant_ref,
        credential_source_ref=stable_hash("persona_source", persona.persona_id),
        credential_epoch=0,
        credential_freshness=CredentialFreshness.UNKNOWN,
        resource_id=stable_hash("resource", specification.binding.binding_id),
        representation_id=stable_hash("representation", "workflow-effect"),
    )
    evidence = WorkflowEffectEvidence.build(
        source_receipt_id=_SAMPLE_RECEIPT_ID,
        execution_admission_ref=_SAMPLE_ADMISSION_REF,
        specification_id=run.specification_id,
        transport_specification_id=run.transport_specification_id,
        candidate_id=run.candidate.candidate_id,
        result_id=run.candidate.result_id,
        evidence_id=run.candidate.evidence_id,
        target_origin=ORIGIN,
        assessment_session_id=identity.session_id,
        identity_binding=identity.to_dict(),
        experiment_world_ref=world.world_ref,
        authority_ref=experiment_authority_context_ref(envelope, ORIGIN, (WORKFLOW,)),
        tenant_ref=specification.binding.fixture.contract.tenant_ref,
        source_evidence_ref=specification.binding.capture.source_evidence_refs[0],
        oracle={
            "outcome": run.result.evidence.oracle_outcome.value,
            "correspondence": run.result.correspondence.value,
            "effect_observed": True,
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
        },
        compensating_cleanup_verified=run.result.compensating_cleanup_verified,
        producer_identity=workflow_effect_producer_build_identity(),
        observed_at_epoch=100.0,
        runtime_evidence_classification="unknown",
    )
    return evidence, run, case


def _rebuilt(evidence, **changes):
    payload = evidence.to_dict()
    payload.pop("schema_version")
    payload.pop("evidence_root")
    payload.update(changes)
    return WorkflowEffectEvidence.build(**payload)


def test_canonical_round_trip_and_rejects_noncanonical_json(tmp_path, monkeypatch):
    evidence, _, _ = _sample(tmp_path, monkeypatch)
    payload = evidence.to_dict()
    assert WorkflowEffectEvidence.from_mapping(payload).to_dict() == payload
    encoded = evidence.to_json_bytes()
    assert WorkflowEffectEvidence.from_json_bytes(encoded).to_dict() == payload
    assert len(encoded) < WORKFLOW_EFFECT_EVIDENCE_MAX_BYTES
    with pytest.raises(WorkflowEffectEvidenceError, match="not canonical"):
        WorkflowEffectEvidence.from_json_bytes(encoded + b"\n")
    duplicate = encoded.replace(
        b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1
    )
    with pytest.raises(WorkflowEffectEvidenceError, match="duplicate"):
        WorkflowEffectEvidence.from_json_bytes(duplicate)
    with pytest.raises(WorkflowEffectEvidenceError, match="oversized"):
        WorkflowEffectEvidence.from_json_bytes(
            b" " * (WORKFLOW_EFFECT_EVIDENCE_MAX_BYTES + 1)
        )
    with pytest.raises(WorkflowEffectEvidenceError, match="constant"):
        WorkflowEffectEvidence.from_json_bytes(
            encoded.replace(b'"observed_at_epoch":100.0', b'"observed_at_epoch":NaN')
        )
    payload["extra"] = True
    with pytest.raises(WorkflowEffectEvidenceError, match="fields"):
        WorkflowEffectEvidence.from_mapping(payload)
    payload.pop("extra")
    payload["evidence_root"] = "0" * 64
    with pytest.raises(WorkflowEffectEvidenceError, match="root"):
        WorkflowEffectEvidence.from_mapping(payload)


def test_oracle_is_authority_free_and_effect_observed_is_derived(tmp_path, monkeypatch):
    evidence, _, _ = _sample(tmp_path, monkeypatch)
    value = evidence.to_dict()
    assert "promotion_authority" not in value
    assert "finding_authority" not in value
    assert value["oracle"] == {
        "outcome": "effect_observed_violation",
        "correspondence": "coherent",
        "effect_observed": True,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }
    with pytest.raises(WorkflowEffectEvidenceError, match="oracle"):
        _rebuilt(evidence, oracle={**value["oracle"], "promotion_authority": True})
    with pytest.raises(WorkflowEffectEvidenceError, match="oracle"):
        _rebuilt(evidence, oracle={**value["oracle"], "finding_authority": True})


@pytest.mark.parametrize(
    "outcome,correspondence",
    [
        ("effect_absent", "coherent"),
        ("malformed", "invalid_evidence"),
        ("effect_observed_violation", "invalid_evidence"),
    ],
)
def test_effect_observed_cannot_be_true_without_both_conditions(
    tmp_path, monkeypatch, outcome, correspondence
):
    evidence, _, _ = _sample(tmp_path, monkeypatch)
    oracle = evidence.to_dict()["oracle"]
    oracle.update(outcome=outcome, correspondence=correspondence, effect_observed=False)
    assert _rebuilt(evidence, oracle=oracle).oracle["effect_observed"] is False
    oracle["effect_observed"] = True
    with pytest.raises(WorkflowEffectEvidenceError, match="oracle"):
        _rebuilt(evidence, oracle=oracle)


def test_delta1_source_receipt_id_is_bare_behavioral_citation(tmp_path, monkeypatch):
    """DELTA-1: the receipt is cited by the ledger's bare behavioral-<hash> id."""

    evidence, _, _ = _sample(tmp_path, monkeypatch)
    assert evidence.source_receipt_id == _SAMPLE_RECEIPT_ID
    assert _BEHAVIORAL_RECEIPT.fullmatch(evidence.source_receipt_id)
    # The old R5E9b typed behavioral_receipt:<hash> reference is now rejected.
    with pytest.raises(WorkflowEffectEvidenceError, match="source receipt id"):
        _rebuilt(evidence, source_receipt_id=f"behavioral_receipt:{'9' * 64}")
    with pytest.raises(WorkflowEffectEvidenceError, match="source receipt id"):
        _rebuilt(evidence, source_receipt_id="behavioral-invalid")
    with pytest.raises(WorkflowEffectEvidenceError, match="source receipt id"):
        _rebuilt(evidence, source_receipt_id=f"behavioral-{'9' * 63}")


def test_delta2_execution_admission_ref_is_typed(tmp_path, monkeypatch):
    """DELTA-2: the execution admission reference is a typed journal reference."""

    evidence, _, _ = _sample(tmp_path, monkeypatch)
    assert evidence.execution_admission_ref == _SAMPLE_ADMISSION_REF
    with pytest.raises(WorkflowEffectEvidenceError, match="execution_admission_ref"):
        _rebuilt(
            evidence,
            execution_admission_ref=f"capability_effect_execution_admission:{'a' * 64}",
        )
    with pytest.raises(WorkflowEffectEvidenceError, match="execution_admission_ref"):
        _rebuilt(evidence, execution_admission_ref="not-typed")


def test_binding_succeeds_for_the_completed_authority_free_run(tmp_path, monkeypatch):
    evidence, run, _ = _sample(tmp_path, monkeypatch)
    for name in (
        "finding_authority",
        "promotion_authority",
        "real_workflow_effect_observed",
        "wired_into_production",
    ):
        assert getattr(run, name) is False
    assert bind_to_run(evidence, run) is None


@pytest.mark.parametrize(
    "field",
    [
        "specification_id",
        "transport_specification_id",
        "candidate_id",
        "result_id",
        "evidence_id",
    ],
)
def test_binding_refuses_each_run_identifier_mismatch(tmp_path, monkeypatch, field):
    evidence, run, _ = _sample(tmp_path, monkeypatch)
    prefix = getattr(evidence, field).split(":", 1)[0]
    changed = _rebuilt(evidence, **{field: f"{prefix}:{'0' * 64}"})
    with pytest.raises(WorkflowEffectEvidenceError, match="does not bind"):
        bind_to_run(changed, run)


def test_binding_refuses_disabled_and_non_candidate_runs(tmp_path, monkeypatch):
    evidence, _, case = _sample(tmp_path, monkeypatch)
    disabled = case[0].WorkflowEffectOneClickRun.disabled(case[1])
    with pytest.raises(WorkflowEffectEvidenceError, match="candidate"):
        bind_to_run(evidence, disabled)
    secure_case = _case(tmp_path / "secure", monkeypatch, secure=True)
    non_candidate = asyncio.run(_dispatcher(secure_case, enabled=True).run())
    assert non_candidate.dispatched and non_candidate.candidate is None
    with pytest.raises(WorkflowEffectEvidenceError, match="candidate"):
        bind_to_run(evidence, non_candidate)


@pytest.mark.parametrize(
    "field",
    [
        "finding_authority",
        "promotion_authority",
        "real_workflow_effect_observed",
        "wired_into_production",
    ],
)
def test_binding_refuses_any_run_authority_claim(tmp_path, monkeypatch, field):
    evidence, run, _ = _sample(tmp_path, monkeypatch)
    object.__setattr__(run, field, True)
    with pytest.raises(WorkflowEffectEvidenceError, match="authority-free"):
        bind_to_run(evidence, run)


def test_binding_refuses_changed_oracle_or_cleanup(tmp_path, monkeypatch):
    evidence, run, _ = _sample(tmp_path, monkeypatch)
    oracle = evidence.to_dict()["oracle"]
    oracle.update(outcome="effect_absent", effect_observed=False)
    with pytest.raises(WorkflowEffectEvidenceError, match="does not bind"):
        bind_to_run(_rebuilt(evidence, oracle=oracle), run)
    with pytest.raises(WorkflowEffectEvidenceError, match="does not bind"):
        bind_to_run(_rebuilt(evidence, compensating_cleanup_verified=False), run)


def test_classification_and_producer_identity_are_explicit(monkeypatch):
    monkeypatch.delenv(
        "SENTINELFORGE_BEHAVIOR_WORKFLOW_EVIDENCE_CLASSIFICATION", raising=False
    )
    assert workflow_runtime_evidence_classification() == "unknown"
    monkeypatch.setenv(
        "SENTINELFORGE_BEHAVIOR_WORKFLOW_EVIDENCE_CLASSIFICATION",
        "controlled_owned_lab",
    )
    assert workflow_runtime_evidence_classification() == "controlled_owned_lab"
    monkeypatch.setenv(
        "SENTINELFORGE_BEHAVIOR_WORKFLOW_EVIDENCE_CLASSIFICATION", "live"
    )
    with pytest.raises(WorkflowEffectEvidenceError, match="classification"):
        workflow_runtime_evidence_classification()
    monkeypatch.delenv("SENTINEL_BUILD_SHA", raising=False)
    monkeypatch.delenv("SENTINEL_BUILD_DIRTY", raising=False)
    monkeypatch.delenv("SENTINEL_BUILD_ID", raising=False)
    assert workflow_effect_producer_build_identity()["source_state"] == "unknown"
    monkeypatch.setenv("SENTINEL_BUILD_SHA", "a" * 40)
    monkeypatch.setenv("SENTINEL_BUILD_DIRTY", "false")
    assert workflow_effect_producer_build_identity()["source_state"] == "clean"
    monkeypatch.setenv("SENTINEL_BUILD_DIRTY", "true")
    assert workflow_effect_producer_build_identity()["source_state"] == "dirty"


def test_internal_identity_and_ref_consistency(tmp_path, monkeypatch):
    evidence, _, _ = _sample(tmp_path, monkeypatch)
    with pytest.raises(WorkflowEffectEvidenceError, match="identity bindings"):
        _rebuilt(evidence, target_origin="https://other.example.test")
    with pytest.raises(WorkflowEffectEvidenceError, match="candidate_id"):
        _rebuilt(evidence, candidate_id="bad")
    with pytest.raises(WorkflowEffectEvidenceError, match="source receipt id"):
        _rebuilt(evidence, source_receipt_id="behavioral-invalid")
    identity = evidence.to_dict()["identity_binding"]
    identity["digest"] = "assessment_identity:" + "0" * 64
    with pytest.raises(WorkflowEffectEvidenceError, match="identity"):
        _rebuilt(evidence, identity_binding=identity)


def test_eligibility_is_a_pure_authority_free_truth_table(tmp_path, monkeypatch):
    # The base sample is honest in every respect EXCEPT its runtime class is
    # "unknown", so it is ineligible on exactly that clause.
    evidence, _, _ = _sample(tmp_path, monkeypatch)
    unknown = evaluate_workflow_effect_eligibility(evidence)
    assert unknown.eligible is False
    assert unknown.reason_code == "runtime_classification_not_honest"
    assert unknown.failed_clauses == (5,)

    # An honest runtime class with an observed, cleaned-up violation is eligible
    # to ENTER triage — which grants no authority.
    honest = _rebuilt(evidence, runtime_evidence_classification="controlled_owned_lab")
    verdict = evaluate_workflow_effect_eligibility(honest)
    assert verdict.eligible is True
    assert verdict.reason_code == "eligible_workflow_effect"
    assert verdict.failed_clauses == ()

    # A coherent "no effect observed" (the secure/negative-control shape) is not
    # eligible and is named distinctly.
    secure_oracle = honest.to_dict()["oracle"]
    secure_oracle.update(outcome="effect_absent", effect_observed=False)
    secure = evaluate_workflow_effect_eligibility(_rebuilt(honest, oracle=secure_oracle))
    assert secure.eligible is False
    assert secure.reason_code == "effect_absent_secure_workflow"
    assert secure.failed_clauses[0] == 1

    # Unverified compensating cleanup is ineligible on its own clause.
    dirty = evaluate_workflow_effect_eligibility(
        _rebuilt(honest, compensating_cleanup_verified=False)
    )
    assert dirty.eligible is False
    assert dirty.reason_code == "compensating_cleanup_not_verified"
    assert dirty.failed_clauses[0] == 4

    with pytest.raises(TypeError):
        evaluate_workflow_effect_eligibility(object())


def test_eligibility_record_validates_its_own_fields():
    with pytest.raises(TypeError):
        WorkflowEffectEligibility(eligible="yes", reason_code="x", failed_clauses=())
    with pytest.raises(ValueError):
        WorkflowEffectEligibility(
            eligible=False, reason_code="x", failed_clauses=(7,)
        )
    with pytest.raises(WorkflowEffectEvidenceError):
        WorkflowEffectEligibility(
            eligible=False, reason_code="NotSemantic", failed_clauses=(1,)
        )


def _evidence_response(evidence):
    return {
        "kind": "workflow_invariant_effect_one_click",
        "status": evidence.oracle["correspondence"],
        "workflow_effect_evidence": evidence.to_dict(),
    }


def test_receipt_redactor_embeds_evidence_and_strips_authority(tmp_path, monkeypatch):
    evidence, _, _ = _sample(tmp_path, monkeypatch)
    outcome = redacted_outcome(_evidence_response(evidence))
    assert set(outcome) == {
        "kind",
        "status",
        "workflow_effect_evidence",
        "finding",
        "finding_confirmed",
        "promotion_authority",
        "finding_authority",
    }
    assert outcome["kind"] == "workflow_invariant_effect_one_click"
    assert outcome["status"] == "coherent"
    assert outcome["finding"] is None
    assert outcome["finding_confirmed"] is False
    assert outcome["promotion_authority"] is False
    assert outcome["finding_authority"] is False
    embedded = outcome["workflow_effect_evidence"]
    assert embedded == evidence.to_dict()
    assert embedded["evidence_root"] == evidence.evidence_root
    # The embedded root is citable: it round-trips back through the contract.
    assert WorkflowEffectEvidence.from_mapping(embedded).to_dict() == embedded
    # Authority flags on the input response cannot leak into the retained
    # receipt: the redactor always emits the false, authority-free shape.
    forced = {
        **_evidence_response(evidence),
        "finding_confirmed": True,
        "promotion_authority": True,
        "finding_authority": True,
    }
    assert redacted_outcome(forced) == outcome


def test_receipt_redactor_round_trips_through_store(tmp_path, monkeypatch):
    evidence, _, case = _sample(tmp_path, monkeypatch)
    outcome = redacted_outcome(_evidence_response(evidence))
    root = tmp_path / "receipts"
    store = BehavioralReceiptStore(root)
    fingerprint = "9" * 64
    reservation = store.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=case[6].envelope_id,
            source_persona_id=case[7].persona_id,
            peer_persona_id="owned-workflow-peer",
        ),
    )
    assert reservation.reservation_token is not None
    store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=outcome,
    )
    reloaded = BehavioralReceiptStore(root).load(fingerprint)
    assert reloaded is not None and reloaded.outcome == outcome
    assert (
        WorkflowEffectEvidence.from_mapping(
            reloaded.outcome["workflow_effect_evidence"]
        ).to_dict()
        == evidence.to_dict()
    )
    # Reload re-redacts and refuses a tampered on-disk evidence root.
    receipt_path = next(root.glob("behavioral-*.json"))
    stored = json.loads(receipt_path.read_text())
    stored["outcome"]["workflow_effect_evidence"]["evidence_root"] = "0" * 64
    receipt_path.write_text(json.dumps(stored))
    with pytest.raises(ReceiptStoreError, match="evidence is invalid"):
        BehavioralReceiptStore(root).load(fingerprint)


def test_receipt_redactor_refuses_mismatch_missing_and_invalid_evidence(
    tmp_path, monkeypatch
):
    evidence, _, _ = _sample(tmp_path, monkeypatch)
    mismatch = {**_evidence_response(evidence), "status": "invalid_evidence"}
    with pytest.raises(ReceiptStoreError, match="status is inconsistent"):
        redacted_outcome(mismatch)
    with pytest.raises(ReceiptStoreError, match="evidence is missing"):
        redacted_workflow_effect_evidence_outcome(
            {"kind": "workflow_invariant_effect_one_click", "status": "coherent"}
        )
    with pytest.raises(ReceiptStoreError, match="kind is invalid"):
        redacted_workflow_effect_evidence_outcome(
            {"kind": "unrelated", "workflow_effect_evidence": evidence.to_dict()}
        )
    tampered = {
        **_evidence_response(evidence),
        "workflow_effect_evidence": {
            **evidence.to_dict(),
            "evidence_root": "0" * 64,
        },
    }
    with pytest.raises(ReceiptStoreError, match="evidence is invalid"):
        redacted_outcome(tampered)


def test_only_receipts_ledger_promotion_and_inner_foundry_consume_evidence():
    repository = Path(__file__).resolve().parents[2]
    module_path = repository / "core/behavior/workflow_effect_evidence.py"
    consumers = find_module_consumers(
        (path for path in (repository / "core").rglob("*.py") if path != module_path),
        "core.behavior.workflow_effect_evidence",
        repository_root=repository,
    )
    # R5E9f-c adds only the local promotion service and inner Foundry capture.
    # The outer route and unrelated consumers remain outside this list.
    relative = tuple(path.relative_to(repository).as_posix() for path in consumers)
    assert relative == (
        "core/behavior/receipts.py",
        "core/behavior/workflow_effect_promotion.py",
        "core/epistemic/ledger.py",
        "core/server/routers/foundry.py",
    )
    imports = []
    allowed_effect_symbols = []
    allowed_run_symbols = []
    for node in ast.walk(ast.parse(module_path.read_text())):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
            if node.module == "workflow_invariant_effect":
                allowed_effect_symbols.extend(alias.name for alias in node.names)
            if node.module == "workflow_invariant_effect_one_click":
                allowed_run_symbols.extend(alias.name for alias in node.names)
    assert sorted(allowed_effect_symbols) == [
        "WorkflowEffectCorrespondence",
        "WorkflowEffectOutcome",
    ]
    assert allowed_run_symbols == ["WorkflowEffectOneClickRun"]
    assert not any(
        "capability_effect_" in name
        or name.endswith(".ledger")
        or name.endswith(".persistence")
        or "triage" in name
        for name in imports
    )
