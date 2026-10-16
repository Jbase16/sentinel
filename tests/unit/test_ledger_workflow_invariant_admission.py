"""Synthetic R5E9d ledger admission and restart checks; no production caller."""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3

import pytest

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    BehavioralReceiptStore,
    redacted_receipt_context,
)
from core.behavior.workflow_effect_evidence import (
    WorkflowEffectEvidence,
    workflow_invariant_finding_material,
)
from core.epistemic.ledger import ActiveProofCitation, Citation, EvidenceLedger
from core.identity.context import AssessmentIdentityContext
from tests.unit.test_behavior_workflow_effect_evidence import (
    _evidence_response,
    _rebuilt,
    _sample,
)
from tests.unit.test_epistemic_persistence_workflow_journal import (
    _bundle,
    _reservation,
)


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    sample, _, case = _sample(tmp_path, monkeypatch)
    context = _reservation()
    context.update(
        session_id=sample.assessment_session_id,
        target_origin=sample.target_origin,
        identity=dict(sample.identity_binding),
        specification_id=sample.specification_id,
        transport_specification_id=sample.transport_specification_id,
        candidate_id=sample.candidate_id,
        producer=dict(sample.producer_identity),
    )
    context["admission_id"] = stable_hash(
        "workflow_effect_promotion_admission",
        {
            "session_id": context["session_id"],
            "target_origin": context["target_origin"],
            "identity_digest": context["identity"]["digest"],
            "specification_id": context["specification_id"],
            "transport_specification_id": context["transport_specification_id"],
            "candidate_id": context["candidate_id"],
            "producer": context["producer"],
        },
    )
    binding = _bundle(context)
    evidence = _rebuilt(
        sample,
        source_receipt_id=binding["source_receipt_id"],
        execution_admission_ref=context["admission_id"],
        runtime_evidence_classification="controlled_in_memory_twin",
    )
    receipts = BehavioralReceiptStore(tmp_path / "receipts")
    reservation = receipts.reserve(
        binding["source_fingerprint"],
        context=redacted_receipt_context(
            target_origin=evidence.target_origin,
            envelope_id=case[6].envelope_id,
            source_persona_id=case[7].persona_id,
            peer_persona_id="owned-workflow-peer",
        ),
    )
    assert reservation.reservation_token is not None
    receipts.complete(
        binding["source_fingerprint"],
        reservation_token=reservation.reservation_token,
        outcome=_evidence_response(evidence),
    )
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    ledger = EvidenceLedger(config, receipt_store=receipts)
    ledger._repository.reserve_workflow_effect_promotion(**context)
    ledger._repository.bind_workflow_effect_source(
        admission_id=context["admission_id"],
        source_receipt_id=binding["source_receipt_id"],
        source_fingerprint=binding["source_fingerprint"],
    )
    ledger._repository.set_workflow_effect_state(
        admission_id=context["admission_id"],
        state="eligible_awaiting_processing",
    )
    return ledger, evidence, context, receipts


@pytest.fixture
def admitted(prepared):
    ledger, evidence, context, receipts = prepared
    observation, finding = ledger.admit_workflow_invariant_finding(
        evidence=evidence,
        admission_id=context["admission_id"],
        event_timestamp=context["event_timestamp"],
        event_run_id=context["event_run_id"],
    )
    return ledger, evidence, context, receipts, observation, finding


def _active_check(ledger, observation, finding):
    ledger._validate_active_proof(
        evidence_citations=finding.citations,
        observations=[observation],
        active_proof=finding.active_proof,
    )


def test_happy_path_atomic_admission_idempotence_and_restart(admitted):
    ledger, evidence, context, receipts, observation, finding = admitted
    assert isinstance(evidence, WorkflowEffectEvidence)
    assert observation.tool.name == "workflow_effect_evidence"
    assert observation.tool.args == (evidence.source_receipt_id,)
    assert observation.tool.version == evidence.schema_version
    assert observation.timestamp == evidence.observed_at_epoch
    assert finding.metadata == workflow_invariant_finding_material(evidence)["metadata"]
    assert finding.metadata["finding_class"] == "workflow_invariant_violation_v1"
    assert finding.active_proof == [
        ActiveProofCitation(
            observation_id=observation.id,
            receipt_id=evidence.source_receipt_id,
            provenance_root=evidence.evidence_root,
        )
    ]
    row = ledger._repository.load_workflow_effect_admission(context["admission_id"])
    assert row is not None and row["state"] == "promoted"
    assert (row["evidence_root"], row["cas_blob_hash"]) == (
        evidence.evidence_root,
        observation.blob_hash,
    )
    assert (row["observation_id"], row["finding_id"]) == (
        observation.id,
        finding.id,
    )
    entities, events = ledger._repository.load()
    assert len(entities) == len(events) == 2
    assert [event["event_type"] for event in events] == ["observed", "promoted"]
    replay = ledger.admit_workflow_invariant_finding(
        evidence=evidence,
        admission_id=context["admission_id"],
        event_timestamp=context["event_timestamp"],
        event_run_id=context["event_run_id"],
    )
    assert replay == (observation, finding)
    assert ledger._repository.load() == (entities, events)
    reopened = EvidenceLedger(ledger.config, receipt_store=receipts)
    model = reopened.session_read_model(evidence.assessment_session_id)
    assert model.observations == (observation,)
    assert model.findings == (finding,)
    assert reopened.admit_workflow_invariant_finding(
        evidence=evidence,
        admission_id=context["admission_id"],
        event_timestamp=context["event_timestamp"],
        event_run_id=context["event_run_id"],
    ) == (observation, finding)


@pytest.mark.parametrize("timestamp", [True, 0, -1, "1"])
def test_admission_rejects_invalid_timestamp(prepared, timestamp):
    ledger, evidence, context, _ = prepared
    with pytest.raises(ValueError, match="timestamp"):
        ledger.admit_workflow_invariant_finding(
            evidence=evidence,
            admission_id=context["admission_id"],
            event_timestamp=timestamp,
            event_run_id=context["event_run_id"],
        )
    assert ledger._repository.load() == ((), ())


def test_admission_requires_typed_eligible_evidence_and_matching_journal(prepared):
    ledger, evidence, context, _ = prepared
    with pytest.raises(TypeError, match="typed evidence"):
        ledger.admit_workflow_invariant_finding(
            evidence=evidence.to_dict(),
            admission_id=context["admission_id"],
            event_timestamp=context["event_timestamp"],
            event_run_id=context["event_run_id"],
        )
    ineligible = _rebuilt(evidence, compensating_cleanup_verified=False)
    with pytest.raises(ValueError, match="not eligible"):
        ledger.admit_workflow_invariant_finding(
            evidence=ineligible,
            admission_id=context["admission_id"],
            event_timestamp=context["event_timestamp"],
            event_run_id=context["event_run_id"],
        )
    with pytest.raises(ValueError, match="journal is missing"):
        ledger.admit_workflow_invariant_finding(
            evidence=evidence,
            admission_id="workflow_effect_promotion_admission:" + "0" * 64,
            event_timestamp=context["event_timestamp"],
            event_run_id=context["event_run_id"],
        )
    ledger._repository.set_workflow_effect_state(
        admission_id=context["admission_id"], state="blocked_by_policy"
    )
    with pytest.raises(ValueError, match="context does not match"):
        ledger.admit_workflow_invariant_finding(
            evidence=evidence,
            admission_id=context["admission_id"],
            event_timestamp=context["event_timestamp"],
            event_run_id=context["event_run_id"],
        )
    assert ledger._repository.load() == ((), ())
    with pytest.raises(ValueError, match="not an invariant violation"):
        workflow_invariant_finding_material(ineligible)


@pytest.mark.parametrize(
    "key,wrong",
    [
        ("admission_id", "workflow_effect_promotion_admission:" + "0" * 64),
        ("session_id", "other-session"),
        ("source_receipt_id", "behavioral-" + "0" * 64),
        ("source_fingerprint", "0" * 64),
        ("target_origin", "https://other.invalid"),
        ("identity_data", {}),
        ("specification_id", "workflow_effect_one_click_specification:" + "0" * 64),
        (
            "transport_specification_id",
            "workflow_effect_transport_specification:" + "0" * 64,
        ),
        ("candidate_id", "workflow_effect_finding_candidate:" + "0" * 64),
        ("producer_data", {}),
        ("evidence_root", "0" * 64),
        ("cas_blob_hash", "0" * 64),
        ("observation_id", "obs-wrong"),
    ],
)
def test_active_proof_refuses_each_journal_cross_check(
    admitted, monkeypatch, key, wrong
):
    ledger, evidence, _, _, observation, finding = admitted
    journal = ledger._repository.load_workflow_effect_admission(evidence.source_receipt_id)
    assert journal is not None
    monkeypatch.setattr(
        ledger._repository,
        "load_workflow_effect_admission",
        lambda _identifier: {**journal, key: wrong},
    )
    with pytest.raises(ValueError, match="workflow active proof evidence does not match"):
        _active_check(ledger, observation, finding)


def test_active_proof_refuses_missing_journal(admitted, monkeypatch):
    ledger, _, _, _, observation, finding = admitted
    monkeypatch.setattr(
        ledger._repository, "load_workflow_effect_admission", lambda _: None
    )
    with pytest.raises(ValueError, match="workflow active proof evidence does not match"):
        _active_check(ledger, observation, finding)


@pytest.mark.parametrize("value", [None, {"evidence_root": "0" * 64}])
def test_active_proof_refuses_missing_or_invalid_embedded_evidence(
    admitted, monkeypatch, value
):
    ledger, evidence, _, receipts, observation, finding = admitted
    receipt = receipts.load(evidence.source_receipt_id.removeprefix("behavioral-"))
    assert receipt is not None and receipt.outcome is not None
    outcome = dict(receipt.outcome)
    outcome["workflow_effect_evidence"] = value
    monkeypatch.setattr(receipts, "load", lambda _: replace(receipt, outcome=outcome))
    with pytest.raises(ValueError, match="workflow active proof evidence is (missing|invalid)"):
        _active_check(ledger, observation, finding)


def test_active_proof_refuses_cas_and_provenance_mismatch(admitted, monkeypatch):
    ledger, _, _, _, observation, finding = admitted
    with monkeypatch.context() as patch:
        patch.setattr(ledger.cas, "load", lambda _: b"different")
        with pytest.raises(ValueError, match="workflow active proof evidence does not match"):
            _active_check(ledger, observation, finding)
    wrong_proof = ActiveProofCitation(
        observation_id=observation.id,
        receipt_id=finding.active_proof[0].receipt_id,
        provenance_root="0" * 64,
    )
    with pytest.raises(ValueError, match="workflow active proof evidence does not match"):
        ledger._validate_active_proof(
            evidence_citations=finding.citations,
            observations=[observation],
            active_proof=[wrong_proof],
        )


@pytest.mark.parametrize(
    "field",
    [
        "source_receipt_id",
        "assessment_session_id",
        "identity_binding",
        "compensating_cleanup_verified",
    ],
)
def test_active_proof_refuses_typed_evidence_cross_checks(
    admitted, monkeypatch, field
):
    ledger, evidence, _, receipts, observation, finding = admitted
    identity = AssessmentIdentityContext.from_dict(evidence.identity_binding)
    if field == "assessment_session_id":
        changes = {
            "assessment_session_id": "other-session",
            "identity_binding": replace(identity, session_id="other-session").to_dict(),
        }
    else:
        changes = {
            "source_receipt_id": {"source_receipt_id": "behavioral-" + "0" * 64},
            "identity_binding": {
                "identity_binding": replace(
                    identity, resource_id=stable_hash("resource", "other")
                ).to_dict()
            },
            "compensating_cleanup_verified": {
                "compensating_cleanup_verified": False
            },
        }[field]
    changed = _rebuilt(evidence, **changes)
    receipt = receipts.load(evidence.source_receipt_id.removeprefix("behavioral-"))
    assert receipt is not None and receipt.outcome is not None
    outcome = {**receipt.outcome, "workflow_effect_evidence": changed.to_dict()}
    monkeypatch.setattr(receipts, "load", lambda _: replace(receipt, outcome=outcome))
    monkeypatch.setattr(ledger.cas, "load", lambda _: changed.to_json_bytes())
    proof = ActiveProofCitation(
        observation_id=observation.id,
        receipt_id=evidence.source_receipt_id,
        provenance_root=changed.evidence_root,
    )
    with pytest.raises(ValueError, match="workflow active proof evidence does not match"):
        ledger._validate_active_proof(
            evidence_citations=finding.citations,
            observations=[observation],
            active_proof=[proof],
        )


@pytest.mark.parametrize(
    "field,wrong",
    [
        ("title", "other title"),
        ("severity", "critical"),
        ("description", "other description"),
        ("remediation", "other remediation"),
        ("confirmation_level", "probable"),
        ("metadata", {"finding_class": "workflow_invariant_violation_v1"}),
        ("citations", [Citation(observation_id="obs-wrong")]),
        ("active_proof", []),
    ],
)
def test_finding_class_refuses_template_or_shape_tamper(admitted, field, wrong):
    ledger, _, _, _, observation, finding = admitted
    changed = replace(finding, **{field: wrong})
    with pytest.raises(ValueError, match="workflow invariant finding"):
        ledger._validate_workflow_invariant_finding(
            changed, [observation], require_committed_journal=False
        )


def test_finding_class_refuses_missing_class_and_extra_observation(admitted):
    ledger, _, _, _, observation, finding = admitted
    with pytest.raises(ValueError, match="class is invalid"):
        ledger._validate_workflow_invariant_finding(
            replace(finding, metadata={}), [observation], require_committed_journal=False
        )
    with pytest.raises(ValueError, match="evidence shape is invalid"):
        ledger._validate_workflow_invariant_finding(
            finding, [observation, None], require_committed_journal=False
        )


@pytest.mark.parametrize("blob", [None, b"not canonical JSON"])
def test_finding_class_refuses_missing_or_invalid_cas(admitted, monkeypatch, blob):
    ledger, _, _, _, observation, finding = admitted
    monkeypatch.setattr(ledger.cas, "load", lambda _: blob)
    with pytest.raises(ValueError, match="workflow invariant finding evidence"):
        ledger._validate_workflow_invariant_finding(
            finding, [observation], require_committed_journal=False
        )


@pytest.mark.parametrize(
    "key,wrong",
    [
        ("state", "eligible_awaiting_processing"),
        ("evidence_root", "0" * 64),
        ("cas_blob_hash", "0" * 64),
        ("observation_id", "obs-wrong"),
        ("finding_id", "find-wrong"),
    ],
)
def test_finding_class_refuses_each_committed_journal_result(
    admitted, monkeypatch, key, wrong
):
    ledger, evidence, _, _, observation, finding = admitted
    row = ledger._repository.load_workflow_effect_admission(evidence.source_receipt_id)
    assert row is not None
    monkeypatch.setattr(
        ledger._repository,
        "load_workflow_effect_admission",
        lambda _: {**row, key: wrong},
    )
    with pytest.raises(ValueError, match="promotion journal mismatch"):
        ledger._validate_workflow_invariant_finding(finding, [observation])


def test_restart_refuses_uncommitted_workflow_journal(admitted):
    ledger, _, context, receipts, _, _ = admitted
    with sqlite3.connect(ledger.config.storage.db_path) as connection:
        connection.execute(
            "UPDATE workflow_effect_promotion_journal SET state = ? WHERE admission_id = ?",
            ("eligible_awaiting_processing", context["admission_id"]),
        )
    with pytest.raises(ValueError, match="workflow invariant promotion journal mismatch"):
        EvidenceLedger(ledger.config, receipt_store=receipts)


def test_honest_ceiling_limits_production_admission_to_gated_service():
    repository = Path(__file__).resolve().parents[2]
    ledger_path = repository / "core/epistemic/ledger.py"
    ledger_source = ledger_path.read_text()
    ledger_tree = ast.parse(ledger_source)
    capability = ledger_source.split(
        '            if observation.tool.name == "capability_effect_evidence":\n', 1
    )[1].split('            if observation.tool.name == "workflow_effect_evidence":\n', 1)[0]
    capability = (
        '            if observation.tool.name == "capability_effect_evidence":\n'
        + capability
    )
    generic = ledger_source.split(
        '            if not self._contains_provenance_root(\n', 1
    )[1].split('    def _validate_capability_replay_finding(\n', 1)[0]
    generic = '            if not self._contains_provenance_root(\n' + generic
    assert hashlib.sha256(capability.encode()).hexdigest() == (
        "121083ab4474c4309c6001d967cf60912b80f29c82ae6bff678f2af96538177e"
    )
    assert hashlib.sha256(generic.encode()).hexdigest() == (
        "a4fe9fd86e887445fcf2e8618e359fe3da5c0cccb5da5c86f72a7af389372f62"
    )
    methods = {
        node.name: node
        for node in ast.walk(ledger_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    admission = methods["admit_workflow_invariant_finding"]
    assert "_validate_workflow_invariant_finding" in methods
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "commit_workflow_effect_promotion"
        for node in ast.walk(admission)
    )
    constructors = []
    outcome_writers = []
    callers = []
    for path in (repository / "core").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "admit_workflow_invariant_finding"
                ):
                    callers.append(path)
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "ToolContext"
                    and any(
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value == "workflow_effect_evidence"
                        for keyword in node.keywords
                    )
                ):
                    constructors.append((path, node.lineno))
            if isinstance(node, ast.Dict) and any(
                isinstance(key, ast.Constant)
                and key.value == "workflow_effect_evidence"
                for key in node.keys
            ):
                outcome_writers.append(path)
    assert callers == [repository / "core/behavior/workflow_effect_promotion.py"]
    assert constructors == [(ledger_path, next(
        node.lineno for node in ast.walk(admission)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ToolContext"
    ))]
    assert outcome_writers == [repository / "core/behavior/receipts.py"]
