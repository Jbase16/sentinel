"""R5E5 retained offline evidence, inert reload and eligibility honesty proof."""

import ast
from dataclasses import replace
import json
from pathlib import Path

import pytest

from core.behavior import workflow_invariant_evidence as module
from core.behavior.normalize import stable_hash
from core.behavior.workflow_invariant_binding import evaluate_offline
from core.behavior.workflow_invariant_contract import WorkflowInvariantOutcome
from core.behavior.workflow_invariant_evidence import (
    WORKFLOW_INVARIANT_EVIDENCE_ENV,
    StoredWorkflowInvariantEvidence,
    WorkflowInvariantEvidenceError,
    WorkflowInvariantEvidenceStore,
    offline_promotion_eligibility,
)
from core.behavior.workflow_invariant_ledger import (
    WorkflowTransitionLedger,
    evaluate_sequence,
)
from core.behavior.workflow_invariant_store import WorkflowInvariantSequenceStore
from tests.unit.test_behavior_workflow_invariant_binding import binding


def completed(**values):
    bound = binding(**values)
    return evaluate_sequence(bound, bound.capture, at_index=10)


@pytest.mark.parametrize(
    "secure,amounts,outcome,eligible",
    [
        (False, (6, 6), WorkflowInvariantOutcome.INVARIANT_VIOLATED, True),
        (True, (6, 6), WorkflowInvariantOutcome.OPERATION_REFUSED, False),
        (True, (4, 6), WorkflowInvariantOutcome.INVARIANT_HELD, False),
    ],
)
def test_retained_twins_and_boundary_have_only_offline_eligibility(
    tmp_path, secure, amounts, outcome, eligible
):
    result = completed(secure=secure, amounts=amounts)
    store = WorkflowInvariantEvidenceStore(tmp_path / "evidence")
    written = store.persist(result)
    retained = WorkflowInvariantEvidenceStore(store.root).load(
        written.evidence.evidence_id
    )
    assert type(retained) is StoredWorkflowInvariantEvidence
    assert retained.reloaded is True and retained.outcome is outcome
    assert retained is not result and retained.result_ref == result.result_id
    eligibility = offline_promotion_eligibility(
        retained, result.ledger.binding.capture, at_index=11
    )
    assert eligibility.eligible is eligible
    assert eligibility.to_dict()["promotion_authority"] is False
    assert retained.to_dict()["observed_target_effect"] is False
    assert retained.to_dict()["target_requests_sent"] == 0


def test_full_passive_chain_uses_durable_ledger_then_evidence(tmp_path):
    bound = binding()
    sequences = WorkflowInvariantSequenceStore(tmp_path / "sequence")
    for operation in bound.fixture.contract.operations:
        sequences.record_operation(bound, bound.capture, operation, at_index=10)
    reloaded = WorkflowInvariantSequenceStore(sequences.root).load(bound)
    result = evaluate_sequence(bound, bound.capture, at_index=10, ledger=reloaded)
    offline = evaluate_offline(bound, bound.capture, at_index=10)
    assert result.decision == offline.decision
    written = WorkflowInvariantEvidenceStore(tmp_path / "evidence").persist(result)
    assert (
        offline_promotion_eligibility(
            written.evidence, bound.capture, at_index=10
        ).eligible
        is True
    )
    assert len(list(sequences.root.iterdir())) == 2


def test_duplicate_retention_preserves_bytes_and_mtime(tmp_path):
    store = WorkflowInvariantEvidenceStore(tmp_path / "evidence")
    result = completed()
    first = store.persist(result)
    path = next(store.root.iterdir())
    before = path.read_bytes(), path.stat().st_mtime_ns
    second = store.persist(result)
    assert first.durable_written is True and second.durable_written is False
    assert first.evidence == second.evidence
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_ephemeral_result_and_serialized_projection_are_not_retained_evidence(tmp_path):
    result = completed()
    for unretained in (result, result.to_dict(), None):
        assert (
            offline_promotion_eligibility(
                unretained, result.ledger.binding.capture, at_index=10
            ).eligible
            is False
        )
    with pytest.raises(WorkflowInvariantEvidenceError, match="retained"):
        StoredWorkflowInvariantEvidence(module._evidence_id(result), result, object())
    store = WorkflowInvariantEvidenceStore(tmp_path / "evidence")
    with pytest.raises(WorkflowInvariantEvidenceError, match="completed"):
        store.persist(WorkflowTransitionLedger(result.ledger.binding))
    assert not store.root.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "stale",
        "before_capture",
        "cross_account",
        "cross_tenant",
        "other_world",
        "changed_capture",
        "invalid_index",
    ],
)
def test_ineligible_contexts_fail_closed_after_storage(tmp_path, mutation):
    result = completed()
    bound = result.ledger.binding
    retained = (
        WorkflowInvariantEvidenceStore(tmp_path / "evidence").persist(result).evidence
    )
    current, index = bound.capture, 11
    if mutation == "stale":
        index = 20
    elif mutation == "before_capture":
        index = 9
    elif mutation == "invalid_index":
        index = True
    else:
        fields = {
            "cross_account": ("account_ref", "experiment_persona"),
            "cross_tenant": ("tenant_ref", "owned_tenant"),
            "other_world": ("world_binding_ref", "experiment_world_binding"),
            "changed_capture": (
                "capture_generation_ref",
                "workflow_capture_generation",
            ),
        }
        field, prefix = fields[mutation]
        current = replace(current, **{field: stable_hash(prefix, "other")})
    decision = offline_promotion_eligibility(retained, current, at_index=index)
    assert decision.eligible is False and decision.evidence_ref is None


@pytest.mark.parametrize(
    "mutation",
    [
        "address",
        "decision",
        "terminal",
        "ledger",
        "binding",
        "authority",
        "extra",
        "noncanonical",
        "oversize",
    ],
)
def test_tampered_retained_artifacts_fail_closed(tmp_path, mutation):
    store = WorkflowInvariantEvidenceStore(tmp_path / "evidence")
    written = store.persist(completed())
    path = next(store.root.iterdir())
    value = json.loads(path.read_text())
    if mutation == "address":
        value["evidence_id"] = stable_hash("workflow_invariant_evidence", "forged")
    elif mutation == "decision":
        value["sequence_result"]["decision"]["outcome"] = "invariant_held"
    elif mutation == "terminal":
        value["sequence_result"]["decision"]["terminal_state"]["consumed"] = 10
    elif mutation == "ledger":
        value["sequence_result"]["ledger"]["entries"] = []
    elif mutation == "binding":
        value["sequence_result"]["ledger"]["binding"]["capture"]["tenant_ref"] = (
            stable_hash("owned_tenant", "other")
        )
    elif mutation == "authority":
        value["promotion_authority"] = True
    elif mutation == "extra":
        value["retained"] = True
    payload = (
        json.dumps(value, indent=2)
        if mutation == "noncanonical"
        else module._canonical_json(value)
    )
    if mutation == "oversize":
        payload = " " * (module._MAX_RECEIPT_BYTES + 1)
    path.write_text(payload)
    with pytest.raises(WorkflowInvariantEvidenceError):
        store.load(written.evidence.evidence_id)


def test_forged_live_value_refused_by_pure_eligibility(tmp_path):
    result = completed()
    stored = (
        WorkflowInvariantEvidenceStore(tmp_path / "evidence").persist(result).evidence
    )
    object.__setattr__(
        stored, "evidence_id", stable_hash("workflow_invariant_evidence", "forged")
    )
    assert (
        offline_promotion_eligibility(
            stored, result.ledger.binding.capture, at_index=10
        ).eligible
        is False
    )


@pytest.mark.parametrize("surface", ["root_symlink", "file_symlink", "file_mode"])
def test_unsafe_evidence_filesystem_refused(tmp_path, surface):
    store = WorkflowInvariantEvidenceStore(tmp_path / "evidence")
    if surface == "root_symlink":
        target = tmp_path / "target"
        target.mkdir()
        store.root.symlink_to(target, target_is_directory=True)
        with pytest.raises(WorkflowInvariantEvidenceError):
            store.persist(completed())
        assert list(target.iterdir()) == []
        return
    written = store.persist(completed())
    path = next(store.root.iterdir())
    if surface == "file_symlink":
        target = tmp_path / "target.json"
        path.rename(target)
        path.symlink_to(target)
    else:
        path.chmod(0o644)
    with pytest.raises(WorkflowInvariantEvidenceError):
        store.load(written.evidence.evidence_id)


def test_publication_error_does_not_mint_retained_value(tmp_path, monkeypatch):
    def fail(*_):
        raise OSError("injected retention failure")

    monkeypatch.setattr(module.BehavioralReceiptStore, "_link_exclusive", fail)
    store = WorkflowInvariantEvidenceStore(tmp_path / "evidence")
    with pytest.raises(WorkflowInvariantEvidenceError, match="publication"):
        store.persist(completed())
    assert list(store.root.iterdir()) == []


def test_evidence_namespace_and_absent_load_are_inert(tmp_path, monkeypatch):
    monkeypatch.setenv(WORKFLOW_INVARIANT_EVIDENCE_ENV, str(tmp_path / "override"))
    assert WorkflowInvariantEvidenceStore()._root() == tmp_path / "override"
    monkeypatch.delenv(WORKFLOW_INVARIANT_EVIDENCE_ENV)
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
    assert (
        WorkflowInvariantEvidenceStore()._root()
        == tmp_path / "data" / "workflow_invariant_evidence"
    )
    store = WorkflowInvariantEvidenceStore(tmp_path / "evidence")
    assert store.load(stable_hash("workflow_invariant_evidence", "absent")) is None
    assert not store.root.exists()
    with pytest.raises(WorkflowInvariantEvidenceError):
        store.load("../raw-id")


def test_all_five_layers_are_unwired_and_have_no_target_imports():
    repository = Path(__file__).resolve().parents[2]
    names = {
        f"workflow_invariant_{suffix}"
        for suffix in ("contract", "binding", "ledger", "store", "evidence")
    }
    forbidden = {
        "httpx",
        "requests",
        "socket",
        "asyncio",
        "subprocess",
        "time",
        "foundry",
        "submission_candidate",
        "capability_effect_promotion",
    }
    for name in names:
        path = repository / "core" / "behavior" / f"{name}.py"
        tree = ast.parse(path.read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.update((node.module or "").split("."))
        assert not imports & forbidden
    permitted_consumers = {
        "workflow_invariant_effect",
        "workflow_invariant_effect_transport",
    }
    consumers = []
    for path in (repository / "core").rglob("*.py"):
        if path.stem in names or path.stem in permitted_consumers:
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                referenced = set((node.module or "").split(".")) | {
                    alias.name for alias in node.names
                }
            elif isinstance(node, ast.Import):
                referenced = {
                    part for alias in node.names for part in alias.name.split(".")
                }
            else:
                continue
            if referenced & names:
                consumers.append(str(path))
    assert consumers == []
