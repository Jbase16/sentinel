"""R5E4 local durability proof, including fresh-exec process contention."""

from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from core.behavior import workflow_invariant_store as module
from core.behavior.normalize import stable_hash
from core.behavior.workflow_invariant_binding import (
    WorkflowBindingDenied,
    WorkflowInvariantBinding,
)
from core.behavior.workflow_invariant_ledger import (
    WorkflowLedgerDenied,
    WorkflowTransitionOutcome,
)
from core.behavior.workflow_invariant_store import (
    WORKFLOW_INVARIANT_STORE_ENV,
    WorkflowInvariantSequenceStore,
    WorkflowInvariantStoreError,
)
from tests.unit.test_behavior_workflow_invariant_binding import ORIGIN, binding

REPOSITORY = Path(__file__).resolve().parents[2]


def record(store, bound, index=0, at_index=10):
    return store.record_operation(
        bound,
        bound.capture,
        bound.fixture.contract.operations[index],
        at_index=at_index,
    )


def snapshot(root):
    return {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.iterdir()
    }


def test_first_application_survives_reload_with_safe_permissions(tmp_path):
    bound = binding()
    root = tmp_path / "sequence"
    result = record(WorkflowInvariantSequenceStore(root), bound)
    loaded = WorkflowInvariantSequenceStore(root).load(bound)
    assert result.durable_state_written is True and loaded == result.result.ledger
    assert loaded.terminal_state.consumed == 6
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    path = next(root.iterdir())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.geteuid()
    value = json.loads(path.read_text())
    assert path.read_text() == module._canonical_json(value)
    assert len(list(root.iterdir())) == 1


@pytest.mark.parametrize(
    "secure,second_outcome,files",
    [
        (False, WorkflowTransitionOutcome.FIRST_APPLICATION, 2),
        (True, WorkflowTransitionOutcome.OPERATION_REFUSED, 1),
    ],
)
def test_durable_twins_and_refusal_preserve_snapshots(
    tmp_path, secure, second_outcome, files
):
    bound = binding(secure=secure)
    root = tmp_path / "sequence"
    store = WorkflowInvariantSequenceStore(root)
    record(store, bound)
    before = snapshot(root)
    second = record(WorkflowInvariantSequenceStore(root), bound, index=1)
    assert second.result.outcome is second_outcome
    assert len(snapshot(root)) == files
    if secure:
        assert snapshot(root) == before


def test_replay_budget_and_restart_leave_bytes_and_mtimes_unchanged(tmp_path):
    bound = binding(budget=1)
    root = tmp_path / "sequence"
    record(WorkflowInvariantSequenceStore(root), bound)
    before = snapshot(root)
    replay = record(WorkflowInvariantSequenceStore(root), bound)
    exhausted = record(WorkflowInvariantSequenceStore(root), bound, index=1)
    assert replay.result.outcome is WorkflowTransitionOutcome.REPLAY_REFUSED
    assert exhausted.result.outcome is WorkflowTransitionOutcome.BUDGET_EXHAUSTED
    assert replay.durable_state_written is exhausted.durable_state_written is False
    assert snapshot(root) == before


# These children use fresh exec, not multiprocessing spawn of the extension-heavy
# pytest parent. They therefore also run safely in the unmarked repository gate.
CHILD = """
import json, sys
from pathlib import Path
from core.behavior.workflow_invariant_binding import WorkflowInvariantBinding
from core.behavior.workflow_invariant_store import WorkflowInvariantSequenceStore
bound = WorkflowInvariantBinding.from_dict(json.loads(sys.argv[2]))
class InterleavedStore(WorkflowInvariantSequenceStore):
    def _publish_state(self, root, binding, ledger):
        print('READY', flush=True)
        input()
        super()._publish_state(root, binding, ledger)
store = InterleavedStore(Path(sys.argv[1])) if sys.argv[3] == 'barrier' else WorkflowInvariantSequenceStore(Path(sys.argv[1]))
result = store.record_operation(bound, bound.capture, bound.fixture.contract.operations[0], at_index=10)
print(json.dumps({'outcome': result.result.outcome.value, 'written': result.durable_state_written}), flush=True)
"""


def test_exclusive_create_refuses_double_application_across_processes(tmp_path):
    bound = binding()
    root = tmp_path / "sequence"
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                CHILD,
                str(root),
                json.dumps(bound.to_dict()),
                "barrier",
            ],
            cwd=REPOSITORY,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    try:
        assert [process.stdout.readline().strip() for process in processes] == [
            "READY",
            "READY",
        ]
        outputs = [process.communicate(input="\n", timeout=20) for process in processes]
        assert [process.returncode for process in processes] == [0, 0], outputs
        results = [json.loads(output) for output, _ in outputs]
        assert sorted(result["written"] for result in results) == [False, True]
        assert {result["outcome"] for result in results} == {
            "first_application",
            "replay_refused",
        }
        assert len(WorkflowInvariantSequenceStore(root).load(bound).entries) == 1
        assert len(list(root.iterdir())) == 1
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)


def test_fresh_process_restart_refuses_already_applied_operation(tmp_path):
    bound = binding()
    root = tmp_path / "sequence"
    record(WorkflowInvariantSequenceStore(root), bound)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            CHILD,
            str(root),
            json.dumps(bound.to_dict()),
            "restart",
        ],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    assert json.loads(child.stdout) == {"outcome": "replay_refused", "written": False}


@pytest.mark.parametrize(
    "mutation",
    [
        "stale",
        "cross_account",
        "cross_tenant",
        "changed_capture",
        "out_of_order",
        "forged_operation",
    ],
)
def test_bad_context_refused_before_creating_store(tmp_path, mutation):
    bound = binding()
    root = tmp_path / "sequence"
    current, operation, index = bound.capture, bound.fixture.contract.operations[0], 10
    if mutation == "stale":
        index = 20
    elif mutation in {"cross_account", "cross_tenant"}:
        field = "account_ref" if mutation == "cross_account" else "tenant_ref"
        prefix = "experiment_persona" if field == "account_ref" else "owned_tenant"
        current = replace(current, **{field: stable_hash(prefix, "other")})
    elif mutation == "changed_capture":
        current = replace(
            current,
            capture_generation_ref=stable_hash("workflow_capture_generation", "new"),
        )
    elif mutation == "out_of_order":
        operation = bound.fixture.contract.operations[1]
    else:
        operation = replace(operation, amount=5)
    with pytest.raises((WorkflowBindingDenied, WorkflowLedgerDenied)):
        WorkflowInvariantSequenceStore(root).record_operation(
            bound, current, operation, at_index=index
        )
    assert not root.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "slot",
        "slot_key",
        "ledger_hash",
        "entry_hash",
        "state",
        "extra_field",
        "noncanonical",
        "oversized",
        "mode",
    ],
)
def test_corrupted_state_refused_on_load(tmp_path, mutation):
    bound = binding()
    store = WorkflowInvariantSequenceStore(tmp_path / "sequence")
    record(store, bound)
    path = next(store.root.iterdir())
    value = json.loads(path.read_text())
    if mutation == "slot":
        value["slot"] = True
    elif mutation == "slot_key":
        value["slot_key"] = "0" * 64
    elif mutation == "ledger_hash":
        value["ledger"]["ledger_id"] = stable_hash(
            "workflow_transition_ledger", "forged"
        )
    elif mutation == "entry_hash":
        value["ledger"]["entries"][0]["entry_id"] = stable_hash(
            "workflow_transition_entry", "forged"
        )
    elif mutation == "state":
        value["ledger"]["entries"][0]["after_state"]["consumed"] = 5
    elif mutation == "extra_field":
        value["injected"] = True
    elif mutation == "mode":
        value["mode"] = "other"
    payload = (
        json.dumps(value, indent=2)
        if mutation == "noncanonical"
        else module._canonical_json(value)
    )
    if mutation == "oversized":
        payload = " " * (module._MAX_RECEIPT_BYTES + 1)
    path.write_text(payload)
    with pytest.raises(WorkflowInvariantStoreError):
        store.load(bound)


def test_missing_prefix_slot_and_invalid_filename_fail_closed(tmp_path):
    bound = binding()
    store = WorkflowInvariantSequenceStore(tmp_path / "sequence")
    record(store, bound)
    record(store, bound, index=1)
    (store.root / store._file_name(bound, 0)).unlink()
    with pytest.raises(WorkflowInvariantStoreError, match="gap"):
        store.load(bound)
    remaining = next(store.root.iterdir())
    remaining.rename(remaining.with_name(remaining.name.replace("-1-", "-01-")))
    with pytest.raises(WorkflowInvariantStoreError, match="filename"):
        store.load(bound)


@pytest.mark.parametrize(
    "surface", ["root_symlink", "file_symlink", "unsafe_mode", "wrong_owner"]
)
def test_unsafe_filesystem_refused(tmp_path, monkeypatch, surface):
    bound = binding()
    root = tmp_path / "sequence"
    store = WorkflowInvariantSequenceStore(root)
    if surface == "root_symlink":
        target = tmp_path / "target"
        target.mkdir()
        root.symlink_to(target, target_is_directory=True)
    else:
        record(store, bound)
        path = next(root.iterdir())
        if surface == "file_symlink":
            target = tmp_path / "target.json"
            path.rename(target)
            path.symlink_to(target)
        elif surface == "unsafe_mode":
            path.chmod(0o644)
        else:
            actual = os.geteuid()
            monkeypatch.setattr(module.os, "geteuid", lambda: actual + 1)
    with pytest.raises(WorkflowInvariantStoreError):
        store.load(bound)


def test_recapture_cannot_reset_persisted_stream(tmp_path):
    bound = binding()
    store = WorkflowInvariantSequenceStore(tmp_path / "sequence")
    record(store, bound)
    before = snapshot(store.root)
    changed = replace(
        bound.capture,
        capture_generation_ref=stable_hash("workflow_capture_generation", "new"),
    )
    renewed = WorkflowInvariantBinding.build(
        fixture=bound.fixture, capture=changed, target_origin=ORIGIN
    )
    with pytest.raises(WorkflowInvariantStoreError, match="binding"):
        record(store, renewed)
    assert snapshot(store.root) == before


def test_publication_failure_is_not_reported_as_success(tmp_path, monkeypatch):
    def fail(*_):
        raise OSError("injected failure")

    monkeypatch.setattr(module.BehavioralReceiptStore, "_link_exclusive", fail)
    store = WorkflowInvariantSequenceStore(tmp_path / "sequence")
    with pytest.raises(WorkflowInvariantStoreError, match="publication"):
        record(store, binding())
    assert list(store.root.iterdir()) == []


def test_storage_namespace_and_independent_fixtures(tmp_path, monkeypatch):
    monkeypatch.setenv(WORKFLOW_INVARIANT_STORE_ENV, str(tmp_path / "override"))
    assert WorkflowInvariantSequenceStore()._root() == tmp_path / "override"
    monkeypatch.delenv(WORKFLOW_INVARIANT_STORE_ENV)
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
    assert (
        WorkflowInvariantSequenceStore()._root()
        == tmp_path / "data" / "workflow_invariant_sequences"
    )
    store = WorkflowInvariantSequenceStore(tmp_path / "sequence")
    alice, bob = binding(), binding(suffix="bob")
    record(store, alice)
    record(store, bob)
    assert len(store.load(alice).entries) == len(store.load(bob).entries) == 1
    assert len(list(store.root.iterdir())) == 2
