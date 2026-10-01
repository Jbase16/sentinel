"""R5F4 bounded exclusive local schedule/decision persistence and collision proof."""

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from core.behavior.concurrency_invariant_ledger import evaluate_schedule
from core.behavior.concurrency_invariant_store import (
    CONCURRENCY_INVARIANT_STORE_ENV,
    ConcurrencyInvariantScheduleStore,
    ConcurrencyInvariantStoreError,
    DurableConcurrencySchedule,
)
from tests.unit.test_behavior_concurrency_invariant_binding import binding


def result():
    bound, schedule = binding()
    return evaluate_schedule(bound, bound.capture, schedule, at_index=10)


def test_store_reloads_exact_decision_and_duplicate_preserves_bytes(tmp_path):
    root = tmp_path / "schedules"
    store = ConcurrencyInvariantScheduleStore(root)
    completed = result()
    assert store.load(completed.result_id) is None
    assert not root.exists()
    first = store.persist(completed)
    path = next(root.iterdir())
    before = path.read_bytes(), path.stat().st_mtime_ns
    second = ConcurrencyInvariantScheduleStore(root).persist(completed)
    assert first.durable_written is True and second.durable_written is False
    assert first.result == second.result == completed
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert (
        ConcurrencyInvariantScheduleStore(root).load(completed.result_id) == completed
    )
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.geteuid()
    assert DurableConcurrencySchedule.from_dict(first.to_dict()) == first


def test_environment_override_and_tampered_collision_fail_closed(tmp_path, monkeypatch):
    root = tmp_path / "override"
    monkeypatch.setenv(CONCURRENCY_INVARIANT_STORE_ENV, str(root))
    store = ConcurrencyInvariantScheduleStore()
    assert store._root() == root
    completed = result()
    store.persist(completed)
    path = next(root.iterdir())
    value = json.loads(path.read_text())
    value["result"]["decision"]["race_confirmed"] = False
    path.write_text(json.dumps(value))
    with pytest.raises(ConcurrencyInvariantStoreError):
        store.load(completed.result_id)
    with pytest.raises(ConcurrencyInvariantStoreError):
        store.persist(completed)
    with pytest.raises(ConcurrencyInvariantStoreError):
        store.load("../raw")
    raw = deepcopy(completed.to_dict())
    raw["executable"] = True
    with pytest.raises(ValueError):
        type(completed).from_dict(raw)


CHILD = """
import json, sys
from pathlib import Path
from core.behavior.concurrency_invariant_ledger import ConcurrencyScheduleResult
from core.behavior.concurrency_invariant_store import ConcurrencyInvariantScheduleStore
result = ConcurrencyScheduleResult.from_dict(json.loads(sys.argv[2]))
stored = ConcurrencyInvariantScheduleStore(Path(sys.argv[1])).persist(result)
print(json.dumps({'written': stored.durable_written, 'result_id': stored.result.result_id}), flush=True)
"""


def test_cross_process_exclusive_publication(tmp_path):
    completed = result()
    root = tmp_path / "cross-process"
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", CHILD, str(root), json.dumps(completed.to_dict())],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=Path(__file__).resolve().parents[2],
        )
        for _ in range(2)
    ]
    outputs = [process.communicate(timeout=60) for process in processes]
    assert all(process.returncode == 0 for process in processes), outputs
    assert sorted(json.loads(output[0])["written"] for output in outputs) == [
        False,
        True,
    ]
    assert (
        ConcurrencyInvariantScheduleStore(root).load(completed.result_id) == completed
    )
