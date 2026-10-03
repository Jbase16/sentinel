"""R5F5 retained inert evidence, eligibility, import boundaries and registry proof."""

import ast
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.behavior import concurrency_invariant_evidence as module
from core.behavior.concurrency_invariant_evidence import (
    ConcurrencyInvariantEvidenceError,
    ConcurrencyInvariantEvidenceStore,
    ConcurrencyPromotionEligibility,
    StoredConcurrencyInvariantEvidence,
    offline_promotion_eligibility,
)
from core.behavior.concurrency_invariant_ledger import evaluate_schedule
from core.behavior.normalize import stable_hash
from tests.import_contract import find_module_consumers, source_imports_module
from tests.unit.test_behavior_concurrency_invariant_binding import binding

REPOSITORY = Path(__file__).resolve().parents[2]
SUFFIXES = ("contract", "binding", "ledger", "store", "evidence")
MODULE_NAMES = tuple(
    f"core.behavior.concurrency_invariant_{suffix}" for suffix in SUFFIXES
)
MODULE_PATHS = tuple(
    REPOSITORY / Path(name.replace(".", "/") + ".py") for name in MODULE_NAMES
)
TEST_PATHS = tuple(
    REPOSITORY / "tests/unit" / f"test_behavior_concurrency_invariant_{suffix}.py"
    for suffix in SUFFIXES
)
EFFECT_MODULE_PATH = REPOSITORY / "core/behavior/concurrency_invariant_effect.py"
EFFECT_TEST_PATH = (
    REPOSITORY / "tests/unit/test_behavior_concurrency_invariant_effect.py"
)
EFFECT_TRANSPORT_MODULE_PATH = REPOSITORY / "core/behavior/concurrency_invariant_effect_transport.py"
EFFECT_ONE_CLICK_MODULE_PATH = REPOSITORY / "core/behavior/concurrency_invariant_effect_one_click.py"
EFFECT_ONE_CLICK_TEST_PATH = REPOSITORY / "tests/unit/test_behavior_concurrency_invariant_effect_one_click.py"
EFFECT_TRANSPORT_TEST_PATH = REPOSITORY / "tests/unit/test_behavior_concurrency_invariant_effect_transport.py"
FORBIDDEN = {
    "threading",
    "asyncio",
    "multiprocessing",
    "concurrent",
    "queue",
    "socket",
    "ssl",
    "http",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
    "subprocess",
    "signal",
    "time",
    "datetime",
    "random",
    "secrets",
}
ALLOWED_OS_ATTRIBUTES = {"environ", "open", "fstat", "close", "fdopen", "O_RDONLY"}
SHARED = {"normalize", "experiment_sdk", "payout_goals", "receipts"}


def completed(*, secure=False, limit=1):
    bound, schedule = binding(secure=secure, limit=limit)
    return evaluate_schedule(bound, bound.capture, schedule, at_index=10)


@pytest.mark.parametrize(
    "secure,limit,eligible", [(False, 1, True), (True, 1, False), (False, 2, False)]
)
def test_retained_twins_and_boundary_are_only_offline_eligible(
    tmp_path, secure, limit, eligible
):
    result = completed(secure=secure, limit=limit)
    store = ConcurrencyInvariantEvidenceStore(tmp_path / "evidence")
    written = store.persist(result)
    retained = ConcurrencyInvariantEvidenceStore(store.root).load(
        written.evidence.evidence_id
    )
    assert type(retained) is StoredConcurrencyInvariantEvidence
    assert retained.reloaded is True and retained.result_ref == result.result_id
    bound = result.ledger.binding
    answer = offline_promotion_eligibility(retained, bound, bound.capture, at_index=11)
    assert answer.eligible is eligible
    assert answer.to_dict()["promotion_authority"] is False
    assert answer.to_dict()["finding_authority"] is False
    assert retained.to_dict()["observed_target_effect"] is False
    assert retained.to_dict()["target_requests_sent"] == 0
    assert ConcurrencyPromotionEligibility.from_dict(answer.to_dict()) == answer


def test_retention_reloads_and_duplicate_preserves_bytes(tmp_path):
    result = completed()
    store = ConcurrencyInvariantEvidenceStore(tmp_path / "evidence")
    first = store.persist(result)
    path = next(store.root.iterdir())
    before = path.read_bytes(), path.stat().st_mtime_ns
    second = store.persist(result)
    assert first.durable_written is True and second.durable_written is False
    assert first.evidence == second.evidence
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    with pytest.raises(ConcurrencyInvariantEvidenceError, match="retention"):
        StoredConcurrencyInvariantEvidence.from_dict(first.evidence.to_dict())


def test_unretained_or_stale_or_wrong_binding_is_ineligible(tmp_path):
    result = completed()
    bound = result.ledger.binding
    retained = (
        ConcurrencyInvariantEvidenceStore(tmp_path / "evidence")
        .persist(result)
        .evidence
    )
    for unretained in (result, result.to_dict(), None):
        assert not offline_promotion_eligibility(
            unretained, bound, bound.capture, at_index=11
        ).eligible
    with pytest.raises(ConcurrencyInvariantEvidenceError, match="retained"):
        StoredConcurrencyInvariantEvidence(
            module._evidence_id(result), result, object()
        )
    assert not offline_promotion_eligibility(
        retained, bound, bound.capture, at_index=20
    ).eligible
    other, _ = binding(secure=True)
    assert not offline_promotion_eligibility(
        retained, other, bound.capture, at_index=11
    ).eligible
    changed = replace(
        bound.capture,
        capture_generation_ref=stable_hash("concurrency_capture_generation", "other"),
    )
    assert not offline_promotion_eligibility(
        retained, bound, changed, at_index=11
    ).eligible


@pytest.mark.parametrize("mutation", ["authority", "race", "schedule"])
def test_evidence_tamper_and_collision_refused(tmp_path, mutation):
    result = completed()
    store = ConcurrencyInvariantEvidenceStore(tmp_path / "evidence")
    written = store.persist(result)
    path = next(store.root.iterdir())
    value = deepcopy(written.evidence.to_dict())
    if mutation == "authority":
        value["finding_authority"] = True
    elif mutation == "race":
        value["schedule_result"]["decision"]["race_confirmed"] = False
    else:
        value["schedule_result"]["decision"]["schedule"]["schedule_id"] = stable_hash(
            "concurrency_workflow_schedule", "wrong"
        )
    path.write_text(module._canonical_json(value))
    with pytest.raises(ConcurrencyInvariantEvidenceError):
        store.load(written.evidence.evidence_id)
    with pytest.raises(ConcurrencyInvariantEvidenceError):
        store.persist(result)
    with pytest.raises(ConcurrencyInvariantEvidenceError):
        store.load("../raw")


CHILD = """
import json, sys
from pathlib import Path
from core.behavior.concurrency_invariant_evidence import ConcurrencyInvariantEvidenceStore
from core.behavior.concurrency_invariant_ledger import ConcurrencyScheduleResult
result = ConcurrencyScheduleResult.from_dict(json.loads(sys.argv[2]))
stored = ConcurrencyInvariantEvidenceStore(Path(sys.argv[1])).persist(result)
print(json.dumps({'written': stored.durable_written, 'evidence_id': stored.evidence.evidence_id}), flush=True)
"""


def test_evidence_cross_process_exclusive_publication(tmp_path):
    result = completed()
    root = tmp_path / "cross-process"
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", CHILD, str(root), json.dumps(result.to_dict())],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=REPOSITORY,
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
        ConcurrencyInvariantEvidenceStore(root).load(module._evidence_id(result))
        is not None
    )


def _import_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                names.add((node.module or "").split(".")[0])
            else:
                names.add((node.module or "").split(".")[0])
    return names


def test_all_five_unwired_and_no_forbidden_primitives():
    core_paths = tuple((REPOSITORY / "core").rglob("*.py"))
    for name, path in zip(MODULE_NAMES, MODULE_PATHS):
        tree = ast.parse(path.read_text())
        imports = _import_names(tree)
        assert not imports & FORBIDDEN
        assert not imports & {
            "workflow_invariant_contract",
            "workflow_invariant_binding",
            "workflow_invariant_ledger",
            "workflow_invariant_store",
            "workflow_invariant_evidence",
            "router",
            "foundry",
            "scan",
            "scheduler",
            "coordinator",
            "capability_effect",
            "role",
            "prerequisite",
        }
        os_attributes = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        }
        if path.stem in {
            "concurrency_invariant_store",
            "concurrency_invariant_evidence",
        }:
            assert os_attributes <= ALLOWED_OS_ATTRIBUTES
        else:
            assert "os" not in imports and not os_attributes
        relative_imports = {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level
        }
        assert relative_imports <= {
            *(f"concurrency_invariant_{suffix}" for suffix in SUFFIXES),
            *SHARED,
        }
        assert (
            find_module_consumers(
                core_paths,
                name,
                repository_root=REPOSITORY,
                exclude=(
                    *MODULE_PATHS,
                    EFFECT_MODULE_PATH,
                    EFFECT_TRANSPORT_MODULE_PATH,
                    EFFECT_ONE_CLICK_MODULE_PATH,
                ),
            )
            == ()
        )


def test_each_f_module_has_only_family_consumers():
    paths = tuple((REPOSITORY / "core").rglob("*.py")) + tuple(
        (REPOSITORY / "tests").rglob("*.py")
    )
    allowed = {
        *MODULE_PATHS,
        *TEST_PATHS,
        EFFECT_MODULE_PATH,
        EFFECT_TEST_PATH,
        EFFECT_TRANSPORT_MODULE_PATH,
        EFFECT_TRANSPORT_TEST_PATH,
        EFFECT_ONE_CLICK_MODULE_PATH,
        EFFECT_ONE_CLICK_TEST_PATH,
    }
    for name, own_path in zip(MODULE_NAMES, MODULE_PATHS):
        consumers = find_module_consumers(
            paths, name, repository_root=REPOSITORY, exclude=(own_path,)
        )
        assert set(consumers) <= allowed


@pytest.mark.parametrize(
    "stem", ["unrelated_consumer", "concurrency_invariant_contract_extra"]
)
@pytest.mark.parametrize("imported", MODULE_NAMES)
def test_both_consumer_audits_detect_injected_import(monkeypatch, stem, imported):
    added = REPOSITORY / "core/behavior" / f"{stem}.py"
    original_rglob, original_read = Path.rglob, Path.read_text

    def with_consumer(path, pattern):
        yield from original_rglob(path, pattern)
        if path == REPOSITORY / "core":
            yield added

    def read(path, *args, **kwargs):
        if path == added:
            return f"from core.behavior import {imported.rsplit('.', 1)[1]}\n"
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", with_consumer)
    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_all_five_unwired_and_no_forbidden_primitives()
    with pytest.raises(AssertionError):
        test_each_f_module_has_only_family_consumers()


@pytest.mark.parametrize("forbidden", sorted(FORBIDDEN))
def test_primitive_audit_detects_injected_import(monkeypatch, forbidden):
    path = MODULE_PATHS[0]
    original_read = Path.read_text

    def read(candidate, *args, **kwargs):
        source = original_read(candidate, *args, **kwargs)
        return source + f"\nimport {forbidden}\n" if candidate == path else source

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        test_all_five_unwired_and_no_forbidden_primitives()


def test_exact_stem_matching_ignores_lookalike_module_name():
    source = "from core.behavior import concurrency_invariant_contract_extra\n"
    assert (
        source_imports_module(
            source, MODULE_NAMES[0], current_module="core.behavior.other"
        )
        is False
    )
    assert (
        source_imports_module(
            "from core.behavior import concurrency_invariant_contract\n",
            MODULE_NAMES[0],
            current_module="core.behavior.other",
        )
        is True
    )


def test_registry_has_exact_eight_additive_slice_records():
    from core.contracts.architecture_ids import (
        IdentifierRegistry,
        default_registry_path,
    )

    registry = IdentifierRegistry.load(default_registry_path(REPOSITORY))
    assert all(f"R5F{index}" in registry.canonical_ids for index in range(1, 9))
    records = json.loads(
        (REPOSITORY / "docs/architecture/CANONICAL_ID_REGISTRY.json").read_text()
    )["canonical_ids"]
    assert [record["id"] for record in records if record["id"].startswith("R5F")] == [
        "R5F1",
        "R5F2",
        "R5F3",
        "R5F4",
        "R5F5",
        "R5F6",
        "R5F7",
        "R5F8",
    ]
    assert not any(record["id"] == "OCB-S22" for record in records)
