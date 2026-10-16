"""R5E9 storage-only workflow journal: synthetic bundles, temp DBs, no authority."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3

import pytest

from core.epistemic.persistence import (
    CanonicalEvidenceRepository,
    CanonicalEvidenceRepositoryCorruption,
    _workflow_admission_id,
)


PREFIXES = {
    "specification_id": "workflow_effect_one_click_specification",
    "transport_specification_id": "workflow_effect_transport_specification",
    "candidate_id": "workflow_effect_finding_candidate",
}


def _reservation(index=0):
    context = {
        "session_id": f"synthetic-session-{index}",
        "target_origin": "https://workflow.invalid",
        "identity": {"digest": "assessment_identity:" + "1" * 64},
        **{key: prefix + ":" + "2" * 64 for key, prefix in PREFIXES.items()},
        "producer": {"name": "synthetic-only", "version": 1},
        "event_timestamp": 1_788_800_000.0,
        "event_run_id": "synthetic-run",
    }
    # Independent derivation pins both the seven-key set and the kind literal.
    material = {
        key: context[key]
        for key in (
            "session_id",
            "target_origin",
            "specification_id",
            "transport_specification_id",
            "candidate_id",
            "producer",
        )
    }
    material["identity_digest"] = context["identity"]["digest"]
    digest = hashlib.sha256(
        json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()
    context["admission_id"] = "workflow_effect_promotion_admission:" + digest
    return context


def _bundle(context):
    fingerprint = "3" * 64
    observation_id, finding_id = "obs-synthetic", "find-synthetic"
    observation = {"id": observation_id, "synthetic": True}
    finding = {"id": finding_id, "synthetic": True}
    return {
        **{
            key: value
            for key, value in context.items()
            if key not in {"event_timestamp", "event_run_id"}
        },
        "source_receipt_id": f"behavioral-{fingerprint}",
        "source_fingerprint": fingerprint,
        "observation_id": observation_id,
        "observation_commitment": "synthetic-observation-commitment",
        "observation": observation,
        "observation_event": {
            "id": "evt-synthetic-observation",
            "entity_id": observation_id,
            "event_type": "observed",
            "payload": observation,
            "timestamp": context["event_timestamp"],
            "run_id": context["event_run_id"],
        },
        "finding_id": finding_id,
        "finding_commitment": "synthetic-finding-commitment",
        "finding": finding,
        "finding_event": {
            "id": "evt-synthetic-finding",
            "entity_id": finding_id,
            "event_type": "promoted",
            "payload": finding,
            "timestamp": context["event_timestamp"],
            "run_id": context["event_run_id"],
        },
        "evidence_root": "4" * 64,
        "cas_blob_hash": "5" * 64,
    }


def _ready(tmp_path):
    repo = CanonicalEvidenceRepository(tmp_path / "journal.db")
    context = _reservation()
    bundle = _bundle(context)
    repo.reserve_workflow_effect_promotion(**context)
    repo.bind_workflow_effect_source(
        **{
            key: bundle[key]
            for key in (
                "admission_id",
                "source_receipt_id",
                "source_fingerprint",
            )
        }
    )
    repo.set_workflow_effect_state(
        admission_id=context["admission_id"], state="eligible_awaiting_processing"
    )
    return repo, context, bundle


def _counts(repo):
    entities, events = repo.load()
    return len(entities), len(events)


def test_row_column_count_refuses_corruption():
    with pytest.raises(CanonicalEvidenceRepositoryCorruption, match="column count"):
        CanonicalEvidenceRepository._workflow_promotion_row(())


def test_schema_and_pinned_admission_derivation(tmp_path):
    repo = CanonicalEvidenceRepository(tmp_path / "journal.db")
    context = _reservation()
    material = {
        key: context[key]
        for key in (
            "session_id",
            "target_origin",
            "specification_id",
            "transport_specification_id",
            "candidate_id",
            "producer",
        )
    }
    material["identity_digest"] = context["identity"]["digest"]
    assert _workflow_admission_id(**material) == context["admission_id"]
    with sqlite3.connect(repo.db_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        columns = connection.execute(
            "PRAGMA table_info(workflow_effect_promotion_journal)"
        ).fetchall()
        assert len(columns) == 20
        assert not {"intake_id", "operation_data", "storage_data"} & {
            c[1] for c in columns
        }
        assert next(c for c in columns if c[1] == "event_run_id")[3] == 1
        assert connection.execute(
            "PRAGMA index_info(idx_workflow_effect_promotion_state)"
        ).fetchall() == [(0, 14, "state"), (1, 0, "admission_id")]
        assert (
            connection.execute(
                "SELECT * FROM workflow_effect_persistence_preflight"
            ).fetchall()
            == []
        )
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'sessions'"
            ).fetchall()
            == []
        )


def test_happy_path_restart_and_idempotence(tmp_path):
    repo = CanonicalEvidenceRepository(tmp_path / "journal.db")
    context = _reservation()
    bundle = _bundle(context)
    reserved = repo.reserve_workflow_effect_promotion(**context)
    assert reserved["state"] == "source_incomplete"
    assert reserved["source_receipt_id"] is None
    assert repo.reserve_workflow_effect_promotion(**context) == reserved
    # Like capability, the first event timestamp/run remain authoritative on retry.
    assert (
        repo.reserve_workflow_effect_promotion(
            **{
                **context,
                "event_timestamp": context["event_timestamp"] + 1,
                "event_run_id": "retry",
            }
        )
        == reserved
    )
    binding = {
        key: bundle[key]
        for key in (
            "admission_id",
            "source_receipt_id",
            "source_fingerprint",
        )
    }
    bound = repo.bind_workflow_effect_source(**binding)
    assert bound["state"] == "awaiting_source"
    assert repo.bind_workflow_effect_source(**binding) == bound
    attempted = repo.record_workflow_effect_attempt(
        admission_id=context["admission_id"],
        attempt={"reason": "synthetic-policy-block"},
        state="blocked_by_policy",
        last_error="synthetic-error",
    )
    assert attempted["attempt_count"] == 1
    assert attempted["attempts_data"] == [{"reason": "synthetic-policy-block"}]
    assert attempted["last_error"] == "synthetic-error"
    repo.set_workflow_effect_state(
        admission_id=context["admission_id"], state="eligible_awaiting_processing"
    )
    promoted, created = repo.commit_workflow_effect_promotion(**bundle)
    assert created and promoted["state"] == "promoted"
    assert promoted["last_error"] is None
    reopened = CanonicalEvidenceRepository(repo.db_path)
    for identifier in (
        context["admission_id"],
        bundle["source_receipt_id"],
        bundle["source_fingerprint"],
    ):
        assert reopened.load_workflow_effect_admission(identifier) == promoted
    assert reopened.reserve_workflow_effect_promotion(**context) == promoted
    assert reopened.bind_workflow_effect_source(**binding) == promoted
    assert reopened.commit_workflow_effect_promotion(**bundle) == (promoted, False)
    assert _counts(reopened) == (2, 2)
    assert {row["session_id"] for row in reopened.load()[0]} == {context["session_id"]}
    assert (
        reopened.set_workflow_effect_state(
            admission_id=context["admission_id"],
            state="invalid_evidence",
            last_error="retry",
        )
        == promoted
    )
    attempted = reopened.record_workflow_effect_attempt(
        admission_id=context["admission_id"],
        attempt={"retry": True},
        state="invalid_evidence",
        last_error="retry",
    )
    assert attempted["state"] == "promoted" and attempted["last_error"] is None
    assert attempted["attempt_count"] == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("admission_id", "workflow_effect_execution_admission:" + "0" * 64),
        ("admission_id", "workflow_effect_promotion_admission:" + "0" * 64),
        ("admission_id", "workflow_effect_promotion_admission:extra:" + "0" * 64),
        ("session_id", "other-session"),
        ("session_id", "global_scan"),
        ("target_origin", "https://substituted.invalid"),
        ("identity", {"digest": "assessment_identity:" + "a" * 64}),
        ("identity", {"digest": "wrong:" + "1" * 64}),
        ("identity", {"digest": "assessment_identity:" + "A" * 64}),
        ("producer", {"name": "different-producer"}),
        *[(key, "wrong:" + "2" * 64) for key in PREFIXES],
        *[(key, prefix + ":" + "a" * 64) for key, prefix in PREFIXES.items()],
        ("event_timestamp", 0),
        ("event_timestamp", float("inf")),
        ("event_run_id", None),
    ],
)
def test_invalid_reservation_is_not_persisted(tmp_path, field, value):
    repo = CanonicalEvidenceRepository(tmp_path / "journal.db")
    with pytest.raises(ValueError):
        repo.reserve_workflow_effect_promotion(**{**_reservation(), field: value})
    assert repo.list_workflow_effect_admissions() == ()


def test_reservation_collision_in_non_digest_identity_field(tmp_path):
    repo, context, _ = _ready(tmp_path)
    with pytest.raises(ValueError, match="context collision"):
        repo.reserve_workflow_effect_promotion(
            **{
                **context,
                "identity": {**context["identity"], "extra": "changed"},
            }
        )


@pytest.mark.parametrize(
    "receipt,fingerprint",
    [
        ("wrong", "3" * 64),
        ("behavioral-" + "A" * 64, "A" * 64),
        ("behavioral-short", "short"),
        (None, None),
    ],
)
def test_bad_binding_rolls_back(tmp_path, receipt, fingerprint):
    repo = CanonicalEvidenceRepository(tmp_path / "journal.db")
    reserved = repo.reserve_workflow_effect_promotion(**_reservation())
    with pytest.raises(ValueError):
        repo.bind_workflow_effect_source(
            admission_id=reserved["admission_id"],
            source_receipt_id=receipt,
            source_fingerprint=fingerprint,
        )
    assert repo.load_workflow_effect_admission(reserved["admission_id"]) == reserved


def test_source_binding_is_immutable_and_unique(tmp_path):
    repo, context, bundle = _ready(tmp_path)
    with pytest.raises(ValueError, match="immutable"):
        repo.bind_workflow_effect_source(
            admission_id=context["admission_id"],
            source_receipt_id="behavioral-" + "a" * 64,
            source_fingerprint="a" * 64,
        )
    other = repo.reserve_workflow_effect_promotion(**_reservation(1))
    with pytest.raises(ValueError, match="owned by another"):
        repo.bind_workflow_effect_source(
            admission_id=other["admission_id"],
            source_receipt_id=bundle["source_receipt_id"],
            source_fingerprint=bundle["source_fingerprint"],
        )


@pytest.mark.parametrize("large", [False, True])
def test_attempt_history_bounds_and_oversize_refusal(tmp_path, large):
    repo, context, _ = _ready(tmp_path)
    # Exactly 4096 bytes, including multibyte JSON, exercises total-history overhead.
    attempt = {"x": "é" * 2044} if large else {"reason": "synthetic"}
    for _ in range(70):
        row = repo.record_workflow_effect_attempt(
            admission_id=context["admission_id"],
            attempt=attempt,
            state="blocked_by_policy",
        )
    assert row["attempt_count"] == 70
    assert len(row["attempts_data"]) == (31 if large else 32)
    with pytest.raises(ValueError, match="too large"):
        repo.record_workflow_effect_attempt(
            admission_id=context["admission_id"],
            attempt={"x": "é" * 2045},
            state="blocked_by_policy",
        )
    assert repo.load_workflow_effect_admission(context["admission_id"]) == row


@pytest.mark.parametrize(
    "column,value",
    [
        ("admission_id", "workflow_effect_promotion_admission:" + "a" * 64),
        ("session_id", "tampered-session"),
        ("target_origin", "https://tampered.invalid"),
        ("identity_data", '{"digest":"assessment_identity:' + "a" * 64 + '"}'),
        ("identity_data", '{"digest":"wrong"}'),
        ("identity_data", "[]"),
        ("producer_data", '{"name":"tampered"}'),
        ("producer_data", "null"),
        *[(key, "wrong:" + "2" * 64) for key in PREFIXES],
        *[(key, prefix + ":" + "a" * 64) for key, prefix in PREFIXES.items()],
        ("source_receipt_id", "behavioral-wrong"),
        ("source_fingerprint", None),
        ("state", "invented"),
        ("attempt_count", -1),
        ("attempt_count", 0.5),
        ("attempts_data", "{}"),
        ("attempts_data", "[1]"),
        ("attempts_data", "bad-json"),
        ("attempts_data", json.dumps([{}] * 33)),
        ("attempts_data", json.dumps([{"x": "a" * 4096}])),
        ("attempts_data", " " * 131073 + "[]"),
        ("event_timestamp", -1),
        *[
            (key, None)
            for key in (
                "evidence_root",
                "cas_blob_hash",
                "observation_id",
                "finding_id",
            )
        ],
        ("evidence_root", "G" * 64),
        ("cas_blob_hash", "short"),
        ("observation_id", "find-wrong"),
        ("finding_id", "obs-wrong"),
    ],
)
def test_every_read_refuses_tampering(tmp_path, column, value):
    repo, _, bundle = _ready(tmp_path)
    repo.commit_workflow_effect_promotion(**bundle)
    # Column is from the static parametrization, never external input.
    with sqlite3.connect(repo.db_path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            f"UPDATE workflow_effect_promotion_journal SET {column} = ?", (value,)
        )
    reopened = CanonicalEvidenceRepository(repo.db_path)
    for read in (
        lambda: reopened.load_workflow_effect_admission(
            value if column == "source_receipt_id" else bundle["source_receipt_id"]
        ),
        reopened.list_workflow_effect_admissions,
        lambda: reopened.list_workflow_effect_admission_ids(
            states=[value if column == "state" else "promoted"]
        ),
    ):
        with pytest.raises(ValueError):
            read()


@pytest.mark.parametrize(
    "state",
    [
        "source_incomplete",
        "awaiting_source",
        "blocked_by_policy",
        "invalid_evidence",
        "not_workflow_invariant_violation",
    ],
)
def test_commit_refuses_ineligible_state(tmp_path, state):
    repo, context, bundle = _ready(tmp_path)
    repo.set_workflow_effect_state(admission_id=context["admission_id"], state=state)
    with pytest.raises(ValueError, match="context does not match"):
        repo.commit_workflow_effect_promotion(**bundle)
    assert _counts(repo) == (0, 0)


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_id", "wrong"),
        ("target_origin", "https://wrong.invalid"),
        ("source_receipt_id", "behavioral-" + "a" * 64),
        ("source_fingerprint", "a" * 64),
        ("identity", {"digest": "wrong"}),
        ("producer", {"name": "wrong"}),
        *[(key, "wrong") for key in PREFIXES],
        ("evidence_root", "wrong"),
        ("cas_blob_hash", "wrong"),
        ("observation_id", "wrong"),
        ("finding_id", "wrong"),
    ],
)
def test_commit_refuses_context_or_result_mismatch_atomically(tmp_path, field, value):
    repo, context, bundle = _ready(tmp_path)
    before = repo.load_workflow_effect_admission(context["admission_id"])
    with pytest.raises(ValueError):
        repo.commit_workflow_effect_promotion(**{**bundle, field: value})
    assert _counts(repo) == (0, 0)
    assert repo.load_workflow_effect_admission(context["admission_id"]) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("evidence_root", "a" * 64),
        ("cas_blob_hash", "a" * 64),
        ("observation_id", "obs-other"),
        ("finding_id", "find-other"),
        ("observation", {"tampered": True}),
        (
            "finding_event",
            {
                "id": "evt-synthetic-finding",
                "entity_id": "find-synthetic",
                "event_type": "promoted",
                "payload": {"tampered": True},
            },
        ),
    ],
)
def test_recommit_refuses_result_or_canonical_collision(tmp_path, field, value):
    repo, context, bundle = _ready(tmp_path)
    promoted, _ = repo.commit_workflow_effect_promotion(**bundle)
    with pytest.raises(ValueError, match="collision"):
        repo.commit_workflow_effect_promotion(**{**bundle, field: value})
    assert repo.load_workflow_effect_admission(context["admission_id"]) == promoted
    assert _counts(repo) == (2, 2)


def test_atomic_rollback_and_retry(tmp_path, monkeypatch):
    repo, context, bundle = _ready(tmp_path)
    original = CanonicalEvidenceRepository._insert_or_verify_event

    def fail_after_event(*args):
        original(*args)
        raise OSError("synthetic interrupted write")

    with monkeypatch.context() as patch:
        patch.setattr(
            CanonicalEvidenceRepository,
            "_insert_or_verify_event",
            staticmethod(fail_after_event),
        )
        with pytest.raises(OSError, match="interrupted write"):
            repo.commit_workflow_effect_promotion(**bundle)
    reopened = CanonicalEvidenceRepository(repo.db_path)
    assert _counts(reopened) == (0, 0)
    assert (
        reopened.load_workflow_effect_admission(context["admission_id"])["state"]
        == "eligible_awaiting_processing"
    )
    reopened.set_workflow_effect_state(
        admission_id=context["admission_id"],
        state="retryable_local_persistence_failure",
    )
    assert reopened.commit_workflow_effect_promotion(**bundle)[1] is True
    assert _counts(reopened) == (2, 2)


def test_bounded_worklist_and_invalid_inputs(tmp_path):
    repo = CanonicalEvidenceRepository(tmp_path / "journal.db")
    rows = [repo.reserve_workflow_effect_promotion(**_reservation(i)) for i in range(3)]
    ids = sorted(row["admission_id"] for row in rows)
    assert repo.list_workflow_effect_admission_ids(
        states=["source_incomplete"], limit=2
    ) == tuple(ids[:2])
    assert len(repo.list_workflow_effect_admissions(limit=1)) == 1
    assert repo.list_workflow_effect_admission_ids(states=[]) == ()
    assert repo.list_workflow_effect_admissions(states=["promoted"]) == ()
    assert repo.load_workflow_effect_admission("unknown") is None
    assert repo.load_workflow_effect_admission("a" * 64) is None
    with pytest.raises(ValueError, match="lookup"):
        repo._load_workflow_effect_admission_by("admission_id OR 1=1", ids[0])
    for limit in (0, -1, True, 1001, 1.5):
        with pytest.raises(ValueError, match="limit"):
            repo.list_workflow_effect_admissions(limit=limit)
        with pytest.raises(ValueError, match="limit"):
            repo.list_workflow_effect_admission_ids(states=[], limit=limit)
    for state in ("bad", "not_replay_leak", "promoted"):
        error = sqlite3.IntegrityError if state == "promoted" else ValueError
        with pytest.raises(error):
            repo.set_workflow_effect_state(admission_id=ids[0], state=state)
        with pytest.raises(error):
            repo.record_workflow_effect_attempt(
                admission_id=ids[0], state=state, attempt={}
            )
    with pytest.raises(ValueError, match="state"):
        repo.list_workflow_effect_admissions(states=["bad"])
    for write in (
        lambda: repo.bind_workflow_effect_source(
            admission_id="missing",
            source_receipt_id="behavioral-" + "3" * 64,
            source_fingerprint="3" * 64,
        ),
        lambda: repo.record_workflow_effect_attempt(
            admission_id="missing", attempt={}, state="awaiting_source"
        ),
        lambda: repo.set_workflow_effect_state(
            admission_id="missing", state="awaiting_source"
        ),
        lambda: repo.commit_workflow_effect_promotion(
            **{**_bundle(_reservation()), "admission_id": "missing"}
        ),
    ):
        with pytest.raises(ValueError):
            write()
    assert _counts(repo) == (0, 0)


def test_concurrent_commit_is_idempotent(tmp_path):
    repo, _, bundle = _ready(tmp_path)

    def commit(_):
        return CanonicalEvidenceRepository(
            repo.db_path
        ).commit_workflow_effect_promotion(**bundle)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(commit, range(2)))
    assert sorted(created for _, created in results) == [False, True]
    assert results[0][0] == results[1][0]
    assert _counts(repo) == (2, 2)


def _crash_commit(path, bundle, boundary):
    repo = CanonicalEvidenceRepository(Path(path))
    if boundary == "during_transaction":
        original = CanonicalEvidenceRepository._insert_or_verify_entity

        def crash(connection, **kwargs):
            original(connection, **kwargs)
            os._exit(86)

        CanonicalEvidenceRepository._insert_or_verify_entity = staticmethod(crash)
    repo.commit_workflow_effect_promotion(**bundle)
    os._exit(86 if boundary == "after_commit" else 87)


@pytest.mark.subprocess_spawn
@pytest.mark.parametrize("boundary", ["during_transaction", "after_commit"])
def test_process_crash_recovery(tmp_path, boundary):
    repo, context, bundle = _ready(tmp_path)
    process = multiprocessing.get_context("spawn").Process(
        target=_crash_commit, args=(str(repo.db_path), bundle, boundary)
    )
    process.start()
    process.join(timeout=30)
    if process.is_alive():
        process.kill()
        process.join(timeout=5)
        pytest.fail("synthetic crash specimen timed out")
    assert process.exitcode == 86
    reopened = CanonicalEvidenceRepository(repo.db_path)
    committed = boundary == "after_commit"
    assert _counts(reopened) == ((2, 2) if committed else (0, 0))
    assert reopened.load_workflow_effect_admission(context["admission_id"])[
        "state"
    ] == ("promoted" if committed else "eligible_awaiting_processing")
    assert reopened.commit_workflow_effect_promotion(**bundle)[1] is not committed
    assert _counts(reopened) == (2, 2)


def test_workflow_journal_has_only_ledger_and_promotion_service_consumers():
    root = Path(__file__).resolve().parents[2]
    names = {
        "reserve_workflow_effect_promotion",
        "bind_workflow_effect_source",
        "record_workflow_effect_attempt",
        "set_workflow_effect_state",
        "commit_workflow_effect_promotion",
        "load_workflow_effect_admission",
        "list_workflow_effect_admissions",
        "list_workflow_effect_admission_ids",
        "_workflow_promotion_row",
        "_workflow_admission_id",
        "workflow_effect_promotion_journal",
        "workflow_effect_persistence_preflight",
    }
    hits = {
        path.relative_to(root).as_posix()
        for path in (root / "core").rglob("*.py")
        if any(name in path.read_text() for name in names)
    }
    # R5E9f-c adds the sole production journal adapter; Foundry calls that
    # service rather than importing the journal's mutation methods directly.
    assert hits == {
        "core/behavior/workflow_effect_promotion.py",
        "core/epistemic/ledger.py",
        "core/epistemic/persistence.py",
    }
    foundry = (root / "core/server/routers/foundry.py").read_text()
    inner = foundry.split("async def run_behavioral_authorization_endpoint(", 1)[1].split(
        "async def run_behavioral_authorization_from_url_endpoint(", 1
    )[0]
    outer = foundry.split("async def run_behavioral_authorization_from_url_endpoint(", 1)[1]
    assert "WorkflowEffectPromotionService" in inner
    assert "WorkflowEffectPromotionService" not in outer
    source = (root / "core/epistemic/persistence.py").read_text()
    assert "workflow_effect_evidence" not in source
    assert "_validate_active_proof" not in source
