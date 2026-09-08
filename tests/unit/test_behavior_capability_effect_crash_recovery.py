"""R5D10 fresh-process crash-boundary acceptance specimens."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.capability_effect_promotion import (
    CAPABILITY_FINDING_PROMOTION_ENV,
    CapabilityEffectPromotionService,
)
from core.behavior.receipts import BehavioralReceiptStore, COMPLETED
from core.epistemic.ledger import EvidenceLedger
from tests.unit.test_behavior_capability_effect_promotion import _completed_source


pytestmark = pytest.mark.subprocess_spawn


_CRASH_EXIT = 86
_MISSED_BOUNDARY_EXIT = 87
_TARGET_TRAFFIC_EXIT = 97


def _fresh_config(base_dir: str) -> SentinelConfig:
    return SentinelConfig(storage=StorageConfig(base_dir=Path(base_dir)))


def _install_target_traffic_tripwire(marker_path: str) -> None:
    """Make an accidental matrix rerun externally observable across processes."""

    from core.behavior.capability_effect_evaluation import (
        CapabilityEffectExperimentExecutor,
    )
    from core.behavior.capability_effect_one_click import (
        CapabilityEffectOneClickDispatcher,
        PolicyExecutorCapabilityEffectTransport,
    )

    async def reject_target_activity(*_args: Any, **_kwargs: Any) -> None:
        Path(marker_path).write_text("unexpected target activity\n", encoding="utf-8")
        os._exit(_TARGET_TRAFFIC_EXIT)

    CapabilityEffectExperimentExecutor.execute = reject_target_activity
    CapabilityEffectOneClickDispatcher.run = reject_target_activity
    PolicyExecutorCapabilityEffectTransport.dispatch = reject_target_activity


def _crash_at_boundary(
    base_dir: str,
    receipt_root: str,
    receipt_id: str,
    expected_cas_hash: str,
    boundary: str,
    target_traffic_marker: str,
) -> None:
    """Terminate a spawned process at one exact durable-promotion boundary."""

    os.environ[CAPABILITY_FINDING_PROMOTION_ENV] = "1"
    _install_target_traffic_tripwire(target_traffic_marker)
    fingerprint = receipt_id.removeprefix("behavioral-")
    receipts = BehavioralReceiptStore(Path(receipt_root))

    if boundary == "after_source_receipt_publication":
        receipt = receipts.load(fingerprint)
        if receipt is None or receipt.state != COMPLETED:
            os._exit(_MISSED_BOUNDARY_EXIT)
        os._exit(_CRASH_EXIT)

    config = _fresh_config(base_dir)
    service = CapabilityEffectPromotionService(config, receipt_store=receipts)

    if boundary == "during_cas_publication":
        import core.epistemic.cas as cas_module

        original_link = cas_module.os.link

        def crash_before_atomic_link(
            source: Any,
            destination: Any,
            **kwargs: Any,
        ) -> None:
            if destination == expected_cas_hash:
                os._exit(_CRASH_EXIT)
            original_link(source, destination, **kwargs)

        cas_module.os.link = crash_before_atomic_link
    elif boundary == "before_canonical_transaction":
        from core.epistemic.persistence import CanonicalEvidenceRepository

        def crash_before_transaction(_self: Any, **_kwargs: Any) -> None:
            os._exit(_CRASH_EXIT)

        CanonicalEvidenceRepository.commit_capability_effect_promotion = (
            crash_before_transaction
        )
    elif boundary == "during_canonical_transaction":
        from core.epistemic.persistence import CanonicalEvidenceRepository

        original_insert = CanonicalEvidenceRepository._insert_or_verify_entity

        def crash_after_first_insert(connection: Any, **kwargs: Any) -> None:
            original_insert(connection, **kwargs)
            os._exit(_CRASH_EXIT)

        CanonicalEvidenceRepository._insert_or_verify_entity = staticmethod(
            crash_after_first_insert
        )
    elif boundary == "after_canonical_commit":
        from core.epistemic.persistence import CanonicalEvidenceRepository

        original_commit = CanonicalEvidenceRepository.commit_capability_effect_promotion

        def crash_after_commit(self: Any, **kwargs: Any) -> None:
            original_commit(self, **kwargs)
            os._exit(_CRASH_EXIT)

        CanonicalEvidenceRepository.commit_capability_effect_promotion = (
            crash_after_commit
        )
    elif boundary != "before_response_delivery":
        os._exit(_MISSED_BOUNDARY_EXIT)

    status = service.promote(receipt_id)
    if boundary == "before_response_delivery" and status.promotion_state == "promoted":
        os._exit(_CRASH_EXIT)
    os._exit(_MISSED_BOUNDARY_EXIT)


def _recover_in_fresh_process(
    base_dir: str,
    receipt_root: str,
    receipt_id: str,
    session_id: str,
    target_traffic_marker: str,
    result_path: str,
) -> None:
    """Rebuild all stores, reconcile locally, and export the recovered read model."""

    os.environ[CAPABILITY_FINDING_PROMOTION_ENV] = "1"
    _install_target_traffic_tripwire(target_traffic_marker)
    config = _fresh_config(base_dir)
    receipts = BehavioralReceiptStore(Path(receipt_root))
    service = CapabilityEffectPromotionService(config, receipt_store=receipts)
    reconciled = service.reconcile()
    status = service.status(receipt_id)
    ledger = EvidenceLedger(
        config,
        receipt_store=BehavioralReceiptStore(Path(receipt_root)),
    )
    read_model = ledger.session_read_model(session_id)
    result = {
        "reconciled": [item.to_dict() for item in reconciled],
        "status": status.to_dict(),
        "observation_ids": [item.id for item in read_model.observations],
        "finding_ids": [item.id for item in read_model.findings],
    }
    Path(result_path).write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def _run_spawned(target: Any, args: tuple[Any, ...]) -> int:
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=target, args=args)
    process.start()
    process.join(timeout=30)
    if process.is_alive():
        process.kill()
        process.join(timeout=5)
        pytest.fail("fresh-process crash specimen exceeded its bounded timeout")
    assert process.exitcode is not None
    return process.exitcode


def _canonical_counts(database_path: Path) -> tuple[int, int]:
    with sqlite3.connect(database_path) as connection:
        entity_count = connection.execute(
            "SELECT COUNT(*) FROM epistemic_entities"
        ).fetchone()[0]
        event_count = connection.execute(
            "SELECT COUNT(*) FROM epistemic_events"
        ).fetchone()[0]
    return int(entity_count), int(event_count)


def _journal_state(database_path: Path, admission_id: str) -> str:
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT state FROM capability_effect_promotion_journal
            WHERE admission_id = ?
            """,
            (admission_id,),
        ).fetchone()
    assert row is not None
    return str(row[0])


@pytest.mark.parametrize(
    (
        "boundary",
        "expected_journal_state",
        "expected_cas_state",
        "expected_canonical_counts",
    ),
    [
        (
            "after_source_receipt_publication",
            "awaiting_source",
            "absent",
            (0, 0),
        ),
        (
            "during_cas_publication",
            "eligible_awaiting_processing",
            "temporary_only",
            (0, 0),
        ),
        (
            "before_canonical_transaction",
            "eligible_awaiting_processing",
            "published",
            (0, 0),
        ),
        (
            "during_canonical_transaction",
            "eligible_awaiting_processing",
            "published",
            (0, 0),
        ),
        (
            "after_canonical_commit",
            "promoted",
            "published",
            (2, 2),
        ),
        (
            "before_response_delivery",
            "promoted",
            "published",
            (2, 2),
        ),
    ],
)
def test_fresh_process_crash_boundaries_converge_without_target_rerun(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    expected_journal_state: str,
    expected_cas_state: str,
    expected_canonical_counts: tuple[int, int],
) -> None:
    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    case_root = tmp_path / boundary
    config, receipts, _service, admission, receipt, evidence, twin = _completed_source(
        case_root, leak=True
    )
    calls_before = (len(twin.calls), len(twin.cleanup_calls))
    assert calls_before == (5, 1)
    target_traffic_marker = case_root / "unexpected-target-traffic"
    cas_hash = hashlib.sha256(evidence.to_json_bytes()).hexdigest()

    crash_exit = _run_spawned(
        _crash_at_boundary,
        (
            str(config.storage.base_dir),
            str(receipts._root()),
            receipt.receipt_id,
            cas_hash,
            boundary,
            str(target_traffic_marker),
        ),
    )

    assert crash_exit == _CRASH_EXIT
    assert _journal_state(config.storage.db_path, admission.admission_id) == (
        expected_journal_state
    )
    assert _canonical_counts(config.storage.db_path) == expected_canonical_counts
    assert not target_traffic_marker.exists()

    blob_directory = config.storage.evidence_path / "blobs"
    published_blob = blob_directory / cas_hash
    temporary_blobs = tuple(blob_directory.glob(f".{cas_hash}.*.tmp"))
    if expected_cas_state == "absent":
        assert not published_blob.exists()
        assert temporary_blobs == ()
    elif expected_cas_state == "temporary_only":
        assert not published_blob.exists()
        assert len(temporary_blobs) == 1
    else:
        assert published_blob.read_bytes() == evidence.to_json_bytes()

    recovery_result = case_root / "fresh-recovery-result.json"
    recovery_exit = _run_spawned(
        _recover_in_fresh_process,
        (
            str(config.storage.base_dir),
            str(receipts._root()),
            receipt.receipt_id,
            admission.session_id,
            str(target_traffic_marker),
            str(recovery_result),
        ),
    )

    assert recovery_exit == 0
    recovered = json.loads(recovery_result.read_text(encoding="utf-8"))
    status = recovered["status"]
    assert status["promotion_state"] == "promoted"
    assert status["assessment_session_id"] == admission.session_id
    assert recovered["observation_ids"] == [status["canonical_observation_id"]]
    assert recovered["finding_ids"] == [status["canonical_finding_id"]]
    if expected_journal_state == "promoted":
        assert recovered["reconciled"] == []
    else:
        assert [item["promotion_state"] for item in recovered["reconciled"]] == [
            "promoted"
        ]
    assert _journal_state(config.storage.db_path, admission.admission_id) == "promoted"
    assert _canonical_counts(config.storage.db_path) == (2, 2)
    assert published_blob.read_bytes() == evidence.to_json_bytes()
    assert not target_traffic_marker.exists()
    assert (len(twin.calls), len(twin.cleanup_calls)) == calls_before

    restarted_receipts = BehavioralReceiptStore(receipts._root())
    restarted_service = CapabilityEffectPromotionService(
        _fresh_config(str(config.storage.base_dir)),
        receipt_store=restarted_receipts,
    )
    repeated = restarted_service.promote(receipt.receipt_id)
    assert repeated.to_dict() == status
    assert _canonical_counts(config.storage.db_path) == (2, 2)
    assert not target_traffic_marker.exists()
