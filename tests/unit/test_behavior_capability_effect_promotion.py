"""R5D10 durable admission, canonical promotion, and recovery acceptance."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3

import pytest

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.capability_effect_evidence import (
    build_capability_effect_evidence,
    evaluate_replay_leak,
)
from core.behavior.capability_effect_promotion import (
    CAPABILITY_FINDING_PROMOTION_ENV,
    CapabilityEffectPromotionService,
)
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    BehavioralReceiptStore,
    redacted_outcome,
    redacted_receipt_context,
)
from core.epistemic.ledger import EvidenceLedger, LifecycleState
from core.epistemic.cas import ContentAddressableStorage
from core.epistemic.persistence import (
    CanonicalEvidenceRepository,
    CanonicalEvidenceRepositoryCorruption,
)
from core.epistemic.storage_boundary import EvidenceStorageBoundaryError
from tests.unit.test_behavior_capability_effect_evidence import (
    ORIGIN,
    _policy,
    _producer,
    _run_result,
)
from tests.unit.test_behavior_receipts import _response as _legacy_response


def _promote_in_fresh_process(
    base_dir: str,
    receipt_root: str,
    execution_id: str,
) -> dict[str, object]:
    os.environ[CAPABILITY_FINDING_PROMOTION_ENV] = "1"
    config = SentinelConfig(storage=StorageConfig(base_dir=Path(base_dir)))
    return (
        CapabilityEffectPromotionService(
            config,
            receipt_store=BehavioralReceiptStore(Path(receipt_root)),
        )
        .promote(execution_id)
        .to_dict()
    )


def _specification() -> dict[str, object]:
    return {
        "schema_version": 1,
        "specification_id": stable_hash(
            "capability_effect_one_click_specification",
            {"fixture": "promotion"},
        ),
        "run_ref": stable_hash("capability_effect_run", "promotion"),
        "target_request_ref": stable_hash(
            "capability_effect_target_request",
            {"fixture": "promotion"},
        ),
        "cleanup_request_ref": stable_hash(
            "capability_effect_cleanup_request",
            {"fixture": "promotion"},
        ),
        "target_endpoint_ref": stable_hash(
            "experiment_endpoint",
            {"fixture": "promotion-target"},
        ),
        "cleanup_endpoint_ref": stable_hash(
            "experiment_endpoint",
            {"fixture": "promotion-cleanup"},
        ),
    }


def _completed_source(tmp_path, *, leak: bool):
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    receipts = BehavioralReceiptStore(tmp_path / "receipts")
    service = CapabilityEffectPromotionService(config, receipt_store=receipts)
    fingerprint = ("2" if leak else "4") * 64
    persona_id = f"r5d6-promotion-{'leak' if leak else 'secure'}"
    envelope_id = "authorization-r5d10"
    reservation = receipts.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=envelope_id,
            source_persona_id=persona_id,
            peer_persona_id="controlled-peer-r5d10",
        ),
    )
    assert reservation.reservation_token is not None
    policy = _policy()
    producer = _producer()
    admission = service.reserve_execution(
        intake_id=stable_hash(
            "capability_effect_intake",
            {"fixture": fingerprint},
        ),
        target_origin=ORIGIN,
        authorization_envelope_id=envelope_id,
        authorization_envelope_ref=f"authorization_envelope:{'1' * 64}",
        persona_id=persona_id,
        persona_source_ref=stable_hash("persona_vault", persona_id),
        specification=_specification(),
        execution_policy=policy.to_dict(),
        source_fingerprint=fingerprint,
        observed_at=1_788_800_000.0,
        producer_identity=producer.to_dict(),
    )
    result, twin = _run_result(
        leak_kind="replayed_capability_probe" if leak else None,
        suffix=f"promotion-{'leak' if leak else 'secure'}",
    )
    export = result.evidence_export()
    evidence = build_capability_effect_evidence(
        execution_export=export,
        source_receipt_id=f"behavioral-{fingerprint}",
        execution_admission_ref=admission.admission_id,
        assessment_session_id=admission.session_id,
        identity_binding=admission.identity_binding,
        target_origin=admission.target_origin,
        specification_ref=admission.specification_ref,
        operation_ref=admission.operation_ref,
        execution_policy=policy,
        conduct_provenance_root="3" * 64,
        producer_identity=producer,
        observed_at_epoch=max(
            float(item["observed_epoch"]) for item in export["terminal_receipts"]
        ),
        runtime_evidence_classification="controlled_in_memory_twin",
    )
    receipt = receipts.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome={
            "kind": "capability_effect_one_click",
            "status": evidence.oracle["verdict"],
            "capability_effect_evidence": evidence.to_dict(),
        },
    )
    return config, receipts, service, admission, receipt, evidence, twin


def test_gate_off_then_on_promotes_saved_source_once_in_original_session(
    tmp_path,
    monkeypatch,
):
    monkeypatch.delenv(CAPABILITY_FINDING_PROMOTION_ENV, raising=False)
    config, receipts, service, admission, receipt, evidence, twin = _completed_source(
        tmp_path, leak=True
    )

    blocked = service.promote(receipt.receipt_id)
    assert blocked.promotion_state == "blocked_by_policy"
    assert blocked.reason_code == "blocked_by_policy"
    assert evaluate_replay_leak(evidence).eligible is True
    calls_before = (len(twin.calls), len(twin.cleanup_calls))

    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    promoted = CapabilityEffectPromotionService(
        config,
        receipt_store=receipts,
    ).promote(receipt.receipt_id)
    duplicate = CapabilityEffectPromotionService(
        config,
        receipt_store=receipts,
    ).promote(receipt.receipt_id)

    assert promoted.promotion_state == "promoted"
    assert duplicate.to_dict() == promoted.to_dict()
    assert promoted.assessment_session_id == admission.session_id
    assert promoted.canonical_observation_id
    assert promoted.canonical_finding_id
    assert (len(twin.calls), len(twin.cleanup_calls)) == calls_before

    monkeypatch.delenv(CAPABILITY_FINDING_PROMOTION_ENV, raising=False)
    committed_with_gate_off = CapabilityEffectPromotionService(
        config,
        receipt_store=receipts,
    ).promote(receipt.receipt_id)
    assert committed_with_gate_off.to_dict() == promoted.to_dict()

    read_model = EvidenceLedger(
        config,
        receipt_store=receipts,
    ).session_read_model(admission.session_id)
    assert [item.id for item in read_model.observations] == [
        promoted.canonical_observation_id
    ]
    assert [item.id for item in read_model.findings] == [promoted.canonical_finding_id]
    assert read_model.findings[0].remediation
    assert "promotion" not in json.dumps(read_model.findings[0].metadata)
    with sqlite3.connect(config.storage.db_path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM epistemic_entities").fetchone()[0]
            == 2
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM epistemic_events").fetchone()[0]
            == 2
        )


def test_secure_completed_source_is_retained_without_finding(tmp_path, monkeypatch):
    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    config, receipts, service, admission, receipt, evidence, twin = _completed_source(
        tmp_path, leak=False
    )

    status = service.promote(receipt.receipt_id)

    assert status.promotion_state == "not_eligible"
    assert status.reason_code == "secure_one_time_authorized_effect"
    assert status.canonical_finding_id is None
    assert evaluate_replay_leak(evidence).eligible is False
    assert len(twin.calls) == 5
    assert len(twin.cleanup_calls) == 1
    assert (
        EvidenceLedger(
            config,
            receipt_store=receipts,
        )
        .session_read_model(admission.session_id)
        .findings
        == ()
    )


def test_legacy_completed_receipt_loads_without_claiming_r5d10_evidence(tmp_path):
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    receipts = BehavioralReceiptStore(tmp_path / "receipts")
    fingerprint = "9" * 64
    reservation = receipts.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id="legacy-authorization",
            source_persona_id="legacy-source",
            peer_persona_id="legacy-peer",
        ),
    )
    assert reservation.reservation_token is not None
    legacy = receipts.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=redacted_outcome(_legacy_response()),
    )

    service = CapabilityEffectPromotionService(config, receipt_store=receipts)
    status = service.status(legacy.receipt_id)
    repeated = service.promote(legacy.receipt_id)

    assert receipts.load(fingerprint) == legacy
    assert status.to_dict() == repeated.to_dict()
    assert status.execution_state == "completed"
    assert status.evidence_classification == "legacy_unavailable"
    assert status.promotion_state == "not_eligible"
    assert status.reason_code == "legacy_evidence_unavailable"
    assert status.assessment_session_id is None
    assert status.canonical_observation_id is None
    assert status.canonical_finding_id is None


def test_duplicate_source_preserves_owner_and_refuses_context_substitution(tmp_path):
    _config, _receipts, service, admission, receipt, _evidence, _twin = (
        _completed_source(tmp_path, leak=True)
    )
    common = {
        "target_origin": admission.target_origin,
        "authorization_envelope_id": admission.identity_binding[
            "authorization_envelope_id"
        ],
        "authorization_envelope_ref": admission.operation[
            "authorization_envelope_ref"
        ],
        "persona_id": admission.identity_binding["persona_id"],
        "persona_source_ref": admission.identity_binding["credential_source_ref"],
        "specification": admission.operation["specification"],
        "execution_policy": admission.execution_policy,
        "source_fingerprint": receipt.fingerprint,
        "observed_at": 1_788_800_100.0,
        "producer_identity": admission.producer_identity,
    }

    cross_session = service.reserve_execution(
        intake_id=stable_hash("capability_effect_intake", "cross-session"),
        requested_session_id="substituted-session",
        **common,
    )
    assert cross_session.admission_id == admission.admission_id
    assert cross_session.session_id == admission.session_id

    with pytest.raises(ValueError, match="source owner context collision"):
        service.reserve_execution(
            intake_id=stable_hash("capability_effect_intake", "cross-persona"),
            requested_session_id="substituted-session",
            **{
                **common,
                "persona_id": "substituted-persona",
                "persona_source_ref": stable_hash(
                    "persona_vault",
                    "substituted-persona",
                ),
            },
        )

    substituted_specification = dict(admission.operation["specification"])
    substituted_specification["specification_id"] = stable_hash(
        "capability_effect_one_click_specification",
        "substituted-capability",
    )
    with pytest.raises(ValueError, match="source owner context collision"):
        service.reserve_execution(
            intake_id=stable_hash("capability_effect_intake", "cross-capability"),
            requested_session_id="substituted-session",
            **{
                **common,
                "specification": substituted_specification,
            },
        )


def test_suppression_survives_restart_and_cannot_be_repromoted(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    config, receipts, service, admission, receipt, _evidence, twin = _completed_source(
        tmp_path, leak=True
    )
    promoted = service.promote(receipt.receipt_id)
    ledger = EvidenceLedger(config, receipt_store=receipts)
    state = ledger.suppress(
        promoted.canonical_finding_id,
        "review_suppressed",
        "bounded test",
        timestamp_override=1_788_800_100.0,
    )
    assert state.state is LifecycleState.SUPPRESSED
    calls_before = (len(twin.calls), len(twin.cleanup_calls))

    restarted = CapabilityEffectPromotionService(config, receipt_store=receipts)
    status = restarted.promote(receipt.receipt_id)
    reconciled = restarted.reconcile()

    assert status.promotion_state == "canonical_result_inactive"
    assert reconciled == ()
    assert (len(twin.calls), len(twin.cleanup_calls)) == calls_before
    assert (
        EvidenceLedger(
            config,
            receipt_store=receipts,
        )
        .session_read_model(admission.session_id)
        .findings
        == ()
    )


def test_storage_boundary_rejects_symlink_escape_into_git_worktree(
    tmp_path,
):
    worktree = tmp_path / "subject"
    worktree.mkdir()
    (worktree / ".git").mkdir()
    (worktree / "evidence").mkdir()
    base = tmp_path / "outside"
    config = SentinelConfig(storage=StorageConfig(base_dir=base))
    config.storage.evidence_path.rmdir()
    config.storage.evidence_path.symlink_to(worktree / "evidence")

    with pytest.raises(EvidenceStorageBoundaryError):
        CapabilityEffectPromotionService(
            config,
            receipt_store=BehavioralReceiptStore(tmp_path / "receipts"),
        )


def test_promotion_attempt_history_and_gate_off_reconciliation_are_bounded(
    tmp_path,
    monkeypatch,
):
    monkeypatch.delenv(CAPABILITY_FINDING_PROMOTION_ENV, raising=False)
    _config, _receipts, service, admission, receipt, _evidence, _twin = (
        _completed_source(tmp_path, leak=True)
    )

    for _ in range(70):
        assert service.promote(receipt.receipt_id).promotion_state == (
            "blocked_by_policy"
        )
    before_reconcile = service.repository.load_capability_effect_admission(
        admission.admission_id
    )
    assert before_reconcile is not None
    assert before_reconcile["attempt_count"] == 70
    assert len(before_reconcile["attempts_data"]) == 32

    assert service.reconcile() == ()
    after_reconcile = service.repository.load_capability_effect_admission(
        admission.admission_id
    )
    assert after_reconcile is not None
    assert after_reconcile["attempt_count"] == 70
    assert len(after_reconcile["attempts_data"]) == 32


@pytest.mark.parametrize(
    ("assignment", "expected"),
    [
        ("attempts_data = '{}'", "JSON shape"),
        ("state = 'invented_state'", "state is invalid"),
        (
            "state = 'promoted', evidence_root = NULL, cas_blob_hash = NULL, "
            "observation_id = NULL, finding_id = NULL",
            "result is incomplete",
        ),
    ],
)
def test_corrupt_promotion_journal_rows_fail_closed(
    tmp_path,
    assignment,
    expected,
):
    config, _receipts, service, admission, _receipt, _evidence, _twin = (
        _completed_source(tmp_path, leak=True)
    )
    with sqlite3.connect(config.storage.db_path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            f"""
            UPDATE capability_effect_promotion_journal
            SET {assignment}
            WHERE admission_id = ?
            """,
            (admission.admission_id,),
        )

    with pytest.raises(CanonicalEvidenceRepositoryCorruption, match=expected):
        service.repository.load_capability_effect_admission(admission.admission_id)


def test_reconciliation_isolates_one_corrupt_journal_row(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    service = CapabilityEffectPromotionService(
        config,
        receipt_store=BehavioralReceiptStore(tmp_path / "receipts"),
    )
    admission_ids = []
    for index in range(2):
        fingerprint = str(index + 6) * 64
        intake_id = stable_hash(
            "capability_effect_intake",
            {"reconcile": index},
        )
        identity = {
            "digest": stable_hash(
                "assessment_identity",
                {"reconcile": index},
            )
        }
        operation = {"reconcile": index}
        producer = {"reconcile": index}
        storage = {"reconcile": index}
        admission_id = stable_hash(
            "capability_effect_execution_admission",
            {
                "intake_id": intake_id,
                "session_id": f"reconcile-session-{index}",
                "target_origin": ORIGIN,
                "identity_digest": identity["digest"],
                "operation": operation,
                "producer": producer,
                "storage": storage,
            },
        )
        admission_ids.append(admission_id)
        service.repository.reserve_capability_effect_admission(
            admission_id=admission_id,
            intake_id=intake_id,
            session_id=f"reconcile-session-{index}",
            target_origin=ORIGIN,
            identity=identity,
            operation=operation,
            producer=producer,
            storage=storage,
            event_timestamp=1_788_800_000.0 + index,
            event_run_id=None,
        )
        service.repository.bind_capability_effect_source(
            admission_id=admission_id,
            source_receipt_id=f"behavioral-{fingerprint}",
            source_fingerprint=fingerprint,
        )
    corrupt_id, valid_id = sorted(admission_ids)
    with sqlite3.connect(config.storage.db_path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            """
            UPDATE capability_effect_promotion_journal
            SET attempts_data = '{}'
            WHERE admission_id = ?
            """,
            (corrupt_id,),
        )

    results = service.reconcile()

    assert len(results) == 1
    valid = service.repository.load_capability_effect_admission(valid_id)
    assert valid is not None
    assert valid["attempt_count"] == 1
    assert valid["state"] == "retryable_local_persistence_failure"


def test_restart_rejects_mutated_immutable_admission_context(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    config, receipts, service, admission, receipt, _evidence, _twin = _completed_source(
        tmp_path, leak=True
    )
    promoted = service.promote(receipt.receipt_id)
    assert promoted.promotion_state == "promoted"
    journal = service.repository.load_capability_effect_admission(
        admission.admission_id
    )
    assert journal is not None
    operation = dict(journal["operation_data"])
    specification = dict(operation["specification"])
    specification["cleanup_endpoint_ref"] = stable_hash(
        "experiment_endpoint",
        "substituted-cleanup",
    )
    operation["specification"] = specification
    with sqlite3.connect(config.storage.db_path) as connection:
        connection.execute(
            """
            UPDATE capability_effect_promotion_journal
            SET operation_data = ?
            WHERE admission_id = ?
            """,
            (
                json.dumps(operation, sort_keys=True, separators=(",", ":")),
                admission.admission_id,
            ),
        )

    with pytest.raises(
        CanonicalEvidenceRepositoryCorruption,
        match="admission commitment",
    ):
        CapabilityEffectPromotionService(
            config,
            receipt_store=receipts,
        ).status(receipt.receipt_id)
    with pytest.raises(
        CanonicalEvidenceRepositoryCorruption,
        match="admission commitment",
    ):
        EvidenceLedger(config, receipt_store=receipts)


def test_retry_converges_after_cas_and_transaction_failures(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    config, receipts, service, _admission, receipt, _evidence, twin = _completed_source(
        tmp_path, leak=True
    )
    calls_before = (len(twin.calls), len(twin.cleanup_calls))
    original_store = ContentAddressableStorage.store

    def fail_store(_self, _payload):
        raise OSError("simulated CAS interruption")

    monkeypatch.setattr(ContentAddressableStorage, "store", fail_store)
    failed_cas = service.promote(receipt.receipt_id)
    assert failed_cas.promotion_state == "retryable_local_persistence_failure"
    monkeypatch.setattr(ContentAddressableStorage, "store", original_store)

    original_commit = CanonicalEvidenceRepository.commit_capability_effect_promotion
    failures = 0

    def fail_first_transaction(self, **kwargs):
        nonlocal failures
        if failures == 0:
            failures += 1
            raise sqlite3.OperationalError("simulated canonical interruption")
        return original_commit(self, **kwargs)

    monkeypatch.setattr(
        CanonicalEvidenceRepository,
        "commit_capability_effect_promotion",
        fail_first_transaction,
    )
    failed_transaction = CapabilityEffectPromotionService(
        config,
        receipt_store=receipts,
    ).promote(receipt.receipt_id)
    assert failed_transaction.promotion_state == ("retryable_local_persistence_failure")
    promoted = CapabilityEffectPromotionService(
        config,
        receipt_store=receipts,
    ).promote(receipt.receipt_id)

    assert promoted.promotion_state == "promoted"
    assert failures == 1
    assert (len(twin.calls), len(twin.cleanup_calls)) == calls_before


def test_separate_process_promotion_race_converges_on_one_result(
    tmp_path,
    monkeypatch,
):
    monkeypatch.delenv(CAPABILITY_FINDING_PROMOTION_ENV, raising=False)
    config, receipts, _service, _admission, receipt, _evidence, twin = (
        _completed_source(tmp_path, leak=True)
    )
    calls_before = (len(twin.calls), len(twin.cleanup_calls))
    context = multiprocessing.get_context("spawn")

    with ProcessPoolExecutor(max_workers=4, mp_context=context) as workers:
        results = tuple(
            workers.map(
                _promote_in_fresh_process,
                (str(config.storage.base_dir),) * 4,
                (str(receipts._root()),) * 4,
                (receipt.receipt_id,) * 4,
            )
        )

    assert {result["promotion_state"] for result in results} == {"promoted"}
    assert len({result["canonical_observation_id"] for result in results}) == 1
    assert len({result["canonical_finding_id"] for result in results}) == 1
    assert (len(twin.calls), len(twin.cleanup_calls)) == calls_before
    with sqlite3.connect(config.storage.db_path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM epistemic_entities").fetchone()[0]
            == 2
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM epistemic_events").fetchone()[0]
            == 2
        )
    audit_lines = [
        line
        for line in (config.storage.base_dir / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]
    assert len(audit_lines) == 3
    assert json.loads(audit_lines[0])["type"] == "header"
