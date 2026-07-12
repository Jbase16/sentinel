"""Durable behavioral execution receipt tests."""

from __future__ import annotations

import json
import stat
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from core.behavior.receipts import (
    ABORTED,
    COMPLETED,
    RESERVED,
    BehavioralReceiptStore,
    BehavioralReceiptContext,
    ReceiptStoreError,
    redacted_outcome,
    redacted_receipt_context,
    request_fingerprint,
)


def _fingerprint():
    return request_fingerprint({"capture": [{"token": "raw-secret", "id": "object-42"}]})


def _context():
    return redacted_receipt_context(
        target_origin="https://api.example.test",
        envelope_id="env-secret",
        source_persona_id="source-secret",
        peer_persona_id="peer-secret",
    )


def _response():
    return {
        "status": "completed",
        "plan": {
            "selected_proposal_id": "authorization_proposal:" + "a" * 64,
            "ranked": [{"operation_label": "GetPrivateSecret"}],
        },
        "execution": {
            "status": "completed",
            "legacy_verdict": "BOLA_CONFIRMED",
            "legacy_detail": "peer-private-secret",
            "finding_confirmed": True,
            "requests_attempted": 3,
            "requests_sent": 3,
            "policy_denials": 0,
        },
        "finding": {"evidence": "peer-private-secret"},
        "graphql_resolution": {
            "catalog": {
                "artifacts": 1,
                "artifact_bytes": 200,
                "documents": 1,
                "operation_names": 1,
                "dropped": {"artifacts": 0, "artifact_bytes": 0, "documents": 0},
            },
            "assets": {
                "attempted": 1,
                "fetched": 1,
                "failed": 0,
                "documents_added": 1,
            },
            "source": {
                "resolved_operations": 1,
                "unresolved_operations": 0,
                "ambiguous_operations": 0,
            },
            "peer": {
                "resolved_operations": 1,
                "unresolved_operations": 0,
                "ambiguous_operations": 0,
            },
        },
    }


def test_receipt_reservation_is_atomic_and_owner_only(tmp_path):
    store = BehavioralReceiptStore(tmp_path / "receipts")
    fingerprint = _fingerprint()
    context = _context()

    first = store.reserve(fingerprint, context=context)
    second = store.reserve(fingerprint, context=context)

    assert first.created is True
    assert first.reservation_token is not None
    assert first.receipt.state == RESERVED
    assert second.created is False
    assert second.reservation_token is None
    assert second.receipt.receipt_id == first.receipt.receipt_id
    path = tmp_path / "receipts" / f"behavioral-{fingerprint}.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    encoded = path.read_text()
    for secret in ("raw-secret", "object-42", "env-secret", "source-secret", "peer-secret"):
        assert secret not in encoded


def test_concurrent_reservations_have_exactly_one_owner(tmp_path):
    root = tmp_path / "receipts"
    fingerprint = _fingerprint()
    barrier = Barrier(8)

    def reserve():
        barrier.wait()
        return BehavioralReceiptStore(root).reserve(fingerprint, context=_context())

    with ThreadPoolExecutor(max_workers=8) as pool:
        reservations = list(pool.map(lambda _index: reserve(), range(8)))

    winners = [reservation for reservation in reservations if reservation.created]
    assert len(winners) == 1
    assert winners[0].reservation_token is not None
    assert all(
        reservation.reservation_token is None
        for reservation in reservations
        if not reservation.created
    )
    loaded = BehavioralReceiptStore(root).load(fingerprint)
    assert loaded is not None
    assert loaded.state == RESERVED


def test_completed_receipt_returns_redacted_cached_outcome(tmp_path):
    store = BehavioralReceiptStore(tmp_path)
    fingerprint = _fingerprint()
    reservation = store.reserve(fingerprint, context=_context())
    assert reservation.reservation_token is not None

    completed = store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=redacted_outcome(_response()),
    )
    duplicate = store.reserve(fingerprint, context=_context())

    assert completed.state == COMPLETED
    assert duplicate.created is False
    assert duplicate.receipt.outcome["finding"] is None
    assert duplicate.receipt.outcome["finding_confirmed"] is True
    assert duplicate.receipt.outcome["execution"] == {
        "status": "completed",
        "legacy_verdict": "BOLA_CONFIRMED",
        "finding_confirmed": True,
        "requests_attempted": 3,
        "requests_sent": 3,
        "policy_denials": 0,
    }
    assert "peer-private-secret" not in json.dumps(duplicate.receipt.to_dict())
    assert "GetPrivateSecret" not in json.dumps(duplicate.receipt.to_dict())


def test_read_exploration_receipt_persists_only_bounded_counters(tmp_path):
    response = _response()
    response["read_exploration"] = {
        "status": "completed",
        "pairs_attempted": 1,
        "pairs_completed": 1,
        "requests_attempted": 2,
        "requests_sent": 2,
        "successful_responses": 2,
        "policy_denials": 0,
        "failed_requests": 0,
        "candidates_discovered": 2,
        "selected_after_pair": 1,
        "frontier_exhausted": False,
        "raw_urls": ["https://api.example.test/private/raw-secret"],
    }
    store = BehavioralReceiptStore(tmp_path)
    fingerprint = _fingerprint()
    reservation = store.reserve(fingerprint, context=_context())
    assert reservation.reservation_token is not None

    completed = store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token,
        outcome=redacted_outcome(response),
    )

    assert completed.outcome is not None
    assert completed.outcome["read_exploration"] == {
        "status": "completed",
        "pairs_attempted": 1,
        "pairs_completed": 1,
        "requests_attempted": 2,
        "requests_sent": 2,
        "successful_responses": 2,
        "policy_denials": 0,
        "failed_requests": 0,
        "candidates_discovered": 2,
        "selected_after_pair": 1,
        "frontier_exhausted": False,
    }
    assert "raw-secret" not in json.dumps(completed.to_dict())


def test_aborted_or_reserved_receipt_cannot_refresh_budget(tmp_path):
    store = BehavioralReceiptStore(tmp_path)
    fingerprint = _fingerprint()
    reservation = store.reserve(fingerprint, context=_context())
    assert reservation.reservation_token is not None
    aborted = store.abort(
        fingerprint,
        reservation_token=reservation.reservation_token,
        reason="transport_failure",
    )

    assert aborted.state == ABORTED
    assert store.reserve(fingerprint, context=_context()).created is False
    with pytest.raises(ReceiptStoreError, match="already terminal"):
        store.complete(
            fingerprint,
            reservation_token=reservation.reservation_token,
            outcome=redacted_outcome(_response()),
        )


def test_only_reserving_process_can_finalize_receipt(tmp_path):
    store = BehavioralReceiptStore(tmp_path)
    fingerprint = _fingerprint()
    reservation = store.reserve(fingerprint, context=_context())
    assert reservation.reservation_token is not None

    with pytest.raises(ReceiptStoreError, match="token mismatch"):
        store.complete(
            fingerprint,
            reservation_token="not-the-reservation-token",
            outcome=redacted_outcome(_response()),
        )

    loaded = store.load(fingerprint)
    assert loaded is not None
    assert loaded.state == RESERVED


def test_corrupt_existing_receipt_fails_closed(tmp_path):
    store = BehavioralReceiptStore(tmp_path)
    fingerprint = _fingerprint()
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / f"behavioral-{fingerprint}.json"
    path.write_text("not-json")
    path.chmod(0o600)

    with pytest.raises(ReceiptStoreError, match="cannot be read safely"):
        store.reserve(fingerprint, context=_context())


def test_receipt_with_unsafe_permissions_fails_closed(tmp_path):
    store = BehavioralReceiptStore(tmp_path)
    fingerprint = _fingerprint()
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / f"behavioral-{fingerprint}.json"
    path.write_text("{}")
    path.chmod(0o644)

    with pytest.raises(ReceiptStoreError, match="attributes are unsafe"):
        store.reserve(fingerprint, context=_context())


def test_raw_context_cannot_be_constructed_or_persisted():
    with pytest.raises(ReceiptStoreError, match="context is not redacted"):
        BehavioralReceiptContext(
            target_ref="https://api.example.test",
            envelope_ref="secret-envelope",
            source_persona_ref="source-secret",
            peer_persona_ref="peer-secret",
        )


def test_fingerprint_is_deterministic_but_order_sensitive():
    first = request_fingerprint({"records": [{"a": 1}, {"b": 2}]})
    same = request_fingerprint({"records": [{"a": 1}, {"b": 2}]})
    reordered = request_fingerprint({"records": [{"b": 2}, {"a": 1}]})

    assert first == same
    assert first != reordered

    with pytest.raises(ValueError, match="Out of range float values"):
        request_fingerprint({"records": [float("nan")]})
