"""Adversarial location-swap specimens for the R5D10 evidence boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.capability_effect_promotion import (
    CapabilityEffectPromotionService,
)
from core.behavior.receipts import (
    BehavioralReceiptStore,
    ReceiptStoreError,
    redacted_receipt_context,
)
from core.epistemic.storage_boundary import EvidenceStorageBoundaryError


def _replacement_tree(base_dir: Path, receipt_root: Path) -> None:
    (base_dir / "evidence" / "blobs").mkdir(parents=True)
    (base_dir / "reports").mkdir()
    receipt_root.mkdir(parents=True)


def _move_into_worktree(container: Path, destination: Path) -> None:
    destination.mkdir()
    (destination / ".git").mkdir()
    container.rename(destination / "relocated-evidence")


def test_ancestor_replacement_refuses_receipt_publication(tmp_path: Path) -> None:
    container = tmp_path / "admitted-location"
    base_dir = container / "data"
    receipt_root = container / "receipts"
    config = SentinelConfig(storage=StorageConfig(base_dir=base_dir))
    receipts = BehavioralReceiptStore(receipt_root)
    service = CapabilityEffectPromotionService(config, receipt_store=receipts)
    service.preflight_local_persistence()

    _move_into_worktree(container, tmp_path / "subject-worktree")
    _replacement_tree(base_dir, receipt_root)

    with pytest.raises(
        ReceiptStoreError,
        match="storage changed after admission",
    ):
        receipts.reserve(
            "a" * 64,
            context=redacted_receipt_context(
                target_origin="https://owned.test",
                envelope_id="authorization-r5d10-anchor",
                source_persona_id="owned-source",
                peer_persona_id="owned-peer",
            ),
        )

    assert tuple(receipt_root.iterdir()) == ()


def test_ancestor_replacement_refuses_later_promotion_db_access(
    tmp_path: Path,
) -> None:
    container = tmp_path / "admitted-location"
    base_dir = container / "data"
    receipt_root = tmp_path / "receipts"
    config = SentinelConfig(storage=StorageConfig(base_dir=base_dir))
    service = CapabilityEffectPromotionService(
        config,
        receipt_store=BehavioralReceiptStore(receipt_root),
    )
    service.preflight_local_persistence()

    _move_into_worktree(container, tmp_path / "subject-worktree")
    _replacement_tree(base_dir, tmp_path / "unused-receipts")

    with pytest.raises(
        EvidenceStorageBoundaryError,
        match="anchor_changed_after_admission",
    ):
        service.promote(f"behavioral-{'b' * 64}")

    assert not config.storage.db_path.exists()
    assert not (base_dir / "audit.jsonl").exists()
    assert tuple((base_dir / "evidence" / "blobs").iterdir()) == ()
