from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.contracts.architecture_ids import (
    IdentifierRegistry,
    IdentifierRegistryError,
    default_registry_path,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_registry_accepts_historical_aliases_and_rejects_new_bare_ids() -> None:
    registry = IdentifierRegistry.load(default_registry_path(REPOSITORY_ROOT))

    registry.validate_historical_sources(REPOSITORY_ROOT)
    registry.validate_source("docs/architecture/new-plan.md", "Next: DB-R1 and DB-S15")

    with pytest.raises(
        IdentifierRegistryError, match=r"bare or unregistered IDs: R1, S15"
    ):
        registry.validate_source("docs/architecture/new-plan.md", "Next: R1 and S15")


def test_registry_rejects_colliding_canonical_ids() -> None:
    payload = json.loads(
        default_registry_path(REPOSITORY_ROOT).read_text(encoding="utf-8")
    )
    payload["canonical_ids"].append(dict(payload["canonical_ids"][0]))

    with pytest.raises(IdentifierRegistryError, match=r"colliding canonical IDs: C0"):
        IdentifierRegistry.from_dict(payload)


def test_registry_accepts_registered_family_slice_ids() -> None:
    registry = IdentifierRegistry.load(default_registry_path(REPOSITORY_ROOT))

    assert {"R5D1", "R5D2", "R5D3", "R5D4", "R5D5"} <= registry.canonical_ids
