from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from core.identity import AssessmentIdentityContext, CredentialFreshness


def _identity(**changes: object) -> AssessmentIdentityContext:
    values = {
        "session_id": "session-7",
        "authorization_envelope_id": "envelope-7",
        "authorization_envelope_ref": f"authorization_envelope:{'7' * 64}",
        "target_origin": "https://Example.Test:443/account/42",
        "target_reset_epoch": 4,
        "world_id": "world-primary",
        "persona_id": "persona-alice",
        "target_actor_id": "actor-42",
        "tenant_id": "tenant-red",
        "credential_source_ref": "vault:persona-alice",
        "credential_epoch": 9,
        "credential_freshness": CredentialFreshness.FRESH,
        "resource_id": "resource:document-17",
        "representation_id": "representation:http-json-v1",
        "display_name": "Alex",
    }
    values.update(changes)
    return AssessmentIdentityContext(**values)


def test_display_name_never_merges_distinct_tenant_or_world_identity() -> None:
    first = _identity()
    other_tenant = _identity(tenant_id="tenant-blue")
    other_world = _identity(world_id="world-reset")
    renamed = replace(first, display_name="Same actor, renamed")

    assert first.target_origin == "https://example.test"
    assert first.digest != other_tenant.digest
    assert first.digest != other_world.digest
    assert not first.is_merge_compatible(other_tenant)
    assert not first.is_merge_compatible(other_world)
    assert first.digest == renamed.digest
    assert first.is_merge_compatible(renamed)


def test_stale_credential_epoch_cannot_merge() -> None:
    current = _identity()
    stale = _identity(
        credential_epoch=8,
        credential_freshness=CredentialFreshness.STALE,
    )

    assert current.digest != stale.digest
    assert not current.is_merge_compatible(stale)
    assert not stale.is_merge_compatible(stale)


def test_identity_is_immutable_and_digest_is_serialized() -> None:
    identity = _identity()

    with pytest.raises(FrozenInstanceError):
        identity.tenant_id = "tenant-blue"  # type: ignore[misc]

    serialized = identity.to_dict()
    assert serialized["digest"] == identity.digest
    assert serialized["credential_freshness"] == "fresh"
