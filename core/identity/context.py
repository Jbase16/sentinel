"""Immutable identity aggregate for observations and controlled actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any

from core.base.scope import canonical_origin


class CredentialFreshness(str, Enum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > 512:
        raise ValueError(f"{name} must be a non-empty bounded value")
    if any(ord(character) < 0x20 for character in normalized):
        raise ValueError(f"{name} contains control characters")
    return normalized


@dataclass(frozen=True)
class AssessmentIdentityContext:
    """One exact identity binding; display metadata never establishes identity."""

    session_id: str
    target_origin: str
    target_reset_epoch: int
    world_id: str
    persona_id: str
    target_actor_id: str
    tenant_id: str
    credential_source_ref: str
    credential_epoch: int
    credential_freshness: CredentialFreshness
    resource_id: str
    representation_id: str
    display_name: str = field(default="", compare=False, hash=False)

    def __post_init__(self) -> None:
        for name in (
            "session_id",
            "world_id",
            "persona_id",
            "target_actor_id",
            "tenant_id",
            "credential_source_ref",
            "resource_id",
            "representation_id",
        ):
            object.__setattr__(self, name, _required(getattr(self, name), name))

        origin = canonical_origin(self.target_origin)
        if origin is None:
            raise ValueError("target_origin must be an absolute HTTP(S) URL")
        object.__setattr__(self, "target_origin", origin.as_url())

        if not isinstance(self.target_reset_epoch, int) or self.target_reset_epoch < 0:
            raise ValueError("target_reset_epoch must be a non-negative integer")
        if not isinstance(self.credential_epoch, int) or self.credential_epoch < 0:
            raise ValueError("credential_epoch must be a non-negative integer")
        if not isinstance(self.credential_freshness, CredentialFreshness):
            raise ValueError("credential_freshness must be a CredentialFreshness")
        if not isinstance(self.display_name, str) or len(self.display_name) > 512:
            raise ValueError("display_name must be a bounded string")

    def identity_material(self) -> dict[str, Any]:
        return {
            "schema": "assessment_identity_v1",
            "session_id": self.session_id,
            "target_origin": self.target_origin,
            "target_reset_epoch": self.target_reset_epoch,
            "world_id": self.world_id,
            "persona_id": self.persona_id,
            "target_actor_id": self.target_actor_id,
            "tenant_id": self.tenant_id,
            "credential_source_ref": self.credential_source_ref,
            "credential_epoch": self.credential_epoch,
            "credential_freshness": self.credential_freshness.value,
            "resource_id": self.resource_id,
            "representation_id": self.representation_id,
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.identity_material(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return f"assessment_identity:{hashlib.sha256(encoded).hexdigest()}"

    def is_merge_compatible(self, other: object) -> bool:
        """Allow merging only for the same exact, currently fresh binding."""

        return (
            isinstance(other, AssessmentIdentityContext)
            and self.credential_freshness is CredentialFreshness.FRESH
            and other.credential_freshness is CredentialFreshness.FRESH
            and self.digest == other.digest
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.identity_material(),
            "display_name": self.display_name,
            "digest": self.digest,
        }
