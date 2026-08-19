"""Typed inputs for attributing authenticated work to a target principal.

Display names are deliberately absent.  A label can help an operator read a
trace, but it is not evidence that two credential uses belong to one actor.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from core.base.scope import canonical_origin

from .context import AssessmentIdentityContext, CredentialFreshness


@dataclass(frozen=True)
class IdentityAuthorityBinding:
    """An already-admitted authorization reference used for attribution only.

    This value cannot authorize traffic.  Execution remains owned by the
    existing policy/egress gates; the binding only carries their durable
    authorization identity into an ``AssessmentIdentityContext``.
    """

    authorization_envelope_id: str
    authorization_envelope_ref: str
    target_origin: str

    def __post_init__(self) -> None:
        for field_name in ("authorization_envelope_id", "authorization_envelope_ref"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        origin = canonical_origin(self.target_origin)
        if origin is None or origin.as_url() != self.target_origin:
            raise ValueError("target_origin must be canonical")

    def bind(self, target_origin: str) -> tuple[str, str]:
        origin = canonical_origin(target_origin)
        if origin is None or origin.as_url() != self.target_origin:
            raise ValueError("identity target is outside the admitted authorization binding")
        return self.authorization_envelope_id, self.authorization_envelope_ref

    @classmethod
    def from_identity(
        cls,
        identity: AssessmentIdentityContext,
    ) -> "IdentityAuthorityBinding":
        return cls(
            authorization_envelope_id=identity.authorization_envelope_id,
            authorization_envelope_ref=identity.authorization_envelope_ref,
            target_origin=identity.target_origin,
        )


@dataclass(frozen=True)
class PrincipalIdentityBinding:
    """Target-side principal coordinates supplied independently of a label."""

    persona_id: str
    target_reset_epoch: int
    world_id: str
    target_actor_id: str
    tenant_id: str
    credential_epoch: int
    credential_freshness: CredentialFreshness

    def __post_init__(self) -> None:
        for field_name in ("persona_id", "world_id", "target_actor_id", "tenant_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip() or len(value) > 512:
                raise ValueError(f"{field_name} must be a bounded non-empty string")
        for field_name in ("target_reset_epoch", "credential_epoch"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if not isinstance(self.credential_freshness, CredentialFreshness):
            raise ValueError("credential_freshness must be a CredentialFreshness")

    @classmethod
    def from_mapping(cls, value: object) -> "PrincipalIdentityBinding":
        if not isinstance(value, Mapping):
            raise ValueError("identity_binding must be an object")
        required = {
            "persona_id",
            "target_reset_epoch",
            "world_id",
            "target_actor_id",
            "tenant_id",
            "credential_epoch",
            "credential_freshness",
        }
        keys = set(value)
        if any(not isinstance(key, str) for key in keys):
            raise ValueError("identity_binding field names must be strings")
        missing = required - keys
        unknown = keys - required
        if missing:
            raise ValueError(
                "identity_binding is missing: " + ", ".join(sorted(missing))
            )
        if unknown:
            raise ValueError(
                "identity_binding has unknown fields: " + ", ".join(sorted(unknown))
            )
        try:
            freshness = CredentialFreshness(value["credential_freshness"])
        except (TypeError, ValueError) as exc:
            raise ValueError("identity_binding credential_freshness is invalid") from exc
        return cls(
            persona_id=value["persona_id"],
            target_reset_epoch=value["target_reset_epoch"],
            world_id=value["world_id"],
            target_actor_id=value["target_actor_id"],
            tenant_id=value["tenant_id"],
            credential_epoch=value["credential_epoch"],
            credential_freshness=freshness,
        )

    def identity_kwargs(self) -> dict[str, Any]:
        return {
            "persona_id": self.persona_id,
            "target_reset_epoch": self.target_reset_epoch,
            "world_id": self.world_id,
            "target_actor_id": self.target_actor_id,
            "tenant_id": self.tenant_id,
            "credential_epoch": self.credential_epoch,
            "credential_freshness": self.credential_freshness,
        }
