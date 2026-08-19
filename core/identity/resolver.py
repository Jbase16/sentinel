"""Session-scoped target-principal attribution without label authority."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from core.behavior.normalize import stable_hash

from .context import AssessmentIdentityContext


class IdentityResolutionRefused(ValueError):
    """Raised when a caller attempts an unsafe principal merge."""


@dataclass(frozen=True)
class PrincipalResolution:
    principal_ref: str
    identity: AssessmentIdentityContext
    label_collision: bool = False


class PrincipalIdentityResolver:
    """Resolve exact identity atoms while treating display labels as metadata.

    ``AssessmentIdentityContext.is_merge_compatible`` is the sole merge gate.
    A colliding label is observable, but cannot select or merge a principal.
    """

    def __init__(self, session_id: str):
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("identity resolver requires a non-empty session_id")
        self.session_id = session_id
        self._by_ref: dict[str, PrincipalResolution] = {}
        self._by_digest: dict[str, PrincipalResolution] = {}
        self._refs_by_label: dict[str, set[str]] = {}
        self._lock = RLock()

    def _require_live_session(self, identity: AssessmentIdentityContext) -> None:
        if identity.session_id != self.session_id:
            raise IdentityResolutionRefused(
                "identity belongs to a different assessment session"
            )
        # Freshness is part of the canonical merge contract. Calling the
        # contract against itself deliberately makes stale/unknown identities
        # ineligible for live resolution.
        if not identity.is_merge_compatible(identity):
            raise IdentityResolutionRefused(
                "stale or unknown credentials cannot resolve as a live principal"
            )

    def attribute(self, identity: AssessmentIdentityContext) -> PrincipalResolution:
        """Return an exact principal reference; never unify by display label."""

        self._require_live_session(identity)
        with self._lock:
            existing = self._by_digest.get(identity.digest)
            if existing is not None:
                if not existing.identity.is_merge_compatible(identity):
                    raise IdentityResolutionRefused(
                        "matching digest failed the canonical identity merge gate"
                    )
                return existing

            label_refs = self._refs_by_label.get(identity.display_name, set())
            label_collision = False
            if identity.display_name:
                for principal_ref in label_refs:
                    candidate = self._by_ref[principal_ref]
                    if candidate.identity.is_merge_compatible(identity):
                        return candidate
                    label_collision = True

            resolution = PrincipalResolution(
                principal_ref=stable_hash(
                    "principal",
                    {
                        "session_id": self.session_id,
                        "identity_digest": identity.digest,
                    },
                ),
                identity=identity,
                label_collision=label_collision,
            )
            self._by_ref[resolution.principal_ref] = resolution
            self._by_digest[identity.digest] = resolution
            if identity.display_name:
                self._refs_by_label.setdefault(identity.display_name, set()).add(
                    resolution.principal_ref
                )
            return resolution

    def merge(
        self,
        principal_ref: str,
        candidate: AssessmentIdentityContext,
    ) -> PrincipalResolution:
        """Explicitly merge only an exact, fresh canonical identity match."""

        self._require_live_session(candidate)
        with self._lock:
            existing = self._by_ref.get(principal_ref)
            if existing is None:
                raise IdentityResolutionRefused("principal reference is unknown")
            if not existing.identity.is_merge_compatible(candidate):
                raise IdentityResolutionRefused(
                    "display label cannot merge incompatible principal identities"
                )
            return existing


__all__ = [
    "IdentityResolutionRefused",
    "PrincipalIdentityResolver",
    "PrincipalResolution",
]
