"""Identity-bound in-memory access to captured authentication material."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .context import AssessmentIdentityContext, CredentialFreshness


class IdentityBindingMismatch(PermissionError):
    """Credential material was requested under a different identity binding."""


@dataclass(frozen=True, repr=False)
class BoundCredentialMaterial:
    identity_digest: str
    credential_source_ref: str
    _headers: tuple[tuple[str, str], ...]
    _cookies: tuple[tuple[str, str], ...]

    @classmethod
    def seal(
        cls,
        identity: AssessmentIdentityContext,
        *,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
    ) -> "BoundCredentialMaterial":
        if identity.credential_freshness is not CredentialFreshness.FRESH:
            raise IdentityBindingMismatch("only fresh credential material can be sealed")
        normalized_headers = tuple(
            sorted((str(name).lower(), str(value)) for name, value in headers.items())
        )
        normalized_cookies = tuple(
            sorted((str(name), str(value)) for name, value in cookies.items())
        )
        if not normalized_headers and not normalized_cookies:
            raise ValueError("credential material is empty")
        return cls(
            identity_digest=identity.digest,
            credential_source_ref=identity.credential_source_ref,
            _headers=normalized_headers,
            _cookies=normalized_cookies,
        )

    def consume(
        self,
        identity: AssessmentIdentityContext,
    ) -> tuple[dict[str, str], dict[str, str]]:
        if (
            identity.credential_freshness is not CredentialFreshness.FRESH
            or identity.digest != self.identity_digest
            or identity.credential_source_ref != self.credential_source_ref
        ):
            raise IdentityBindingMismatch(
                "credential material does not match this assessment identity"
            )
        return dict(self._headers), dict(self._cookies)

    def to_dict(self) -> dict[str, object]:
        """Return audit metadata only; secret names and values stay in memory."""

        return {
            "identity_digest": self.identity_digest,
            "credential_source_ref": self.credential_source_ref,
            "has_headers": bool(self._headers),
            "has_cookies": bool(self._cookies),
        }

    def __repr__(self) -> str:
        return (
            "BoundCredentialMaterial("
            f"identity_digest={self.identity_digest!r}, "
            f"credential_source_ref={self.credential_source_ref!r}, "
            "headers=<redacted>, cookies=<redacted>)"
        )
