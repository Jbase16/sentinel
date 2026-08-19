"""Wraith verification confirmations adapted into canonical observations."""

from __future__ import annotations

from typing import Any, Mapping

from core.base.scope import canonical_origin
from core.epistemic.ledger import EvidenceLedger, ObservationEnvelope
from core.identity import (
    CredentialFreshness,
    IdentityAuthorityBinding,
    PrincipalIdentityBinding,
)
from core.identity.http_observation import (
    http_representation_ref,
    http_resource_ref,
    record_http_observation,
)
from core.wraith.identity_adapter import identity_from_wraith_persona
from core.wraith.personas import Persona, PersonaType


def authority_from_wraith_session(session: object, target_url: str) -> IdentityAuthorityBinding:
    scope_context = getattr(session, "scope_context", None)
    if scope_context is None:
        raise ValueError("Wraith canonical attribution requires an admitted scope context")
    origin = canonical_origin(target_url)
    if origin is None:
        raise ValueError("Wraith canonical attribution target has no valid origin")
    return IdentityAuthorityBinding(
        authorization_envelope_id=scope_context.authorization_envelope_id,
        authorization_envelope_ref=scope_context.authorization_envelope_ref,
        target_origin=origin.as_url(),
    )


class WraithCanonicalEvidenceAdapter:
    """Admit a Wraith result only when its target principal is exact and fresh."""

    def __init__(self, ledger: EvidenceLedger):
        self.ledger = ledger

    def record_confirmation(
        self,
        session: object,
        *,
        persona_config: Mapping[str, Any],
        binding: PrincipalIdentityBinding,
        name: str,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
        url: str,
        label: str,
        kind: str,
        confidence: float,
        evidence: str,
        payload: object,
    ) -> ObservationEnvelope:
        if binding.credential_freshness is not CredentialFreshness.FRESH:
            raise ValueError("Wraith canonical attribution requires a fresh credential")
        try:
            persona_type = PersonaType(
                str(persona_config.get("persona_type") or persona_config.get("type") or "custom")
                .strip()
                .lower()
            )
        except ValueError:
            persona_type = PersonaType.CUSTOM
        persona = Persona(
            name=name,
            persona_type=persona_type,
            cookie_jar=dict(cookies),
            extra_headers=dict(headers),
        )
        authority = authority_from_wraith_session(session, url)
        origin = canonical_origin(url)
        if origin is None:
            raise ValueError("Wraith canonical attribution target has no valid origin")
        identity = identity_from_wraith_persona(
            authority,
            persona,
            session_id=str(getattr(session, "id")),
            target_origin=origin.as_url(),
            resource_id=http_resource_ref(url),
            representation_id=http_representation_ref("PROBE", None),
            credential_headers=headers,
            credential_cookies=cookies,
            **binding.identity_kwargs(),
        )
        return record_http_observation(
            self.ledger,
            source="wraith_verify",
            identity=identity,
            method="PROBE",
            url=url,
            response_status=0,
            raw_evidence={
                "probe_label": label,
                "vulnerability_class": kind,
                "confidence": float(confidence),
                "evidence": evidence,
                "payload": payload,
            },
        )


__all__ = ["WraithCanonicalEvidenceAdapter", "authority_from_wraith_session"]
