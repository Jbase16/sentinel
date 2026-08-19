"""Verify Console session auth adapted into canonical identity bindings."""

from __future__ import annotations

from typing import Mapping

from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.identity_adapter import (
    authorization_envelope_binding,
    stable_identity_source_ref,
)
from core.identity import (
    AssessmentIdentityContext,
    BoundCredentialMaterial,
    CredentialFreshness,
    IdentityAuthorityBinding,
)
from core.identity.credential_material import credential_material_commitment
from core.verify.console import VerificationSession


def identity_from_verification_session(
    envelope: AuthorizationEnvelope | IdentityAuthorityBinding,
    session: VerificationSession,
    *,
    persona_id: str,
    target_reset_epoch: int,
    world_id: str,
    target_actor_id: str,
    tenant_id: str,
    credential_epoch: int,
    credential_freshness: CredentialFreshness,
    resource_id: str,
    representation_id: str,
    credential_headers: Mapping[str, str] | None = None,
    credential_cookies: Mapping[str, str] | None = None,
) -> tuple[AssessmentIdentityContext, BoundCredentialMaterial]:
    """Seal session-only Verify auth to its exact actor/tenant/session."""

    if isinstance(envelope, IdentityAuthorityBinding):
        envelope_id, envelope_ref = envelope.bind(session.target_origin)
    else:
        envelope_id, envelope_ref = authorization_envelope_binding(
            envelope,
            target_origin=session.target_origin,
        )
    sealed_headers = (
        credential_headers if credential_headers is not None else session.persona_headers
    )
    sealed_cookies = (
        credential_cookies if credential_cookies is not None else session.persona_cookies
    )
    source_ref = stable_identity_source_ref(
        "verify_session_auth",
        {
            "session_id": session.canonical_session_id or session.session_id,
            "finding_id": session.finding_id,
            "credential_epoch": credential_epoch,
            "credential_material": credential_material_commitment(
                headers=sealed_headers,
                cookies=sealed_cookies,
            ),
        },
    )
    identity = AssessmentIdentityContext(
        session_id=session.canonical_session_id or session.session_id,
        authorization_envelope_id=envelope_id,
        authorization_envelope_ref=envelope_ref,
        target_origin=session.target_origin,
        target_reset_epoch=target_reset_epoch,
        world_id=world_id,
        persona_id=persona_id,
        target_actor_id=target_actor_id,
        tenant_id=tenant_id,
        credential_source_ref=source_ref,
        credential_epoch=credential_epoch,
        credential_freshness=credential_freshness,
        resource_id=resource_id,
        representation_id=representation_id,
        display_name=session.persona_name or "",
    )
    lease = BoundCredentialMaterial.seal(
        identity,
        headers=sealed_headers,
        cookies=sealed_cookies,
    )
    return identity, lease
