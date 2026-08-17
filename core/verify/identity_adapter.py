"""Verify Console session auth adapted into canonical identity bindings."""

from __future__ import annotations

from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.identity_adapter import (
    authorization_envelope_binding,
    stable_identity_source_ref,
)
from core.identity import (
    AssessmentIdentityContext,
    BoundCredentialMaterial,
    CredentialFreshness,
)
from core.verify.console import VerificationSession


def identity_from_verification_session(
    envelope: AuthorizationEnvelope,
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
) -> tuple[AssessmentIdentityContext, BoundCredentialMaterial]:
    """Seal session-only Verify auth to its exact actor/tenant/session."""

    envelope_id, envelope_ref = authorization_envelope_binding(
        envelope,
        target_origin=session.target_origin,
    )
    source_ref = stable_identity_source_ref(
        "verify_session_auth",
        {
            "session_id": session.session_id,
            "finding_id": session.finding_id,
            "credential_epoch": credential_epoch,
        },
    )
    identity = AssessmentIdentityContext(
        session_id=session.session_id,
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
        headers=session.persona_headers,
        cookies=session.persona_cookies,
    )
    return identity, lease
