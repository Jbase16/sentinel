"""Foundry inputs adapted into the canonical assessment identity."""

from __future__ import annotations

import hashlib
import json

from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import ResearchPersona
from core.identity import AssessmentIdentityContext, CredentialFreshness


def stable_identity_source_ref(kind: str, material: object) -> str:
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"{kind}:{hashlib.sha256(encoded).hexdigest()}"


def authorization_envelope_binding(
    envelope: AuthorizationEnvelope,
    *,
    target_origin: str,
) -> tuple[str, str]:
    """Bind an exact signed envelope without granting execution authority."""

    if not envelope.signature_is_valid():
        raise ValueError("identity requires a valid signed authorization envelope")
    if not envelope.authorizes_origin(target_origin):
        raise ValueError("identity target is outside the authorization envelope")
    return (
        envelope.envelope_id,
        f"authorization_envelope:{envelope.attestation_signature}",
    )


def identity_from_vault_persona(
    envelope: AuthorizationEnvelope,
    persona: ResearchPersona,
    *,
    session_id: str,
    target_origin: str,
    target_reset_epoch: int,
    world_id: str,
    target_actor_id: str,
    tenant_id: str,
    credential_epoch: int,
    credential_freshness: CredentialFreshness,
    resource_id: str,
    representation_id: str,
) -> AssessmentIdentityContext:
    """Adapt vault identity without copying contact details or credentials."""

    envelope_id, envelope_ref = authorization_envelope_binding(
        envelope,
        target_origin=target_origin,
    )
    source_ref = stable_identity_source_ref(
        "persona_vault",
        {"persona_id": persona.persona_id, "created_at": persona.created_at},
    )
    return AssessmentIdentityContext(
        session_id=session_id,
        authorization_envelope_id=envelope_id,
        authorization_envelope_ref=envelope_ref,
        target_origin=target_origin,
        target_reset_epoch=target_reset_epoch,
        world_id=world_id,
        persona_id=persona.persona_id,
        target_actor_id=target_actor_id,
        tenant_id=tenant_id,
        credential_source_ref=source_ref,
        credential_epoch=credential_epoch,
        credential_freshness=credential_freshness,
        resource_id=resource_id,
        representation_id=representation_id,
        display_name=persona.label,
    )
