"""Wraith authentication inputs adapted into canonical assessment identity."""

from __future__ import annotations

from typing import Mapping

from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.identity_adapter import (
    authorization_envelope_binding,
    stable_identity_source_ref,
)
from core.identity import (
    AssessmentIdentityContext,
    CredentialFreshness,
    IdentityAuthorityBinding,
)
from core.identity.credential_material import credential_material_commitment
from core.wraith.personas import Persona


def _credential_kinds(persona: Persona) -> tuple[str, ...]:
    kinds = []
    if persona.cookie_jar is not None:
        kinds.append("cookie")
    if persona.bearer_token is not None:
        kinds.append("bearer")
    if persona.login_flow is not None:
        kinds.append("login_flow")
    if persona.extra_headers:
        kinds.append("headers")
    if not kinds:
        kinds.append("anonymous")
    return tuple(kinds)


def identity_from_wraith_persona(
    envelope: AuthorizationEnvelope | IdentityAuthorityBinding,
    persona: Persona,
    *,
    persona_id: str,
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
    credential_headers: Mapping[str, str] | None = None,
    credential_cookies: Mapping[str, str] | None = None,
) -> AssessmentIdentityContext:
    """Adapt Wraith material by mechanism only; credential values never cross."""

    if isinstance(envelope, IdentityAuthorityBinding):
        envelope_id, envelope_ref = envelope.bind(target_origin)
    else:
        envelope_id, envelope_ref = authorization_envelope_binding(
            envelope,
            target_origin=target_origin,
        )
    source_ref = stable_identity_source_ref(
        "wraith_auth",
        {
            "persona_id": persona_id,
            "persona_type": persona.persona_type.value,
            "credential_kinds": _credential_kinds(persona),
            "credential_material": credential_material_commitment(
                headers=(
                    credential_headers
                    if credential_headers is not None
                    else persona.extra_headers
                ),
                cookies=(
                    credential_cookies
                    if credential_cookies is not None
                    else persona.cookie_jar
                ),
            ),
        },
    )
    return AssessmentIdentityContext(
        session_id=session_id,
        authorization_envelope_id=envelope_id,
        authorization_envelope_ref=envelope_ref,
        target_origin=target_origin,
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
        display_name=persona.name,
    )
