"""Ghost captures adapted into exact canonical identity bindings."""

from __future__ import annotations

from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.identity_adapter import (
    authorization_envelope_binding,
    stable_identity_source_ref,
)
from core.ghost.flow import FlowStep, UserFlow
from core.identity import (
    AssessmentIdentityContext,
    BoundCredentialMaterial,
    CredentialFreshness,
)


_CREDENTIAL_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-csrf-token"}
)


def identity_from_ghost_capture(
    envelope: AuthorizationEnvelope,
    flow: UserFlow,
    step: FlowStep,
    *,
    session_id: str,
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
    """Seal captured credentials to the exact assessment identity coordinates."""

    envelope_id, envelope_ref = authorization_envelope_binding(
        envelope,
        target_origin=step.url,
    )
    source_ref = stable_identity_source_ref(
        "ghost_capture",
        {
            "session_id": session_id,
            "flow_id": flow.id,
            "step_id": step.id,
            "credential_epoch": credential_epoch,
        },
    )
    identity = AssessmentIdentityContext(
        session_id=session_id,
        authorization_envelope_id=envelope_id,
        authorization_envelope_ref=envelope_ref,
        target_origin=step.url,
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
        display_name=step.persona_at_capture or flow.name,
    )
    headers = {
        name: value
        for name, value in step.headers.items()
        if name.lower() in _CREDENTIAL_HEADERS
    }
    lease = BoundCredentialMaterial.seal(
        identity,
        headers=headers,
        cookies=step.cookies_after_step,
    )
    return identity, lease
