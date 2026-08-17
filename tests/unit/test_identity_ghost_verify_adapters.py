from __future__ import annotations

from dataclasses import replace
import json

import pytest

from core.foundry.authorization import AuthorizationEnvelope
from core.ghost.flow import FlowStep, UserFlow
from core.ghost.identity_adapter import identity_from_ghost_capture
from core.identity import CredentialFreshness, IdentityBindingMismatch
from core.verify.console import VerificationSession
from core.verify.identity_adapter import identity_from_verification_session


ORIGIN = "https://app.example.test"


def _envelope() -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="envelope-ghost-verify",
        researcher_identity="researcher",
        target_handle="owned-lab",
        authorized_origins=[ORIGIN],
        authorization_basis="owned local lab",
        disclosure_attestation=True,
        created_at=1_700_000_000.0,
        expires_at=4_000_000_000.0,
    )
    envelope.sign()
    return envelope


def _coordinates() -> dict[str, object]:
    return {
        "persona_id": "persona-alice",
        "target_reset_epoch": 2,
        "world_id": "world-primary",
        "target_actor_id": "actor-alice",
        "tenant_id": "tenant-red",
        "credential_epoch": 5,
        "credential_freshness": CredentialFreshness.FRESH,
        "resource_id": "resource:document-7",
        "representation_id": "representation:http-json-v1",
    }


def _assert_cross_binding_refused(identity, lease) -> None:
    for mismatch in (
        replace(identity, session_id="different-session"),
        replace(identity, target_actor_id="actor-bob"),
        replace(identity, tenant_id="tenant-blue"),
    ):
        with pytest.raises(IdentityBindingMismatch, match="does not match"):
            lease.consume(mismatch)


def test_ghost_cookie_and_header_require_exact_identity_binding() -> None:
    flow = UserFlow("Alice display", flow_id="flow-1")
    step = FlowStep(
        "GET",
        f"{ORIGIN}/documents/7",
        headers={"Authorization": "Bearer ghost-secret", "Accept": "application/json"},
    )
    step.id = "step-1"
    step.persona_at_capture = "Alice display"
    step.cookies_after_step = {"session": "ghost-cookie-secret"}
    flow.add_step(step)

    identity, lease = identity_from_ghost_capture(
        _envelope(),
        flow,
        step,
        session_id="assessment-session-1",
        **_coordinates(),
    )

    headers, cookies = lease.consume(identity)
    assert headers == {"authorization": "Bearer ghost-secret"}
    assert cookies == {"session": "ghost-cookie-secret"}
    _assert_cross_binding_refused(identity, lease)
    serialized = json.dumps({"identity": identity.to_dict(), "lease": lease.to_dict()})
    assert "ghost-secret" not in serialized
    assert "ghost-cookie-secret" not in serialized


def test_verify_auth_requires_exact_identity_binding() -> None:
    session = VerificationSession(
        session_id="verify-session-1",
        finding_id="finding-7",
        target_url=f"{ORIGIN}/documents/7",
        target_origin=ORIGIN,
        allowed_origins={ORIGIN},
        persona_name="Alice display",
        persona_headers={"Authorization": "Bearer verify-secret"},
        persona_cookies={"session": "verify-cookie-secret"},
    )

    identity, lease = identity_from_verification_session(
        _envelope(),
        session,
        **_coordinates(),
    )

    headers, cookies = lease.consume(identity)
    assert headers == {"authorization": "Bearer verify-secret"}
    assert cookies == {"session": "verify-cookie-secret"}
    _assert_cross_binding_refused(identity, lease)
    serialized = json.dumps({"identity": identity.to_dict(), "lease": lease.to_dict()})
    assert "verify-secret" not in serialized
    assert "verify-cookie-secret" not in serialized
