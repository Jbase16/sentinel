from __future__ import annotations

import json

import pytest

from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.identity_adapter import identity_from_vault_persona
from core.foundry.vault import ResearchPersona
from core.identity import CredentialFreshness
from core.wraith.identity_adapter import identity_from_wraith_persona
from core.wraith.personas import Persona, PersonaType


ORIGIN = "https://api.example.test"


def _envelope() -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="envelope-17",
        researcher_identity="researcher",
        target_handle="owned-lab",
        authorized_origins=[ORIGIN],
        authorization_basis="owned local lab",
        disclosure_attestation=True,
        allowed_workflows=["verify"],
        created_at=1_700_000_000.0,
        expires_at=4_000_000_000.0,
    )
    envelope.sign()
    return envelope


def _binding() -> dict[str, object]:
    return {
        "session_id": "session-17",
        "target_origin": f"{ORIGIN}/documents/9",
        "target_reset_epoch": 3,
        "world_id": "world-a",
        "target_actor_id": "actor-9",
        "tenant_id": "tenant-2",
        "credential_epoch": 11,
        "credential_freshness": CredentialFreshness.FRESH,
        "resource_id": "resource:document-9",
        "representation_id": "representation:http-json-v1",
    }


def test_foundry_adapter_preserves_binding_without_serializing_vault_secrets() -> None:
    persona = ResearchPersona(
        persona_id="vault-persona-1",
        label="Alice display",
        email="alice-secret@example.test",
        password="vault-password-secret",
        phone="+15555550100",
        created_at=1_700_000_001.0,
    )
    envelope = _envelope()

    identity = identity_from_vault_persona(envelope, persona, **_binding())
    serialized = json.dumps(identity.to_dict(), sort_keys=True)

    assert identity.authorization_envelope_id == envelope.envelope_id
    assert identity.authorization_envelope_ref.endswith(envelope.attestation_signature)
    assert identity.persona_id == persona.persona_id
    assert identity.target_actor_id == "actor-9"
    assert identity.tenant_id == "tenant-2"
    assert identity.credential_freshness is CredentialFreshness.FRESH
    assert "vault-password-secret" not in serialized
    assert "alice-secret@example.test" not in serialized
    assert "+15555550100" not in serialized


def test_wraith_adapter_uses_explicit_identity_and_omits_auth_material() -> None:
    persona = Persona(
        name="Shared display",
        persona_type=PersonaType.USER,
        bearer_token="bearer-token-secret",
        extra_headers={"X-API-Key": "api-key-secret"},
    )

    identity = identity_from_wraith_persona(
        _envelope(),
        persona,
        persona_id="wraith-persona-44",
        **_binding(),
    )
    serialized = json.dumps(identity.to_dict(), sort_keys=True)

    assert identity.persona_id == "wraith-persona-44"
    assert identity.credential_source_ref.startswith("wraith_auth:")
    assert "bearer-token-secret" not in serialized
    assert "api-key-secret" not in serialized
    assert "Authorization" not in serialized


def test_identity_adapter_rejects_a_tampered_envelope() -> None:
    envelope = _envelope()
    envelope.target_handle = "tampered"
    persona = ResearchPersona(
        persona_id="vault-persona-1",
        label="Alice",
        email="alice@example.test",
    )

    with pytest.raises(ValueError, match="valid signed authorization envelope"):
        identity_from_vault_persona(envelope, persona, **_binding())
