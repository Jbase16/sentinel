from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx

from core.base.config import SentinelConfig, StorageConfig
from core.base.context import ScopeContext
from core.epistemic.ledger import EvidenceLedger, ObservationEnvelope
from core.identity import IdentityAuthorityBinding
from core.server.routers.verify import (
    BindPersonaRequest,
    ExchangeRequest,
    bind_persona,
    send_exchange,
)
from core.verify.console import create_session_from_target
from core.wraith.verify_phase import run_verify_phase


ORIGIN = "https://identity.example.test"


def _run(coro):
    return asyncio.run(coro)


def _binding(*, persona: str, actor: str, tenant: str) -> dict[str, object]:
    return {
        "persona_id": persona,
        "target_reset_epoch": 7,
        "world_id": "world-owned-lab",
        "target_actor_id": actor,
        "tenant_id": tenant,
        "credential_epoch": 4,
        "credential_freshness": "fresh",
    }


def _ledger(tmp_path: Path) -> EvidenceLedger:
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path))
    return EvidenceLedger(config)


def test_verify_exchange_reaches_canonical_ledger_with_full_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ledger = _ledger(tmp_path / "verify")
    session = create_session_from_target(f"{ORIGIN}/documents/7")
    session.canonical_session_id = "canonical-verify-session"
    session.identity_authority = IdentityAuthorityBinding(
        authorization_envelope_id="envelope-verify",
        authorization_envelope_ref=f"authorization_envelope:{'a' * 64}",
        target_origin=ORIGIN,
    )
    session.canonical_evidence_ledger = ledger

    _run(
        bind_persona(
            session.session_id,
            BindPersonaRequest(
                persona_name="Shared display",
                headers={"Authorization": "Bearer verify-secret"},
                identity_binding=_binding(
                    persona="persona-verify",
                    actor="actor-verify",
                    tenant="tenant-red",
                ),
            ),
            _=True,
        )
    )

    original_client = httpx.AsyncClient

    class MockedAsyncClient(original_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=b'{"owner":"verify"}',
                    request=request,
                )
            )
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", MockedAsyncClient)
    response = _run(
        send_exchange(
            session.session_id,
            ExchangeRequest(
                method="GET",
                url=f"{ORIGIN}/documents/7",
            ),
            _=True,
        )
    )

    observation = ledger.get_observation(response.canonical_observation_id)
    assert isinstance(observation, ObservationEnvelope)
    assert observation.identity.session_id == "canonical-verify-session"
    assert observation.identity.persona_id == "persona-verify"
    assert observation.identity.target_actor_id == "actor-verify"
    assert observation.identity.tenant_id == "tenant-red"
    assert observation.identity.credential_freshness.value == "fresh"
    assert "verify-secret" not in json.dumps(observation.to_dict())


def test_wraith_confirmation_reaches_canonical_ledger_with_full_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ledger = _ledger(tmp_path / "wraith")

    class Session:
        id = "canonical-wraith-session"
        knowledge: dict = {}
        scope_context = ScopeContext(
            authorization_envelope_id="scan-admission-wraith",
            authorization_envelope_ref=f"authorization_envelope:{'b' * 64}",
        )
        canonical_evidence_ledger = ledger

    async def fake_auth(_persona, **_kwargs):
        return {"Authorization": "Bearer wraith-secret"}, {}

    async def fake_verify(self, **_kwargs):
        return [(0.91, "owned marker returned", "7", "IDOR")], 1

    monkeypatch.setattr(
        "core.wraith.persona_auth.authenticate_persona",
        fake_auth,
    )
    monkeypatch.setattr(
        "core.wraith.vuln_verifier.VulnVerifier.verify_finding",
        fake_verify,
    )
    findings = _run(
        run_verify_phase(
            session=Session(),
            targets=[ORIGIN],
            personas=[
                {
                    "name": "Shared display",
                    "identity_binding": _binding(
                        persona="persona-wraith",
                        actor="actor-wraith",
                        tenant="tenant-blue",
                    ),
                }
            ],
            enable_discovery=False,
        )
    )

    canonical = [
        item for item in findings if item.get("metadata", {}).get("observation_id")
    ]
    assert canonical
    observation = ledger.get_observation(canonical[0]["metadata"]["observation_id"])
    assert isinstance(observation, ObservationEnvelope)
    assert observation.identity.session_id == "canonical-wraith-session"
    assert observation.identity.persona_id == "persona-wraith"
    assert observation.identity.target_actor_id == "actor-wraith"
    assert observation.identity.tenant_id == "tenant-blue"
    assert observation.identity.credential_freshness.value == "fresh"
    assert "wraith-secret" not in json.dumps(observation.to_dict())

    all_observations = ledger.session_read_model(
        "canonical-wraith-session"
    ).observations
    assert all(item.identity.digest for item in all_observations)
    assert all(item.identity.target_actor_id for item in all_observations)
    assert all(item.identity.tenant_id for item in all_observations)
