from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from core.base.config import SentinelConfig, StorageConfig
from core.epistemic.ledger import EvidenceLedger, ObservationEnvelope
from core.foundry.authorization import AuthorizationEnvelope
from core.ghost.canonical_evidence import GhostCanonicalEvidenceAdapter
from core.ghost.flow import FlowStep, UserFlow


ORIGIN = "https://ghost.example.test"


def _envelope() -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="ghost-canonical-envelope",
        researcher_identity="researcher",
        target_handle="ghost-lab",
        authorized_origins=[ORIGIN],
        authorization_basis="owned local fixture",
        disclosure_attestation=True,
        created_at=1_700_000_000.0,
        expires_at=4_000_000_000.0,
    )
    envelope.sign()
    return envelope


def test_ghost_flow_reaches_canonical_ledger_and_planner_without_promotion(
    tmp_path: Path,
) -> None:
    flow = UserFlow("Same display label", flow_id="ghost-flow-1")
    step = FlowStep(
        "GET",
        f"{ORIGIN}/api/documents/12345?include=owner",
        headers={
            "Authorization": "Bearer ghost-secret",
            "Accept": "application/json",
        },
    )
    step.id = "ghost-step-1"
    step.timestamp = 1_700_000_010.0
    step.persona_at_capture = "Same display label"
    step.set_response(
        status=200,
        headers={"Content-Type": "application/json", "Server": "fixture"},
        body='{"documentId":"doc-secret-12345","privateNote":"classified"}',
        content_type="application/json",
        cookies_after_step={"session": "ghost-cookie-secret"},
    )
    flow.add_step(step)

    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path))
    with patch("core.base.sequence.GlobalSequenceAuthority") as sequence:
        sequence.instance.return_value.run_id = "run-wo12"
        ledger = EvidenceLedger(config)
        adapter = GhostCanonicalEvidenceAdapter(ledger)
        result = adapter.record_flow(
            flow,
            session_id="ghost-session-1",
            envelope=_envelope(),
        )

    read_model = ledger.session_read_model("ghost-session-1")
    assert len(result.observation_ids) == len(read_model.observations) == 1
    assert read_model.findings == ()
    assert not hasattr(adapter, "promote_finding")

    observation = read_model.observations[0]
    assert isinstance(observation, ObservationEnvelope)
    assert observation.identity.session_id == "ghost-session-1"
    assert observation.identity.authorization_envelope_id == "ghost-canonical-envelope"
    assert observation.identity.world_id == "ghost-flow-1"
    assert observation.identity.display_name == "Same display label"
    assert observation.identity.credential_source_ref.startswith("ghost_capture:")
    assert observation.operation_instance.source_ref in (
        observation.operation_family.source_refs
    )
    assert observation.operation_instance.response_status == 200

    assert len(result.planner_operations) == 1
    planned = result.planner_operations[0]
    assert planned.operation_id == observation.operation_family.action_id
    assert planned.observed_success is True
    assert planned.source_refs == (observation.operation_instance.source_ref,)

    serialized = json.dumps(observation.to_dict(), sort_keys=True)
    stored = ledger.cas.load(observation.blob_hash)
    assert stored is not None
    assert b"ghost-secret" not in stored
    assert b"ghost-cookie-secret" not in stored
    assert b"classified" not in stored
    assert "ghost-secret" not in serialized
    assert "ghost-cookie-secret" not in serialized

    proxy_source = Path("core/ghost/proxy.py").read_text()
    lazarus_source = Path("core/ghost/lazarus.py").read_text()
    router_source = Path("core/server/routers/ghost.py").read_text()
    assert "add_finding" not in proxy_source
    assert "reasoning_session.evidence" not in proxy_source
    assert "GraphEventType.FINDING_CREATED" not in lazarus_source
    assert "GhostCanonicalEvidenceAdapter(ledger).record_flow" in router_source
