from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.compiler import operation_atoms_from_records
from core.behavior.normalize import stable_hash
from core.epistemic.ledger import (
    Citation,
    ConfirmationLevel,
    EvidenceLedger,
    LifecycleState,
    ObservationEnvelope,
)
from core.identity import AssessmentIdentityContext, CredentialFreshness


ORIGIN = "https://api.example.test"
SESSION_ID = "session-restart-proof"


def _identity() -> AssessmentIdentityContext:
    return AssessmentIdentityContext(
        session_id=SESSION_ID,
        authorization_envelope_id="envelope-one",
        authorization_envelope_ref=f"authorization_envelope:{'a' * 64}",
        target_origin=ORIGIN,
        target_reset_epoch=7,
        world_id="alice",
        persona_id="persona-alice",
        target_actor_id="actor-alice",
        tenant_id="tenant-red",
        credential_source_ref="credential:alice",
        credential_epoch=3,
        credential_freshness=CredentialFreshness.FRESH,
        resource_id="resource:users",
        representation_id="representation:http-json-v1",
    )


def test_restart_restores_canonical_evidence_without_global_scan(
    tmp_path: Path,
) -> None:
    families, instances = operation_atoms_from_records(
        (
            {
                "id": "alice-read",
                "persona_id": "alice",
                "method": "GET",
                "url": f"{ORIGIN}/api/users/7",
                "response_status": 200,
                "response_body": '{"userId":"user_alice_12345678"}',
            },
        )
    )
    instance = next(
        item for item in instances if item.world_ref == stable_hash("world", "alice")
    )
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path))

    with (
        patch("core.base.sequence.GlobalSequenceAuthority") as sequence,
        patch("core.data.findings_store.findings_store"),
    ):
        sequence.instance.return_value.run_id = "run-before-restart"
        ledger = EvidenceLedger(config)
        observation = ledger.record_canonical_observation(
            tool_name="mock-http",
            tool_args=["GET", "/api/users/7"],
            target=f"{ORIGIN}/api/users/7",
            raw_output=b'{"userId":"user_alice_12345678"}',
            identity=_identity(),
            operation_family=families[0],
            operation_instance=instance,
            timestamp_override=1_700_001_001.0,
        )
        finding = ledger.promote_canonical_finding(
            title="Cross-tenant user disclosure",
            severity="high",
            citations=[Citation(observation_id=observation.id, snippet="userId")],
            description="The owned-lab response disclosed the other test actor.",
            confirmation_level=ConfirmationLevel.CONFIRMED.value,
            timestamp_override=1_700_001_002.0,
        )
        ledger.invalidate_finding(
            finding.id,
            "reset epoch changed",
            timestamp_override=1_700_001_003.0,
        )
        original_event_ids = tuple(item.id for item in ledger._event_log)

        sequence.instance.return_value.run_id = "run-after-restart"
        restored = EvidenceLedger(config)

    restored_observation = restored.get_observation(observation.id)
    restored_finding = restored.get_finding(finding.id)
    assert isinstance(restored_observation, ObservationEnvelope)
    assert restored_observation.commitment == observation.commitment
    assert restored.get_blob(observation.id) == b'{"userId":"user_alice_12345678"}'
    assert restored_finding is not None
    assert restored_finding.commitment == finding.commitment
    assert restored.get_state(finding.id).state is LifecycleState.INVALIDATED
    assert tuple(item.id for item in restored._event_log) == original_event_ids
    assert {item.payload["session_id"] for item in restored._event_log} == {SESSION_ID}

    with sqlite3.connect(config.storage.db_path) as connection:
        sessions = connection.execute(
            """
            SELECT session_id FROM epistemic_entities
            UNION ALL
            SELECT session_id FROM epistemic_events
            """
        ).fetchall()
        event_payloads = connection.execute(
            "SELECT data FROM epistemic_events"
        ).fetchall()
    assert sessions and {item[0] for item in sessions} == {SESSION_ID}
    assert all("global_scan" not in item[0] for item in event_payloads)
