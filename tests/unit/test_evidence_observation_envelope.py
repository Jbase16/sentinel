from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.compiler import OperationOutcome, operation_atoms_from_records
from core.behavior.normalize import stable_hash
from core.epistemic.events import EventType
from core.epistemic.ledger import EvidenceLedger, ObservationEnvelope
from core.identity import AssessmentIdentityContext, CredentialFreshness


ORIGIN = "https://api.example.test"


def _identity(world_id: str, actor_id: str) -> AssessmentIdentityContext:
    return AssessmentIdentityContext(
        session_id="session-one",
        authorization_envelope_id="envelope-one",
        authorization_envelope_ref=f"authorization_envelope:{'a' * 64}",
        target_origin=ORIGIN,
        target_reset_epoch=1,
        world_id=world_id,
        persona_id=f"persona-{world_id}",
        target_actor_id=actor_id,
        tenant_id="tenant-red",
        credential_source_ref=f"credential:{world_id}",
        credential_epoch=1,
        credential_freshness=CredentialFreshness.FRESH,
        resource_id="resource:users",
        representation_id="representation:http-json-v1",
        display_name="Same display",
    )


def test_same_action_in_two_worlds_is_two_instances_of_one_family(tmp_path: Path) -> None:
    records = (
        {
            "id": "alice-create",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/users",
            "request_body": "{}",
            "response_status": 201,
            "response_body": '{"userId":"user_alice_12345678"}',
        },
        {
            "id": "bob-create",
            "persona_id": "bob",
            "method": "POST",
            "url": f"{ORIGIN}/api/users",
            "request_body": "{}",
            "response_status": 403,
            "response_body": '{"errorId":"error_bob_12345678"}',
        },
    )
    families, instances = operation_atoms_from_records(records)
    assert len(families) == 1
    assert {item.outcome for item in instances} == {
        OperationOutcome.SUCCESS,
        OperationOutcome.CLIENT_ERROR,
    }

    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path))
    with patch("core.base.sequence.GlobalSequenceAuthority") as sequence:
        sequence.instance.return_value.run_id = "run-wo05"
        ledger = EvidenceLedger(config)
        by_world = {item.world_ref: item for item in instances}
        alice = ledger.record_canonical_observation(
            tool_name="mock-http",
            tool_args=["POST", "/api/users"],
            target=f"{ORIGIN}/api/users",
            raw_output=b"201 created",
            identity=_identity("alice", "actor-alice"),
            operation_family=families[0],
            operation_instance=by_world[stable_hash("world", "alice")],
            timestamp_override=1_700_000_001.0,
        )
        bob = ledger.record_canonical_observation(
            tool_name="mock-http",
            tool_args=["POST", "/api/users"],
            target=f"{ORIGIN}/api/users",
            raw_output=b"403 denied",
            identity=_identity("bob", "actor-bob"),
            operation_family=families[0],
            operation_instance=by_world[stable_hash("world", "bob")],
            timestamp_override=1_700_000_002.0,
        )
        alice_again = ledger.record_canonical_observation(
            tool_name="mock-http",
            tool_args=["POST", "/api/users"],
            target=f"{ORIGIN}/api/users",
            raw_output=b"201 created",
            identity=_identity("alice", "actor-alice"),
            operation_family=families[0],
            operation_instance=by_world[stable_hash("world", "alice")],
            timestamp_override=1_700_000_099.0,
        )

    related = ledger.observations_for_family(families[0].family_id)
    assert isinstance(alice, ObservationEnvelope)
    assert isinstance(bob, ObservationEnvelope)
    assert alice.id != bob.id
    assert alice_again is alice
    assert alice.identity.digest != bob.identity.digest
    assert alice.operation_instance.instance_id != bob.operation_instance.instance_id
    assert len(related) == 2
    assert {item.operation_family.family_id for item in related} == {
        families[0].family_id
    }
    assert all(event.event_type is EventType.OBSERVED for event in ledger._event_log)
    assert {event.payload["session_id"] for event in ledger._event_log} == {
        "session-one"
    }
