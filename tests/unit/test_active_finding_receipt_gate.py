from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.compiler import operation_atoms_from_records
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    BehavioralReceiptStore,
    redacted_receipt_context,
    request_fingerprint,
)
from core.epistemic.ledger import (
    ActiveProofCitation,
    Citation,
    ConfirmationLevel,
    EvidenceLedger,
    LifecycleState,
)
from core.identity import AssessmentIdentityContext, CredentialFreshness


ORIGIN = "https://owned.example.test"
SESSION_ID = "session-wo08"
PROVENANCE_ROOT = "c" * 64


def _identity() -> AssessmentIdentityContext:
    return AssessmentIdentityContext(
        session_id=SESSION_ID,
        authorization_envelope_id="envelope-wo08",
        authorization_envelope_ref=f"authorization_envelope:{'a' * 64}",
        target_origin=ORIGIN,
        target_reset_epoch=1,
        world_id="alice",
        persona_id="persona-alice",
        target_actor_id="actor-alice",
        tenant_id="tenant-owned",
        credential_source_ref="credential:alice",
        credential_epoch=1,
        credential_freshness=CredentialFreshness.FRESH,
        resource_id="resource:owned-note",
        representation_id="representation:http-json-v1",
    )


def _completed_response() -> dict:
    empty_resolution = {
        "resolved_operations": 0,
        "unresolved_operations": 0,
        "ambiguous_operations": 0,
    }
    return {
        "status": "completed",
        "plan": {
            "selected_proposal_id": f"authorization_proposal:{'b' * 64}",
        },
        "execution": {
            "status": "completed",
            "legacy_verdict": "BOLA_CONFIRMED",
            "finding_confirmed": True,
            "requests_attempted": 1,
            "requests_sent": 1,
            "policy_denials": 0,
            "provenance_root": PROVENANCE_ROOT,
        },
        "finding_confirmed": True,
        "finding": {"redacted": True},
        "graphql_resolution": {
            "catalog": {
                "artifacts": 0,
                "artifact_bytes": 0,
                "documents": 0,
                "operation_names": 0,
                "dropped": {
                    "artifacts": 0,
                    "artifact_bytes": 0,
                    "documents": 0,
                },
            },
            "assets": {
                "attempted": 0,
                "fetched": 0,
                "failed": 0,
                "documents_added": 0,
            },
            "source": empty_resolution,
            "peer": empty_resolution,
        },
    }


def test_active_promotion_requires_completed_receipt_but_passive_observation_does_not(
    tmp_path: Path,
) -> None:
    families, instances = operation_atoms_from_records(
        (
            {
                "id": "passive-owned-read",
                "persona_id": "alice",
                "method": "GET",
                "url": f"{ORIGIN}/notes/1",
                "response_status": 200,
                "response_body": '{"id":"note-owned"}',
            },
        )
    )
    instance = next(
        item for item in instances if item.world_ref == stable_hash("world", "alice")
    )
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path))
    receipt_store = BehavioralReceiptStore(tmp_path / "receipts")

    with patch("core.base.sequence.GlobalSequenceAuthority") as sequence:
        sequence.instance.return_value.run_id = "run-wo08"
        ledger = EvidenceLedger(config, receipt_store=receipt_store)
        observation = ledger.record_canonical_observation(
            tool_name="passive-mock-http",
            tool_args=["GET", "/notes/1"],
            target=f"{ORIGIN}/notes/1",
            raw_output=b'{"id":"note-owned"}',
            identity=_identity(),
            operation_family=families[0],
            operation_instance=instance,
        )

        assert ledger.get_state(observation.id).state is LifecycleState.OBSERVED
        assert ledger._findings == {}

        with pytest.raises(
            ValueError,
            match="requires a completed behavioral receipt and safety provenance",
        ):
            ledger.promote_canonical_finding(
                title="Owned note crossed the persona boundary",
                severity="high",
                citations=[Citation(observation_id=observation.id)],
                description="Active claim without a receipt must fail closed.",
                confirmation_level=ConfirmationLevel.CONFIRMED.value,
            )

        fingerprint = request_fingerprint(
            {"session_id": SESSION_ID, "observation_id": observation.id}
        )
        reservation = receipt_store.reserve(
            fingerprint,
            context=redacted_receipt_context(
                target_origin=ORIGIN,
                envelope_id=_identity().authorization_envelope_id,
                source_persona_id=_identity().persona_id,
                peer_persona_id="persona-peer",
            ),
        )
        proof = ActiveProofCitation(
            observation_id=observation.id,
            receipt_id=reservation.receipt.receipt_id,
            provenance_root=PROVENANCE_ROOT,
        )
        with pytest.raises(ValueError, match="receipt is not completed"):
            ledger.promote_canonical_finding(
                title="Owned note crossed the persona boundary",
                severity="high",
                citations=[Citation(observation_id=observation.id)],
                description="A reserved receipt is not proof.",
                confirmation_level=ConfirmationLevel.CONFIRMED.value,
                active_proof=[proof],
            )

        receipt_store.complete(
            fingerprint,
            reservation_token=reservation.reservation_token or "",
            outcome=_completed_response(),
        )
        finding = ledger.promote_canonical_finding(
            title="Owned note crossed the persona boundary",
            severity="high",
            citations=[Citation(observation_id=observation.id)],
            description="The completed R0 receipt binds the active claim.",
            confirmation_level=ConfirmationLevel.CONFIRMED.value,
            active_proof=[proof],
        )

    assert finding.active_proof == [proof]
    assert ledger.get_state(finding.id).state is LifecycleState.PROMOTED

