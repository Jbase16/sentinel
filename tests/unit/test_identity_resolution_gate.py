from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from core.base.config import SentinelConfig, StorageConfig
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
)
from core.ghost.flow import FlowStep
from core.identity import (
    CredentialFreshness,
    IdentityAuthorityBinding,
    IdentityResolutionRefused,
    PrincipalIdentityBinding,
)
from core.verify.canonical_evidence import VerifyCanonicalEvidenceAdapter
from core.verify.console import VerificationSession


ORIGIN = "https://identity.example.test"
SESSION_ID = "identity-resolution-session"
URL = f"{ORIGIN}/api/documents/7"
PROVENANCE_ROOT = "c" * 64


def _ledger(tmp_path: Path) -> EvidenceLedger:
    return EvidenceLedger(
        SentinelConfig(storage=StorageConfig(base_dir=tmp_path)),
        receipt_store=BehavioralReceiptStore(tmp_path / "receipts"),
    )


def _completed_bola_outcome() -> dict[str, object]:
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


def _complete_receipt(
    ledger: EvidenceLedger,
    observation,
    *,
    peer_persona_id: str,
) -> ActiveProofCitation:
    fingerprint = request_fingerprint(
        {"session_id": SESSION_ID, "observation_id": observation.id}
    )
    reservation = ledger._receipt_store.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=observation.identity.authorization_envelope_id,
            source_persona_id=observation.identity.persona_id,
            peer_persona_id=peer_persona_id,
        ),
    )
    ledger._receipt_store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token or "",
        outcome=_completed_bola_outcome(),
    )
    return ActiveProofCitation(
        observation_id=observation.id,
        receipt_id=reservation.receipt.receipt_id,
        provenance_root=PROVENANCE_ROOT,
    )


def _session(ledger: EvidenceLedger) -> VerificationSession:
    return VerificationSession(
        session_id="verify-workbench",
        finding_id="finding-bola",
        target_url=URL,
        target_origin=ORIGIN,
        canonical_session_id=SESSION_ID,
        allowed_origins={ORIGIN},
        persona_name="Shared display",
        identity_authority=IdentityAuthorityBinding(
            authorization_envelope_id="envelope-identity-resolution",
            authorization_envelope_ref=f"authorization_envelope:{'a' * 64}",
            target_origin=ORIGIN,
        ),
        canonical_evidence_ledger=ledger,
    )


def _binding(
    *,
    persona: str,
    actor: str,
    tenant: str,
    epoch: int,
    freshness: CredentialFreshness = CredentialFreshness.FRESH,
) -> PrincipalIdentityBinding:
    return PrincipalIdentityBinding(
        persona_id=persona,
        target_reset_epoch=3,
        world_id="world-owned-lab",
        target_actor_id=actor,
        tenant_id=tenant,
        credential_epoch=epoch,
        credential_freshness=freshness,
    )


def _step(token: str, owner: str) -> FlowStep:
    step = FlowStep(
        "GET",
        URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    step.persona_at_capture = "Shared display"
    step.set_response(
        status=200,
        headers={"content-type": "application/json"},
        body=f'{{"owner":"{owner}","document":7}}',
        content_type="application/json",
    )
    return step


def _record_owner_and_accessor(tmp_path: Path):
    ledger = _ledger(tmp_path)
    session = _session(ledger)
    adapter = VerifyCanonicalEvidenceAdapter(ledger)
    owner = adapter.record_exchange(
        session,
        _step("owner-secret", "owner-actor"),
        authority=session.identity_authority,
        binding=_binding(
            persona="persona-owner",
            actor="actor-owner",
            tenant="tenant-red",
            epoch=8,
        ),
    )
    accessor = adapter.record_exchange(
        session,
        _step("accessor-secret", "owner-actor"),
        authority=session.identity_authority,
        binding=_binding(
            persona="persona-accessor",
            actor="actor-accessor",
            tenant="tenant-blue",
            epoch=11,
        ),
    )
    return ledger, session, owner, accessor


def test_same_display_name_cannot_merge_different_principals(
    tmp_path: Path,
) -> None:
    _ledger_value, session, owner, accessor = _record_owner_and_accessor(tmp_path)
    resolver = session.identity_resolver
    owner_ref = session.canonical_principal_refs[owner.id]
    accessor_ref = session.canonical_principal_refs[accessor.id]

    assert owner.identity.display_name == accessor.identity.display_name
    assert owner.identity.target_actor_id != accessor.identity.target_actor_id
    assert owner.identity.tenant_id != accessor.identity.tenant_id
    assert owner.identity.credential_source_ref != accessor.identity.credential_source_ref
    assert owner.identity.credential_epoch != accessor.identity.credential_epoch
    assert owner_ref != accessor_ref
    assert resolver.attribute(accessor.identity).label_collision is True
    with pytest.raises(IdentityResolutionRefused, match="cannot merge"):
        resolver.merge(owner_ref, accessor.identity)


def test_cross_principal_finding_keeps_owner_and_accessor_citations(
    tmp_path: Path,
) -> None:
    ledger, session, owner, accessor = _record_owner_and_accessor(tmp_path)
    active_proof = [
        _complete_receipt(
            ledger,
            owner,
            peer_persona_id=accessor.identity.persona_id,
        ),
        _complete_receipt(
            ledger,
            accessor,
            peer_persona_id=owner.identity.persona_id,
        ),
    ]

    finding = ledger.promote_canonical_finding(
        title="BOLA owner object readable by a different actor",
        severity="high",
        citations=[
            Citation(observation_id=owner.id, snippet="owner-actor"),
            Citation(observation_id=accessor.id, snippet="owner-actor"),
        ],
        description=(
            "The owner observation and different accessor observation are both "
            "required to establish the authorization boundary failure."
        ),
        confirmation_level=ConfirmationLevel.CONFIRMED.value,
        active_proof=active_proof,
    )

    assert {item.observation_id for item in finding.citations} == {
        owner.id,
        accessor.id,
    }
    assert (
        session.canonical_principal_refs[owner.id]
        != session.canonical_principal_refs[accessor.id]
    )


def test_stale_credential_cannot_resolve_or_merge_as_live_principal(
    tmp_path: Path,
) -> None:
    _ledger_value, session, owner, _accessor = _record_owner_and_accessor(tmp_path)
    resolver = session.identity_resolver
    owner_ref = session.canonical_principal_refs[owner.id]
    stale = replace(
        owner.identity,
        credential_freshness=CredentialFreshness.STALE,
    )

    with pytest.raises(IdentityResolutionRefused, match="stale or unknown"):
        resolver.attribute(stale)
    with pytest.raises(IdentityResolutionRefused, match="stale or unknown"):
        resolver.merge(owner_ref, stale)
