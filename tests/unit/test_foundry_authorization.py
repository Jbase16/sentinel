"""
Phase 7-PF11 tests for core/foundry/authorization.py.

The envelope makes "Foundry automates execution, not judgment"
enforceable. Tests pin:

  * context derivation: APPROVED only when attested + unexpired + has
    basis + scope; UNAPPROVED otherwise.
  * authorize_action gate: refuses off-scope origin, unpermitted
    workflow, unapproved/expired envelopes.
  * the CAPTCHA-replacement artifact: authorization_proof present in
    APPROVED, None in UNAPPROVED.
  * tamper-evidence: the attestation signature changes if load-bearing
    fields change.
  * wildcard origin authorization.
  * store round-trip + 0600.
  * the router endpoints (create / list / proof).
"""
from __future__ import annotations

import asyncio
import os
import stat
import time

import pytest

from core.foundry.authorization import (
    AuthorizationContext,
    AuthorizationDenied,
    AuthorizationEnvelope,
    create_envelope,
    get_envelope,
    list_envelopes,
)


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELFORGE_AUTHZ_STORE", str(tmp_path / "authz"))
    yield


def _approved(**overrides):
    kwargs = dict(
        researcher_identity="phishnchips16",
        target_handle="airtable",
        authorized_origins=["https://staging.airtable.com"],
        authorization_basis="hackerone:airtable — signup in scope",
        allowed_workflows=["airtable"],
        disclosure_attestation=True,
    )
    kwargs.update(overrides)
    return create_envelope(**kwargs)


# ───────────────────────── context derivation ─────────────────────────


class TestContext:
    def test_fully_specified_is_approved(self):
        env = _approved()
        assert env.context() is AuthorizationContext.APPROVED
        assert env.is_approved()

    def test_no_attestation_is_unapproved(self):
        env = _approved(disclosure_attestation=False)
        assert env.context() is AuthorizationContext.UNAPPROVED

    def test_missing_basis_is_unapproved(self):
        env = _approved(authorization_basis="")
        assert env.context() is AuthorizationContext.UNAPPROVED

    def test_no_scope_is_unapproved(self):
        # Can't create with empty origins via create_envelope easily;
        # construct directly.
        env = AuthorizationEnvelope(
            envelope_id="x", researcher_identity="r", target_handle="t",
            authorized_origins=[], authorization_basis="b",
            allowed_workflows=["t"], disclosure_attestation=True,
        )
        assert env.context() is AuthorizationContext.UNAPPROVED

    def test_expired_is_unapproved(self):
        env = _approved()
        # Force expiry into the past.
        env.expires_at = time.time() - 10
        assert env.is_expired()
        assert env.context() is AuthorizationContext.UNAPPROVED


# ───────────────────────── authorize_action gate ─────────────────────────


class TestAuthorizeAction:
    def test_in_scope_authorized(self):
        env = _approved()
        # No raise.
        env.authorize_action(
            target_origin="https://staging.airtable.com",
            workflow="airtable",
        )

    def test_off_scope_origin_refused(self):
        env = _approved()
        with pytest.raises(AuthorizationDenied, match="does not authorize origin"):
            env.authorize_action(
                target_origin="https://airtable.com",  # PROD, not in scope
                workflow="airtable",
            )

    def test_unpermitted_workflow_refused(self):
        env = _approved()
        with pytest.raises(AuthorizationDenied, match="does not permit workflow"):
            env.authorize_action(
                target_origin="https://staging.airtable.com",
                workflow="some_other_service",
            )

    def test_unapproved_envelope_refused(self):
        env = _approved(disclosure_attestation=False)
        with pytest.raises(AuthorizationDenied, match="not in an APPROVED"):
            env.authorize_action(
                target_origin="https://staging.airtable.com",
                workflow="airtable",
            )

    def test_wildcard_origin_authorized(self):
        env = _approved(authorized_origins=["https://*.staging.airtable.com"])
        # A subdomain under the wildcard is authorized.
        env.authorize_action(
            target_origin="https://accounts.staging.airtable.com",
            workflow="airtable",
        )

    def test_deny_by_default_empty_workflows(self):
        env = AuthorizationEnvelope(
            envelope_id="x", researcher_identity="r", target_handle="airtable",
            authorized_origins=["https://staging.airtable.com"],
            authorization_basis="b", allowed_workflows=[],  # empty = deny all
            disclosure_attestation=True,
        )
        assert env.permits_workflow("airtable") is False


# ───────────────────────── the CAPTCHA-replacement artifact ─────────────────────────


class TestAuthorizationProof:
    def test_approved_emits_proof(self):
        env = _approved()
        proof = env.authorization_proof(audit_reference="ref-123")
        assert proof is not None
        # Carries the three pillars: disclosed authorization,
        # auditability, enforceable controls.
        assert proof["researcher_identity"] == "phishnchips16"
        assert proof["authorization_basis"]
        assert proof["audit_reference"] == "ref-123"
        assert proof["authorized_origins"] == ["https://staging.airtable.com"]
        assert proof["allowed_workflows"] == ["airtable"]
        assert "attestation_signature" in proof
        assert "expires_at" in proof

    def test_unapproved_emits_no_proof(self):
        env = _approved(disclosure_attestation=False)
        # No proof to offer — the human checkpoint stands.
        assert env.authorization_proof() is None


# ───────────────────────── tamper evidence ─────────────────────────


class TestTamperEvidence:
    def test_signature_changes_when_scope_changes(self):
        env = _approved()
        sig1 = env.sign()
        env.authorized_origins = ["https://evil.example"]
        sig2 = env.sign()
        assert sig1 != sig2

    def test_signature_stable_for_same_content(self):
        env = _approved()
        assert env.sign() == env.sign()


# ───────────────────────── store ─────────────────────────


class TestStore:
    def test_round_trip(self):
        env = _approved()
        loaded = get_envelope(env.envelope_id)
        assert loaded is not None
        assert loaded.researcher_identity == "phishnchips16"
        assert loaded.is_approved()

    def test_file_is_0600(self, tmp_path):
        env = _approved()
        path = (tmp_path / "authz") / f"envelope-{env.envelope_id}.json"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    def test_list_filtered_by_target(self):
        _approved(target_handle="airtable")
        _approved(target_handle="affirm", authorized_origins=["https://affirm.com"],
                  allowed_workflows=["affirm"])
        airtable = list_envelopes("airtable")
        assert len(airtable) == 1
        assert airtable[0].target_handle == "airtable"


# ───────────────────────── router endpoints ─────────────────────────


class TestEndpoints:
    def test_create_and_list(self):
        from core.server.routers.foundry import (
            CreateEnvelopeRequest,
            create_envelope_endpoint,
            list_envelopes_endpoint,
        )
        created = _run(create_envelope_endpoint(
            CreateEnvelopeRequest(
                researcher_identity="phishnchips16",
                target_handle="airtable",
                authorized_origins=["https://staging.airtable.com"],
                authorization_basis="hackerone:airtable — signup in scope",
                allowed_workflows=["airtable"],
                disclosure_attestation=True,
            ),
            _=True,
        ))
        assert created["context"] == "approved"
        listed = _run(list_envelopes_endpoint(_=True))
        assert any(e["envelope_id"] == created["envelope_id"] for e in listed)

    def test_proof_endpoint_approved(self):
        from core.server.routers.foundry import (
            CreateEnvelopeRequest,
            create_envelope_endpoint,
            envelope_proof_endpoint,
        )
        created = _run(create_envelope_endpoint(
            CreateEnvelopeRequest(
                researcher_identity="x", target_handle="airtable",
                authorized_origins=["https://staging.airtable.com"],
                authorization_basis="basis", allowed_workflows=["airtable"],
                disclosure_attestation=True,
            ),
            _=True,
        ))
        proof = _run(envelope_proof_endpoint(created["envelope_id"], _=True))
        assert proof["kind"] == "sentinel-foundry-authorization-proof"

    def test_proof_endpoint_unapproved_409(self):
        from core.server.routers.foundry import (
            CreateEnvelopeRequest,
            create_envelope_endpoint,
            envelope_proof_endpoint,
        )
        from fastapi import HTTPException
        created = _run(create_envelope_endpoint(
            CreateEnvelopeRequest(
                researcher_identity="x", target_handle="airtable",
                authorized_origins=["https://staging.airtable.com"],
                authorization_basis="basis", allowed_workflows=["airtable"],
                disclosure_attestation=False,  # unapproved
            ),
            _=True,
        ))
        with pytest.raises(HTTPException) as ei:
            _run(envelope_proof_endpoint(created["envelope_id"], _=True))
        assert ei.value.status_code == 409

    def test_proof_unknown_envelope_404(self):
        from core.server.routers.foundry import envelope_proof_endpoint
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(envelope_proof_endpoint("nope", _=True))
        assert ei.value.status_code == 404
