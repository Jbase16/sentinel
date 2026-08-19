"""Verify Console exchanges adapted into the canonical EvidenceLedger."""

from __future__ import annotations

from core.epistemic.ledger import EvidenceLedger, ObservationEnvelope
from core.ghost.flow import FlowStep
from core.identity import (
    AssessmentIdentityContext,
    CredentialFreshness,
    IdentityAuthorityBinding,
    PrincipalIdentityBinding,
    PrincipalIdentityResolver,
)
from core.identity.credential_material import credential_headers
from core.identity.http_observation import (
    http_representation_ref,
    http_resource_ref,
    record_http_observation,
)
from core.verify.console import VerificationSession
from core.verify.identity_adapter import identity_from_verification_session


class VerifyCanonicalEvidenceAdapter:
    """Admit only fully attributed Verify exchanges as canonical evidence."""

    def __init__(self, ledger: EvidenceLedger):
        self.ledger = ledger

    def record_exchange(
        self,
        session: VerificationSession,
        step: FlowStep,
        *,
        authority: IdentityAuthorityBinding,
        binding: PrincipalIdentityBinding,
    ) -> ObservationEnvelope:
        if binding.credential_freshness is not CredentialFreshness.FRESH:
            raise ValueError("Verify canonical attribution requires a fresh credential")

        auth_headers = credential_headers(step.headers)
        identity, lease = identity_from_verification_session(
            authority,
            session,
            resource_id=http_resource_ref(step.url),
            representation_id=http_representation_ref(
                step.method,
                step.request_content_type,
            ),
            credential_headers=auth_headers,
            credential_cookies={},
            **binding.identity_kwargs(),
        )
        # Consume the lease at the exact identity being recorded. This catches
        # accidental actor/tenant/session substitution before ledger admission.
        lease.consume(identity)
        resolver = session.identity_resolver
        if resolver is None:
            resolver = PrincipalIdentityResolver(identity.session_id)
            session.identity_resolver = resolver
        resolution = resolver.attribute(identity)
        observation = record_http_observation(
            self.ledger,
            source="verify_console",
            identity=identity,
            method=step.method,
            url=step.url,
            response_status=step.response_status,
            raw_evidence={
                "response_status": step.response_status,
                "response_body": step.response_body,
                "response_body_truncated": step.response_body_truncated,
                "response_content_type": step.response_content_type,
                "elapsed_ms": step.response_elapsed_ms,
                "principal_ref": resolution.principal_ref,
            },
        )
        session.canonical_observation_ids.append(observation.id)
        session.canonical_principal_refs[
            observation.id
        ] = resolution.principal_ref
        return observation


__all__ = ["VerifyCanonicalEvidenceAdapter"]
