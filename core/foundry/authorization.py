"""
core/foundry/authorization.py — Phase 7-PF11: the Authorization Envelope.

The artifact that makes "Foundry automates execution, not judgment"
ENFORCEABLE rather than merely claimed.

The principle, stated precisely:

  The researcher makes the meaningful decisions UP FRONT — identity,
  target, scope, rate limits, legal posture, allowed workflows. The
  agent performs the mechanical work strictly WITHIN that policy
  envelope. Judgment is a precondition, checked in code, before any
  execution.

So this module gives that envelope a first-class representation, and
the signup orchestrator + replay engine REQUIRE one: an action against
a target the envelope doesn't authorize, or a workflow it doesn't
permit, is refused before any network I/O. The envelope isn't a
document that describes intent — it's a gate execution passes through.

────────────────────────────────────────────────────────────────────
The CAPTCHA stance, encoded
────────────────────────────────────────────────────────────────────

The Foundry does NOT argue that agents should be admitted because they
can beat human-verification puzzles. It never solves a CAPTCHA. The
argument it makes is different: advanced agents make those puzzles
OBSOLETE in approved contexts, because the envelope produces something
strictly stronger than a puzzle —

    disclosed authorization + auditability + enforceable controls.

  * APPROVED context (a valid, attested, in-scope envelope): the
    envelope emits an `authorization_proof` — a signed, time-bounded,
    scoped, audit-linked attestation. That proof is the artifact that
    SHOULD replace CAPTCHA for an authorized researcher-agent. Until a
    program accepts it, the system still routes the anti-bot wall to
    the human — but the handoff is annotated with the authorization
    basis, so the audit trail shows the action occurred under
    disclosed authorization, not as an anonymous bot.

  * UNAPPROVED context (no valid envelope): CAPTCHA remains a hard
    human checkpoint, and the risky workflows (account creation) are
    refused entirely. No envelope, no automated signup. The puzzle
    keeps doing its job against unauthorized automation — exactly as
    intended.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


_ENV_STORE_ENV = "SENTINELFORGE_AUTHZ_STORE"
_DEFAULT_ENV_STORE = Path.home() / ".sentinelforge" / "authorizations"


def _store_dir() -> Path:
    override = os.environ.get(_ENV_STORE_ENV)
    if override:
        return Path(override)
    return _DEFAULT_ENV_STORE


class AuthorizationContext(str, Enum):
    """Whether an action is operating under disclosed authorization."""
    APPROVED = "approved"        # valid, attested, in-scope envelope
    UNAPPROVED = "unapproved"    # no valid envelope


def _origin_of(url_or_origin: str) -> Optional[str]:
    s = (url_or_origin or "").strip()
    if not s:
        return None
    parsed = urlparse(s if "://" in s else "https://" + s)
    if not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


@dataclass
class AuthorizationEnvelope:
    """The researcher's up-front judgment, made enforceable.

    Every field is a decision the human made BEFORE any execution. The
    agent reads this and operates within it; it never decides any of
    these itself.
    """
    envelope_id: str
    # WHO is accountable — the platform handle the researcher operates
    # under (e.g. the HackerOne handle). The audit trail ties every
    # action to this identity.
    researcher_identity: str
    # WHAT program/target this authorizes.
    target_handle: str
    # The origins this envelope authorizes execution against. Matches
    # the program's in-scope assets. An action off these origins is
    # refused — same structural-scope discipline as Phase 5 VC2.
    authorized_origins: List[str] = field(default_factory=list)
    # The disclosed authorization basis — a human-readable reference to
    # WHY this is authorized (e.g. "hackerone:airtable public bug bounty;
    # account signup explicitly in scope per program policy"). This is
    # the "disclosed authorization" half of the CAPTCHA-replacement
    # argument.
    authorization_basis: str = ""
    # The researcher attests they are operating under disclosed,
    # legitimate authorization. Without this attestation the envelope is
    # NOT approved.
    disclosure_attestation: bool = False
    # Which workflows the envelope permits: recipe service handles and/or
    # vuln-class ids the researcher pre-approved. Empty = none permitted
    # (deny by default).
    allowed_workflows: List[str] = field(default_factory=list)
    # The constraints — these bound the mechanical work.
    max_accounts_per_service: int = 3
    rate_limit_window_days: int = 30
    # Legal posture notes (safe-harbor reference, program policy URL).
    legal_posture: str = ""
    # Envelopes EXPIRE — authorization is not forever. Default 30 days.
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(
        default_factory=lambda: time.time() + 30 * 24 * 3600
    )
    # The attestation signature — a hash binding identity + basis +
    # scope + time, so the proof is tamper-evident.
    attestation_signature: str = ""

    # ── derivation ──

    def sign(self) -> str:
        """Compute (and store) the attestation signature: a hash over
        the load-bearing fields. Recomputing it lets a verifier detect
        tampering. (Not a cryptographic signature — a tamper-evidence
        digest; a real deployment would HMAC with an operator key.)"""
        material = json.dumps({
            "researcher_identity": self.researcher_identity,
            "target_handle": self.target_handle,
            "authorized_origins": sorted(self.authorized_origins),
            "authorization_basis": self.authorization_basis,
            "disclosure_attestation": self.disclosure_attestation,
            "allowed_workflows": sorted(self.allowed_workflows),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }, sort_keys=True)
        self.attestation_signature = hashlib.sha256(material.encode()).hexdigest()
        return self.attestation_signature

    def is_expired(self, *, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return now >= self.expires_at

    def context(self, *, now: Optional[float] = None) -> AuthorizationContext:
        """APPROVED iff attested, unexpired, and has a basis + scope.
        Otherwise UNAPPROVED."""
        if (
            self.disclosure_attestation
            and not self.is_expired(now=now)
            and self.authorization_basis.strip()
            and self.authorized_origins
        ):
            return AuthorizationContext.APPROVED
        return AuthorizationContext.UNAPPROVED

    def is_approved(self, *, now: Optional[float] = None) -> bool:
        return self.context(now=now) is AuthorizationContext.APPROVED

    # ── enforcement ──

    def authorizes_origin(self, url_or_origin: str) -> bool:
        origin = _origin_of(url_or_origin)
        if origin is None:
            return False
        for allowed in self.authorized_origins:
            a = _origin_of(allowed)
            if a is None:
                continue
            if origin == a:
                return True
            # Wildcard subdomain support: an authorized origin of
            # "https://*.staging.example" matches "https://x.staging.example".
            if "*." in allowed:
                suffix = allowed.split("*.", 1)[1]
                host = origin.split("://", 1)[-1]
                if host.endswith(suffix.split("://")[-1]):
                    return True
        return False

    def permits_workflow(self, workflow: str) -> bool:
        """Deny by default — a workflow must be explicitly in
        allowed_workflows."""
        return workflow in self.allowed_workflows

    def authorize_action(
        self,
        *,
        target_origin: str,
        workflow: str,
        now: Optional[float] = None,
    ) -> None:
        """Raise AuthorizationDenied unless this envelope authorizes the
        action. The single gate the orchestrator calls before execution.
        """
        if self.context(now=now) is not AuthorizationContext.APPROVED:
            raise AuthorizationDenied(
                f"envelope {self.envelope_id} is not in an APPROVED context "
                f"(attested={self.disclosure_attestation}, "
                f"expired={self.is_expired(now=now)}). Execution refused — "
                f"the researcher's up-front authorization is a precondition."
            )
        if not self.authorizes_origin(target_origin):
            raise AuthorizationDenied(
                f"envelope {self.envelope_id} does not authorize origin "
                f"{target_origin!r} (authorized: {self.authorized_origins}). "
                f"Refusing — the agent operates only within the policy "
                f"envelope's scope."
            )
        if not self.permits_workflow(workflow):
            raise AuthorizationDenied(
                f"envelope {self.envelope_id} does not permit workflow "
                f"{workflow!r} (allowed: {self.allowed_workflows}). "
                f"Refusing — deny by default."
            )

    # ── the CAPTCHA-replacement artifact ──

    def authorization_proof(self, *, audit_reference: str = "") -> Optional[Dict[str, Any]]:
        """In an APPROVED context, emit the structured authorization
        proof — the artifact that SHOULD replace CAPTCHA for an
        authorized researcher-agent: disclosed authorization +
        auditability + enforceable controls, signed + time-bounded +
        scoped.

        Returns None in an UNAPPROVED context (no proof to offer — the
        human checkpoint stands).
        """
        if not self.is_approved():
            return None
        if not self.attestation_signature:
            self.sign()
        return {
            "kind": "sentinel-foundry-authorization-proof",
            "version": "1",
            # disclosed authorization
            "researcher_identity": self.researcher_identity,
            "target_handle": self.target_handle,
            "authorization_basis": self.authorization_basis,
            "legal_posture": self.legal_posture,
            # enforceable controls
            "authorized_origins": list(self.authorized_origins),
            "allowed_workflows": list(self.allowed_workflows),
            "max_accounts_per_service": self.max_accounts_per_service,
            "expires_at": self.expires_at,
            # auditability
            "audit_reference": audit_reference,
            "attestation_signature": self.attestation_signature,
            "issued_at": time.time(),
        }

    # ── serialization ──

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "researcher_identity": self.researcher_identity,
            "target_handle": self.target_handle,
            "authorized_origins": list(self.authorized_origins),
            "authorization_basis": self.authorization_basis,
            "disclosure_attestation": self.disclosure_attestation,
            "allowed_workflows": list(self.allowed_workflows),
            "max_accounts_per_service": self.max_accounts_per_service,
            "rate_limit_window_days": self.rate_limit_window_days,
            "legal_posture": self.legal_posture,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "attestation_signature": self.attestation_signature,
            "context": self.context().value,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthorizationEnvelope":
        env = cls(
            envelope_id=d["envelope_id"],
            researcher_identity=d["researcher_identity"],
            target_handle=d["target_handle"],
            authorized_origins=list(d.get("authorized_origins", [])),
            authorization_basis=d.get("authorization_basis", ""),
            disclosure_attestation=bool(d.get("disclosure_attestation", False)),
            allowed_workflows=list(d.get("allowed_workflows", [])),
            max_accounts_per_service=int(d.get("max_accounts_per_service", 3)),
            rate_limit_window_days=int(d.get("rate_limit_window_days", 30)),
            legal_posture=d.get("legal_posture", ""),
            created_at=float(d.get("created_at", time.time())),
            expires_at=float(d.get("expires_at", time.time() + 30 * 24 * 3600)),
            attestation_signature=d.get("attestation_signature", ""),
        )
        return env


class AuthorizationDenied(Exception):
    """Raised when an action falls outside the policy envelope. The
    caller MUST NOT proceed."""


# ─────────────────────────── store ───────────────────────────


def save_envelope(envelope: AuthorizationEnvelope) -> Path:
    """Persist an envelope (signs it first). 0600 — it carries the
    researcher's attestation."""
    envelope.sign()
    d = _store_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"envelope-{envelope.envelope_id}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(envelope.to_dict(), indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    logger.info(
        "[authz] saved envelope %s for %s (context=%s)",
        envelope.envelope_id, envelope.target_handle, envelope.context().value,
    )
    return path


def get_envelope(envelope_id: str) -> Optional[AuthorizationEnvelope]:
    path = _store_dir() / f"envelope-{envelope_id}.json"
    if not path.exists():
        return None
    try:
        return AuthorizationEnvelope.from_dict(json.loads(path.read_text()))
    except Exception as e:
        logger.error("[authz] failed to load envelope %s: %s", envelope_id, e)
        return None


def list_envelopes(target_handle: Optional[str] = None) -> List[AuthorizationEnvelope]:
    d = _store_dir()
    if not d.exists():
        return []
    out: List[AuthorizationEnvelope] = []
    for p in sorted(d.glob("envelope-*.json")):
        try:
            env = AuthorizationEnvelope.from_dict(json.loads(p.read_text()))
        except Exception:
            continue
        if target_handle and env.target_handle != target_handle:
            continue
        out.append(env)
    return out


def create_envelope(
    *,
    researcher_identity: str,
    target_handle: str,
    authorized_origins: List[str],
    authorization_basis: str,
    allowed_workflows: List[str],
    disclosure_attestation: bool = False,
    max_accounts_per_service: int = 3,
    legal_posture: str = "",
    ttl_days: int = 30,
) -> AuthorizationEnvelope:
    """Create + persist an envelope from the researcher's up-front
    decisions. The attestation MUST be set True by the researcher for
    the envelope to reach an APPROVED context."""
    env = AuthorizationEnvelope(
        envelope_id=uuid.uuid4().hex,
        researcher_identity=researcher_identity,
        target_handle=target_handle,
        authorized_origins=list(authorized_origins),
        authorization_basis=authorization_basis,
        disclosure_attestation=disclosure_attestation,
        allowed_workflows=list(allowed_workflows),
        max_accounts_per_service=max_accounts_per_service,
        legal_posture=legal_posture,
        expires_at=time.time() + ttl_days * 24 * 3600,
    )
    save_envelope(env)
    return env
