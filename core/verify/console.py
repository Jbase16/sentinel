"""
core/verify/console.py — Phase 5-VC1: VerificationSession lifecycle.

A VerificationSession is the operator's per-finding workspace. It binds
together:

  * The finding being verified (its target, origin, original payload)
  * The scope: a SET of allowed URL origins. The default — and the
    constraint-inversion point — is just ONE entry: the finding's own
    origin. Out-of-scope is structurally impossible because the gate
    refuses any URL whose origin isn't in this set.
  * Optional persona auth (headers + cookies) bound by name. Tokens
    are session-only; never persisted with the finding.
  * A structured transcript of exchanges (FlowStep-shaped), populated
    by the request console in VC2 and consumed by the repro promoter
    in VC3.

Design choices worth keeping in mind:

  * In-memory session store. A VerificationSession is short-lived —
    typically minutes to an hour while the operator verifies one
    finding. If the FastAPI process restarts, the operator opens a
    new session. (Matches the Ghost router pattern.)

  * Scope is allowlist, not denylist. We don't even know what
    out-of-scope hosts exist; we only know which host(s) the operator
    is verifying. So the default "scope" is precisely those hosts and
    nothing else. Adding to the scope set is an explicit operator
    action — never automatic. This is the "anti-ban" property: the
    system cannot accidentally cross into neighbor hosts.

  * Origin-level scope (scheme + netloc), not URL-level. Anything
    under https://target.example/ is allowed; nothing under
    https://other-target.example/ is. Path-level allowlisting can
    come later if needed; origin is the right granularity for the
    bug-bounty case.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from core.ghost.flow import FlowStep

logger = logging.getLogger(__name__)


def _origin_of(url: str) -> Optional[str]:
    """Return scheme://netloc of url, or None if unparseable / no host."""
    try:
        p = urlparse(url)
    except Exception:
        return None
    if not p.scheme or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}"


@dataclass
class VerificationSession:
    """One operator-driven verification workspace, bound to a finding.

    The session's scope is an EXPLICIT allowlist of origins. Every
    exchange goes through `is_in_scope(url)` before any I/O happens;
    out-of-scope URLs raise structurally (see ScopeViolation in vc2).
    """

    session_id: str
    finding_id: Optional[str]
    target_url: str
    target_origin: str
    # Origin-level allowlist. Always contains target_origin as the
    # minimum-viable scope; operators can extend it via add_origin_to_scope().
    allowed_origins: Set[str] = field(default_factory=set)
    # Persona binding. Empty by default — operator provides via VC2.
    persona_name: Optional[str] = None
    persona_headers: Dict[str, str] = field(default_factory=dict)
    persona_cookies: Dict[str, str] = field(default_factory=dict)
    # Original confirmation context from the finding's metadata —
    # vuln_class, payload, confidence, evidence excerpt. Read-only.
    original_finding: Optional[Dict[str, Any]] = None
    # Structured exchanges, populated by VC2 endpoints. Each is a
    # FlowStep (reusing the Phase 4-G2 atom).
    transcript: List[FlowStep] = field(default_factory=list)
    # Bookkeeping.
    created_at: float = field(default_factory=time.time)
    last_activity_at: float = field(default_factory=time.time)

    # ─────────────── scope ───────────────

    def is_in_scope(self, url: str) -> bool:
        """True iff `url`'s origin is in the allowlist.

        Defaults toward 'no' on anything ambiguous (unparseable URL,
        missing scheme) — fail-closed semantics matching Phase 3."""
        origin = _origin_of(url)
        if origin is None:
            return False
        return origin in self.allowed_origins

    def add_origin_to_scope(self, url_or_origin: str) -> bool:
        """Explicitly add an origin to the session's allowlist. Returns
        True iff the input parsed to a valid origin and got added.

        This is the only way scope can grow. Operators do it
        deliberately ("I need to test this related subdomain too").
        Auto-expansion is intentionally absent — the cost of a wrong
        auto-expansion (out-of-scope request → ban) is too high."""
        origin = _origin_of(url_or_origin)
        if origin is None:
            return False
        if origin in self.allowed_origins:
            return False  # no-op; already there
        self.allowed_origins.add(origin)
        logger.info(
            f"[verify-session {self.session_id[:8]}] "
            f"scope expanded to include {origin!r}"
        )
        return True

    # ─────────────── transcript ───────────────

    def append_exchange(self, step: FlowStep) -> None:
        """Append a captured exchange to the transcript. Updates
        last_activity_at so the session-pruner (future) knows it's
        alive."""
        self.transcript.append(step)
        self.last_activity_at = time.time()

    # ─────────────── serialization ───────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "finding_id": self.finding_id,
            "target_url": self.target_url,
            "target_origin": self.target_origin,
            "allowed_origins": sorted(self.allowed_origins),
            "persona_name": self.persona_name,
            "has_persona_auth": bool(self.persona_headers or self.persona_cookies),
            "original_finding_summary": (
                _summarize_finding(self.original_finding)
                if self.original_finding else None
            ),
            "transcript_length": len(self.transcript),
            "transcript": [s.to_dict() for s in self.transcript],
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,
        }


def _summarize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Distill a full finding dict to the read-only summary the verify
    console needs. We don't expose the entire finding (avoids leaking
    internal evidence fields that aren't relevant to verification)."""
    md = finding.get("metadata") or {}
    return {
        "type": finding.get("type"),
        "severity": finding.get("severity"),
        "target": finding.get("target"),
        "tool": finding.get("tool"),
        "vuln_class": md.get("vuln_class"),
        "payload": md.get("payload"),
        "confidence": md.get("confidence"),
        "probe_label": md.get("probe_label"),
        "persona": md.get("persona"),
        "message": finding.get("message"),
        "proof_excerpt": (finding.get("proof") or "")[:500],
    }


# ─────────────────────── in-memory session store ──────────────────────


_SESSIONS: Dict[str, VerificationSession] = {}
_LOCK = threading.RLock()


def _register(session: VerificationSession) -> None:
    with _LOCK:
        _SESSIONS[session.session_id] = session


def get_session(session_id: str) -> Optional[VerificationSession]:
    with _LOCK:
        return _SESSIONS.get(session_id)


def list_sessions() -> List[VerificationSession]:
    with _LOCK:
        return list(_SESSIONS.values())


def _reset_for_tests() -> None:
    """Test-only helper to drop all sessions. Production callers should
    not touch this."""
    with _LOCK:
        _SESSIONS.clear()


# ─────────────────────── session factories ──────────────────────


def create_session_from_finding(
    finding_id: str,
    *,
    finding_store=None,
) -> VerificationSession:
    """Hydrate a VerificationSession from an existing confirmed finding.

    The finding's target becomes the target URL. The finding's origin
    is the only entry in `allowed_origins` by default — operators must
    explicitly broaden scope.

    The session's `original_finding` is set so VC2 and VC3 can show
    operators "what you're verifying" and so VC3 can pre-populate
    repro prose with the finding's payload + vuln_class.

    Raises ValueError if the finding doesn't exist or has no target.
    """
    if finding_store is None:
        from core.data.findings_store import get_finding_store
        finding_store = get_finding_store()
    finding = finding_store.get(finding_id)
    if finding is None:
        raise ValueError(f"finding {finding_id!r} not found")
    target = finding.get("target")
    if not isinstance(target, str) or not target:
        raise ValueError(
            f"finding {finding_id!r} has no usable target URL "
            f"(target={target!r})"
        )
    origin = _origin_of(target)
    if origin is None:
        raise ValueError(
            f"finding {finding_id!r} target {target!r} is not a parseable URL"
        )

    persona_name = None
    md = finding.get("metadata")
    if isinstance(md, dict):
        persona_name = md.get("persona") or None

    session = VerificationSession(
        session_id=str(uuid.uuid4()),
        finding_id=finding_id,
        target_url=target,
        target_origin=origin,
        allowed_origins={origin},
        persona_name=persona_name if isinstance(persona_name, str) else None,
        original_finding=dict(finding),  # snapshot
    )
    _register(session)
    logger.info(
        f"[verify] created session {session.session_id[:8]} for "
        f"finding {finding_id!r} → {target!r} (scope: {origin})"
    )
    return session


def create_session_from_target(
    target_url: str,
    *,
    note: Optional[str] = None,
) -> VerificationSession:
    """Create a finding-less session bound directly to a target URL.

    Useful when the operator wants to verify something pre-finding
    (e.g. they have a hunch they want to manually probe). Functionally
    identical except `finding_id` is None and `original_finding` is None.

    Raises ValueError if the target URL has no parseable origin."""
    origin = _origin_of(target_url)
    if origin is None:
        raise ValueError(
            f"target {target_url!r} is not a parseable URL"
        )
    session = VerificationSession(
        session_id=str(uuid.uuid4()),
        finding_id=None,
        target_url=target_url,
        target_origin=origin,
        allowed_origins={origin},
    )
    _register(session)
    logger.info(
        f"[verify] created ad-hoc session {session.session_id[:8]} for "
        f"target {target_url!r} (scope: {origin}){f' — {note}' if note else ''}"
    )
    return session
