"""
core/verify — the Verify Console (Phase 5).

Closes the highest-value gap in the product: manual verification +
reproduction (workflow steps 4-5). This is where bounty reports get
REJECTED ("could not reproduce") and where hunters get BANNED
(out-of-scope testing during verification).

Design (single artifact, three uses simultaneously):
  1. Live engine interface — operator drives real requests at the
     target while standing on the policy_enforcer.
  2. Audit trail — every exchange is structured (FlowStep-shaped),
     not text-soup from a shell.
  3. Report repro section — exchanges promote one-click into
     BountyReport.steps_to_reproduce as curl + prose.

Architecture is intentionally a *finding-scoped* specialization of
Phase 4's Ghost flow capture rather than a parallel system. Reuses:
  * core.ghost.flow.FlowStep for the structured request/response record
  * core.intel.policy_enforcer + ScopeContext.registry for the
    per-URL scope gate (constraint inversion — out-of-scope is
    structurally impossible, not just warned)
  * core.wraith.persona_auth for identity binding
"""
from core.verify.console import (
    VerificationSession,
    create_session_from_finding,
    create_session_from_target,
    get_session,
    list_sessions,
)
from core.verify.promoter import (
    ReproEntry,
    promote_transcript_to_repro,
    render_curl,
    render_repro_as_strings,
    sanitize_headers,
)

__all__ = [
    "VerificationSession",
    "create_session_from_finding",
    "create_session_from_target",
    "get_session",
    "list_sessions",
    "ReproEntry",
    "promote_transcript_to_repro",
    "render_curl",
    "render_repro_as_strings",
    "sanitize_headers",
]
