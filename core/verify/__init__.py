"""
core/verify — the Verify Console (Phase 5).

Closes the highest-value gap in the product: manual verification +
reproduction (workflow steps 4-5). This is where bounty reports get
REJECTED ("could not reproduce") and where hunters get BANNED
(out-of-scope testing during verification).

Design (one finding-scoped workflow, three uses simultaneously):
  1. Live engine interface — operator drives explicitly scoped requests
     through the Verify egress broker.
  2. Audit trail — every exchange is structured (FlowStep-shaped),
     not text-soup from a shell.
  3. Candidate evidence — selected exchanges persist only as sanitized,
     receipt-bound inputs to a deterministic SubmissionCandidate draft.

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
