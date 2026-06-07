"""
core/server/routers/verify.py — Verify Console HTTP surface (VC1).

Phase 5-VC1 endpoints (this commit):
  POST /v1/verify/sessions             create from finding_id OR target
  GET  /v1/verify/sessions             list
  GET  /v1/verify/sessions/{id}        full state
  POST /v1/verify/sessions/{id}/scope  add an origin to the allowlist
  POST /v1/verify/sessions/{id}/persona  bind/swap persona auth

Phase 5-VC2 (next): the request console — POST a structured HTTP
exchange through the scope gate and capture the response.
Phase 5-VC3 (after): repro promoter — exchange-ids → BountyReport
steps_to_reproduce.

All endpoints gated by the sensitive token (operator-only).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.server.routers.auth import verify_sensitive_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["verify"])


# ──────────────────────── Pydantic models ────────────────────────


class CreateSessionRequest(BaseModel):
    """Either finding_id OR target_url must be set (XOR enforced
    in the handler). finding_id is the canonical path; target_url
    is for ad-hoc verification without a prior finding."""
    finding_id: Optional[str] = None
    target_url: Optional[str] = None
    note: Optional[str] = Field(
        default=None,
        description="Optional free-text label, e.g. 'manual repro check'.",
    )


class CreateSessionResponse(BaseModel):
    session_id: str
    finding_id: Optional[str]
    target_url: str
    allowed_origins: List[str]
    has_persona_auth: bool


class AddScopeRequest(BaseModel):
    url_or_origin: str = Field(
        ...,
        description=(
            "Full URL or just scheme://netloc. The origin will be "
            "extracted and added to the session's allowlist."
        ),
    )


class AddScopeResponse(BaseModel):
    added: bool
    allowed_origins: List[str]


class BindPersonaRequest(BaseModel):
    """Bind persona auth to a session.

    Two modes:
      1. Provide `persona_spec` with login_url etc. → call
         persona_auth.authenticate_persona() to obtain headers + cookies.
      2. Provide `headers` and/or `cookies` directly → use as-is.

    persona_name is operator-facing only (shown in UI + audit).
    """
    persona_name: str = Field(..., min_length=1)
    persona_spec: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)


class BindPersonaResponse(BaseModel):
    persona_name: str
    has_headers: bool
    has_cookies: bool


# ──────────────────────────── endpoints ────────────────────────────


@router.post("/sessions", response_model=CreateSessionResponse)
async def create_session(
    req: CreateSessionRequest,
    _: bool = Depends(verify_sensitive_token),
) -> CreateSessionResponse:
    """Create a new VerificationSession.

    Provide EITHER finding_id (the canonical path — hydrate from a
    confirmed finding) OR target_url (ad-hoc — verify against a URL
    without a prior finding). Exactly one must be set."""
    from core.verify.console import (
        create_session_from_finding,
        create_session_from_target,
    )

    if bool(req.finding_id) == bool(req.target_url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Provide EITHER finding_id OR target_url, not both/neither."
            ),
        )

    try:
        if req.finding_id:
            session = create_session_from_finding(req.finding_id)
        else:
            session = create_session_from_target(
                req.target_url or "", note=req.note
            )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return CreateSessionResponse(
        session_id=session.session_id,
        finding_id=session.finding_id,
        target_url=session.target_url,
        allowed_origins=sorted(session.allowed_origins),
        has_persona_auth=bool(session.persona_headers or session.persona_cookies),
    )


@router.get("/sessions")
async def list_verify_sessions(
    _: bool = Depends(verify_sensitive_token),
):
    """List one-line summaries of every live VerificationSession.

    For full state including transcript, call /sessions/{id}."""
    from core.verify.console import list_sessions

    out = []
    for s in list_sessions():
        out.append({
            "session_id": s.session_id,
            "finding_id": s.finding_id,
            "target_url": s.target_url,
            "allowed_origins": sorted(s.allowed_origins),
            "persona_name": s.persona_name,
            "has_persona_auth": bool(s.persona_headers or s.persona_cookies),
            "transcript_length": len(s.transcript),
            "created_at": s.created_at,
            "last_activity_at": s.last_activity_at,
        })
    return out


@router.get("/sessions/{session_id}")
async def get_verify_session(
    session_id: str,
    _: bool = Depends(verify_sensitive_token),
):
    """Return the full state of one VerificationSession, including the
    transcript of captured exchanges (each as a FlowStep dict)."""
    from core.verify.console import get_session

    sess = get_session(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail=f"session {session_id!r} not found")
    return sess.to_dict()


@router.post("/sessions/{session_id}/scope", response_model=AddScopeResponse)
async def add_to_scope(
    session_id: str,
    req: AddScopeRequest,
    _: bool = Depends(verify_sensitive_token),
) -> AddScopeResponse:
    """Add an origin to the session's scope allowlist.

    This is the ONLY way scope can grow. The new origin is extracted
    from req.url_or_origin (a full URL or bare scheme://netloc both
    work)."""
    from core.verify.console import get_session

    sess = get_session(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail=f"session {session_id!r} not found")
    added = sess.add_origin_to_scope(req.url_or_origin)
    return AddScopeResponse(
        added=added,
        allowed_origins=sorted(sess.allowed_origins),
    )


@router.post("/sessions/{session_id}/persona", response_model=BindPersonaResponse)
async def bind_persona(
    session_id: str,
    req: BindPersonaRequest,
    _: bool = Depends(verify_sensitive_token),
) -> BindPersonaResponse:
    """Bind (or replace) persona auth on the session.

    persona_spec path runs persona_auth.authenticate_persona() to
    obtain headers + cookies. headers/cookies fields are merged in
    afterward (allow operator to layer static creds on top of dynamic
    ones, same as Phase 3)."""
    from core.verify.console import get_session

    sess = get_session(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail=f"session {session_id!r} not found")

    resolved_headers: Dict[str, str] = {}
    resolved_cookies: Dict[str, str] = {}

    if req.persona_spec and req.persona_spec.get("login_url"):
        from core.wraith.persona_auth import authenticate_persona
        try:
            h, c = await authenticate_persona(req.persona_spec)
            resolved_headers.update(h)
            resolved_cookies.update(c)
        except Exception as e:
            logger.warning(
                f"[verify] persona_auth failed for session {session_id[:8]}: "
                f"{type(e).__name__}: {e}; falling back to explicit creds"
            )

    # Operator-supplied headers/cookies take precedence (they're the
    # most-explicit signal).
    resolved_headers.update(req.headers)
    resolved_cookies.update(req.cookies)

    sess.persona_name = req.persona_name
    sess.persona_headers = resolved_headers
    sess.persona_cookies = resolved_cookies
    sess.last_activity_at = max(sess.last_activity_at, sess.created_at)

    return BindPersonaResponse(
        persona_name=req.persona_name,
        has_headers=bool(resolved_headers),
        has_cookies=bool(resolved_cookies),
    )


# ──────────────────────── VC2: structured request console ────────────────────────


class ExchangeRequest(BaseModel):
    """POST /v1/verify/sessions/{id}/exchange body.

    The structured equivalent of "type curl into a shell." The handler
    routes this through the session's scope gate before any network I/O.
    Out-of-scope URLs raise structurally — they CANNOT be sent. That's
    the constraint-inversion: the scanner makes scope violations
    physically unreachable.
    """
    method: str = Field(
        ...,
        description="HTTP method (GET, POST, PUT, PATCH, DELETE, …).",
    )
    url: str = Field(..., description="Full target URL.")
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Per-request headers. Merged ON TOP of the session's bound "
            "persona headers — request-level headers win on collision "
            "so the operator can override Authorization etc. when they "
            "explicitly want to."
        ),
    )
    body: Optional[str] = Field(
        default=None,
        description="Request body (raw string). Empty/None for GET/HEAD.",
    )
    timeout_s: float = Field(
        default=10.0, ge=0.5, le=60.0,
        description="Per-request timeout. Capped at 60s.",
    )
    follow_redirects: bool = Field(
        default=False,
        description=(
            "If True, httpx will follow redirects. The CAPTURED step "
            "records the final URL, not the intermediate hops — for "
            "fine-grained capture leave this off."
        ),
    )


class ExchangeResponse(BaseModel):
    """Result of one verify exchange.

    The captured exchange (as a FlowStep dict) is included so the
    UI can render the full request + response without a follow-up
    /sessions/{id} fetch."""
    captured_step: Dict[str, Any]
    transcript_length_after: int
    duration_ms: float
    in_scope: bool  # always True for a captured exchange — out-of-scope
                    # paths raise 403 before reaching here. Surfaced for
                    # UI symmetry.


class ScopeViolationError(HTTPException):
    """Operator tried to send a request to an URL not in the session's
    scope allowlist. Surfaced as HTTP 403 — different from 404 (session
    not found) and 400 (malformed input) to disambiguate UI handling.

    The body INCLUDES the rejected URL + the current allowlist so the
    operator can decide whether to (a) fix their request or (b)
    explicitly expand scope via /scope.
    """
    def __init__(self, url: str, allowed_origins: List[str]):
        super().__init__(
            status_code=403,
            detail={
                "code": "out_of_scope",
                "message": (
                    f"URL {url!r} is not in this session's scope. "
                    f"Add the origin via POST /sessions/{{id}}/scope "
                    f"if you intend to verify there."
                ),
                "rejected_url": url,
                "allowed_origins": allowed_origins,
            },
        )


@router.post("/sessions/{session_id}/exchange", response_model=ExchangeResponse)
async def send_exchange(
    session_id: str,
    req: ExchangeRequest,
    _: bool = Depends(verify_sensitive_token),
) -> ExchangeResponse:
    """Send one structured HTTP request through the session's scope gate.

    Order of operations (critical):
      1. Session must exist           → 404 if not
      2. URL must be in session scope → 403 with rejection details
      3. Persona auth + per-request headers merged
      4. THEN AND ONLY THEN network I/O happens
      5. Response captured as FlowStep, appended to transcript

    Out-of-scope requests never reach the wire. That's the property
    that makes Verify Console safe to use during manual bounty
    verification.
    """
    import time as _t
    import httpx
    from core.ghost.flow import FlowStep, MAX_BODY_BYTES
    from core.verify.console import get_session

    sess = get_session(session_id)
    if sess is None:
        raise HTTPException(
            status_code=404, detail=f"session {session_id!r} not found"
        )

    # ── Step 2 — STRUCTURAL scope gate. Out-of-scope = cannot send. ──
    if not sess.is_in_scope(req.url):
        logger.warning(
            f"[verify] BLOCKED out-of-scope request "
            f"{req.method} {req.url} in session {session_id[:8]}"
        )
        raise ScopeViolationError(
            url=req.url, allowed_origins=sorted(sess.allowed_origins)
        )

    # ── Step 3 — merge headers. Session persona is the base; per-
    # request headers (from req.headers) override on collision.
    merged_headers: Dict[str, str] = {}
    # Persona headers go first (they're already lowercased).
    for k, v in (sess.persona_headers or {}).items():
        merged_headers[str(k).lower()] = str(v)
    # Cookie jar from persona — encoded as Cookie header. If the
    # operator's per-request headers already specify a Cookie, that
    # wins (typical case: they're testing a custom session token).
    if sess.persona_cookies and "cookie" not in {k.lower() for k in req.headers}:
        merged_headers["cookie"] = "; ".join(
            f"{k}={v}" for k, v in sess.persona_cookies.items()
        )
    for k, v in req.headers.items():
        merged_headers[str(k).lower()] = str(v)

    # ── Step 4 — network I/O.
    started = _t.time()
    try:
        async with httpx.AsyncClient(
            timeout=req.timeout_s,
            follow_redirects=req.follow_redirects,
        ) as client:
            httpx_req = client.build_request(
                method=req.method,
                url=req.url,
                headers=merged_headers,
                content=(req.body.encode("utf-8") if req.body else None),
            )
            resp = await client.send(httpx_req)
        status = int(resp.status_code)
        body_bytes = resp.content or b""
        truncated = len(body_bytes) > MAX_BODY_BYTES
        if truncated:
            body_bytes = body_bytes[:MAX_BODY_BYTES]
        body_str = body_bytes.decode("utf-8", errors="replace")
        response_headers = {k: v for k, v in resp.headers.items()}
        # The URL the response actually came from (post-redirect if any).
        final_url = str(resp.url)
        content_type = response_headers.get("content-type")
    except httpx.TimeoutException as e:
        # Capture the timeout as a step with status=0 (matches the
        # Phase 4 replay-engine convention for failed exchanges).
        status = 0
        body_str = f"<verify-error: timeout after {req.timeout_s}s: {e}>"
        response_headers = {}
        final_url = req.url
        content_type = None
        truncated = False
    except Exception as e:
        status = 0
        body_str = f"<verify-error: {type(e).__name__}: {e}>"
        response_headers = {}
        final_url = req.url
        content_type = None
        truncated = False

    elapsed_ms = (_t.time() - started) * 1000.0

    # ── Step 5 — capture as FlowStep, append to transcript.
    step = FlowStep(
        method=req.method,
        url=final_url,
        params={},  # we record headers + body; query params encoded in URL
        headers=merged_headers,
        request_body=req.body or "",
        request_content_type=merged_headers.get("content-type"),
    )
    step.set_response(
        status=status,
        headers=response_headers,
        body=body_str,
        body_truncated=truncated,
        content_type=content_type,
        elapsed_ms=elapsed_ms,
        cookies_after_step={},  # verify console doesn't carry jar
                                # across exchanges by design (each
                                # exchange is hermetic; persona is the
                                # source of identity)
    )
    sess.append_exchange(step)

    return ExchangeResponse(
        captured_step=step.to_dict(),
        transcript_length_after=len(sess.transcript),
        duration_ms=elapsed_ms,
        in_scope=True,
    )


# ──────────────────────── VC3: promote to repro ────────────────────────


class PromoteRequest(BaseModel):
    """POST /v1/verify/sessions/{id}/promote body.

    Empty `exchange_indices` means "promote the whole transcript."
    Most operators select a subset — the one or two requests that
    cleanly demonstrate the bug, not every exploratory probe."""
    exchange_indices: Optional[List[int]] = Field(
        default=None,
        description=(
            "Zero-based indices into session.transcript. None or "
            "omitted means include every captured exchange."
        ),
    )
    sanitize: bool = Field(
        default=True,
        description=(
            "If True, auth headers/cookies in the rendered curl are "
            "replaced with operator-readable placeholders ($TOKEN, "
            "$SESSION_ID, etc.). Set False ONLY for local-debug "
            "renders — the result is NOT safe to paste into a public "
            "report."
        ),
    )


class PromoteResponse(BaseModel):
    """Rendered repro ready to drop into BountyReport.steps_to_reproduce."""
    finding_id: Optional[str]
    target_url: str
    entry_count: int
    # The List[str] shape BountyReport expects directly.
    steps_to_reproduce: List[str]
    # Operator-readable expansion of every placeholder, so the report
    # template can render "Substitute before running: $TOKEN = …".
    placeholder_legend: Dict[str, str]
    # Structured per-entry view for UI consumers.
    entries: List[Dict[str, Any]]


@router.post("/sessions/{session_id}/promote", response_model=PromoteResponse)
async def promote_to_repro(
    session_id: str,
    req: PromoteRequest,
    _: bool = Depends(verify_sensitive_token),
) -> PromoteResponse:
    """Render selected exchanges as BountyReport-ready repro steps.

    The output's `steps_to_reproduce` field is the EXACT shape
    BountyReport consumes. The UI / CLI can either:
      * Push directly into a BountyReport draft.
      * Copy to clipboard.
      * Show for operator review before pushing.

    Sanitization replaces real auth tokens with placeholders. The
    operator's session transcript still contains the real values
    (they need them for their own debugging); the rendered repro
    is the public-to-program version.
    """
    from core.verify.console import get_session
    from core.verify.promoter import (
        promote_transcript_to_repro,
        render_repro_as_strings,
    )

    sess = get_session(session_id)
    if sess is None:
        raise HTTPException(
            status_code=404, detail=f"session {session_id!r} not found"
        )

    if not sess.transcript:
        raise HTTPException(
            status_code=400,
            detail=(
                "Session transcript is empty — capture at least one "
                "exchange via /exchange before promoting to repro."
            ),
        )

    entries, legend = promote_transcript_to_repro(
        sess,
        exchange_indices=req.exchange_indices,
        sanitize=req.sanitize,
    )
    return PromoteResponse(
        finding_id=sess.finding_id,
        target_url=sess.target_url,
        entry_count=len(entries),
        steps_to_reproduce=render_repro_as_strings(entries),
        placeholder_legend=legend,
        entries=[
            {
                "index": e.index,
                "method": e.method,
                "url": e.url,
                "prose": e.prose,
                "curl": e.curl,
                "response_status": e.response_status,
                "response_excerpt": e.response_excerpt,
                "markdown": e.markdown,
            }
            for e in entries
        ],
    )
