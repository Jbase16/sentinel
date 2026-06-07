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
