from __future__ import annotations

import logging
from typing import Dict, Any

from fastapi import APIRouter, Depends, Body
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from core.server.routers.auth import verify_token, check_ai_rate_limit
from core.base.action_dispatcher import ActionDispatcher
from core.ai.ai_engine import AIEngine
from core.errors import SentinelError, ErrorCode
from core.data.db import Database
from core.epistemic.ledger import load_canonical_session_read_model
from core.cortex.canonical_graph import build_causal_graph_snapshot

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["ai"])


async def _canonical_report_context(session_id: str) -> Dict[str, Any]:
    """Build AI-report inputs from the same revision as every other reader."""

    db = Database.instance()
    await db.init()
    read_model = load_canonical_session_read_model(session_id)
    issues = read_model.filter_cited_issues(await db.get_issues(session_id))
    graph = build_causal_graph_snapshot(read_model, issues=issues)
    return {
        "session_id": session_id,
        "evidence_revision": read_model.revision,
        "findings": read_model.finding_views(),
        "issues": issues,
        "risk": {},
        "killchain": graph.graph_dto.get("edges", []),
        "causal_graph_snapshot": graph.graph_dto,
        "attack_path_contract": graph.attack_path_contract,
        "reasoning": {},
        "decisions": [],
    }

class ChatTurn(BaseModel):
    role: str = Field(..., max_length=16)
    content: str = Field(..., max_length=8000)


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=32000)
    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    # Prior conversation turns for multi-turn memory. The endpoint is stateless;
    # the client replays the thread. Bounded to keep the prompt inside budget.
    history: list[ChatTurn] | None = Field(default=None, max_length=50)


# Phase 3 — active vulnerability verification endpoint. The map normalizes
# the user-facing string to the canonical VulnerabilityClass enum name so we
# can keep the request schema stable even if the enum evolves.
_VERIFY_VULN_CLASS_MAP = {
    "sqli": "SQLI",
    "sql_injection": "SQLI",
    "xss": "XSS",
    "idor": "IDOR",
    "ssrf": "SSRF",
    "path_traversal": "PATH_TRAVERSAL",
    "open_redirect": "OPEN_REDIRECT",
    "generic": "GENERIC",
}


class VerifyRequest(BaseModel):
    """Active vulnerability verification request.

    Sends detection probes against `target_url` and matches responses against
    known vulnerability signatures. Read-only by design — no data mutation,
    no DoS, budget-bounded.
    """
    target_url: str = Field(..., min_length=8, max_length=2048)
    vuln_class: str = Field(default="sqli", max_length=32)
    headers: Dict[str, str] | None = Field(default=None)
    cookies: Dict[str, str] | None = Field(default=None)
    budget: int = Field(default=5, ge=1, le=20)

@router.get("/status", dependencies=[Depends(verify_token)])
async def get_ai_status():
    """Get status of the local AI engine."""
    return AIEngine.instance().status()

@router.post("/chat", dependencies=[Depends(verify_token), Depends(check_ai_rate_limit)])
async def chat_with_ai(req: ChatRequest):
    """
    Chat with the security AI (Sentinel).
    
    Streams the response token-by-token.
    """
    ai = AIEngine.instance()

    history = [turn.model_dump() for turn in req.history] if req.history else None

    # Use streaming response for real-time feel
    return StreamingResponse(
        ai.stream_chat(req.prompt, session_id=req.session_id, history=history),
        media_type="text/plain"
    )

@router.post("/verify", dependencies=[Depends(verify_token), Depends(check_ai_rate_limit)])
async def verify_vulnerability(req: VerifyRequest):
    """Actively confirm a vulnerability on a target URL via VulnVerifier.

    Sends boundary-breaking probes (and timing checks where applicable) and
    matches responses against known DB-error / reflection / IDOR / SSRF /
    redirect / traversal signatures. Returns confirmations (with confidence
    and the payload that tripped detection) or an empty list if not detected.

    This is the active-verification spine that the AI assistant can call
    (via the EXEC protocol) and that the scan pipeline can call as a
    post-recon hook (Phase 3 wiring). Read-only, budget-bounded.
    """
    from core.base.session import ScanSession
    from core.wraith.mutation_engine import MutationEngine
    from core.wraith.vuln_verifier import VulnVerifier
    from core.web.contracts.enums import VulnerabilityClass

    vc_key = (req.vuln_class or "").strip().lower()
    canonical = _VERIFY_VULN_CLASS_MAP.get(vc_key)
    if canonical is None or not hasattr(VulnerabilityClass, canonical):
        raise SentinelError(
            ErrorCode.SCAN_TARGET_INVALID,
            f"Unsupported vuln_class {req.vuln_class!r}; "
            f"supported: {sorted(_VERIFY_VULN_CLASS_MAP)}",
        )
    vc = getattr(VulnerabilityClass, canonical)

    session = ScanSession(req.target_url)
    verifier = VulnVerifier(session)
    engine = MutationEngine()
    try:
        results, probes = await verifier.verify_finding(
            engine=engine,
            finding={},
            url=req.target_url,
            vuln_class=vc,
            headers=req.headers or {},
            cookies=req.cookies or {},
            budget=req.budget,
        )
    finally:
        # Best-effort cleanup of the engine's internal httpx client.
        close = getattr(engine, "close", None)
        if callable(close):
            try:
                await close()
            except Exception:
                pass

    return {
        "target_url": req.target_url,
        "vuln_class": req.vuln_class,
        "probes_sent": probes,
        "confirmed": [
            {"confidence": float(c), "evidence": d, "payload": p, "kind": k}
            for c, d, p, k in (results or [])
        ],
    }


@router.post("/generate-report", dependencies=[Depends(verify_token)])
async def generate_report(
    session_id: str = Body(..., embed=True),
    finding_id: str | None = Body(None, embed=True),
    report_type: str = Body("executive", embed=True),
    format: str = Body("markdown", embed=True)
):
    """Render the AI report route from one immutable SubmissionCandidate."""
    import json

    candidate, rendered, payload = await _candidate_report_state(
        session_id,
        finding_id=finding_id,
    )
    report_format = format.lower()
    if report_format not in {"markdown", "json"}:
        raise SentinelError(
            ErrorCode.SESSION_INVALID_STATE,
            "Unsupported candidate report format",
        )
    if report_type not in {"full", "executive", "technical"}:
        raise SentinelError(
            ErrorCode.SESSION_INVALID_STATE,
            "Unsupported candidate report type",
        )
    report_content = (
        json.dumps(payload, sort_keys=True, indent=2)
        if report_format == "json"
        else rendered.markdown
    )
    return {
        "session_id": session_id,
        "finding_id": candidate.finding_id,
        "candidate_digest": candidate.candidate_digest,
        "render_digest": rendered.render_digest,
        "canonical_revision": candidate.canonical_revision,
        "type": report_type,
        "format": report_format,
        "claims": payload["claims"],
        "content": report_content,
    }


async def _candidate_report_state(
    session_id: str,
    *,
    finding_id: str | None,
):
    from core.reporting.submission_candidate import (
        candidate_report_payload,
        render_submission_candidate,
        resolve_submission_candidate,
    )

    db = Database.instance()
    await db.init()
    if await db.get_session(session_id) is None:
        raise SentinelError(
            ErrorCode.SESSION_NOT_FOUND,
            f"Session {session_id} not found",
        )
    read_model = load_canonical_session_read_model(session_id)
    try:
        candidate = resolve_submission_candidate(
            read_model,
            finding_id=finding_id,
        )
        rendered = render_submission_candidate(candidate)
    except ValueError as exc:
        raise SentinelError(
            ErrorCode.SESSION_INVALID_STATE,
            str(exc),
        ) from exc
    return (
        candidate,
        rendered,
        candidate_report_payload(candidate, rendered=rendered),
    )

@router.post("/generate-section", dependencies=[Depends(verify_token)])
async def generate_section(
    session_id: str = Body(..., embed=True),
    finding_id: str | None = Body(None, embed=True),
    section: str = Body(..., embed=True),
    context: Dict[str, Any] | None = Body(None, embed=True)
):
    """Render a named candidate section; caller/model claims are not accepted."""
    if context:
        raise SentinelError(
            ErrorCode.SESSION_INVALID_STATE,
            "Candidate report sections do not accept caller-provided claims",
        )
    candidate, rendered, payload = await _candidate_report_state(
        session_id,
        finding_id=finding_id,
    )
    try:
        from core.reporting.submission_candidate import candidate_section_content

        content = candidate_section_content(candidate, section=section)
    except ValueError as exc:
        raise SentinelError(
            ErrorCode.SESSION_INVALID_STATE,
            str(exc),
        ) from exc

    return {
        "session_id": session_id,
        "finding_id": candidate.finding_id,
        "candidate_digest": candidate.candidate_digest,
        "render_digest": rendered.render_digest,
        "canonical_revision": candidate.canonical_revision,
        "section": section,
        "claims": payload["claims"],
        "content": content,
    }


# ---------------------------------------------------------
# Action Dispatcher: approval queue endpoints
# ---------------------------------------------------------


@router.get("/actions/pending", dependencies=[Depends(verify_token)])
async def get_pending_actions():
    """List AI-suggested actions awaiting human approval."""
    return ActionDispatcher.instance().get_pending()


@router.post("/actions/{action_id}/approve", dependencies=[Depends(verify_token)])
async def approve_action(action_id: str):
    """Approve a pending AI-suggested action for execution."""
    ok = ActionDispatcher.instance().approve_action(action_id)
    if not ok:
        raise SentinelError(
            ErrorCode.SESSION_NOT_FOUND,
            f"Action {action_id} not found or already processed",
        )
    return {"status": "approved", "action_id": action_id}


@router.post("/actions/{action_id}/deny", dependencies=[Depends(verify_token)])
async def deny_action(action_id: str):
    """Deny a pending AI-suggested action."""
    ok = ActionDispatcher.instance().deny_action(action_id)
    if not ok:
        raise SentinelError(
            ErrorCode.SESSION_NOT_FOUND,
            f"Action {action_id} not found or already processed",
        )
    return {"status": "denied", "action_id": action_id}
