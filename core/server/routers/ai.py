from __future__ import annotations

import logging
from typing import Dict, Any, List

from fastapi import APIRouter, Depends, Body, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from core.server.routers.auth import verify_token, check_ai_rate_limit
from core.ai.ai_engine import AIEngine
from core.ai.reporting import ReportComposer
from core.server.state import get_state
from core.errors import SentinelError, ErrorCode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["ai"])

class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=32000)

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
    
    # Use streaming response for real-time feel
    return StreamingResponse(
        ai.stream_chat(req.prompt),
        media_type="text/plain"
    )

@router.post("/generate-report", dependencies=[Depends(verify_token)])
async def generate_report(
    session_id: str = Body(..., embed=True),
    report_type: str = Body("executive", embed=True),
    format: str = Body("markdown", embed=True)
):
    """
    Generate a security report for a specific scan session.
    """
    state = get_state()
    session = await state.get_session(session_id)
    context_override: Dict[str, Any] | None = None

    if not session:
        db = Database.instance()
        await db.init()
        findings = await db.get_findings(session_id)
        issues = await db.get_issues(session_id)
        _, db_edges = await db.load_graph_snapshot(session_id)

        if not findings and not issues:
            raise SentinelError(ErrorCode.SESSION_NOT_FOUND, f"Session {session_id} not found")

        context_override = {
            "findings": findings,
            "issues": issues,
            "risk": {},
            "killchain": db_edges,
            "reasoning": {},
            "decisions": [],
        }

    composer = ReportComposer(session)
    report_content = await composer.generate_async(
        report_type=report_type,
        format=format,
        context_override=context_override,
    )
    
    return {
        "session_id": session_id,
        "type": report_type,
        "format": format,
        "content": report_content
    }

@router.post("/generate-section", dependencies=[Depends(verify_token)])
async def generate_section(
    session_id: str = Body(..., embed=True),
    section: str = Body(..., embed=True),
    context: Dict[str, Any] = Body(None, embed=True)
):
    """
    Generate a specific section of a security report.
    """
    state = get_state()
    session = await state.get_session(session_id)

    # ReportComposer tolerates session=None — it falls back to global stores.
    composer = ReportComposer(session)

    if section not in composer.SECTIONS:
        raise SentinelError(ErrorCode.SESSION_INVALID_STATE, f"Invalid section name: {section}")

    try:
        content = await composer.generate_section(section, context_override=context)
    except Exception as exc:
        logger.error("[AI] Report section '%s' generation failed: %s", section, exc, exc_info=True)
        raise SentinelError(
            ErrorCode.AI_INVALID_RESPONSE,
            f"Failed to generate section '{section}': {exc}",
        )

    return {
        "session_id": session_id,
        "section": section,
        "content": content
    }


# ---------------------------------------------------------
# Action Dispatcher: approval queue endpoints
# ---------------------------------------------------------
from core.base.action_dispatcher import ActionDispatcher


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
