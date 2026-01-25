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
    
    if not session:
        # Try to load from DB if not in memory
        # This is a simplification; ideally we'd have a unified SessionLoader
        raise SentinelError(ErrorCode.RESOURCE_NOT_FOUND, f"Session {session_id} not active or found")

    composer = ReportComposer(session)
    report_content = await composer.generate_async(report_type=report_type, format=format)
    
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
    
    # If session not found in memory, we still want to allow reporting 
    # if the data exists in the database (persisted session).
    # For now, if session is None, ReportComposer might fallback to skeletal data or error.
    # Ideally, we should resuscitate the session context from DB here.
    
    composer = ReportComposer(session)
    
    # Check if section is valid
    if section not in composer.SECTIONS:
         raise SentinelError(ErrorCode.INVALID_REQUEST, f"Invalid section name: {section}")
         
    content = await composer.generate_section(section, context_override=context)
    
    return {
        "session_id": session_id,
        "section": section,
        "content": content
    }
