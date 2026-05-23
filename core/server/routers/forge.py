"""
core/server/routers/forge.py

API Endpoints for the JIT Exploit Compiler (FORGE).
"""

import logging
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, Dict

from core.forge.compiler import ExploitCompiler
from core.server.routers.auth import verify_sensitive_token

logger = logging.getLogger(__name__)

# Forge endpoints generate executable exploit code via the AI. They are listed
# in get_sensitive_endpoints() in core/base/config.py and must always require
# a token — even on loopback, even when require_auth is somehow off — because
# any process on the box could otherwise drive exploit generation.
router = APIRouter(
    prefix="/forge",
    tags=["Forge (Exploitation)"],
    dependencies=[Depends(verify_sensitive_token)],
)

class CompileRequest(BaseModel):
    target: str
    anomaly_context: str

class CompileResponse(BaseModel):
    status: str
    filepath: Optional[str] = None
    error: Optional[str] = None

@router.post("/compile", response_model=CompileResponse)
async def compile_exploit(req: CompileRequest):
    """
    Request the AI to generate a custom exploit for a specific anomaly.
    
    This process involves:
    1. AI Generation
    2. Static Validation (Safety checks)
    3. Adversarial Debate (Arbiter review)
    4. Disk Persistence (No auto-execution)
    """
    compiler = ExploitCompiler.instance()
    
    logger.info(f"[ForgeAPI] Received compilation request for {req.target}")
    
    filepath = await compiler.compile_exploit_async(req.target, req.anomaly_context)
    
    if filepath:
        return CompileResponse(
            status="success", 
            filepath=filepath
        )
    else:
        # If it returns None, it usually means AI failure or safety rejection
        # In a real system we'd want more granular errors, but this is a start
        return CompileResponse(
            status="failed",
            error="Compilation failed (AI timeout or Safety Rejection)"
        )
