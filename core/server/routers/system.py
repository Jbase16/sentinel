from __future__ import annotations

import logging
import asyncio
from typing import Dict, Any, List

from fastapi import APIRouter, Depends, Body
from pydantic import BaseModel

from core.server.routers.auth import verify_token, verify_sensitive_token
from core.server.state import get_state
from core.toolkit.tools import get_installed_tools, install_tools, uninstall_tools
from core.base.config import get_config

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system"])

class ToolInstallRequest(BaseModel):
    tools: List[str]

class LogBatch(BaseModel):
    lines: List[str]

@router.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "ok", "timestamp": asyncio.get_running_loop().time()}

@router.get("/tools", dependencies=[Depends(verify_token)])
async def list_tools():
    """List all available and installed security tools."""
    return get_installed_tools()

@router.post("/tools/install", dependencies=[Depends(verify_sensitive_token)])
async def install_tool_packages(req: ToolInstallRequest):
    """
    Install security tools via system package managers (brew/pip).
    """
    results = await install_tools(req.tools)
    return {"results": results}

@router.post("/tools/uninstall", dependencies=[Depends(verify_sensitive_token)])
async def uninstall_tool_packages(req: ToolInstallRequest):
    """
    Uninstall security tools.
    """
    results = await uninstall_tools(req.tools)
    return {"results": results}

@router.get("/config", dependencies=[Depends(verify_sensitive_token)])
async def get_system_config():
    """
    Get current system configuration (redacted).
    """
    conf = get_config()
    # Return a safe subset or redacted version
    return {
        "api_host": conf.api_host,
        "api_port": conf.api_port,
        "ai_provider": conf.ai.provider,
        "environment": conf.environment,
        "log_level": conf.logging.level
    }

@router.get("/logs", response_model=LogBatch, dependencies=[Depends(verify_token)])
async def fetch_logs():
    """
    Flush up to 2000 buffered log lines from the global queue.
    """
    state = get_state()
    lines = []
    try:
        # Fetch up to 2000 lines to avoid massive payloads
        for _ in range(2000):
            if state.log_queue.empty():
                break
            lines.append(state.log_queue.get_nowait())
    except Exception:
        pass
        
    return {"lines": lines}
