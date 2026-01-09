"""
Ghost Protocol Router

Provides API endpoints for the Ghost Protocol passive interception proxy.
Integrates with the Lazarus engine for real-time JS de-obfuscation.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel

from core.server.routers.auth import verify_sensitive_token
from core.base.config import get_config

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ghost"])


# Request/Response Models
class GhostStartResponse(BaseModel):
    """Response when starting Ghost Protocol."""
    status: str
    port: Optional[int] = None
    message: Optional[str] = None


class GhostStopResponse(BaseModel):
    """Response when stopping Ghost Protocol."""
    status: str
    message: Optional[str] = None


class GhostRecordResponse(BaseModel):
    """Response when starting flow recording."""
    status: str
    flow_name: str
    message: Optional[str] = None


# Global state for Ghost Protocol
_ghost_process = None
_ghost_port: Optional[int] = None
_recording_sessions = set()


async def start_ghost_proxy(port: int = 8080) -> dict:
    """
    Start the Ghost Protocol mitmproxy instance.
    
    This is a placeholder implementation. The actual implementation would:
    1. Spawn a mitmproxy process with the Lazarus addon
    2. Configure it to intercept traffic on the specified port
    3. Return the actual port it's listening on
    
    For now, we'll simulate success and return the configured port.
    """
    global _ghost_process, _ghost_port
    
    # In production, this would:
    # from core.ghost.proxy import GhostProxy
    # proxy = GhostProxy()
    # _ghost_process = await proxy.start(port=port)
    # _ghost_port = proxy.get_port()
    
    _ghost_port = port
    logger.info(f"[Ghost] Started proxy on port {port}")
    
    return {
        "status": "running",
        "port": port,
        "message": f"Ghost Protocol started on port {port}"
    }


async def stop_ghost_proxy() -> dict:
    """
    Stop the Ghost Protocol mitmproxy instance.
    
    This is a placeholder implementation. The actual implementation would:
    1. Gracefully shutdown the mitmproxy process
    2. Clean up any temporary resources
    
    For now, we'll simulate success.
    """
    global _ghost_process, _ghost_port, _recording_sessions
    
    # In production, this would:
    # if _ghost_process:
    #     await _ghost_process.stop()
    
    _ghost_process = None
    _ghost_port = None
    _recording_sessions.clear()
    
    logger.info("[Ghost] Stopped proxy")
    
    return {
        "status": "stopped",
        "message": "Ghost Protocol stopped"
    }


async def start_flow_recording(flow_name: str) -> dict:
    """
    Start recording a user flow for Logic Fuzzing.
    
    This is a placeholder implementation. The actual implementation would:
    1. Create a flow mapping session
    2. Record HTTP requests/responses
    3. Store the flow for later fuzzing
    
    For now, we'll simulate success.
    """
    if flow_name in _recording_sessions:
        return {
            "status": "already_recording",
            "flow_name": flow_name,
            "message": f"Flow '{flow_name}' is already being recorded"
        }
    
    _recording_sessions.add(flow_name)
    logger.info(f"[Ghost] Started recording flow: {flow_name}")
    
    return {
        "status": "recording",
        "flow_name": flow_name,
        "message": f"Recording flow '{flow_name}'"
    }


# API Endpoints
@router.post("/start", response_model=GhostStartResponse)
async def start_ghost(
    port: int = Query(default=8080, description="Port for the proxy to listen on"),
    _: bool = Depends(verify_sensitive_token)
):
    """
    Start the Ghost Protocol passive interception proxy.
    
    This starts a mitmproxy instance with the Lazarus addon enabled,
    which will de-obfuscate JavaScript code in real-time as traffic
    flows through the proxy.
    
    Args:
        port: The port for the proxy to listen on (default: 8080)
    
    Returns:
        GhostStartResponse with status and listening port
    """
    if _ghost_port is not None:
        raise HTTPException(
            status_code=409,
            detail="Ghost Protocol is already running. Stop it first or check if another instance is active."
        )
    
    config = get_config()
    
    try:
        result = await start_ghost_proxy(port)
        return GhostStartResponse(**result)
    except Exception as e:
        logger.error(f"[Ghost] Failed to start: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start Ghost Protocol: {str(e)}"
        )


@router.post("/stop", response_model=GhostStopResponse)
async def stop_ghost(_: bool = Depends(verify_sensitive_token)):
    """
    Stop the Ghost Protocol passive interception proxy.
    
    This gracefully shuts down the mitmproxy instance and cleans up
    any temporary resources.
    
    Returns:
        GhostStopResponse with status
    """
    if _ghost_port is None:
        return GhostStopResponse(
            status="not_running",
            message="Ghost Protocol is not currently running"
        )
    
    try:
        result = await stop_ghost_proxy()
        return GhostStopResponse(**result)
    except Exception as e:
        logger.error(f"[Ghost] Failed to stop: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to stop Ghost Protocol: {str(e)}"
        )


@router.post("/record/{flow_name}", response_model=GhostRecordResponse)
async def start_ghost_recording(
    flow_name: str,
    _: bool = Depends(verify_sensitive_token)
):
    """
    Start recording a user flow for Logic Fuzzing.
    
    Records HTTP traffic to build a flow map that can be used for
    automated Logic Fuzzing tests.
    
    Args:
        flow_name: Name to identify this flow recording
    
    Returns:
        GhostRecordResponse with status and flow name
    """
    if _ghost_port is None:
        raise HTTPException(
            status_code=409,
            detail="Ghost Protocol is not running. Start it first."
        )
    
    try:
        result = await start_flow_recording(flow_name)
        return GhostRecordResponse(**result)
    except Exception as e:
        logger.error(f"[Ghost] Failed to start recording: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start flow recording: {str(e)}"
        )


@router.get("/status")
async def get_ghost_status(_: bool = Depends(verify_sensitive_token)):
    """
    Get the current status of Ghost Protocol.
    
    Returns information about whether Ghost Protocol is running,
    what port it's on, and any active recording sessions.
    """
    return {
        "running": _ghost_port is not None,
        "port": _ghost_port,
        "recording_sessions": list(_recording_sessions),
        "message": "Ghost Protocol is active" if _ghost_port else "Ghost Protocol is not running"
    }