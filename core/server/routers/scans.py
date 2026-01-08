from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator

from core.server.state import get_state
from core.server.routers.auth import verify_sensitive_token
from core.errors import SentinelError, ErrorCode
from core.data.db import Database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    modules: Optional[List[str]] = None
    force: bool = False
    mode: str = "standard"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        dangerous_patterns = [";", "&&", "||", "`", "$(", "\n", "\r"]
        for pattern in dangerous_patterns:
            if pattern in v:
                raise ValueError(f"Invalid character in target: {pattern}")
        return v

    @field_validator("modules")
    @classmethod
    def validate_modules(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        from core.toolkit.tools import TOOLS
        valid_tools = set(TOOLS.keys())
        invalid = [tool for tool in v if tool not in valid_tools]
        if invalid:
            raise ValueError(f"Invalid tool names: {', '.join(invalid)}")
        return v

def _log_sink_sync(msg: str) -> None:
    state = get_state()
    loop = None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = state.api_loop

    if loop is not None:
        try:
            if state.log_queue.full():
                logger.warning("Log queue overflow, dropping entry.")
            else:
                state.log_queue.put_nowait(msg)
        except Exception:
            pass

async def begin_scan_logic(req: ScanRequest) -> str:
    state = get_state()
    
    from core.base.session import ScanSession
    from core.cortex.events import get_event_bus
    from core.engine.scanner_engine import ScannerEngine
    from core.toolkit.tools import get_installed_tools
    from core.cortex.reasoning import reasoning_engine
    from core.cortex.events import GraphEvent, GraphEventType

    async with state.scan_lock:
        if state.active_scan_task and not state.active_scan_task.done():
            if req.force:
                logger.info("Force-killing active scan...")
                state.cancel_requested.set()
                state.active_scan_task.cancel()
                try:
                    await state.active_scan_task
                except asyncio.CancelledError:
                    pass
                state.active_scan_task = None
            else:
                raise SentinelError(
                    ErrorCode.SCAN_ALREADY_RUNNING,
                    "Cannot start scan while another is active",
                    details={"active_target": state.scan_state.get("target")}
                )

        previous_session_id = state.scan_state.get("session_id")
        if previous_session_id:
            try:
                await state.unregister_session(previous_session_id)
            except Exception:
                pass

        state.cancel_requested.clear()

        session = ScanSession(req.target)
        session.set_external_log_sink(_log_sink_sync)
        await state.register_session(session.id, session)

        Database.instance().save_session(session.to_dict())

        installed_tools = list(get_installed_tools().keys())
        requested_tools = list(dict.fromkeys(req.modules or []))
        allowed_tools = (
            [t for t in requested_tools if t in installed_tools]
            if requested_tools
            else installed_tools
        )
        
        state.scan_state = {
            "target": req.target,
            "modules": req.modules,
            "mode": req.mode,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "session_id": session.id,
        }

        event_bus = get_event_bus()
        event_bus.emit_scan_started(req.target, allowed_tools, session.id)

        async def _runner() -> None:
            start_time = time.time()
            try:
                async def dispatch_tool(tool: str) -> List[Dict]:
                    findings = []
                    exit_code = 0
                    
                    if tool not in allowed_tools:
                        session.log(f"⚠️ [Security] Tool '{tool}' blocked")
                        return []
                        
                    engine = ScannerEngine(session=session)
                    try:
                        event_bus.emit_tool_invoked(tool=tool, target=req.target, args=[], session_id=session.id)
                        if state.cancel_requested.is_set():
                            return []

                        async for log_line in engine.scan(
                            req.target, selected_tools=[tool], cancel_flag=state.cancel_requested
                        ):
                            session.log(log_line)

                        findings = engine.get_last_results() or []
                        exit_code = 130 if state.cancel_requested.is_set() else 0
                        return findings
                    except asyncio.CancelledError:
                        state.cancel_requested.set()
                        raise
                    except Exception as exc:
                        session.log(f"[Strategos] Tool failed ({tool}): {exc}")
                        return []
                    finally:
                        event_bus.emit_tool_completed(
                            tool=tool, exit_code=exit_code, findings_count=len(findings), session_id=session.id
                        )

                mission = await reasoning_engine.start_scan(
                    target=req.target,
                    available_tools=allowed_tools,
                    mode=req.mode,
                    dispatch_tool=dispatch_tool,
                    log_fn=session.log
                )
                
                state.scan_state["status"] = "completed"
                state.scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
                
                duration = time.time() - start_time
                event_bus.emit_scan_completed("completed", len(session.findings.get_all()), duration, session_id=session.id)

            except asyncio.CancelledError:
                state.scan_state["status"] = "cancelled"
                duration = time.time() - start_time
                event_bus.emit_scan_completed("cancelled", len(session.findings.get_all()), duration, session_id=session.id)
            except Exception as e:
                state.scan_state["status"] = "error"
                logger.error(f"Scan error: {e}", exc_info=True)
                event_bus.emit(GraphEvent(
                    type=GraphEventType.SCAN_FAILED,
                    payload={"error": str(e), "target": req.target, "session_id": session.id}
                ))

        state.active_scan_task = asyncio.create_task(_runner())
        return session.id

@router.post("/start", dependencies=[Depends(verify_sensitive_token)])
async def start_scan(req: ScanRequest):
    session_id = await begin_scan_logic(req)
    return {"session_id": session_id, "status": "started"}

@router.get("/status")
async def get_scan_status():
    return get_state().scan_state
