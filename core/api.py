# core/api.py
# Production-grade FastAPI server (Hybrid Version)

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, validator

import pyperclip

from core.config import get_config, setup_logging
from core.ai_engine import AIEngine
from core.task_router import TaskRouter
from core.action_dispatcher import ActionDispatcher
from core.reporting import ReportComposer
from core.pty_manager import PTYManager
from core.db import Database

logger = logging.getLogger(__name__)

# --- Models ---

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    modules: Optional[List[str]] = None
    force: bool = False # Added for UX robustness
    
    @validator("target")
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        dangerous_patterns = [";", "&&", "||", "`", "$(", "\n", "\r"]
        for pattern in dangerous_patterns:
            if pattern in v:
                raise ValueError(f"Invalid character in target: {pattern}")
        return v


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=32000)


# --- App Setup ---

app = FastAPI(
    title="SentinelForge API",
    description="AI-augmented offensive security platform",
    version="1.0.0",
)

security = HTTPBearer(auto_error=False)

# --- Rate Limiting ---

class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window = 60.0
        with self._lock:
            self.requests[key] = [t for t in self.requests[key] if now - t < window]
            if len(self.requests[key]) >= self.requests_per_minute:
                return False
            self.requests[key].append(now)
            return True

_rate_limiter = RateLimiter()
_ai_rate_limiter = RateLimiter(requests_per_minute=10)

# --- State ---

_log_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
_scan_state: Dict[str, Any] = {}
_cancel_requested = threading.Event()
_active_scan_task: Optional[asyncio.Task] = None
_scan_lock = asyncio.Lock()

# --- Middleware & Auth ---

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

async def verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> bool:
    config = get_config()
    if not config.security.require_auth:
        return True
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing auth")
    if credentials.credentials != config.security.api_token:
        raise HTTPException(status_code=401, detail="Invalid token")
    return True

async def check_rate_limit(request: Request) -> None:
    if not _rate_limiter.is_allowed(get_client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

async def check_ai_rate_limit(request: Request) -> None:
    if not _ai_rate_limiter.is_allowed(get_client_ip(request)):
        raise HTTPException(status_code=429, detail="AI rate limit exceeded")

@app.on_event("startup")
def startup_event():
    config = get_config()
    setup_logging(config)
    logger.info(f"SentinelForge API Starting on {config.api_host}:{config.api_port}")
    
    # Async DB Init
    db = Database.instance()
    # await db.init() # This needs to be awaited in an async context

def setup_cors():
    config = get_config()
    # Simplified CORS for dev
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], # For local dev simplicity
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
setup_cors()

# --- Helpers ---

def _log_sink_sync(msg: str) -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(lambda: _log_queue.put_nowait(msg) if not _log_queue.full() else None)
    except Exception:
        pass
    
    try:
        # Bridge to TaskRouter for SSE
        TaskRouter.instance().ui_event.emit("log", {"line": msg})
    except Exception:
        pass

def _ai_status() -> Dict[str, Any]:
    try:
        return AIEngine.instance().status()
    except Exception as e:
        return {"connected": False, "error": str(e)}

def _get_latest_results() -> Dict[str, Any]:
    from core.findings_store import findings_store
    from core.issues_store import issues_store
    from core.killchain_store import killchain_store
    return {
        "findings": findings_store.get_all(),
        "issues": issues_store.get_all(),
        "killchain_edges": killchain_store.get_all(),
        "scan": _scan_state,
    }

# --- Routes ---

@app.get("/ping")
async def ping():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/status")
async def get_status(_: bool = Depends(verify_token)):
    from core.tools import get_installed_tools, TOOLS
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]
    
    return {
        "status": "ok",
        "scan_running": _active_scan_task is not None and not _active_scan_task.done(),
        "latest_target": _scan_state.get("target"),
        "ai": _ai_status(),
        "tools": {
            "installed": list(installed.keys()),
            "missing": missing,
            "count_installed": len(installed),
            "count_total": len(all_tools),
        },
    }

@app.get("/logs")
async def get_logs(limit: int = 100, _: bool = Depends(verify_token)):
    lines = []
    while not _log_queue.empty() and len(lines) < limit:
        lines.append(_log_queue.get_nowait())
    return {"lines": lines}

@app.get("/results")
async def get_results(_: bool = Depends(verify_token)):
    return _get_latest_results()

@app.post("/scan")
async def start_scan(
    req: ScanRequest,
    _: bool = Depends(verify_token),
    __: None = Depends(check_rate_limit),
):
    global _active_scan_task, _scan_state
    
    async with _scan_lock:
        if _active_scan_task and not _active_scan_task.done():
            if req.force:
                logger.info("Force-killing active scan...")
                _active_scan_task.cancel()
                try:
                    await _active_scan_task
                except asyncio.CancelledError:
                    pass
                _active_scan_task = None
            else:
                raise HTTPException(status_code=409, detail="Scan already running")
        
        _cancel_requested.clear()
        _scan_state = {
            "target": req.target,
            "modules": req.modules,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        
        async def _runner():
            from core.scan_orchestrator import ScanOrchestrator
            orch = ScanOrchestrator(log_fn=_log_sink_sync)
            try:
                await orch.run(req.target, modules=req.modules, cancel_flag=_cancel_requested)
                _scan_state["status"] = "completed"
                _scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
            except asyncio.CancelledError:
                _scan_state["status"] = "cancelled"
            except Exception as e:
                _scan_state["status"] = "error"
                _scan_state["error"] = str(e)
                logger.error(f"Scan error: {e}", exc_info=True)

        _active_scan_task = asyncio.create_task(_runner())
        return JSONResponse(
            {"status": "started", "target": req.target},
            status_code=202,
        )

@app.post("/cancel")
async def cancel_scan(_: bool = Depends(verify_token)):
    if _active_scan_task and not _active_scan_task.done():
        _cancel_requested.set()
        _active_scan_task.cancel()
        return JSONResponse({"status": "cancelling"}, status_code=202)
    raise HTTPException(status_code=409, detail="No active scan")

@app.post("/chat")
async def chat(
    req: ChatRequest,
    request: Request,
    _: bool = Depends(verify_token),
    __: None = Depends(check_ai_rate_limit),
):
    async def _stream():
        full_response = ""
        try:
            for token in AIEngine.instance().stream_chat(req.prompt):
                if await request.is_disconnected():
                    break
                
                # Buffer for EXEC parsing
                full_response += token
                lines = full_response.splitlines()
                for line in lines:
                    if ">>> EXEC:" in line:
                        try:
                            clean_line = line.strip()
                            if clean_line.startswith(">>> EXEC:") and clean_line.endswith("}"):
                                json_str = clean_line.replace(">>> EXEC:", "").strip()
                                action = json.loads(json_str)
                                dispatcher = ActionDispatcher.instance()
                                target = _scan_state.get("target") or "manual-interaction"
                                status = dispatcher.request_action(action, target)
                                if status != "DROPPED":
                                    logger.info(f"Action Requested: {action} -> {status}")
                        except:
                            pass

                payload = json.dumps({"token": token})
                yield f"data: {payload}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error(f"Chat error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")

@app.get("/events")
async def events(request: Request, _: bool = Depends(verify_token)):
    async def _event_stream():
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        
        def _cb(event_type: str, payload: dict) -> None:
            try:
                loop = asyncio.get_running_loop()
                data = json.dumps(payload, default=str)
                msg = f"event: {event_type}\ndata: {data}\n\n"
                loop.call_soon_threadsafe(lambda: q.put_nowait(msg) if not q.full() else None)
            except Exception:
                pass
        
        def _action_cb(aid: str, action: dict) -> None:
            _cb("action_needed", action)
            
        TaskRouter.instance().ui_event.connect(_cb)
        ActionDispatcher.instance().action_needed.connect(_action_cb)
        
        try:
            yield "event: connected\ndata: {}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield data
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            try:
                TaskRouter.instance().ui_event.disconnect(_cb)
                ActionDispatcher.instance().action_needed.disconnect(_action_cb)
            except:
                pass

    return StreamingResponse(_event_stream(), media_type="text/event-stream")

@app.get("/report/generate")
async def generate_report(
    request: Request,
    section: str = Query(default="executive_summary", pattern="^[a-z_]+$"),
    _: bool = Depends(verify_token),
):
    async def _stream():
        try:
            composer = ReportComposer()
            content = await asyncio.to_thread(composer.generate_section, section)
            chunk_size = 512
            for i in range(0, len(content), chunk_size):
                if await request.is_disconnected():
                    break
                chunk = content[i : i + chunk_size]
                payload = json.dumps({"token": chunk})
                yield f"data: {payload}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")

@app.get("/clipboard")
async def get_clipboard(_: bool = Depends(verify_token)):
    try:
        content = pyperclip.paste()
        return {"content": content[:10000]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/actions/{action_id}/{verb}")
async def handle_action(action_id: str, verb: str, _: bool = Depends(verify_token)):
    dispatcher = ActionDispatcher.instance()
    success = False
    if verb == "approve":
        success = dispatcher.approve_action(action_id)
    elif verb == "deny":
        success = dispatcher.deny_action(action_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Action not found")
    return {"status": "ok", "action_id": action_id, "result": verb}

@app.websocket("/ws/terminal")
async def terminal_websocket(websocket: WebSocket):
    config = get_config()
    if not config.security.terminal_enabled:
        await websocket.close(code=4003)
        return

    await websocket.accept()
    pty_session = PTYManager.instance().get_session()
    
    async def read_pty():
        try:
            while True:
                data = await asyncio.to_thread(pty_session.read)
                if data:
                    await websocket.send_text(data.decode(errors="ignore"))
                else:
                    await asyncio.sleep(0.01)
        except:
            pass
    
    reader_task = asyncio.create_task(read_pty())
    try:
        while True:
            msg = await websocket.receive_text()
            if msg.startswith("{"):
                try:
                    cmd = json.loads(msg)
                    if cmd.get("type") == "resize":
                        pty_session.resize(cmd.get("rows", 24), cmd.get("cols", 80))
                        continue
                except:
                    pass
            pty_session.write(msg)
    except WebSocketDisconnect:
        pass
    finally:
        reader_task.cancel()

def serve(port: Optional[int] = None, host: Optional[str] = None):
    config = get_config()
    uvicorn.run(app, host=host or config.api_host, port=port or config.api_port, log_level="info")

if __name__ == "__main__":
    serve()
