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



from core.base.config import get_config, setup_logging
from core.ai.ai_engine import AIEngine
from core.base.task_router import TaskRouter
from core.cortex.reasoning import ReasoningEngine, reasoning_engine
from core.cortex.events import EventStore, get_event_store, GraphEventType
from core.wraith.evasion import WraithEngine
from core.ghost.flow import FlowMapper
from core.forge.compiler import ExploitCompiler
from core.forge.sandbox import SandboxRunner
from core.chat.chat_engine import GraphAwareChat
from core.engine.orchestrator import Orchestrator
from core.base.action_dispatcher import ActionDispatcher
from core.ai.reporting import ReportComposer
from core.engine.pty_manager import PTYManager
from core.data.db import Database

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

# --- SSE Event Buffer for late-connecting clients ---

class EventBuffer:
    """Circular buffer to store recent SSE events for replay to late-connecting clients."""
    
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def add(self, event_type: str, payload: dict) -> None:
        """Add an event to the buffer."""
        with self._lock:
            self._buffer.append({
                "type": event_type,
                "payload": payload,
                "timestamp": time.time()
            })
            # Keep buffer size in check
            if len(self._buffer) > self.max_size:
                self._buffer = self._buffer[-self.max_size:]
    
    def get_recent(self, since_timestamp: float = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent events, optionally filtered by timestamp."""
        with self._lock:
            events = [e for e in self._buffer if e["timestamp"] > since_timestamp]
            return events[-limit:]
    
    def clear(self) -> None:
        """Clear all buffered events."""
        with self._lock:
            self._buffer.clear()

_event_buffer = EventBuffer(max_size=200)

# --- Session Manager ---

_session_manager: Dict[str, Any] = {}
_session_manager_lock = asyncio.Lock()

async def register_session(session_id: str, session) -> None:
    """Register a session for tracking."""
    async with _session_manager_lock:
        _session_manager[session_id] = session

async def get_session(session_id: str):
    """Get a session by ID."""
    async with _session_manager_lock:
        return _session_manager.get(session_id)

async def unregister_session(session_id: str) -> None:
    """Unregister a session."""
    async with _session_manager_lock:
        if session_id in _session_manager:
            del _session_manager[session_id]

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
async def startup_event():
    config = get_config()
    setup_logging(config)
    logger.info(f"SentinelForge API Starting on {config.api_host}:{config.api_port}")
    
    # Async DB Init
    db = Database.instance()
    await db.init()  # Ensure DB is ready before requests

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
        # Bridge to TaskRouter for SSE AND buffer for late-connecting clients
        event_payload = {"line": msg}
        TaskRouter.instance().ui_event.emit("log", event_payload)
        _event_buffer.add("log", event_payload)
    except Exception:
        pass

def _ai_status() -> Dict[str, Any]:
    try:
        return AIEngine.instance().status()
    except Exception as e:
        return {"connected": False, "error": str(e)}

def _get_latest_results_sync() -> Dict[str, Any]:
    """Synchronous version for non-async contexts."""
    from core.data.findings_store import findings_store
    from core.data.issues_store import issues_store
    from core.data.killchain_store import killchain_store
    return {
        "findings": findings_store.get_all(),
        "issues": issues_store.get_all(),
        "killchain_edges": killchain_store.get_all(),
        "scan": _scan_state,
    }

async def _get_latest_results() -> Dict[str, Any]:
    from core.data.findings_store import findings_store
    from core.data.issues_store import issues_store
    from core.data.killchain_store import killchain_store
    
    # Use session-scoped stores if available, otherwise fallback to global singletons
    session_id = _scan_state.get("session_id")
    
    if session_id:
        # Session-based query using session manager
        session = await get_session(session_id)
        if session:
            return {
                "findings": session.findings.get_all(),
                "issues": session.issues.get_all(),
                "killchain": {"edges": session.killchain.get_all()},  # Nested to match Swift
                "scan": _scan_state,
                "session_id": session_id,
            }
    
    # Fallback to global stores (legacy behavior or no session)
    return {
        "findings": findings_store.get_all(),
        "issues": issues_store.get_all(),
        "killchain": {"edges": killchain_store.get_all()},  # Nested to match Swift Killchain struct
        "scan": _scan_state,
    }

# --- Routes ---

@app.get("/ping")
async def ping():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/status")
async def get_status(_: bool = Depends(verify_token)):
    from core.toolkit.tools import get_installed_tools, TOOLS
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

@app.get("/tools/status")
async def tools_status(_: bool = Depends(verify_token)):
    from core.toolkit.tools import get_installed_tools, TOOLS
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]
    payload = {
        "installed": list(installed.keys()),
        "missing": missing,
        "count_installed": len(installed),
        "count_total": len(all_tools),
    }
    # Also emit a UI event so the Tools tab can update via SSE if connected
    try:
        TaskRouter.instance().emit_ui_event("tools_status", payload)
    except Exception:
        pass
    return {"tools": payload}

@app.get("/logs")
async def get_logs(limit: int = 100, _: bool = Depends(verify_token)):
    lines = []
    session_id = _scan_state.get("session_id")
    
    # First try to get session-specific logs
    if session_id:
        session = await get_session(session_id)
        if session and hasattr(session, "logs"):
            # Return session logs (most recent first, respecting limit)
            lines = session.logs[-limit:] if len(session.logs) > limit else session.logs
            return {"lines": lines, "session_id": session_id}
    
    # Fallback to global queue for legacy behavior
    while not _log_queue.empty() and len(lines) < limit:
        lines.append(_log_queue.get_nowait())
    return {"lines": lines}

@app.get("/results")
async def get_results(_: bool = Depends(verify_token)):
    return await _get_latest_results()

@app.get("/cortex/graph")
async def get_cortex_graph(_: bool = Depends(verify_token)):
    from core.cortex.memory import KnowledgeGraph
    return KnowledgeGraph.instance().export_json()

@app.get("/cortex/reasoning")
async def get_cortex_reasoning(_: bool = Depends(verify_token)):
    return reasoning_engine.analyze()

# --- God-Tier Endpoints ---

@app.post("/wraith/evade")
async def wraith_evade(
    target: str, 
    payload: str, 
    _: bool = Depends(verify_token)
):
    """
    Trigger the Autonomous Evasion Loop.
    """
    import httpx
    async with httpx.AsyncClient() as client:
        return await WraithEngine.instance().stealth_send(client, target, "GET", payload)

@app.post("/ghost/record/{flow_name}")
async def ghost_record(flow_name: str, _: bool = Depends(verify_token)):
    """
    Start recording a user flow for Logic Fuzzing.
    """
    fid = FlowMapper.instance().start_recording(flow_name)
    return {"status": "recording", "flow_id": fid}

@app.post("/forge/compile")
async def forge_compile(
    target: str,
    anomaly: str,
    _: bool = Depends(verify_token)
):
    """
    Trigger the JIT Exploit Compiler.
    """
    try:
        script_path = ExploitCompiler.instance().compile_exploit(target, anomaly)
        return {"status": "compiled", "script_path": script_path}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/forge/execute")
async def forge_execute(
    script_path: str,
    _: bool = Depends(verify_token)
):
    """
    Execute a compiled exploit in the sandbox.
    """
    result = await SandboxRunner.run(script_path)
    return result

# --- Command Deck Endpoints ---

class InstallRequest(BaseModel):
    tools: List[str]

@app.post("/tools/install")
async def tools_install(req: InstallRequest, _: bool = Depends(verify_token)):
    """
    Install selected tools using Homebrew or pip (best-effort).
    Returns per-tool status. The process output tail is included for diagnostics.
    """
    from core.toolkit.tools import install_tools, get_installed_tools, TOOLS
    # Notify UI: installation started
    try:
        TaskRouter.instance().emit_ui_event("tools_install_started", {"tools": req.tools})
    except Exception:
        pass

    results = await install_tools(req.tools)

    # Compute updated tool status
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]
    status_payload = {
        "installed": list(installed.keys()),
        "missing": missing,
        "count_installed": len(installed),
        "count_total": len(all_tools),
    }

    # Emit UI events so the Tools tab updates live
    try:
        TaskRouter.instance().emit_ui_event("tools_install_result", {"results": results})
        TaskRouter.instance().emit_ui_event("tools_status", status_payload)
    except Exception:
        pass

    return {"results": results, "tools": status_payload}

@app.post("/tools/uninstall")
async def tools_uninstall(req: InstallRequest, _: bool = Depends(verify_token)):
    """
    Uninstall selected tools using Homebrew or pip (best-effort).
    """
    from core.toolkit.tools import uninstall_tools, get_installed_tools, TOOLS
    
    results = await uninstall_tools(req.tools)

    # Compute updated tool status
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]
    status_payload = {
        "installed": list(installed.keys()),
        "missing": missing,
        "count_installed": len(installed),
        "count_total": len(all_tools),
    }

    # Emit UI events
    try:
        TaskRouter.instance().emit_ui_event("tools_status", status_payload)
    except Exception:
        pass

    return {"results": results, "tools": status_payload}

@app.post("/chat/query")
async def chat_query(
    question: str,
    _: bool = Depends(verify_token)
):
    """
    Context-Aware RAG Chat.
    """
    answer = GraphAwareChat.instance().query(question)
    return {"response": answer}

@app.post("/mission/start")
async def mission_start(
    target: str,
    _: bool = Depends(verify_token)
):
    """
    The ONE-CLICK Button. Starts the full autonomous loop.
    """
    mission_id = await Orchestrator.instance().start_mission(target)
    return {"status": "started", "mission_id": mission_id}

# --- WebSockets ---

@app.websocket("/ws/graph")
async def ws_graph_endpoint(websocket: WebSocket):
    await websocket.accept()
    from core.cortex.memory import KnowledgeGraph
    try:
        while True:
            # Stream the graph state every 500ms
            graph_data = KnowledgeGraph.instance().export_json()
            await websocket.send_json(graph_data)
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        logger.info("Graph WS disconnected")

@app.websocket("/ws/terminal")
async def ws_terminal_endpoint(websocket: WebSocket):
    await websocket.accept()
    session = PTYManager.instance().get_session()
    
    # Simple loop to pipe PTY output to WS
    try:
        while True:
            output = session.read()
            if output:
                await websocket.send_text(output.decode(errors="ignore"))
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass

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
            from core.engine.scan_orchestrator import ScanOrchestrator
            from core.base.session import ScanSession
            from core.cortex.events import get_event_bus
            
            event_bus = get_event_bus()
            
            # Create a session for this scan to isolate data
            session = ScanSession(req.target)
            _scan_state["session_id"] = session.id
            
            # Register the session with the session manager
            await register_session(session.id, session)
            
            # Emit SCAN_STARTED event
            event_bus.emit_scan_started(req.target, req.modules or [], session.id)
            
            orch = ScanOrchestrator(session=session, log_fn=_log_sink_sync)
            start_time = time.time()
            try:
                await orch.run(req.target, modules=req.modules, cancel_flag=_cancel_requested)
                _scan_state["status"] = "completed"
                _scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
                # Store session summary in scan state
                _scan_state["summary"] = session.to_dict()
                
                # Emit SCAN_COMPLETED event
                duration = time.time() - start_time
                event_bus.emit_scan_completed("completed", len(session.findings), duration)
                
            except asyncio.CancelledError:
                _scan_state["status"] = "cancelled"
                _scan_state["summary"] = session.to_dict()
                
                duration = time.time() - start_time
                event_bus.emit_scan_completed("cancelled", len(session.findings), duration)
                
            except Exception as e:
                _scan_state["status"] = "error"
                _scan_state["error"] = str(e)
                _scan_state["summary"] = session.to_dict()
                logger.error(f"Scan error: {e}", exc_info=True)
                
                # Emit error via event store
                event_bus._store.append(
                    GraphEventType.SCAN_ERROR,
                    {"error": str(e), "target": req.target},
                    source="orchestrator"
                )
                
            finally:
                # Unregister session when scan is complete
                await unregister_session(session.id)

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
                
                full_response += token
                payload = json.dumps({"token": token})
                yield f"data: {payload}\n\n"
            
            # Parse EXEC commands only after streaming completes
            # This avoids issues with JSON split across tokens
            for line in full_response.splitlines():
                if ">>> EXEC:" in line:
                    try:
                        clean_line = line.strip()
                        if clean_line.startswith(">>> EXEC:"):
                            json_str = clean_line.replace(">>> EXEC:", "").strip()
                            action = json.loads(json_str)
                            dispatcher = ActionDispatcher.instance()
                            target = _scan_state.get("target") or "manual-interaction"
                            status = dispatcher.request_action(action, target)
                            if status != "DROPPED":
                                logger.info(f"Action Requested: {action} -> {status}")
                    except json.JSONDecodeError:
                        pass
            
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
        connection_time = time.time()
        
        def _cb(event_type: str, payload: dict) -> None:
            try:
                loop = asyncio.get_running_loop()
                data = json.dumps(payload, default=str)
                msg = f"event: {event_type}\ndata: {data}\n\n"
                loop.call_soon_threadsafe(lambda: q.put_nowait(msg) if not q.full() else None)
                # Also buffer for other late-connecting clients
                _event_buffer.add(event_type, payload)
            except Exception:
                pass
        
        def _action_cb(aid: str, action: dict) -> None:
            _cb("action_needed", action)
            # Buffer action_needed events too
            _event_buffer.add("action_needed", action)
            
        TaskRouter.instance().ui_event.connect(_cb)
        ActionDispatcher.instance().action_needed.connect(_action_cb)
        
        try:
            # Send initial connection event
            yield "event: connected\ndata: {}\n\n"
            
            # CRITICAL: Replay recent buffered events for late-connecting clients
            # Get events from the last 60 seconds (scan might have started before we connected)
            recent_events = _event_buffer.get_recent(since_timestamp=connection_time - 60, limit=50)
            for evt in recent_events:
                data = json.dumps(evt["payload"], default=str)
                yield f"event: {evt['type']}\ndata: {data}\n\n"
            
            # Now stream live events
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


# ============================================================================
# Event-Sourced Reactive Graph Stream (ESRG)
# ============================================================================

@app.get("/events/stream")
async def events_stream(
    request: Request,
    since: int = Query(default=0, description="Sequence number to replay from"),
    _: bool = Depends(verify_token),
):
    """
    Unified SSE stream for all graph events.
    
    This is the primary real-time API for the UI. It:
    1. Replays missed events from `since` sequence
    2. Streams new events as they occur
    3. Sends keepalives every 15s to maintain connection
    
    Event format:
        event: <event_type>
        data: {"id": "...", "type": "...", "sequence": N, "payload": {...}}
    
    The client should track the highest `sequence` received and use it
    as the `since` parameter on reconnection.
    """
    event_store = get_event_store()
    
    async def _generate():
        try:
            # Phase 1: Replay missed events
            missed_events = event_store.get_since(since)
            for event in missed_events:
                if await request.is_disconnected():
                    return
                yield f"event: {event.type.value}\ndata: {event.to_json()}\n\n"
            
            # Phase 2: Stream live events
            async for event in event_store.subscribe():
                if await request.is_disconnected():
                    break
                yield f"event: {event.type.value}\ndata: {event.to_json()}\n\n"
                
        except asyncio.CancelledError:
            logger.debug("[EventStream] Client disconnected")
        except Exception as e:
            logger.error(f"[EventStream] Error: {e}")
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


@app.get("/events/stats")
async def events_stats(_: bool = Depends(verify_token)):
    """Return diagnostic stats about the event store."""
    return get_event_store().stats()

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
    return {"content": "Clipboard unavailable in container environment"}

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

# Terminal WebSocket endpoint with config check
@app.websocket("/ws/pty")
async def terminal_websocket_pty(websocket: WebSocket):
    """Alternative terminal endpoint at /ws/pty for PTY access."""
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
        except Exception:
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
                except json.JSONDecodeError:
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
