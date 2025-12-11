# core/api.py
# FastAPI Migration - The F1 Engine

import asyncio
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import pyperclip

from core.ai_engine import AIEngine
from core.evidence_store import EvidenceStore
from core.reasoning import reasoning_engine
from core.scan_orchestrator import ScanOrchestrator
from core.tools import get_installed_tools, TOOLS
from core.task_router import TaskRouter
from core.action_dispatcher import ActionDispatcher
from core.reporting import ReportComposer
from core.pty_manager import PTYManager
from core.db import Database

# --- Models ---
class ScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None

class ChatRequest(BaseModel):
    prompt: str

# --- App Setup ---
app = FastAPI(title="SentinelForge API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- State ---
_log_queue: asyncio.Queue = asyncio.Queue()
_scan_state: Dict[str, Any] = {}
_cancel_requested = threading.Event()
_scan_lock = asyncio.Lock()
_active_scan_task: Optional[asyncio.Task] = None

# --- Helpers ---

async def _log_sink_async(msg: str):
    await _log_queue.put(msg)
    # Broadcast to SSE via TaskRouter if needed, or just let SSE listener pick it up
    # Actually, TaskRouter uses Signals which are synchronous. 
    # We need a bridge.
    TaskRouter.instance().ui_event.emit("log", {"line": msg})

def _log_sink_sync(msg: str):
    # Bridge sync callback to async queue via loop
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(_log_queue.put_nowait, msg)
        TaskRouter.instance().ui_event.emit("log", {"line": msg})
    except RuntimeError:
        pass

def _ai_status() -> Dict[str, Any]:
    return AIEngine.instance().status()

def _get_latest_results():
    # In the new architecture, we might just query the Stores directly
    from core.findings_store import findings_store
    from core.issues_store import issues_store
    from core.killchain_store import killchain_store
    
    # We construct the envelope dynamically
    ctx = {
        "findings": findings_store.get_all(),
        "issues": issues_store.get_all(),
        "killchain_edges": killchain_store.get_all(),
        "scan": _scan_state
    }
    return ctx # Simplified for now, can expand to full envelope

# --- Routes ---

@app.get("/ping")
async def ping():
    return {"status": "ok"}

@app.get("/status")
async def status():
    installed = get_installed_tools()
    all_tools = list(TOOLS.keys())
    missing = [t for t in all_tools if t not in installed]
    
    return {
        "status": "ok",
        "scan_running": (_active_scan_task is not None and not _active_scan_task.done()),
        "latest_target": _scan_state.get("target"),
        "ai": _ai_status(),
        "tools": {
            "installed": list(installed.keys()),
            "missing": missing,
            "count_installed": len(installed),
            "count_total": len(all_tools)
        }
    }

@app.get("/logs")
async def get_logs():
    # Legacy poll endpoint support
    lines = []
    while not _log_queue.empty():
        lines.append(_log_queue.get_nowait())
    return {"lines": lines}

@app.get("/results")
async def get_results():
    return _get_latest_results()

@app.post("/scan")
async def start_scan(req: ScanRequest):
    global _active_scan_task, _scan_state
    
    if _active_scan_task and not _active_scan_task.done():
        return JSONResponse({"error": "Scan already running"}, status_code=409)

    _cancel_requested.clear()
    _scan_state = {
        "target": req.target,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat()
    }

    # Run orchestrator in background task
    async def _runner():
        orch = ScanOrchestrator(log_fn=_log_sink_sync)
        try:
            # We need to bridge the async run to the sync dispatcher or update orchestrator to be async native
            # ScanOrchestrator.run IS async!
            await orch.run(req.target, modules=req.modules, cancel_flag=_cancel_requested)
            _scan_state["status"] = "completed"
        except Exception as e:
            _scan_state["status"] = "error"
            _scan_state["error"] = str(e)
            print(f"Scan error: {e}")

    _active_scan_task = asyncio.create_task(_runner())
    return JSONResponse({"status": "started", "target": req.target}, status_code=202)

@app.post("/cancel")
async def cancel_scan():
    if _active_scan_task and not _active_scan_task.done():
        _cancel_requested.set()
        return JSONResponse({"status": "cancelling"}, status_code=202)
    return JSONResponse({"error": "no active scan"}, status_code=409)

@app.post("/chat")
async def chat(req: ChatRequest):
    async def _stream():
        for token in AIEngine.instance().stream_chat(req.prompt):
            payload = json.dumps({"token": token})
            yield f"data: {payload}\n\n"
        yield "data: [DONE]\n\n"
    
    return StreamingResponse(_stream(), media_type="text/event-stream")

@app.get("/events")
async def events(request: Request):
    """
    SSE Endpoint using an async generator and queue bridge.
    """
    async def _event_stream():
        q = asyncio.Queue()
        
        # Define a callback to put into our async queue
        def _cb(event_type, payload):
            # This runs in sync context (Signal), so we must use loop.call_soon_threadsafe
            # But wait, we are in an async handler.
            # We can't await q.put here.
            # We rely on threadsafe put.
            try:
                loop = asyncio.get_running_loop()
                data = json.dumps(payload)
                msg = f"event: {event_type}\ndata: {data}\n\n"
                loop.call_soon_threadsafe(q.put_nowait, msg)
            except Exception as e:
                print(f"Event bridge error: {e}")

        # Connect
        TaskRouter.instance().ui_event.connect(_cb)
        
        # Also hook dispatcher
        def _action_cb(aid, action):
            _cb("action_needed", action)
        ActionDispatcher.instance().action_needed.connect(_action_cb)

        try:
            while True:
                if await request.is_disconnected():
                    break
                data = await q.get()
                yield data
        except asyncio.CancelledError:
            pass
        finally:
            # Cleanup
            TaskRouter.instance().ui_event.disconnect(_cb)
            ActionDispatcher.instance().action_needed.disconnect(_action_cb)

    return StreamingResponse(_event_stream(), media_type="text/event-stream")

@app.get("/report/generate")
async def generate_report(section: str = "executive_summary"):
    async def _stream():
        composer = ReportComposer()
        # ReportComposer is currently sync/blocking (HTTPX is sync in there? No, we updated it to sync generate).
        # We should ideally run it in a threadpool to not block the event loop.
        content = await asyncio.to_thread(composer.generate_section, section)
        
        chunk_size = 1024
        for i in range(0, len(content), chunk_size):
            chunk = content[i:i+chunk_size]
            payload = json.dumps({"token": chunk})
            yield f"data: {payload}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")

@app.get("/clipboard")
async def clipboard():
    try:
        return {"content": pyperclip.paste()}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/actions/{action_id}/{verb}")
async def handle_action(action_id: str, verb: str):
    dispatcher = ActionDispatcher.instance()
    success = False
    if verb == "approve":
        success = dispatcher.approve_action(action_id)
    elif verb == "deny":
        success = dispatcher.deny_action(action_id)
    
    if success:
        return {"status": "ok", "action_id": action_id, "result": verb}
    return JSONResponse({"error": "action not found"}, status_code=404)

# --- WebSocket Terminal ---

@app.websocket("/ws/terminal")
async def terminal_websocket(websocket: WebSocket):
    await websocket.accept()
    pty_session = PTYManager.instance().get_session()
    
    # 1. Reader Loop: PTY -> WebSocket
    async def read_pty():
        try:
            while True:
                # Non-blocking read
                data = await asyncio.to_thread(pty_session.read)
                if data:
                    await websocket.send_text(data.decode(errors="ignore"))
                else:
                    await asyncio.sleep(0.01)
        except Exception:
            pass

    # 2. Writer Loop: WebSocket -> PTY
    reader_task = asyncio.create_task(read_pty())
    
    try:
        while True:
            # Receive input from UI
            msg = await websocket.receive_text()
            # If JSON (resize), handle it
            if msg.startswith("{"):
                try:
                    cmd = json.loads(msg)
                    if cmd.get("type") == "resize":
                        pty_session.resize(cmd["rows"], cmd["cols"])
                        continue
                except:
                    pass
            
            # Write to PTY
            pty_session.write(msg)
    except WebSocketDisconnect:
        pass
    finally:
        reader_task.cancel()
        # Note: We don't close the PTY session automatically here to allow persistence?
        # For now, let's keep it persistent per run.

def serve(port: int = 8765):
    # Initialize DB synchronously-ish (or start task)
    db = Database.instance()
    # We can't await here easily, but we can rely on lazy init
    
    print(f"[sentinel-api] listening on http://127.0.0.1:{port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")

if __name__ == "__main__":
    serve()