from __future__ import annotations

import logging
import asyncio
import json
import uuid
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException, Request
from starlette.websockets import WebSocketState

from sse_starlette.sse import EventSourceResponse

from core.base.config import get_config, is_network_exposed
from core.cortex.event_store import get_event_store
from core.engine.pty_manager import PTYManager
from core.server.routers.auth import is_origin_allowed

router = APIRouter(prefix="/ws", tags=["realtime"])
sse_router = APIRouter(tags=["events"])

async def validate_websocket_connection(
    websocket: WebSocket,
    endpoint_name: str,
) -> bool:
    """
    Validate WebSocket connection security.
    """
    config = get_config()
    
    # Origin Check
    origin = websocket.headers.get("origin")
    if origin and not is_origin_allowed(origin, config.security.allowed_origins):
        logger.warning(f"[WebSocket] {endpoint_name} denied origin: {origin}")
        # Reject handshake
        raise HTTPException(status_code=403, detail="Origin not allowed")

    # Auth Check
    is_exposed = is_network_exposed(config.api_host)
    require_auth = is_exposed or config.security.require_auth

    if require_auth:
        token = websocket.query_params.get("token")
        if not token:
            auth_header = websocket.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
        if not token or token != config.security.api_token:
            logger.warning(f"[WebSocket] {endpoint_name} denied: invalid or missing token")
            raise HTTPException(status_code=403, detail="Unauthorized")

    return True

@sse_router.get("/stream")
async def sse_events_endpoint(request: Request):
    """
    Server-Sent Events (SSE) stream for system events.
    Compatible with existing Swift client.
    """
    store = get_event_store()
    
    async def event_generator():
        queue = asyncio.Queue()
        sub_id = store.subscribe(queue.put_nowait)
        try:
            # Check for Last-Event-ID header or query param
            last_id = request.headers.get("last-event-id") or request.query_params.get("since")
            if last_id:
                try:
                    seq = int(last_id)
                    missed = store.get_events_since(seq)
                    for evt in missed:
                        yield {
                            "event": "message",
                            "id": str(evt.sequence),
                            "data": evt.to_json()
                        }
                except ValueError:
                    pass
            
            while True:
                if await request.is_disconnected():
                    break
                evt = await queue.get()
                yield {
                    "event": "message",
                    "id": str(evt.sequence),
                    "data": evt.to_json()
                }
        except asyncio.CancelledError:
            pass
        finally:
            store.unsubscribe(sub_id)

    return EventSourceResponse(event_generator())

@router.websocket("/events")
async def ws_events_endpoint(websocket: WebSocket):
    # ... (existing WS implementation) ...
    await validate_websocket_connection(websocket, "/ws/events")
    await websocket.accept()
    # ... (rest of implementation)

    
    # Handle "since" parameter for event replay
    since_str = websocket.query_params.get("since", "0")
    try:
        last_seq = int(since_str)
    except ValueError:
        last_seq = 0

    store = get_event_store()
    queue = asyncio.Queue()
    
    # Subscribe to new events
    sub_id = store.subscribe(queue.put_nowait)

    try:
        # Replay missed events
        if last_seq >= 0:
            missed = store.get_events_since(last_seq)
            for evt in missed:
                await websocket.send_text(evt.to_json())

        # Stream new events
        while True:
            evt = await queue.get()
            await websocket.send_text(evt.to_json())

    except WebSocketDisconnect:
        logger.debug("[WebSocket] Events client disconnected")
    except Exception as e:
        logger.error(f"[WebSocket] Events stream error: {e}")
    finally:
        store.unsubscribe(sub_id)

@router.websocket("/graph")
async def ws_graph_endpoint(websocket: WebSocket):
    """
    Stream Force-Directed Graph state updates.
    """
    if not await validate_websocket_connection(websocket, "/ws/graph"):
        return

    await websocket.accept()
    
    # Placeholder for graph streaming logic
    # Real implementation would hook into Aegis graph updates
    try:
        while True:
            await asyncio.sleep(5)
            # Heartbeat / Keep-alive
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass

@router.websocket("/pty")
async def terminal_websocket_pty(
    websocket: WebSocket,
    session_id: Optional[str] = Query(None)
):
    """
    Bidirectional PTY access (Terminal Virtual Session).
    """
    config = get_config()
    
    # Feature Flag Check
    if not config.security.terminal_enabled:
        await websocket.close(code=4003, reason="Terminal access disabled by configuration")
        return

    if not await validate_websocket_connection(websocket, "/ws/pty"):
        return

    await websocket.accept()

    pty_mgr = PTYManager.instance()
    
    # Get or Create PTY Session
    if not session_id:
        session_id = str(uuid.uuid4())
        logger.info(f"[PTY] Creating new session {session_id}")
        pty_mgr.create_session(session_id)
    
    # Attach to PTY output stream
    async def output_reader(data: bytes):
        try:
            text = data.decode(errors="replace")
            await websocket.send_text(text)
        except Exception:
            pass

    # Register listener
    listener_id = pty_mgr.attach_listener(session_id, output_reader)
    
    try:
        # Send initial banner/context
        await websocket.send_json({
            "type": "meta",
            "session_id": session_id,
            "connected": True
        })

        # Input Loop
        while True:
            message_text = await websocket.receive_text()
            
            try:
                data = json.loads(message_text)
                msg_type = data.get("type")
                
                if msg_type == "input":
                    # User typed something
                    payload = data.get("data", "")
                    pty_mgr.write_input(session_id, payload)
                    
                elif msg_type == "resize":
                    # Terminal resize event
                    cols = data.get("cols", 80)
                    rows = data.get("rows", 24)
                    pty_mgr.resize(session_id, cols, rows)
                    
                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong"})
                    
            except json.JSONDecodeError:
                # Raw text fallback (assume input)
                pty_mgr.write_input(session_id, message_text)

    except WebSocketDisconnect:
        logger.info(f"[PTY] Client disconnected from {session_id}")
    except Exception as e:
        logger.error(f"[PTY] Error in handler: {e}")
    finally:
        pty_mgr.detach_listener(session_id, listener_id)
