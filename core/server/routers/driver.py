"""
core/server/routers/driver.py — Phase 7-PF11: Sentinel Native Driver (SND) Bridge.

Hosts the WebSocket bridge that connects the Python backend to the
Swift UI Execution Node. This severs the automation driver from the
JS execution environment by relying on physical macOS CGEvent
synthesis inside a pristine WKWebView.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request

logger = logging.getLogger(__name__)

router = APIRouter(tags=["driver"])


class NodeManager:
    """Manages connected Swift execution nodes and routes commands."""
    def __init__(self):
        # We only support one primary connected node for now (the operator's UI).
        self.active_node: Optional[WebSocket] = None
        # request_id -> future waiting for response
        self.pending_responses: Dict[str, asyncio.Future] = {}
        # List of callbacks for spontaneous events
        self.event_handlers = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_node = websocket
        logger.info("[snd-bridge] Swift execution node connected.")

    def disconnect(self, websocket: WebSocket):
        if self.active_node == websocket:
            self.active_node = None
            logger.info("[snd-bridge] Swift execution node disconnected.")
            # Cancel all pending requests
            for fut in self.pending_responses.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("Node disconnected"))
            self.pending_responses.clear()

    async def send_command(self, payload: Dict[str, Any], timeout: float = 30.0) -> Any:
        """Send a command to the swift node and wait for its correlation reply."""
        if self.active_node is None:
            raise RuntimeError("No Swift execution node connected to the SND bridge.")
        
        request_id = payload.get("request_id")
        if not request_id:
            raise ValueError("Payload must contain a request_id for correlation.")
            
        fut = asyncio.get_event_loop().create_future()
        self.pending_responses[request_id] = fut
        
        try:
            await self.active_node.send_text(json.dumps(payload))
            # Wait for response with timeout
            response = await asyncio.wait_for(fut, timeout=timeout)
            if response.get("error"):
                raise RuntimeError(f"Node execution failed: {response['error']}")
            return response.get("result")
        finally:
            self.pending_responses.pop(request_id, None)

    async def handle_response(self, text: str):
        try:
            data = json.loads(text)
            req_id = data.get("request_id")
            if req_id and req_id in self.pending_responses:
                if not self.pending_responses[req_id].done():
                    self.pending_responses[req_id].set_result(data)
            else:
                # Could be a spontaneous event from the node (e.g., recording action)
                event_type = data.get("event")
                if event_type:
                    for handler in self.event_handlers:
                        try:
                            handler(event_type, data)
                        except Exception as ex:
                            logger.error("[snd-bridge] event handler error: %s", ex)
        except Exception as e:
            logger.error("[snd-bridge] failed to handle response: %s", e)

node_manager = NodeManager()

ACTIVE_CAPTURE_PATH = None

# Set up spontaneous event handler for recording and network capture
def _handle_node_event(event_type: str, data: Dict[str, Any]):
    if event_type == "recorded_action":
        action = data.get("action", {})
        if action.get("action") == "network_capture":
            # Append to capture file
            global ACTIVE_CAPTURE_PATH
            if ACTIVE_CAPTURE_PATH:
                capture_file = ACTIVE_CAPTURE_PATH
                os.makedirs(os.path.dirname(capture_file), exist_ok=True)
            else:
                capture_dir = os.path.join(os.getcwd(), "data")
                os.makedirs(capture_dir, exist_ok=True)
                capture_file = os.path.join(capture_dir, "graphql_capture.jsonl")
            try:
                with open(capture_file, "a") as f:
                    f.write(json.dumps(action) + "\n")
            except Exception as e:
                logger.error("[snd-bridge] failed to write network capture: %s", e)

node_manager.event_handlers.append(_handle_node_event)


@router.websocket("/bridge")
async def driver_bridge_endpoint(websocket: WebSocket):
    """The WebSocket upgrade endpoint for the Swift Native Driver node."""
    await node_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await node_manager.handle_response(data)
    except WebSocketDisconnect:
        node_manager.disconnect(websocket)
    except Exception as e:
        logger.error("[snd-bridge] unexpected error: %s", e)
        node_manager.disconnect(websocket)

import uuid
@router.post("/start_capture")
async def start_capture(request: Request):
    global ACTIVE_CAPTURE_PATH
    # Try to get URL from body, fallback to default
    target_url = "https://www.whatnot.com/"
    try:
        body = await request.json()
        target_url = body.get("url", target_url)
        capture_file = body.get("capture_file")
        if capture_file:
            ACTIVE_CAPTURE_PATH = capture_file
            # Clear file for fresh capture
            os.makedirs(os.path.dirname(capture_file), exist_ok=True)
            open(capture_file, "w").close()
    except Exception as e:
        logger.error("[snd-bridge] start_capture err: %s", e)
        
    # Wait for Swift execution node to be connected
    timeout = 10.0
    elapsed = 0.0
    interval = 0.5
    while node_manager.active_node is None and elapsed < timeout:
        await asyncio.sleep(interval)
        elapsed += interval
    if node_manager.active_node is None:
        return {"status": "error", "message": "Swift node not connected"}

    # Launch browser window
    session_id = str(uuid.uuid4())
    await node_manager.send_command({
        "request_id": str(uuid.uuid4()),
        "command": "launch",
        "session_id": session_id,
        "args": {"headless": False}
    }, timeout=5.0)
    
    await asyncio.sleep(2)
    
    await node_manager.send_command({
        "command": "start_network_capture",
        "request_id": str(uuid.uuid4())
    })
    
    await node_manager.send_command({
        "command": "navigate",
        "request_id": str(uuid.uuid4()),
        "args": {"url": target_url}
    })
    
    return {"status": "ok"}

@router.post("/stop_capture")
async def stop_capture():
    global ACTIVE_CAPTURE_PATH
    ACTIVE_CAPTURE_PATH = None
    if node_manager.active_node:
        await node_manager.send_command({
            "request_id": str(uuid.uuid4()),
            "command": "close"
        })
    return {"status": "ok"}
