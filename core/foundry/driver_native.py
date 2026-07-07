"""
core/foundry/driver_native.py — Phase 7-PF11: Ghost Native Driver (SND)

Implements the Foundry's Driver protocol (PF3) by proxying commands to the
Swift UI Execution Node over the WebSocket bridge.
This provides physical OS-level inputs in a native WKWebView, completely
bypassing CDP detection mechanisms.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from core.server.routers.driver import node_manager

logger = logging.getLogger(__name__)


class GhostNativeDriver:
    """A Driver (PF3 protocol) backed by the Sentinel Native Driver (SND) Swift Node."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._is_closed = False

    @classmethod
    async def launch(
        cls, *, headless: bool = False, default_timeout_ms: int = 15000,
        user_agent: Optional[str] = None,
    ) -> "GhostNativeDriver":
        """Request the Swift UI to open a new GhostBrowser window."""
        session_id = str(uuid.uuid4())
        logger.info("[snd-driver] Requesting new native session %s", session_id)
        
        payload = {
            "request_id": str(uuid.uuid4()),
            "command": "launch",
            "session_id": session_id,
            "args": {
                "headless": headless,
                "user_agent": user_agent
            }
        }
        await node_manager.send_command(payload, timeout=5.0)
        return cls(session_id=session_id)

    async def _send(self, command: str, args: Optional[Dict[str, Any]] = None, timeout: float = 30.0) -> Any:
        if self._is_closed:
            raise RuntimeError("Driver is closed")
            
        payload = {
            "request_id": str(uuid.uuid4()),
            "command": command,
            "session_id": self.session_id,
            "args": args or {}
        }
        return await node_manager.send_command(payload, timeout=timeout)

    # ── Driver protocol ──

    async def navigate(self, url: str) -> None:
        await self._send("navigate", {"url": url}, timeout=60.0)

    async def fill(self, selector: Dict[str, str], value: str) -> None:
        await self._send("fill", {"selector": selector, "value": value})

    async def click(self, selector: Dict[str, str]) -> None:
        await self._send("click", {"selector": selector})

    async def wait_for(self, selector: Dict[str, str], timeout_s: float) -> None:
        # We enforce the wait on the Swift side
        await self._send("wait_for", {"selector": selector, "timeout_s": timeout_s}, timeout=timeout_s + 5.0)

    async def extract(self, selector: Dict[str, str], mode: str) -> str:
        return await self._send("extract", {"selector": selector, "mode": mode})

    async def eval(self, js: str) -> Any:
        return await self._send("eval", {"js": js})

    async def screenshot(self) -> bytes:
        try:
            # Swift node should return base64 encoded png
            import base64
            b64 = await self._send("screenshot")
            return base64.b64decode(b64) if b64 else b64
        except Exception as e:
            logger.warning("[snd-driver] screenshot failed: %s", e)
            return b""

    async def current_url(self) -> str:
        return await self._send("current_url")

    # ── Recording ──
    
    async def start_recording(self) -> None:
        """Instructs the node to inject the recording hooks and stream events back."""
        await self._send("start_recording", timeout=10.0)

    async def wait_for_close(self) -> None:
        """Wait until the node reports that the window has been closed."""
        # Wait indefinitely for the window to close
        await self._send("wait_for_close", timeout=86400.0)

    # ── lifecycle ──

    async def close(self) -> None:
        if self._is_closed:
            return
        self._is_closed = True
        try:
            await self._send("close", timeout=3.0)
        except Exception as e:
            logger.warning("[snd-driver] close failed: %s", e)
