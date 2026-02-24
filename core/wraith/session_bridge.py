"""
core/wraith/session_bridge.py

The SessionBridge captures authentication material (Cookies, Bearer tokens)
observed passively by the Ghost Protocol proxy and bridges them into the
active PersonaManager so internal tools like AuthDiffScanner can assume
those specific identities without requiring explicit login flows.
"""

import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from mitmproxy import http

from core.base.session import ScanSession
from core.wraith.personas import Persona, PersonaType
from core.wraith.session_manager import AuthSessionManager

logger = logging.getLogger(__name__)


class SessionBridge:
    """
    Bridges authentication material from Passive observation (Ghost)
    to Active usage (PersonaManager/AuthSessionManager).
    """

    def __init__(self, session: ScanSession):
        self.session = session
        self._captured_tokens: Dict[str, str] = {}
        self._captured_cookies: Dict[str, Dict[str, str]] = {}

    def observe_request(self, flow: http.HTTPFlow) -> None:
        """
        Extract authentication material from an intercepted HTTP request.
        Called by GhostAddon.
        """
        host = flow.request.host
        
        # 1. Capture Authorization headers (Bearer tokens)
        auth_header = flow.request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            if token and token not in self._captured_tokens.values():
                logger.info(f"[SessionBridge] Captured new Bearer token for {host}")
                self._captured_tokens[host] = token
                self._update_session_knowledge(host, bearer_token=token)

        # 2. Capture Cookies sent by the client
        cookie_header = flow.request.headers.get("Cookie", "")
        if cookie_header:
            if host not in self._captured_cookies:
                self._captured_cookies[host] = {}
            
            new_cookies = False
            for part in cookie_header.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                    if self._captured_cookies[host].get(k) != v:
                        self._captured_cookies[host][k] = v
                        new_cookies = True
            
            if new_cookies:
                self._update_session_knowledge(host, cookies=self._captured_cookies[host])

    def observe_response(self, flow: http.HTTPFlow) -> None:
        """
        Extract authentication material from an intercepted HTTP response.
        """
        host = flow.request.host
        
        # Capture Set-Cookie headers
        set_cookies = flow.response.headers.get_all("Set-Cookie")
        if set_cookies:
            if host not in self._captured_cookies:
                self._captured_cookies[host] = {}
                
            new_cookies = False
            for cookie_str in set_cookies:
                # Basic parse: "session_id=1234; HttpOnly; Secure" -> "session_id", "1234"
                parts = cookie_str.split(";")
                if "=" in parts[0]:
                    k, v = parts[0].split("=", 1)
                    k = k.strip()
                    v = v.strip()
                    if self._captured_cookies[host].get(k) != v:
                        self._captured_cookies[host][k] = v
                        new_cookies = True
                        
            if new_cookies:
                logger.info(f"[SessionBridge] Captured new Set-Cookie for {host}")
                self._update_session_knowledge(host, cookies=self._captured_cookies[host])

    def _update_session_knowledge(self, host: str, bearer_token: Optional[str] = None, cookies: Optional[Dict[str, str]] = None) -> None:
        """
        Update the central ScanSession knowledge with the captured persona configuration.
        """
        personas_cfg = self.session.knowledge.get("personas", [])
        
        # Find or create the "GhostCaptured" persona
        ghost_persona = None
        for p in personas_cfg:
            if isinstance(p, dict) and p.get("name") == "GhostCaptured":
                ghost_persona = p
                break
                
        if not ghost_persona:
            ghost_persona = {
                "name": "GhostCaptured",
                "type": PersonaType.USER.value,
                "persist": True,
                "cookie_jar": {},
                "bearer_token": None
            }
            personas_cfg.append(ghost_persona)
            self.session.knowledge["personas"] = personas_cfg

        if bearer_token:
            ghost_persona["bearer_token"] = bearer_token
            
        if cookies:
            if "cookie_jar" not in ghost_persona or not isinstance(ghost_persona["cookie_jar"], dict):
                ghost_persona["cookie_jar"] = {}
            ghost_persona["cookie_jar"].update(cookies)
            
        # Re-initialize the AuthSessionManager if it's already running so it picks up the changes
        mgr = self.session.knowledge.get("session_bridge")
        if isinstance(mgr, AuthSessionManager):
            import asyncio
            # We must run this async or schedule it. Since Ghost Addon hooks might be sync,
            # we can inject a reset flag or task to force the manager to reload.
            # Easiest way is to clear its cache so next request rebuilds it.
            mgr._initialized = False
