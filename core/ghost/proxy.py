#
# PURPOSE:
# This module is part of the ghost package in SentinelForge.
# [Specific purpose based on module name: proxy]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
core/ghost/proxy.py
The Passive Interceptor (Ghost Protocol).
Intersects live traffic and feeds Cortex with real-time attack surface data.
"""

import asyncio
import logging
import threading
from typing import Optional

from mitmproxy import options, http
from mitmproxy.tools.dump import DumpMaster
from core.base.session import ScanSession
from core.ai.strategy import StrategyEngine

logger = logging.getLogger(__name__)

class GhostAddon:
    """
    mitmproxy addon that bridges traffic to the ScanSession.
    Now equipped with Neural Strategy Engine AND MIMIC Shadow Spec.
    """
    def __init__(self, session: ScanSession):
        """Function __init__."""
        self.session = session
        
        # Lazy load Lazarus
        from core.ghost.lazarus import LazarusEngine
        self.lazarus = LazarusEngine.instance()

        # [MIMIC INTEGRATION]
        # The Shadow Spec (Dynamic OpenAPI Store)
        # Ideally this should be persistent on the ScanSession (to be done in refactor)
        # For now, we instantiate it here.
        from core.sentient.mimic.shadow_spec import ShadowSpec
        self.shadow_spec = ShadowSpec()
        
        self.strategy = StrategyEngine(session, shadow_spec=self.shadow_spec)

    def request(self, flow: http.HTTPFlow):
        """
        Intercept requests to identify new endpoints/params.
        """
        # Error handling block.
        try:
            url = flow.request.pretty_url
            method = flow.request.method
            host = flow.request.host
            
            # 1. Log the 'Sight'
            msg = f"[Ghost] Intercepted: {method} {url}"
            self.session.log(msg)

            # [MIMIC INTEGRATION]
            # 1.5 Mine the Route
            self.shadow_spec.observe(method, url)
            
            # 2. Analyze Attack Surface (Quick Heuristics)
            query = flow.request.query
            if query:
                # "Passive Node" discovery
                self.session.findings.add_finding({
                    "tool": "ghost_proxy",
                    "type": "endpoint_discovery",
                    "severity": "INFO",
                    "target": host,
                    "metadata": {
                        "url": url,
                        "params": list(query.keys()),
                        "method": method
                    }
                })

                # 3. TRIGGER NEURAL STRATEGY (The God Tier Logic)
                # Fire and forget analysis
                if self.session.ghost and self.session.ghost._task:
                     # We need to find the main loop. 
                     # self.session.ghost._task.get_loop() might be available?
                     # Safest is to just use asyncio.create_task if we are in the loop.
                     # Since mitmproxy 12 is async, we are in a loop.
                     flow_data = {
                         "url": url,
                         "method": method,
                         "host": host,
                         "params": list(query.keys())
                     }
                     asyncio.create_task(self.strategy.propose_attacks(flow_data))
                
        except Exception as e:
            logger.error(f"[Ghost] Request processing error: {e}")

    def response(self, flow: http.HTTPFlow):
        """
        Intercept responses to identify tech stack / leaks.
        """
        # Error handling block.
        try:
            # Simple header check for now
            server = flow.response.headers.get("Server", "")
            if server:
                self.session.findings.add_finding({
                    "tool": "ghost_proxy",
                    "type": "tech_fingerprint",
                    "severity": "INFO",
                    "target": flow.request.host,
                    "metadata": {"server_header": server}
                })

            # [MIMIC INTEGRATION]
            # Observe Response Body?
            # Doing this carefully to avoid overhead on large binaries
            # For now, simplistic check if JSON
            # if "application/json" in flow.response.headers.get("Content-Type", ""):
            #     # TODO: Decode and pass to self.shadow_spec.observe(..., response_body=json)
            #     pass
            
            # Lazarus Engine: De-obfuscation (async)
            # Note: We use create_task here because mitmproxy's response() hook is sync
            # but LazarusEngine.response() is async (it needs to call AI).
            # This allows the HTTP response to flow through without blocking.
            if self.lazarus.should_process(flow):
                self.session.log(f"[Lazarus] De-obfuscating JS: {flow.request.pretty_url}")
                asyncio.create_task(self._process_lazarus(flow))
                
        except Exception as e:
            logger.error(f"[Ghost] Response processing error: {e}")

    async def _process_lazarus(self, flow: http.HTTPFlow):
        """
        Async helper to process JavaScript de-obfuscation.

        This is called via asyncio.create_task() from the sync response() hook,
        allowing the HTTP response to continue without blocking while AI processes JS.

        Args:
            flow: The HTTP flow containing JavaScript to de-obfuscate

        Side effects:
            - Modifies flow.response.text with de-obfuscated code
            - Adds findings to session on errors
            - Updates Lazarus cache
        """
        try:
            await self.lazarus.response(flow)
        except Exception as e:
            logger.error(f"[Ghost] Lazarus processing failed: {e}")
            # Add finding about the failure
            self.session.findings.add_finding({
                "tool": "ghost_proxy",
                "type": "lazarus_error",
                "severity": "LOW",
                "target": flow.request.host,
                "metadata": {"error": str(e), "url": flow.request.pretty_url}
            })

class GhostInterceptor:
    """
    Manages the background mitmproxy instance.
    """
    def __init__(self, session: ScanSession, port: int = 0):
        """
        Initialize Ghost interceptor.
        
        Args:
            session: The scan session for logging and findings
            port: Port to listen on. 0 means find a free port dynamically.
        """
        self.session = session
        self.port = port if port > 0 else self._find_free_port()
        self.master: Optional[DumpMaster] = None
        self._thread: Optional[threading.Thread] = None
        self._task = None

    @staticmethod
    def _find_free_port() -> int:
        """Find an available port for the proxy."""
        import socket
        # Context-managed operation.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    async def start(self):
        """
        Starts the proxy as an asyncio task.
        """
        opts = options.Options(listen_host='127.0.0.1', listen_port=self.port)
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.master.addons.add(GhostAddon(self.session))
        
        logger.info(f"[*] Ghost Protocol Active on 127.0.0.1:{self.port}")
        self.session.log(f"Ghost Proxy listening on port {self.port}...")

        # Run as async task with error handling
        self._task = asyncio.create_task(self._run_master())

    async def _run_master(self):
        """Run the mitmproxy master with error handling."""
        # Error handling block.
        try:
            await self.master.run()
        except Exception as e:
            logger.error(f"[Ghost] Proxy error: {e}")
            self.session.log(f"Ghost Proxy error: {e}")

    def stop(self):
        """Shutdown the proxy gracefully."""
        # Conditional branch.
        if self.master:
            self.master.shutdown()
        # Conditional branch.
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("[*] Ghost Protocol Deactivated.")

