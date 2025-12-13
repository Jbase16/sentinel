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
from core.session import ScanSession
from core.ai.strategy import StrategyEngine

logger = logging.getLogger(__name__)

class GhostAddon:
    """
    mitmproxy addon that bridges traffic to the ScanSession.
    Now equipped with Neural Strategy Engine.
    """
    def __init__(self, session: ScanSession):
        self.session = session
        self.strategy = StrategyEngine(session)

    def request(self, flow: http.HTTPFlow):
        """
        Intercept requests to identify new endpoints/params.
        """
        try:
            url = flow.request.pretty_url
            method = flow.request.method
            host = flow.request.host
            
            # 1. Log the 'Sight'
            msg = f"[Ghost] Intercepted: {method} {url}"
            self.session.log(msg)
            
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
        except Exception as e:
            logger.error(f"[Ghost] Response processing error: {e}")

class GhostInterceptor:
    """
    Manages the background mitmproxy instance.
    """
    def __init__(self, session: ScanSession, port: int = 8080):
        self.session = session
        self.port = port
        self.master: Optional[DumpMaster] = None
        self._thread: Optional[threading.Thread] = None

    async def start(self):
        """
        Starts the proxy as an asyncio task.
        """
        opts = options.Options(listen_host='127.0.0.1', listen_port=self.port)
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.master.addons.add(GhostAddon(self.session))
        
        logger.info(f"[*] Ghost Protocol Active on 127.0.0.1:{self.port}")
        self.session.log(f"Ghost Proxy listening on port {self.port}...")

        # Run as async task
        self._task = asyncio.create_task(self.master.run())

    def stop(self):
        if self.master:
            self.master.shutdown()
        logger.info("[*] Ghost Protocol Deactivated.")

    def stop(self):
        if self.master:
            self.master.shutdown()
        logger.info("[*] Ghost Protocol Deactivated.")

