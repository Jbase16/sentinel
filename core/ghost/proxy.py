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
    Now equipped with Neural Strategy Engine, MIMIC Shadow Spec, AND CAL Integration.
    
    CAL INTEGRATION:
    Every intercepted request/response is emitted as Evidence to the central
    ReasoningSession, enabling cross-component reasoning.
    """
    def __init__(self, session: ScanSession):
        """Function __init__."""
        self.session = session
        
        # Lazy load Lazarus
        from core.ghost.lazarus import LazarusEngine
        self.lazarus = LazarusEngine.instance()

        # [MIMIC INTEGRATION]
        # The Shadow Spec (Dynamic OpenAPI Store)
        from core.sentient.mimic.shadow_spec import ShadowSpec
        self.shadow_spec = ShadowSpec()
        
        self.strategy = StrategyEngine(session, shadow_spec=self.shadow_spec)
        
        # [CAL INTEGRATION]
        # Get the global ReasoningEngine for system-wide claims
        from core.cortex.reasoning import get_reasoning_engine
        self.reasoning_engine = get_reasoning_engine()
        
        # [SESSION BRIDGE]
        # Intercept auth headers and cookies for Wraith tools
        from core.wraith.session_bridge import SessionBridge
        self.session_bridge = SessionBridge(session)
        
        logger.info("[Ghost] CAL integration enabled - traffic will emit Evidence")

    def request(self, flow: http.HTTPFlow):
        """
        Intercept requests to identify new endpoints/params.
        Emits CAL Evidence for every request.
        Phase 4-G2: also feeds the FlowMapper for any active recordings.
        """
        try:
            url = flow.request.pretty_url
            method = flow.request.method
            host = flow.request.host

            # ═══════════════════════════════════════════════════════════════
            # SCOPE ENFORCEMENT GUARD
            # ═══════════════════════════════════════════════════════════════
            scope_context = getattr(self.session, "scope_context", None)
            if scope_context:
                from core.base.scope import ScopeDecision
                decision = scope_context.registry.resolve(url)
                is_bounty = scope_context.mode.upper() == "BOUNTY"
                if decision.verdict == ScopeDecision.DENY or (decision.verdict == ScopeDecision.UNKNOWN and is_bounty):
                    logger.warning(f"[Ghost] SCOPE BLOCK - {method} {url} (Reason: {decision.reason_code})")
                    from mitmproxy.http import Response
                    flow.response = Response.make(403, b"Blocked by SentinelForge ScopeGuard")
                    return

            # 1. Log the 'Sight'
            msg = f"[Ghost] Intercepted: {method} {url}"
            self.session.log(msg)

            # [MIMIC INTEGRATION]
            # Mine the Route
            self.shadow_spec.observe(method, url)

            # [SESSION BRIDGE]
            # Capture outbound authentication tokens/cookies
            self.session_bridge.observe_request(flow)

            # ═══════════════════════════════════════════════════════════════
            # PHASE 4-G2: Feed the FlowMapper for any active recordings.
            # ═══════════════════════════════════════════════════════════════
            # The addon observes every request. Each active recording flow
            # gets a step recorded. We stash the per-flow step_ids on the
            # mitmproxy flow's metadata so the response hook can finalize
            # the SAME steps when the response lands.
            from core.ghost.flow import FlowMapper, MAX_BODY_BYTES
            fm = FlowMapper.instance()
            req_content_type = flow.request.headers.get("content-type", "") or None
            # Capture request body, capped at MAX_BODY_BYTES to keep flow
            # files reasonably sized. We always decode UTF-8 with replace
            # so binary uploads don't blow up json.dump downstream.
            raw_body = flow.request.content or b""
            truncated = len(raw_body) > MAX_BODY_BYTES
            if truncated:
                raw_body = raw_body[:MAX_BODY_BYTES]
            req_body_str = raw_body.decode("utf-8", errors="replace")
            # Params: union of query and form-data (best-effort — mitmproxy
            # parses these for us).
            params: dict = {}
            try:
                params.update(dict(flow.request.query) if flow.request.query else {})
            except Exception:
                pass
            try:
                if flow.request.urlencoded_form:
                    params.update(dict(flow.request.urlencoded_form))
            except Exception:
                pass
            step_ids = fm.record_request_to_all(
                method=method,
                url=url,
                params=params,
                headers={k: v for k, v in flow.request.headers.items()},
                request_body=req_body_str,
                request_body_truncated=truncated,
                request_content_type=req_content_type,
            )
            # Stash on the mitmproxy flow object so response() can find
            # them. mitmproxy lets us attach arbitrary attributes to
            # flow.metadata (a dict).
            if step_ids:
                flow.metadata["sentinel_step_ids"] = step_ids
                # Record the request-start time for elapsed_ms math in
                # response().
                import time as _t
                flow.metadata["sentinel_request_start"] = _t.time()
            
            # ═══════════════════════════════════════════════════════════════
            # CAL INTEGRATION: Emit Evidence for this request
            # ═══════════════════════════════════════════════════════════════
            # Every HTTP request is a data point that can support/dispute claims.
            # For example:
            #   - If strategy claimed "user_id param exists", this evidence proves it
            #   - If we see auth headers, we have evidence of authentication scheme
            #
            query = flow.request.query
            from core.cal.types import Evidence, Provenance
            traffic_evidence = Evidence(
                content={
                    "method": method,
                    "url": url,
                    "host": host,
                    "params": list(query.keys()) if query else [],
                    "has_auth": "authorization" in [h.lower() for h in flow.request.headers.keys()],
                    "content_type": flow.request.headers.get("content-type", ""),
                },
                description=f"HTTP Request: {method} {url}",
                provenance=Provenance(
                    source="Ghost:request",
                    method="traffic_interception",
                    run_id=self.session.session_id
                ),
                confidence=1.0  # Traffic is fact
            )
            
            # Add to the global reasoning session
            self.reasoning_engine.reasoning_session.evidence[traffic_evidence.id] = traffic_evidence
            logger.debug(f"[CAL] Ghost emitted request Evidence: {traffic_evidence.id}")
            
            # 2. Analyze Attack Surface (Quick Heuristics)
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
                        "method": method,
                        "cal_evidence_id": traffic_evidence.id  # Link to CAL
                    }
                })

                # 3. TRIGGER NEURAL STRATEGY (The God Tier Logic)
                if self.session.ghost and self.session.ghost._task:
                     flow_data = {
                         "url": url,
                         "method": method,
                         "host": host,
                         "params": list(query.keys())
                     }
                     asyncio.create_task(self.strategy.propose_attacks(flow_data))
                
        except Exception as e:
            logger.error(f"[Ghost] Request processing error: {e}")

    async def response(self, flow: http.HTTPFlow):
        """
        Intercept responses to identify tech stack / leaks.
        Phase 4-G2: also finalizes the FlowMapper steps the request hook
        started, populating response status / headers / body / timing /
        cookies-after-step.
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

            # [SESSION BRIDGE]
            # Capture inbound Set-Cookie authentication
            self.session_bridge.observe_response(flow)

            # ═══════════════════════════════════════════════════════════════
            # PHASE 4-G2: finalize FlowMapper steps with response data.
            # ═══════════════════════════════════════════════════════════════
            step_ids = flow.metadata.get("sentinel_step_ids") if flow.metadata else None
            if step_ids:
                from core.ghost.flow import FlowMapper, MAX_BODY_BYTES
                import time as _t
                fm = FlowMapper.instance()
                resp_content_type = flow.response.headers.get("content-type", "") or None
                raw_resp = flow.response.content or b""
                truncated = len(raw_resp) > MAX_BODY_BYTES
                if truncated:
                    raw_resp = raw_resp[:MAX_BODY_BYTES]
                resp_body_str = raw_resp.decode("utf-8", errors="replace")
                started = flow.metadata.get("sentinel_request_start")
                elapsed_ms = None
                if started:
                    try:
                        elapsed_ms = (_t.time() - float(started)) * 1000.0
                    except Exception:
                        pass
                resp_headers = {k: v for k, v in flow.response.headers.items()}
                for sid in step_ids:
                    fm.finalize_step(
                        sid,
                        status=int(flow.response.status_code),
                        headers=resp_headers,
                        body=resp_body_str,
                        body_truncated=truncated,
                        content_type=resp_content_type,
                        elapsed_ms=elapsed_ms,
                    )

            # Lazarus Engine: De-obfuscation (async)
            # We await this so the response is held until the AI is done rewriting it
            if self.lazarus.should_process(flow):
                self.session.log(f"[Lazarus] De-obfuscating JS: {flow.request.pretty_url}")
                await self._process_lazarus(flow)

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
        try:
            await self.master.run()
        except SystemExit:
            logger.info("[Ghost] Proxy stopped (SystemExit).")
        except Exception as e:
            logger.error(f"[Ghost] Proxy error: {e}")
            self.session.log(f"Ghost Proxy error: {e}")
        except BaseException as e:
             # Catch Any other hard crash (KeyboardInterrupt etc)
             logger.warning(f"[Ghost] Proxy hard stop: {e}")

    def stop(self):
        """Shutdown the proxy gracefully."""
        # Conditional branch.
        if self.master:
            self.master.shutdown()
        # Conditional branch.
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("[*] Ghost Protocol Deactivated.")

