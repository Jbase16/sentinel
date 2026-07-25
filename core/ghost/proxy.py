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
import os
import threading
from typing import Optional

from mitmproxy import options, http
from mitmproxy.tools.dump import DumpMaster
from core.base.session import ScanSession
from core.ai.strategy import StrategyEngine

logger = logging.getLogger(__name__)

# Preferred, STABLE proxy port. The capture browser pins --proxy-server at
# launch, so a random port per Start would orphan the browser on every
# restart (and historically left zombie listeners behind). A fixed port keeps
# capture windows valid across restarts. Falls back to an ephemeral port only
# if this one is taken. Override with SENTINEL_GHOST_PORT.
DEFAULT_GHOST_PORT = int(os.getenv("SENTINEL_GHOST_PORT", "8787"))

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

        # [DECONFLICTION HEADER]
        # HackerOne's policy (and most programs) require an identifying header
        # on ALL test traffic so the program can attribute it to you. We stamp
        # every OUTBOUND request with it. Disabled unless a value is set.
        #   SENTINEL_GHOST_BB_HEADER  -> header name  (default "X-Bug-Bounty")
        #   SENTINEL_GHOST_BB_VALUE   -> header value (e.g. your H1 handle)
        self._bb_header = os.getenv("SENTINEL_GHOST_BB_HEADER", "X-Bug-Bounty").strip()
        self._bb_value = os.getenv("SENTINEL_GHOST_BB_VALUE", "").strip()
        if self._bb_value:
            logger.info(
                "[Ghost] deconfliction header enabled: %s: %s",
                self._bb_header, self._bb_value,
            )

        logger.info("[Ghost] CAL integration enabled - traffic will emit Evidence")

    def request(self, flow: http.HTTPFlow):
        """
        Intercept requests to identify new endpoints/params.
        Emits CAL Evidence for every request.
        Phase 4-G2: also feeds the FlowMapper for any active recordings.
        """
        # ── Read the essentials up front (cheap; must not fail) ──────────
        try:
            url = flow.request.pretty_url
            method = flow.request.method
            host = flow.request.host
        except Exception as e:
            logger.error(f"[Ghost] request: unreadable flow, skipping: {e}")
            return

        # ── Deconfliction header (bug-bounty attribution) ────────────────
        # Stamp every outbound request so the program can identify our test
        # traffic. Unlike response handling, modifying the OUTBOUND request is
        # intended here — it's the whole point of the deconfliction marker.
        if self._bb_value:
            try:
                flow.request.headers[self._bb_header] = self._bb_value
            except Exception:
                pass

        # ═══════════════════════════════════════════════════════════════
        # SCOPE ENFORCEMENT GUARD (security — runs before anything else)
        # ═══════════════════════════════════════════════════════════════
        scope_context = getattr(self.session, "scope_context", None)
        if scope_context:
            try:
                from core.base.scope import ScopeDecision
                decision = scope_context.registry.resolve(url)
                is_bounty = scope_context.mode.upper() == "BOUNTY"
                if decision.verdict == ScopeDecision.DENY or (decision.verdict == ScopeDecision.UNKNOWN and is_bounty):
                    logger.warning(f"[Ghost] SCOPE BLOCK - {method} {url} (Reason: {decision.reason_code})")
                    from mitmproxy.http import Response
                    flow.response = Response.make(403, b"Blocked by SentinelForge ScopeGuard")
                    return
            except Exception as e:
                logger.error(f"[Ghost] scope check error: {e}")

        # ═══════════════════════════════════════════════════════════════
        # CAPTURE FIRST — record the step BEFORE any analysis.
        # ═══════════════════════════════════════════════════════════════
        # Recording is the core job of a passive proxy and must never be
        # sacrificed to a downstream analysis failure (a CAL event-contract
        # violation, a strategy/shadow-spec error, etc.). So it runs in its
        # own isolated try, AHEAD of shadow-spec / session-bridge / CAL /
        # strategy. Previously these ran first, and a single contract
        # violation aborted the whole hook — recording nothing.
        try:
            from core.ghost.flow import FlowMapper, MAX_BODY_BYTES
            fm = FlowMapper.instance()
            req_content_type = flow.request.headers.get("content-type", "") or None
            raw_body = flow.request.content or b""
            truncated = len(raw_body) > MAX_BODY_BYTES
            if truncated:
                raw_body = raw_body[:MAX_BODY_BYTES]
            req_body_str = raw_body.decode("utf-8", errors="replace")
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
            if step_ids:
                import time as _t
                flow.metadata["sentinel_step_ids"] = step_ids
                flow.metadata["sentinel_request_start"] = _t.time()
        except Exception as e:
            logger.error(f"[Ghost] step recording failed: {e}")

        # ═══════════════════════════════════════════════════════════════
        # ANALYSIS (best-effort) — MUST NOT be able to abort capture above.
        # ═══════════════════════════════════════════════════════════════
        try:
            self.session.log(f"[Ghost] Intercepted: {method} {url}")

            # [MIMIC] mine the route
            self.shadow_spec.observe(method, url)
            # [SESSION BRIDGE] capture outbound auth tokens/cookies
            self.session_bridge.observe_request(flow)

            # CAL: emit Evidence for this request (traffic is fact)
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
                    run_id=self.session.session_id,
                ),
                confidence=1.0,
            )
            self.reasoning_engine.reasoning_session.evidence[traffic_evidence.id] = traffic_evidence

            # Attack-surface heuristics for parameterized endpoints
            if query:
                self.session.findings.add_finding({
                    "tool": "ghost_proxy",
                    "type": "endpoint_discovery",
                    "severity": "INFO",
                    "target": host,
                    "metadata": {
                        "url": url,
                        "params": list(query.keys()),
                        "method": method,
                        "cal_evidence_id": traffic_evidence.id,
                    }
                })
                # NOTE: We deliberately do NOT spawn per-request LLM strategy
                # analysis here. Doing so (asyncio.create_task(strategy.
                # propose_attacks)) ran an AI call *inside mitmproxy's event
                # loop on every parameterized request*, hit an un-awaited
                # coroutine bug ("object of type 'coroutine' has no len()"),
                # raised "Unhandled error in task", and caused upstream
                # disconnects — which broke the very page being browsed
                # (renders + scrolls, but click handlers never attach).
                # A passive capture proxy must stay lean. Mutation/strategy
                # analysis runs OFFLINE on the recorded flow via the
                # "Propose Mutations" action — no per-request LLM in the
                # interception path.
        except Exception as e:
            logger.error(f"[Ghost] Request analysis error (capture unaffected): {e}")

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

            # Lazarus Engine: PASSIVE route analysis only (read-only).
            # The response body is NEVER modified — Ghost is a passive proxy.
            # This is fast static extraction, not an LLM rewrite.
            if self.lazarus.should_process(flow):
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
        """Find a port for the proxy, preferring the STABLE default.

        Tries DEFAULT_GHOST_PORT first so capture-browser windows (which pin
        --proxy-server at launch) stay valid across proxy restarts. Falls back
        to an ephemeral free port only if the stable one is already in use.
        """
        import socket
        # Try the stable preferred port.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(('127.0.0.1', DEFAULT_GHOST_PORT))
            return DEFAULT_GHOST_PORT
        except OSError:
            logger.info(
                "[Ghost] preferred port %d busy; using an ephemeral port",
                DEFAULT_GHOST_PORT,
            )
        finally:
            probe.close()
        # Ephemeral fallback.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            s.listen(1)
            return s.getsockname()[1]

    async def start(self):
        """
        Starts the proxy as an asyncio task.
        """
        opts = options.Options(listen_host='127.0.0.1', listen_port=self.port)

        # Force HTTP/1.1 for interception. mitmproxy's HTTP/2 handling here
        # throws "RECV_PING in state CLOSED" and disconnects upstream
        # connections; when a site's scripts ride those dropped H2 streams
        # they fail to load and the page renders but its click handlers never
        # attach (scroll works, clicks don't). HTTP/1.1 is slower but far more
        # reliable for capture, and is what Burp/ZAP recommend for stability.
        for _opt in ("http2", "http2_priority"):
            try:
                setattr(opts, _opt, False)
            except Exception:
                pass

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

    async def stop(self):
        """Shut the proxy down and RELEASE THE PORT.

        BUG THIS FIXES: the previous version called master.shutdown() and then
        IMMEDIATELY task.cancel(), cancelling the run task before mitmproxy
        finished closing its listening socket. That leaked the port — every
        Start/Stop left a zombie listener that still accepted connections but
        reset every upstream TLS handshake (SSL_ERROR_SYSCALL). A capture
        browser pointed at a zombie would load nothing / render a dead page.

        FIX: explicitly close the proxyserver's listener (in mitmproxy 12 the
        socket is owned by the proxyserver addon's Servers and is NOT freed
        just by master.shutdown()/run() returning — verified: the port stayed
        bound across stop cycles). We reconfigure to ZERO servers, which closes
        the socket, THEN signal shutdown and await the run task.
        """
        # 1. Close the listener socket(s) — frees the port. mitmproxy 12.
        if self.master:
            try:
                ps = self.master.addons.get("proxyserver")
                if ps is not None and getattr(ps, "servers", None) is not None:
                    await ps.servers.update([])
            except Exception as e:
                logger.warning(f"[Ghost] proxyserver close error: {e}")

        # 2. Signal the master to exit.
        if self.master:
            try:
                self.master.shutdown()
            except Exception as e:
                logger.warning(f"[Ghost] master.shutdown() error: {e}")

        task = self._task
        if task is not None and not task.done():
            try:
                # Let the master close its listener cleanly. Do NOT cancel
                # first — cancelling mid-shutdown is exactly what leaked the
                # socket. shield() so our wait_for timeout doesn't cancel the
                # underlying task prematurely.
                await asyncio.wait_for(asyncio.shield(task), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("[Ghost] master did not exit in 5s; force-cancelling")
                task.cancel()
                try:
                    await task
                except BaseException:
                    pass
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.warning(f"[Ghost] stop wait error: {e}")

        self._task = None
        self.master = None
        logger.info("[*] Ghost Protocol Deactivated (port released).")

