import asyncio
import logging
import time
from typing import AsyncIterator, MutableMapping
from urllib.parse import urlparse

import httpx
from curl_cffi import requests as curl_requests
from curl_cffi.requests.errors import RequestsError
from curl_cffi.curl import CurlError

from core.foundry.driver_native import GhostNativeDriver
from core.server.routers.driver import node_manager

logger = logging.getLogger(__name__)

class GhostGatewayTransport(httpx.AsyncBaseTransport):
    """
    A persistent, device-attested HTTP proxy layer that severs the browser from the request path.
    Uses curl_cffi to match Safari 15.5 JA3/HTTP2 fingerprints.
    Falls back to the native UI Oracle for cf_clearance cookie harvesting if heavily challenged.
    """
    
    def __init__(self):
        # The Product: A persistent, long-lived session that naturally accumulates edge cookies (__cf_bm).
        self.session = curl_requests.AsyncSession(impersonate="safari")
        # Ensure we don't automatically follow redirects, preserving scanner visibility
        self.session.allow_redirects = False
        
        # Oracle User-Agent to strictly match WebKit native
        self.oracle_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
        
        # Self-Heal Guards
        self._heal_lock = asyncio.Lock()
        self._last_heal_timestamp = 0.0
        self._heal_cooldown = 30.0  # seconds to prevent thundering herd

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        
        response = await self._execute_curl(request)
        
        if self._is_cloudflare_block(response):
            logger.warning("[GhostGateway] Cloudflare block detected. Attempting self-heal via Oracle...")
            healed = await self._trigger_self_heal()
            if healed:
                logger.info("[GhostGateway] Self-heal successful. Retrying request...")
                response = await self._execute_curl(request)
            else:
                logger.warning("[GhostGateway] Self-heal skipped or failed. Passing blocked response to scanner.")
                
        return self._translate_response(response, request)

    async def _execute_curl(self, request: httpx.Request) -> curl_requests.Response:
        """Translates and executes an httpx.Request using the persistent curl_cffi session."""
        
        # Request Translation: Preserve Safari Envelope
        # We strip httpx's default headers so they don't override the impersonated browser envelope.
        stripped_headers = {}
        for k, v in request.headers.items():
            k_lower = k.lower()
            # Drop httpx's default envelope headers to let curl_cffi own the fingerprint
            if k_lower in ("accept", "accept-encoding", "connection"):
                continue
            stripped_headers[k] = v
            
        # Strictly enforce the Oracle UA
        stripped_headers["User-Agent"] = self.oracle_ua
        
        # Translate timeouts
        timeout_val = None
        if request.extensions.get("timeout"):
            # httpx passes a dict like {'connect': 5.0, 'read': 5.0, 'write': 5.0, 'pool': 5.0}
            # curl_cffi takes a single float or tuple
            timeouts = request.extensions["timeout"]
            if isinstance(timeouts, dict):
                timeout_val = timeouts.get("read") or timeouts.get("connect") or 30.0

        try:
            return await self.session.request(
                method=request.method,
                url=str(request.url),
                headers=stripped_headers,
                data=request.content, # raw bytes
                timeout=timeout_val
            )
        except RequestsError as e:
            if "Timeout" in str(e) or "timeout" in str(e).lower():
                raise httpx.ReadTimeout(str(e), request=request) from e
            raise httpx.ConnectError(str(e), request=request) from e
        except CurlError as e:
            if "Timeout" in str(e) or "timeout" in str(e).lower() or getattr(e, "code", 0) == 28: # CURLE_OPERATION_TIMEDOUT
                raise httpx.ReadTimeout(str(e), request=request) from e
            raise httpx.ConnectError(str(e), request=request) from e

    def _is_cloudflare_block(self, response: curl_requests.Response) -> bool:
        """Air-tight detection of Cloudflare edge blocks, ignoring app-level 403s."""
        # 1. Explicit Challenge Header
        if "cf-mitigated" in response.headers:
            return True
            
        # 2. Worker threw exception (often happens when JA3 passes but signature lacks cookies)
        if response.status_code == 500 and "Worker threw exception" in response.text:
            return True
            
        # 3. Classic 403 Challenge page
        if response.status_code == 403:
            server_header = response.headers.get("server", "").lower()
            if "cloudflare" in server_header and "Just a moment" in response.text:
                return True
                
        return False

    async def _trigger_self_heal(self) -> bool:
        """
        The Fallback: Engages the native UI Oracle to harvest fresh cookies.
        Gracefully degrades (returns False) if the Oracle is not connected.
        """
        if node_manager.active_node is None:
            logger.info("[GhostGateway] SND Bridge disconnected. Graceful degradation: passing block.")
            return False
            
        async with self._heal_lock:
            if time.time() - self._last_heal_timestamp < self._heal_cooldown:
                logger.info("[GhostGateway] Cooldown active. Skipping redundant self-heal.")
                return True # Assuming a concurrent thread just healed it
                
            try:
                driver = await GhostNativeDriver.launch(headless=True)
                logger.info("[GhostGateway] Oracle launching. Parking on edge for challenge resolution...")
                await driver.navigate('https://www.whatnot.com/')
                
                # Give the native browser time to solve the JS/CAPTCHA challenge natively
                await asyncio.sleep(15.0)
                
                logger.info("[GhostGateway] Harvesting Oracle cookies...")
                cookies = await driver._send('get_cookies')
                
                if cookies:
                    self.session.cookies.update(cookies)
                    self._last_heal_timestamp = time.time()
                    return True
                return False
            except Exception as e:
                logger.error(f"[GhostGateway] Self-heal failed: {e}")
                return False

    def _translate_response(
        self, 
        response: curl_requests.Response,
        request: httpx.Request
    ) -> httpx.Response:
        """
        Converts the curl_cffi Response back to httpx, taking care to preserve
        multi-value headers and reconcile framing headers.
        """
        
        # httpx expects headers as a list of (bytes, bytes) tuples for multi-value support
        translated_headers = []
        for k, v in response.headers.multi_items():
            k_lower = k.lower()
            # Reconcile Framing Headers
            # curl_cffi automatically decompresses and unchunks the body. 
            # If we pass these framing headers back to httpx, it will attempt to decompress plaintext.
            if k_lower in ("content-encoding", "transfer-encoding", "content-length"):
                continue
            translated_headers.append((k.encode("utf-8"), v.encode("utf-8")))

        # Since curl_cffi has buffered the entire uncompressed body, we can just use ByteStream
        stream = httpx.ByteStream(response.content)

        return httpx.Response(
            status_code=response.status_code,
            headers=translated_headers,
            stream=stream,
            request=request,
            # We don't have curl_cffi expose httpx-like extension data, but can populate basics
            extensions={"http_version": b"HTTP/2" if response.http_version == 2 else b"HTTP/1.1"}
        )

    async def aclose(self):
        if hasattr(self.session, "close"):
            await self.session.close()
