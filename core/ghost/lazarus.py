#
# PURPOSE:
# This module is part of the ghost package in SentinelForge.
# [Specific purpose based on module name: lazarus]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
core/ghost/lazarus.py
The Lazarus Engine: Real-time Neural De-obfuscation.

Uses mitmproxy's async addon pattern to prevent blocking HTTP responses
while AI processes JavaScript.
"""
import asyncio
import logging
import hashlib
from mitmproxy import http
from typing import Optional

from core.ai.ai_engine import AIEngine
from core.base.config import get_config

logger = logging.getLogger(__name__)

# Configuration constants - can be overridden in config
MIN_JS_SIZE = 500  # bytes
MAX_JS_SIZE = 100_000  # 100KB
MAX_CONTEXT_CHARS = 2000  # Limit context sent to LLM


class LazarusEngine:
    """
    Neural JavaScript de-obfuscation engine.
    
    Uses mitmproxy's async addon pattern to process JS in background
    without blocking HTTP responses.
    """
    
    _instance: Optional["LazarusEngine"] = None
    
    @staticmethod
    def instance() -> "LazarusEngine":
        """Function instance."""
        # Conditional branch.
        if LazarusEngine._instance is None:
            LazarusEngine._instance = LazarusEngine()
        return LazarusEngine._instance
    
    def __init__(self):
        """Function __init__."""
        self.ai = AIEngine.instance()
        self.cache: dict[str, str] = {}  # hash -> clean_code
        self._processing: set[str] = set()  # Currently processing hashes
        self._shadow_clients: dict[str, dict] = {}  # hash -> Shadow API Client spec
        
        # Load config values from GhostConfig
        config = get_config()
        self.min_js_size = config.ghost.min_js_size
        self.max_js_size = config.ghost.max_js_size
        self.max_context_chars = config.ghost.max_context_chars
    
    def should_process(self, flow: http.HTTPFlow) -> bool:
        """
        Determine if we should de-obfuscate this response.
        
        Criteria:
        1. Content-Type is javascript
        2. Content size is within bounds
        3. Not already being processed
        """
        content_type = flow.response.headers.get("content-type", "")
        # Conditional branch.
        if "javascript" not in content_type:
            return False
        
        content = flow.response.content or b""
        # Conditional branch.
        if len(content) < self.min_js_size or len(content) > self.max_js_size:
            return False
        
        # Check if already processing
        code_hash = hashlib.sha256(content).hexdigest()
        # Conditional branch.
        if code_hash in self._processing:
            return False
            
        return True
    
    async def response(self, flow: http.HTTPFlow):
        """
        Mitmproxy async addon hook.
        Called for every response - processes JS asynchronously.
        """
        # Conditional branch.
        if not self.should_process(flow):
            return
        
        await self._process_async(flow)
    
    async def _process_async(self, flow: http.HTTPFlow):
        """
        PASSIVELY analyze JavaScript for referenced API routes.

        ⚠️  INVARIANT: Ghost is a *passive* interception proxy. This method
        MUST NOT modify ``flow.response`` in any way. The browser must receive
        the site's bytes exactly as the server sent them.

        A previous version replaced the entire JS body with a truncated,
        LLM-"de-obfuscated" rewrite (and, due to an async bug, often with the
        string repr of an un-awaited coroutine). That corrupted every in-bounds
        script: pages rendered and scrolled but all click handlers were dead.
        We now read the response read-only, mine route strings with static
        regexes over the FULL original code, and emit findings off to the side.
        De-obfuscation for human analysis, if ever wanted, must happen on a
        copy in a dedicated viewer — never on the live flow.
        """
        from core.cortex.events import get_event_bus, GraphEvent, GraphEventType

        try:
            original_code = flow.response.text
            if not original_code:
                return

            code_hash = hashlib.sha256(original_code.encode()).hexdigest()
            url = flow.request.pretty_url

            # Dedup: only mine each distinct script once per run.
            if code_hash in self.cache:
                return
            self.cache[code_hash] = code_hash  # marker only; we never serve this

            # Static extraction over the ORIGINAL, full code — no LLM call, no
            # truncation, no write-back. Route strings (fetch/axios/xhr) survive
            # minification, so regexes are sufficient and side-effect free.
            routes = self._extract_api_routes(original_code)
            if not routes:
                return

            event_bus = get_event_bus()
            for route in routes:
                event_bus.emit(GraphEvent(
                    type=GraphEventType.FINDING_CREATED,
                    payload={
                        "finding_id": hashlib.sha256(
                            f"{url}:{route['method']}:{route['path']}".encode()
                        ).hexdigest()[:32],
                        "tool": "lazarus",
                        # INFO, not MEDIUM: an API route referenced in a JS
                        # bundle is an observation, not a vulnerability. The
                        # old MEDIUM severity flooded the findings store and
                        # polluted AI summaries.
                        "severity": "INFO",
                        "title": f"API route referenced in JS: {route['method']} {route['path']}",
                        "target": url,
                    }
                ))
                logger.debug(f"[Lazarus] route (passive): {route['method']} {route['path']}")

            shadow_client = self._generate_shadow_client(routes, url)
            if shadow_client:
                self._shadow_clients[code_hash] = shadow_client
                logger.info(
                    f"[Lazarus] mined {len(routes)} route(s) from {url} (response untouched)"
                )

        except Exception as e:
            logger.error(f"[Lazarus] Passive analysis failed: {e}")
    
    def _extract_api_routes(self, code: str) -> list:
        """
        Extract API routes from de-obfuscated JavaScript.
        
        Looks for common patterns:
        - fetch('/api/...
        - axios.get('/api/...
        - $.ajax({url: '/api/...
        - XMLHttpRequest.open('GET', '/api/...
        """
        import re
        routes = []
        
        # Pattern: fetch('/path') or fetch("/path")
        fetch_pattern = r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(fetch_pattern, code):
            path = match.group(1)
            if '/api' in path or path.startswith('/'):
                routes.append({"method": "GET", "path": path, "source": "fetch"})
        
        # Pattern: axios.get/post/put/delete('/path')
        axios_pattern = r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(axios_pattern, code, re.IGNORECASE):
            method = match.group(1).upper()
            path = match.group(2)
            routes.append({"method": method, "path": path, "source": "axios"})
        
        # Pattern: $.ajax({url: '/path', type: 'POST'})
        ajax_url_pattern = r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"]([^\'"]+)[\'"][^}]*type\s*:\s*[\'"](\w+)[\'"]'
        for match in re.finditer(ajax_url_pattern, code, re.IGNORECASE):
            path = match.group(1)
            method = match.group(2).upper()
            routes.append({"method": method, "path": path, "source": "jquery"})
        
        # Pattern: XMLHttpRequest.open('METHOD', '/path')
        xhr_pattern = r'\.open\s*\(\s*[\'"](\w+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(xhr_pattern, code):
            method = match.group(1).upper()
            path = match.group(2)
            if '/api' in path or path.startswith('/'):
                routes.append({"method": method, "path": path, "source": "xhr"})
        
        # Deduplicate
        seen = set()
        unique_routes = []
        for route in routes:
            key = f"{route['method']}:{route['path']}"
            if key not in seen:
                seen.add(key)
                unique_routes.append(route)
        
        return unique_routes
    
    def _generate_shadow_client(self, routes: list, source_url: str) -> dict:
        """
        Generate a Shadow API Client specification.
        
        THE HOLY FUCK UPGRADE: This allows Strategos to "hallucinate" 
        interactions with the target's internal API before sending real packets.
        
        Returns:
            A specification that can be used by Strategos for pre-flight analysis
        """
        from urllib.parse import urlparse
        
        parsed = urlparse(source_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        shadow_client = {
            "base_url": base_url,
            "source_js": source_url,
            "endpoints": [],
            "generated_at": None,  # Will be set below
        }
        
        from datetime import datetime, timezone
        shadow_client["generated_at"] = datetime.now(timezone.utc).isoformat()
        
        for route in routes:
            endpoint = {
                "method": route["method"],
                "path": route["path"],
                "full_url": f"{base_url}{route['path']}" if route['path'].startswith('/') else route['path'],
                "source": route.get("source", "unknown"),
                "attack_vectors": self._suggest_attack_vectors(route)
            }
            shadow_client["endpoints"].append(endpoint)
        
        return shadow_client
    
    def _suggest_attack_vectors(self, route: dict) -> list:
        """Suggest attack vectors for a discovered route."""
        vectors = []
        path = route["path"]
        method = route["method"]
        
        # IDOR detection
        if any(x in path.lower() for x in ['id=', 'user', 'account', 'order', 'item']):
            vectors.append({
                "type": "IDOR",
                "reason": "Path contains object reference",
                "payloads": ["1", "2", "999", "0", "-1"]
            })
        
        # Auth bypass for admin routes
        if any(x in path.lower() for x in ['admin', 'internal', 'private', 'debug']):
            vectors.append({
                "type": "AuthBypass",
                "reason": "Privileged endpoint discovered",
                "payloads": []
            })
        
        # SQLi for search/query endpoints
        if any(x in path.lower() for x in ['search', 'query', 'filter', 'find']):
            vectors.append({
                "type": "SQLi",
                "reason": "Search/query parameter detected",
                "payloads": ["'", "' OR 1=1--", "1; DROP TABLE users--"]
            })
        
        # Mass assignment for POST/PUT
        if method in ["POST", "PUT", "PATCH"]:
            vectors.append({
                "type": "MassAssignment",
                "reason": "Write endpoint may accept extra fields",
                "payloads": []
            })
        
        return vectors
    
    def get_shadow_client(self, code_hash: str) -> Optional[dict]:
        """Get a previously generated Shadow Client."""
        return self._shadow_clients.get(code_hash)
    
    def clear_cache(self):
        """Clear the de-obfuscation cache."""
        self.cache.clear()
        logger.info("[Lazarus] Cache cleared")


# Mitmproxy addon initialization
addons = [LazarusEngine.instance()]

