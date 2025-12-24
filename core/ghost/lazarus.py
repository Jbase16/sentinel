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
        Process JS de-obfuscation asynchronously.
        Uses asyncio.to_thread to avoid blocking the event loop.
        """
        # Error handling block.
        try:
            original_code = flow.response.text
            if not original_code:
                return
            
            code_hash = hashlib.sha256(original_code.encode()).hexdigest()
            
            # Check cache first (fast path)
            if code_hash in self.cache:
                flow.response.text = self.cache[code_hash]
                flow.response.headers["X-Lazarus-Cache"] = "HIT"
                logger.debug(f"[Lazarus] Cache hit for {code_hash[:8]}")
                return
            
            # Mark as processing to prevent duplicates
            self._processing.add(code_hash)
            
            try:
                # Run AI in thread pool to avoid blocking
                clean_code = await asyncio.to_thread(
                    self.ai.deobfuscate_code,
                    original_code[:self.max_context_chars]
                )
                
                # Fallback if AI fails
                if not clean_code:
                    logger.warning(f"[Lazarus] AI returned empty for {code_hash[:8]}")
                    clean_code = original_code
                else:
                    # Add watermark
                    clean_code = f"// [Lazarus] De-obfuscated by Sentinel\n{clean_code}"
                
                # Cache the result
                self.cache[code_hash] = clean_code
                flow.response.text = clean_code
                flow.response.headers["X-Lazarus-Processed"] = "TRUE"
                
                logger.info(f"[Lazarus] De-obfuscated {code_hash[:8]} ({len(original_code)} -> {len(clean_code)} chars)")
                
            finally:
                # Remove from processing set
                self._processing.discard(code_hash)
                
        except Exception as e:
            logger.error(f"[Lazarus] Failed to process: {e}")
    
    def clear_cache(self):
        """Clear the de-obfuscation cache."""
        self.cache.clear()
        logger.info("[Lazarus] Cache cleared")


# Mitmproxy addon initialization
addons = [LazarusEngine.instance()]

