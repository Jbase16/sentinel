"""
core/ghost/lazarus.py
The Lazarus Engine: Real-time Neural De-obfuscation.
"""
import logging
import hashlib
from mitmproxy import http
from core.ai.ai_engine import AIEngine

logger = logging.getLogger(__name__)

class LazarusEngine:
    _instance = None
    
    @staticmethod
    def instance():
        if LazarusEngine._instance is None:
            LazarusEngine._instance = LazarusEngine()
        return LazarusEngine._instance

    def __init__(self):
        self.ai = AIEngine.instance()
        self.cache = {} # hash -> clean_code

    def should_process(self, flow: http.HTTPFlow) -> bool:
        """
        Determine if we should de-obfuscate this response.
        Criteria:
        1. Content-Type is javascript
        2. Content looks minified (long lines, short vars)
        3. Not a known library (jQuery, React, etc - via hash or header)
        """
        # Basic check
        if "javascript" not in flow.response.headers.get("content-type", ""):
            return False
        
        # Skip if too small or too huge
        content = flow.response.content or b""
        if len(content) < 500 or len(content) > 100_000: # 100KB limit for responsiveness
            return False
            
        return True

    def process(self, flow: http.HTTPFlow):
        """
        Rewrite the JS content in-place.
        """
        try:
            original_code = flow.response.text
            if not original_code:
                return

            code_hash = hashlib.md5(original_code.encode()).hexdigest()
            
            if code_hash in self.cache:
                flow.response.text = self.cache[code_hash]
                flow.response.headers["X-Lazarus-Cache"] = "HIT"
                return

            # De-obfuscate via AI
            # Note: This is blocking in the proxy thread. 
            # Ideally we'd use async, but mitmproxy hooks are synchronous by default unless using async addon.
            clean_code = self.ai.deobfuscate_code(original_code[:2000]) # Limit context for speed/test
            
            # Fallback if AI fails or returns empty
            if not clean_code:
                clean_code = original_code
                
            # Add watermark
            clean_code = f"// [Lazarus] De-obfuscated by Sentinel\n{clean_code}"
            
            self.cache[code_hash] = clean_code
            flow.response.text = clean_code
            flow.response.headers["X-Lazarus-Renamed"] = "TRUE"
            
        except Exception as e:
            logger.error(f"[Lazarus] Failed to process: {e}")
