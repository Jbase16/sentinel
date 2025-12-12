"""
core/cortex/scanner_bridge.py
The Bridge: Routes tool output from ScannerEngine -> Cortex Parsers.
Replaces the legacy 'raw_classifier.py'.
"""

import logging
from typing import List, Dict

from core.cortex.parsers.nmap import NmapParser
from core.cortex.parsers.httpx import HttpxParser
# Future: from core.cortex.parsers.nikto import NiktoParser

logger = logging.getLogger(__name__)

class ScannerBridge:
    """
    Static entry point for the Cortex engine.
    """
    
    _parsers = {
        "nmap": NmapParser(),
        "httpx": HttpxParser(),
    }

    @classmethod
    def classify(cls, tool: str, target: str, output: str) -> List[Dict]:
        """
        Routes the output to the correct parser.
        Returns a list of finding dicts (legacy format) for compatibility.
        """
        parser = cls._parsers.get(tool)
        
        if parser:
            try:
                # 1. Parse and update Knowledge Graph
                return parser.parse(tool, target, output)
            except Exception as e:
                logger.error(f"Cortex parser failed for {tool}: {e}", exc_info=True)
                return cls._fallback(tool, target, output)
        else:
            # Fallback to legacy behavior (or just return basic info)
            return cls._fallback(tool, target, output)

    @classmethod
    def _fallback(cls, tool: str, target: str, output: str) -> List[Dict]:
        """
        Minimal fallback if no parser exists or parsing fails.
        """
        return [{
            "tool": tool,
            "type": "raw_output",
            "severity": "INFO",
            "value": f"{tool} output captured (No Cortex Parser available)",
            "technical_details": output[:500]
        }]
