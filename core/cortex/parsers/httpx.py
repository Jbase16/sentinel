"""
core/cortex/parsers/httpx.py
Parses HTTPX output into Tech Nodes and Vulnerabilities.
"""

import json
import re
from typing import List, Dict
from core.cortex.parser import SignalParser
from core.cortex.memory import NodeType, EdgeType
from core.cortex.synapse import Synapse

class HttpxParser(SignalParser):
    def parse(self, tool_name: str, target: str, output: str) -> List[Dict]:
        findings = []
        synapse = Synapse.instance()
        
        # Ensure Asset Node
        self.graph.add_node(target, NodeType.ASSET)

        # HTTPX often outputs JSON lines if configured, but here we handle raw text for safety
        # Assuming standard output: "https://target [200] [Title] [Server]"
        
        lines = output.splitlines()
        for line in lines:
            if not line.strip(): continue

            # Heuristic: [200]
            if "[200]" in line:
                self.graph.add_node(target, NodeType.ASSET, {"http_status": 200})
            
            # Heuristic: Tech detection (e.g. [nginx/1.14])
            # This is where we might ask Synapse to extract tech stack
            tech_stack = synapse.extract_tech_stack("", line)
            
            for tech, ver in tech_stack.items():
                tech_id = f"tech:{tech}"
                self.graph.add_node(tech_id, NodeType.TECH, {"name": tech, "version": ver})
                self.graph.add_edge(target, tech_id, EdgeType.USES_TECH)
                
                findings.append({
                    "type": "tech_fingerprint",
                    "severity": "INFO",
                    "value": f"Detected {tech} ({ver})"
                })

        return findings
