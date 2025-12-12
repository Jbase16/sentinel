"""
core/cortex/parsers/nmap.py
Parses Nmap output into Graph Nodes (Port, Service).
"""

import re
from typing import List, Dict
from core.cortex.parser import SignalParser
from core.cortex.memory import NodeType, EdgeType

class NmapParser(SignalParser):
    def parse(self, tool_name: str, target: str, output: str) -> List[Dict]:
        findings = []
        
        # Ensure Asset Node Exists
        self.graph.add_node(target, NodeType.ASSET, {"tool": tool_name})
        
        # Regex for '22/tcp open ssh' etc
        # Matches: PORT_NUM/PROTO STATE SERVICE VERSION
        port_re = re.compile(r"^(\d+)/(\w+)\s+(\w+)\s+(.*)$", re.MULTILINE)
        
        for match in port_re.finditer(output):
            port = match.group(1)
            proto = match.group(2)
            state = match.group(3)
            service_line = match.group(4).strip()
            
            if state != "open":
                continue
                
            port_id = f"{target}:{port}"
            
            # 1. Create Port Node
            self.graph.add_node(port_id, NodeType.PORT, {
                "port": int(port), 
                "proto": proto,
                "state": state
            })
            
            # 2. Link Asset -> Port
            self.graph.add_edge(target, port_id, EdgeType.HAS_PORT)
            
            # 3. Create Service Node if detected
            # Simple heuristic: split service line
            # "http Apache httpd 2.4.41" -> "http", "Apache httpd 2.4.41"
            parts = service_line.split(" ", 1)
            service_name = parts[0]
            version_info = parts[1] if len(parts) > 1 else ""
            
            service_id = f"{target}:{port}:{service_name}"
            self.graph.add_node(service_id, NodeType.SERVICE, {
                "name": service_name,
                "version": version_info
            })
            
            # 4. Link Port -> Service
            self.graph.add_edge(port_id, service_id, EdgeType.RUNS)
            
            findings.append({
                "type": "open_port",
                "severity": "LOW",
                "value": f"Port {port}/{proto} is open ({service_name})",
                "technical_details": f"Version: {version_info}"
            })
            
        return findings
