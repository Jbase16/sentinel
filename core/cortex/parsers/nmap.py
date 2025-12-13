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
        
        # Multiple regex patterns to handle various nmap output formats:
        # Format 1: "22/tcp   open  ssh     OpenSSH 8.0"
        # Format 2: "22/tcp open ssh"
        # Format 3: "PORT     STATE SERVICE  VERSION" header followed by data
        
        # Pattern that handles varying whitespace in nmap output
        port_re = re.compile(
            r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?$",
            re.MULTILINE | re.IGNORECASE
        )
        
        for match in port_re.finditer(output):
            port = match.group(1)
            proto = match.group(2).lower()
            state = match.group(3).lower()
            service_name = match.group(4).strip() if match.group(4) else "unknown"
            version_info = match.group(5).strip() if match.group(5) else ""
            
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
            service_id = f"{target}:{port}:{service_name}"
            self.graph.add_node(service_id, NodeType.SERVICE, {
                "name": service_name,
                "version": version_info
            })
            
            # 4. Link Port -> Service
            self.graph.add_edge(port_id, service_id, EdgeType.RUNS)
            
            # 5. Detect tech stack from version info
            if version_info:
                tech_id = f"tech:{service_name}"
                self.graph.add_node(tech_id, NodeType.TECH, {
                    "name": service_name,
                    "version": version_info
                })
                self.graph.add_edge(target, tech_id, EdgeType.USES_TECH)
            
            findings.append({
                "type": "open_port",
                "severity": "LOW",
                "tool": tool_name,
                "target": target,
                "message": f"Port {port}/{proto} is open ({service_name})",
                "proof": f"{port}/{proto} open {service_name} {version_info}".strip(),
                "tags": ["exposure", "port-scan"],
                "families": ["exposure"],
                "metadata": {
                    "port": int(port),
                    "proto": proto,
                    "service": service_name,
                    "version": version_info
                }
            })
            
        return findings
