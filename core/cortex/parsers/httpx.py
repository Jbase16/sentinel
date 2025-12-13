"""
core/cortex/parsers/httpx.py
Parses HTTPX output into Tech Nodes and Vulnerabilities.
Uses regex-based parsing (not LLM) for speed and reliability.
"""

import json
import re
from typing import List, Dict
from core.cortex.parser import SignalParser
from core.cortex.memory import NodeType, EdgeType

# Common tech patterns for fingerprinting
TECH_PATTERNS = {
    "nginx": re.compile(r"nginx/?([\d.]+)?", re.IGNORECASE),
    "apache": re.compile(r"apache/?([\d.]+)?", re.IGNORECASE),
    "iis": re.compile(r"iis/?([\d.]+)?", re.IGNORECASE),
    "php": re.compile(r"php/?([\d.]+)?", re.IGNORECASE),
    "asp.net": re.compile(r"asp\.net(?: core)?/?([\d.]+)?", re.IGNORECASE),
    "express": re.compile(r"express/?([\d.]+)?", re.IGNORECASE),
    "node": re.compile(r"node\.?js/?([\d.]+)?", re.IGNORECASE),
    "tomcat": re.compile(r"tomcat/?([\d.]+)?", re.IGNORECASE),
    "cloudflare": re.compile(r"cloudflare", re.IGNORECASE),
    "varnish": re.compile(r"varnish/?([\d.]+)?", re.IGNORECASE),
    "wordpress": re.compile(r"wordpress/?([\d.]+)?", re.IGNORECASE),
    "react": re.compile(r"react/?([\d.]+)?", re.IGNORECASE),
    "vue": re.compile(r"vue\.?js/?([\d.]+)?", re.IGNORECASE),
    "angular": re.compile(r"angular/?([\d.]+)?", re.IGNORECASE),
    "jquery": re.compile(r"jquery/?([\d.]+)?", re.IGNORECASE),
    "bootstrap": re.compile(r"bootstrap/?([\d.]+)?", re.IGNORECASE),
}

class HttpxParser(SignalParser):
    def parse(self, tool_name: str, target: str, output: str) -> List[Dict]:
        findings = []
        
        # Ensure Asset Node
        self.graph.add_node(target, NodeType.ASSET, {"tool": tool_name})

        # Parse httpx output format: "https://target [STATUS] [TITLE] [TECH,TECH]"
        # Also handles JSON output if httpx was run with -json flag
        
        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Try JSON parsing first (httpx -json output)
            if line.startswith("{"):
                findings.extend(self._parse_json_line(target, line, tool_name))
                continue
            
            # Parse standard httpx output: "URL [STATUS] [TITLE] [TECH]"
            findings.extend(self._parse_text_line(target, line, tool_name))
        
        return findings
    
    def _parse_json_line(self, target: str, line: str, tool_name: str) -> List[Dict]:
        """Parse JSON-formatted httpx output."""
        findings = []
        try:
            data = json.loads(line)
            url = data.get("url", target)
            status = data.get("status_code") or data.get("status-code", 0)
            title = data.get("title", "")
            tech_list = data.get("tech", []) or data.get("technologies", [])
            webserver = data.get("webserver", "")
            
            # Update asset with status
            self.graph.add_node(target, NodeType.ASSET, {"http_status": status, "title": title})
            
            # Process tech stack
            all_tech = tech_list + ([webserver] if webserver else [])
            for tech in all_tech:
                if tech:
                    self._add_tech(target, tech, "")
                    findings.append({
                        "type": "tech_fingerprint",
                        "severity": "INFO",
                        "tool": tool_name,
                        "target": target,
                        "message": f"Detected {tech}",
                        "proof": line[:500],
                        "tags": ["tech-fingerprint"],
                        "families": ["supply-chain"],
                        "metadata": {"tech": tech}
                    })
            
            # Add endpoint finding
            if status:
                findings.append({
                    "type": "HTTP Endpoint",
                    "severity": "INFO" if status < 400 else "MEDIUM",
                    "tool": tool_name,
                    "target": target,
                    "message": f"{url} returned {status}",
                    "proof": f"Status: {status}, Title: {title}",
                    "tags": ["surface-http", f"status-{status}"],
                    "families": ["exposure"],
                    "metadata": {"url": url, "status": status, "title": title}
                })
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_text_line(self, target: str, line: str, tool_name: str) -> List[Dict]:
        """Parse text-formatted httpx output."""
        findings = []
        
        # Pattern: "https://example.com [200] [Page Title] [nginx,php]"
        pattern = re.compile(r"(https?://\S+)\s+\[(\d{3})\](?:\s+\[([^\]]*?)\])?(?:\s+\[([^\]]*?)\])?", re.IGNORECASE)
        match = pattern.match(line)
        
        if match:
            url = match.group(1)
            status = int(match.group(2))
            title = match.group(3) or ""
            tech_str = match.group(4) or ""
            
            # Update asset
            self.graph.add_node(target, NodeType.ASSET, {"http_status": status, "title": title})
            
            # Process tech from brackets
            if tech_str:
                for tech in tech_str.split(","):
                    tech = tech.strip()
                    if tech:
                        self._add_tech(target, tech, "")
                        findings.append({
                            "type": "tech_fingerprint",
                            "severity": "INFO",
                            "tool": tool_name,
                            "target": target,
                            "message": f"Detected {tech}",
                            "proof": line[:500],
                            "tags": ["tech-fingerprint"],
                            "families": ["supply-chain"],
                            "metadata": {"tech": tech}
                        })
            
            # Add endpoint finding
            findings.append({
                "type": "HTTP Endpoint",
                "severity": "INFO" if status < 400 else "MEDIUM",
                "tool": tool_name,
                "target": target,
                "message": f"{url} returned {status}",
                "proof": line[:500],
                "tags": ["surface-http", f"status-{status}"],
                "families": ["exposure"],
                "metadata": {"url": url, "status": status, "title": title}
            })
        else:
            # Fallback: scan the line for tech patterns
            self._extract_tech_from_text(target, line, tool_name, findings)
        
        return findings
    
    def _extract_tech_from_text(self, target: str, text: str, tool_name: str, findings: List[Dict]):
        """Extract technology from arbitrary text using regex patterns."""
        for tech_name, pattern in TECH_PATTERNS.items():
            match = pattern.search(text)
            if match:
                version = match.group(1) if match.lastindex and match.group(1) else ""
                self._add_tech(target, tech_name, version)
                findings.append({
                    "type": "tech_fingerprint",
                    "severity": "INFO",
                    "tool": tool_name,
                    "target": target,
                    "message": f"Detected {tech_name}" + (f" {version}" if version else ""),
                    "proof": text[:200],
                    "tags": ["tech-fingerprint"],
                    "families": ["supply-chain"],
                    "metadata": {"tech": tech_name, "version": version}
                })
    
    def _add_tech(self, target: str, tech: str, version: str):
        """Add a technology node to the graph."""
        tech_id = f"tech:{tech.lower()}"
        self.graph.add_node(tech_id, NodeType.TECH, {"name": tech, "version": version})
        self.graph.add_edge(target, tech_id, EdgeType.USES_TECH)
