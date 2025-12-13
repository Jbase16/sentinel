"""
core/cortex/reasoning.py
The Logic Core: Derives attack opportunities from the Knowledge Graph.
"""

import logging
from typing import List, Dict, Set
from core.cortex.memory import KnowledgeGraph, NodeType, EdgeType

logger = logging.getLogger(__name__)

# Tech patterns that warrant further scanning
VULNERABLE_TECH_PATTERNS = {
    "php": {"tool": "nuclei", "args": ["-t", "cves/", "-t", "vulnerabilities/"], "reason": "PHP detected - check for known CVEs"},
    "wordpress": {"tool": "nuclei", "args": ["-t", "technologies/wordpress/"], "reason": "WordPress detected - check for plugin/core vulnerabilities"},
    "apache": {"tool": "nuclei", "args": ["-t", "cves/"], "reason": "Apache detected - check for known CVEs"},
    "nginx": {"tool": "nuclei", "args": ["-t", "cves/"], "reason": "Nginx detected - check for misconfigurations"},
    "tomcat": {"tool": "nuclei", "args": ["-t", "technologies/tomcat/"], "reason": "Tomcat detected - check for manager/host-manager exposure"},
    "iis": {"tool": "nuclei", "args": ["-t", "technologies/iis/"], "reason": "IIS detected - check for shortname disclosure and misconfigs"},
}

class ReasoningEngine:
    """
    Analyzes the Knowledge Graph to suggest 'Next Best Actions'.
    Implements rule-based reasoning to derive attack opportunities from scan data.
    """
    
    def __init__(self):
        self.graph = KnowledgeGraph.instance()
        self._proposed_actions: Set[str] = set()  # Track proposed actions to avoid duplicates

    def analyze(self) -> Dict[str, object]:
        """
        Main analysis loop.
        Returns opportunities and graph stats.
        """
        opportunities = self._derive_opportunities()
        risks = self._assess_risks()
        
        return {
            "opportunities": opportunities,
            "risks": risks,
            "graph_summary": {
                "nodes": self.graph._graph.number_of_nodes(),
                "edges": self.graph._graph.number_of_edges()
            }
        }

    def _derive_opportunities(self) -> List[Dict]:
        """
        Rule-based logic to suggest tools based on Graph state.
        """
        ops = []
        
        # Get all assets as our primary targets
        assets = self.graph.find_all(NodeType.ASSET)
        
        # 1. Find HTTP services that should be web-scanned
        ops.extend(self._analyze_http_services())
        
        # 2. Find technologies with known vulnerability patterns
        ops.extend(self._analyze_technologies())
        
        # 3. Analyze findings for follow-up opportunities
        ops.extend(self._analyze_findings())
        
        logger.info(f"[ReasoningEngine] Derived {len(ops)} opportunities from {len(assets)} assets")
        return ops

    def _analyze_http_services(self) -> List[Dict]:
        """Find HTTP services that warrant further scanning."""
        ops = []
        http_ports = self.graph.find_all(NodeType.PORT)
        
        for port_node in http_ports:
            port_id = port_node.get('id', '')
            port_num = port_node.get('port', 0)
            
            # Extract target from port_id (format: "target:port")
            parts = port_id.split(':') if port_id else []
            target = parts[0] if parts else ''
            
            if not target or not port_num:
                continue
            
            # Check if this port runs an HTTP service
            neighbors = self.graph.get_neighbors(port_id, EdgeType.RUNS)
            service_names = [n.get("name", "").lower() for n in neighbors]
            is_http = any(svc in ['http', 'https', 'http-proxy', 'https-alt'] or 'http' in svc for svc in service_names)
            
            # Also consider common HTTP ports
            http_ports_common = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
            if is_http or port_num in http_ports_common:
                action_key = f"nikto:{target}:{port_num}"
                if action_key not in self._proposed_actions:
                    self._proposed_actions.add(action_key)
                    ops.append({
                        "tool": "nikto",
                        "target": target,
                        "args": ["-h", target, "-p", str(port_num)],
                        "reason": f"HTTP service on port {port_num} - running web vulnerability scanner"
                    })
        
        return ops

    def _analyze_technologies(self) -> List[Dict]:
        """Find technologies that warrant CVE/vulnerability scanning."""
        ops = []
        tech_nodes = self.graph.find_all(NodeType.TECH)
        
        for tech_node in tech_nodes:
            tech_id = tech_node.get('id', '')
            tech_name = tech_node.get('name', '').lower()
            tech_version = tech_node.get('version', '')
            
            # Find the asset this tech is associated with
            # Tech ID format is typically "tech:name", need to find linked asset
            target = None
            
            # Search for assets that link to this tech
            assets = self.graph.find_all(NodeType.ASSET)
            for asset in assets:
                neighbors = self.graph.get_neighbors(asset['id'], EdgeType.USES_TECH)
                if any(n.get('id') == tech_id for n in neighbors):
                    target = asset['id']
                    break
            
            if not target:
                # Fallback: try to extract from tech_id
                if ':' in tech_id and not tech_id.startswith('tech:'):
                    target = tech_id.split(':')[0]
                else:
                    continue
            
            # Check if this tech matches any vulnerable patterns
            for pattern, config in VULNERABLE_TECH_PATTERNS.items():
                if pattern in tech_name:
                    action_key = f"{config['tool']}:{target}:{pattern}"
                    if action_key not in self._proposed_actions:
                        self._proposed_actions.add(action_key)
                        ops.append({
                            "tool": config['tool'],
                            "target": target,
                            "args": config['args'] + ["-target", target],
                            "reason": f"{config['reason']} (version: {tech_version or 'unknown'})"
                        })
        
        return ops

    def _analyze_findings(self) -> List[Dict]:
        """Analyze existing findings to propose follow-up actions."""
        ops = []
        findings = self.graph.find_all(NodeType.FINDING)
        
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            severity = finding.get('severity', 'INFO').upper()
            target = finding.get('id', '').split(':')[0] if ':' in finding.get('id', '') else ''
            
            if not target:
                continue
            
            # High severity findings warrant deeper investigation
            if severity in ['HIGH', 'CRITICAL']:
                # Suggest directory brute force for interesting findings
                if 'exposure' in finding_type or 'endpoint' in finding_type:
                    action_key = f"gobuster:{target}"
                    if action_key not in self._proposed_actions:
                        self._proposed_actions.add(action_key)
                        ops.append({
                            "tool": "gobuster",
                            "target": target,
                            "args": ["dir", "-u", f"https://{target}", "-w", "/usr/share/wordlists/dirb/common.txt"],
                            "reason": f"High severity finding detected - running directory enumeration"
                        })
        
        return ops

    def _assess_risks(self) -> List[Dict]:
        """
        Aggregates high-severity findings from the graph.
        """
        risks = []
        findings = self.graph.find_all(NodeType.FINDING)
        
        for finding in findings:
            severity = finding.get('severity', 'INFO').upper()
            if severity in ['HIGH', 'CRITICAL']:
                risks.append({
                    "id": finding.get('id', ''),
                    "type": finding.get('type', 'unknown'),
                    "severity": severity,
                    "message": finding.get('message', '')[:200],
                    "tool": finding.get('tool', 'unknown')
                })
        
        return risks
    
    def clear_proposed_actions(self):
        """Clear the set of proposed actions (useful between scans)."""
        self._proposed_actions.clear()

reasoning_engine = ReasoningEngine()
