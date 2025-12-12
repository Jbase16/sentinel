"""
core/cortex/reasoning.py
The Logic Core: Derives attack opportunities from the Knowledge Graph.
"""

from typing import List, Dict
from core.cortex.memory import KnowledgeGraph, NodeType, EdgeType
# from core.config import get_config

class ReasoningEngine:
    """
    Analyzes the Knowledge Graph to suggest 'Next Best Actions'.
    """
    
    def __init__(self):
        self.graph = KnowledgeGraph.instance()

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
        
        # 1. Find HTTP services that haven't been fuzzed
        http_ports = self.graph.find_all(NodeType.PORT)
        for port in http_ports:
            # Check if it has 'http' service
            # In a real graph query this would be: MATCH (p:PORT)-[:RUNS]->(s:SERVICE) WHERE s.name contains 'http'
            neighbors = self.graph.get_neighbors(port['id'], EdgeType.RUNS)
            is_http = any("http" in n.get("name", "").lower() for n in neighbors)
            
            if is_http:
                ops.append({
                    "tool": "nikto",
                    "target": port['id'].split(":")[0], # IP
                    "args": ["-p", str(port['port'])],
                    "reason": f"Open HTTP port {port['port']} detected. Standard web enumeration recommended."
                })
                
        # 2. Find Technolgies with known CVEs (Placeholder logic)
        tech_nodes = self.graph.find_all(NodeType.TECH)
        for tech in tech_nodes:
            name = tech.get("name", "").lower()
            if "php" in name:
                 ops.append({
                    "tool": "nuclei",
                    "target": tech['id'].split(":")[0], # Assuming ID is target:tech
                    "args": ["-t", "cves/"],
                    "reason": f"PHP detected ({tech.get('version')}). Check for known CVEs."
                })
                
        return ops

    def _assess_risks(self) -> List[Dict]:
        """
        Aggregates high-severity findings from the graph.
        """
        # In the future, this queries FINDING nodes directly
        # For now, it's a stub waiting for findings to be fully migrated to Nodes
        return []

reasoning_engine = ReasoningEngine()
