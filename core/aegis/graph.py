"""
Aegis Business Graph Engine.
Manages the "Value Map" of the organization and calculates business risk impact.
"""

from typing import Dict, List, Set, Optional
import logging
import json

from .models import BusinessNode, BusinessEdge

logger = logging.getLogger(__name__)

class BusinessModelGraph:
    """
    Directed graph representing business logic and dependencies.
    Calculates how technical risk propagates to business value.
    """
    
    def __init__(self):
        self.nodes: Dict[str, BusinessNode] = {}
        self.edges: List[BusinessEdge] = []
        
        # Adjacency list: node_id -> list of outgoing edges
        self._adjacency: Dict[str, List[BusinessEdge]] = {}
        # Reverse adjacency: node_id -> list of incoming edges (dependencies)
        self._reverse_adjacency: Dict[str, List[BusinessEdge]] = {}

    def add_node(self, node: BusinessNode) -> None:
        """Add a business node to the graph."""
        self.nodes[node.id] = node
        if node.id not in self._adjacency:
            self._adjacency[node.id] = []
        if node.id not in self._reverse_adjacency:
            self._reverse_adjacency[node.id] = []
        logger.debug(f"[Aegis] Added Node: {node.name} (Val: {node.value})")

    def add_edge(self, edge: BusinessEdge) -> None:
        """Add a directional dependency."""
        self.edges.append(edge)
        
        # Ensure nodes exist (auto-create placeholders if needed, or strictly fail. Let's fail for now to be safe)
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            logger.warning(f"[Aegis] Orphan edge detected: {edge.source_id} -> {edge.target_id}")
            return

        self._adjacency[edge.source_id].append(edge)
        self._reverse_adjacency[edge.target_id].append(edge)
        logger.debug(f"[Aegis] Added Edge: {edge.source_id} -[{edge.type}]-> {edge.target_id}")

    def get_descendants(self, node_id: str) -> Set[str]:
        """Return all node IDs impacted by the given node (downstream)."""
        visited = set()
        stack = [node_id]
        
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            
            for edge in self._adjacency.get(current, []):
                stack.append(edge.target_id)
                
        visited.discard(node_id) # Remove self
        return visited

    def get_ancestors(self, node_id: str) -> Set[str]:
        """Return all node IDs that the given node depends on (upstream)."""
        visited = set()
        stack = [node_id]
        
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            
            for edge in self._reverse_adjacency.get(current, []):
                stack.append(edge.source_id)
                
        visited.discard(node_id)
        return visited

    def calculate_total_risk(self, technical_pressure_map: Dict[str, float]) -> Dict[str, float]:
        """
        Calculate total business risk for each node given a map of technical pressure.
        
        technical_pressure_map: { business_node_id: direct_technical_pressure }
        
        Returns: { business_node_id: aggregated_risk_score }
        """
        # 1. Start with intrinsic risk (Value * Direct Pressure)
        # If no direct pressure, risk is 0 (unless propagated)
        node_risk: Dict[str, float] = {}
        
        # Initialize with direct impact
        for node_id, node in self.nodes.items():
            pressure = technical_pressure_map.get(node_id, 0.0)
            # Base formula: Risk = Asset Value * Technical Likelihood (Pressure)
            node_risk[node_id] = node.value * pressure

        # 2. Propagate risk technical dependencies? 
        # Actually in Aegis, we usually say:
        # If "Auth Service" fails, then "Customer Portal" (which depends on it) is at risk.
        # So Risk flows from Dependency -> Dependent.
        # If A -> B (A affects B), and A is compromised, B is compromised.
        
        # Simple iterative propagation (like PageRank but for Doom)
        # We process in topological order or just iterate until convergence.
        # For active DAGs, recursion works.
        
        # simplified: Risk(Target) += Risk(Source) * EdgeWeight
        # But we need to handle cycles gracefully. Let's use limited iterations.
        
        final_risk = node_risk.copy()
        
        for _ in range(3): # 3 hops of propagation limit for performance/sanity
            next_risk = final_risk.copy()
            for edge in self.edges:
                # Impact flows Source -> Target
                transferred = final_risk[edge.source_id] * edge.weight
                next_risk[edge.target_id] = max(next_risk[edge.target_id], transferred)
                # Or additive? max is cleaner for "weakest link" or "highest threat" logic.
                # If we have multiple dependencies failing, is it worse? Yes.
                # Let's try additive but capped? 
                # For now: MAX(existing, incoming) keeps it normalized.
                
            final_risk = next_risk
            
        return final_risk

