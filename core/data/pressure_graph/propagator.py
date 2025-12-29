"""
Cycle-safe pressure propagation using iterative relaxation.

Uses power iteration to handle graphs with cycles naturally.
Deterministic and guarantees convergence.
"""

from typing import Dict, Set, Optional
from collections import defaultdict

from .models import PressureNode, PressureEdge


class PressurePropagator:
    """
    Deterministic pressure propagation through directed graph.
    
    Algorithm: Iterative Relaxation (Power Iteration)
    Formula: P_new = (1 - d) * Base_Pressure + d * Σ(Inbound_Pressure × Transfer_Factor)
    
    This handles cycles naturally and guarantees convergence for d < 1.
    """
    
    def __init__(self, 
                 nodes: Dict[str, PressureNode],
                 edges: Dict[str, PressureEdge],
                 damping_factor: float = 0.85,
                 epsilon: float = 1e-6,
                 max_iterations: int = 1000):
        """
        Initialize propagator.
        
        Args:
            nodes: Dict of node_id -> PressureNode
            edges: Dict of edge_id -> PressureEdge
            damping_factor: Damping factor d (0 < d < 1), default 0.85
            epsilon: Convergence threshold, default 1e-6
            max_iterations: Safety limit, default 1000
        """
        self.nodes = nodes
        self.edges = edges
        self.damping_factor = damping_factor
        self.epsilon = epsilon
        self.max_iterations = max_iterations
        
        # Pre-compute adjacency lists for O(1) lookups
        self._adjacency: Dict[str, list[str]] = defaultdict(list)
        self._reverse_adjacency: Dict[str, list[str]] = defaultdict(list)
        
        for edge in edges.values():
            self._adjacency[edge.source_id].append(edge.target_id)
            self._reverse_adjacency[edge.target_id].append(edge.source_id)
    
    def propagate(self, 
                crown_jewel_ids: Set[str],
                initial_pressures: Optional[Dict[str, float]] = None) -> Dict[str, float]:
        """
        Propagate pressure through the graph.
        
        Crown jewels are sinks (they accumulate but don't forward pressure).
        
        Args:
            crown_jewel_ids: Set of crown jewel node IDs
            initial_pressures: Optional starting pressures (defaults to base_pressure)
        
        Returns:
            Dict mapping node_id -> total_pressure
        """
        # Initialize pressures
        if initial_pressures is None:
            pressures: Dict[str, float] = {
                node_id: node.base_pressure 
                for node_id, node in self.nodes.items()
            }
        else:
            pressures = dict(initial_pressures)
        
        # Iterate until convergence
        for iteration in range(self.max_iterations):
            max_delta = 0.0
            new_pressures = dict(pressures)
            
            # Compute new pressure for each node
            for node_id, node in self.nodes.items():
                if node_id in crown_jewel_ids:
                    # Crown jewels are sinks - don't forward pressure
                    continue
                
                # Calculate inbound pressure
                inbound_pressure = 0.0
                inbound_edges = self._get_inbound_edges(node_id)
                
                for edge in inbound_edges:
                    source_pressure = pressures.get(edge.source_id, 0.0)
                    inbound_pressure += source_pressure * edge.transfer_factor
                
                # Apply damping formula
                new_pressure = (
                    (1 - self.damping_factor) * node.base_pressure +
                    self.damping_factor * inbound_pressure
                )
                
                # Ensure non-negative
                new_pressure = max(0.0, new_pressure)
                
                # Track maximum change
                delta = abs(new_pressure - pressures[node_id])
                max_delta = max(max_delta, delta)
                
                new_pressures[node_id] = new_pressure
            
            # Update pressures
            pressures = new_pressures
            
            # Check convergence
            if max_delta < self.epsilon:
                break
        
        return pressures
    
    def get_inbound_edges(self, node_id: str) -> list[PressureEdge]:
        """
        Get all edges pointing to this node.
        O(k) where k is number of inbound edges.
        """
        source_ids = self._reverse_adjacency.get(node_id, [])
        edges = []
        
        for source_id in source_ids:
            for edge in self.edges.values():
                if edge.source_id == source_id and edge.target_id == node_id:
                    edges.append(edge)
        
        return edges
    
    def get_outbound_edges(self, node_id: str) -> list[PressureEdge]:
        """
        Get all edges from this node.
        O(k) where k is number of outbound edges.
        """
        target_ids = self._adjacency.get(node_id, [])
        edges = []
        
        for target_id in target_ids:
            for edge in self.edges.values():
                if edge.source_id == node_id and edge.target_id == target_id:
                    edges.append(edge)
        
        return edges
    
    def _get_inbound_edges(self, node_id: str) -> list[PressureEdge]:
        """
        Optimized version using edge cache.
        Builds edge cache on first call if needed.
        """
        # Lazy initialization of edge cache
        if not hasattr(self, '_edge_cache'):
            self._edge_cache: Dict[str, list[PressureEdge]] = defaultdict(list)
            
            for edge in self.edges.values():
                self._edge_cache[edge.target_id].append(edge)
        
        return self._edge_cache.get(node_id, [])
    
    def compute_pressure_contribution(self, 
                                   source_id: str,
                                   crown_jewel_ids: Set[str]) -> Dict[str, float]:
        """
        Compute how much pressure a specific source contributes to each node.
        
        Useful for chokepoint analysis: if removing node X reduces pressure
        on crown jewels by ΔP, X is a high-value remediation target.
        """
        # Propagate with only this source having pressure
        initial_pressures = {
            node_id: 0.0 
            for node_id in self.nodes.keys()
        }
        initial_pressures[source_id] = self.nodes[source_id].base_pressure
        
        pressures = self.propagate(crown_jewel_ids, initial_pressures)
        
        # Remove the source's own pressure (we want contribution, not total)
        contribution = {
            node_id: pressure 
            for node_id, pressure in pressures.items()
            if node_id != source_id
        }
        
        return contribution
    
    def validate_invariant(self,
                         crown_jewel_ids: Set[str],
                         baseline_pressures: Dict[str, float]) -> bool:
        """
        Validate invariant: If node severity increases, Crown Jewel pressure must not decrease.
        
        This is a sanity check that the propagation algorithm is working correctly.
        """
        # For each crown jewel, verify pressure doesn't decrease when upstream severity increases
        for cj_id in crown_jewel_ids:
            baseline_pressure = baseline_pressures.get(cj_id, 0.0)
            
            # Try increasing severity of each upstream node
            for node_id, node in self.nodes.items():
                if node_id == cj_id:
                    continue
                
                # Temporarily increase severity
                original_severity = node.severity
                node.severity = min(10.0, original_severity + 1.0)
                
                # Recompute base pressure
                node.base_pressure = (
                    node.severity *
                    node.exposure *
                    node.exploitability *
                    node.privilege_gain *
                    node.asset_value
                )
                
                # Propagate new pressures
                new_pressures = self.propagate(crown_jewel_ids)
                new_cj_pressure = new_pressures.get(cj_id, 0.0)
                
                # Restore original severity
                node.severity = original_severity
                node.base_pressure = (
                    node.severity *
                    node.exposure *
                    node.exploitability *
                    node.privilege_gain *
                    node.asset_value
                )
                
                # Check invariant
                if new_cj_pressure < baseline_pressure - self.epsilon:
                    return False  # Violation detected
        
        return True  # Invariant holds