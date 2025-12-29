"""
Cycle-safe pressure propagation using iterative relaxation.

Uses power iteration to handle graphs with cycles naturally.
Deterministic and guarantees convergence.
"""

from typing import Dict, Set, Optional, List
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
        
        # Immutability flag
        self._frozen = False
        
        # Pre-compute adjacency lists for O(1) lookups
        self._adjacency: Dict[str, list[str]] = defaultdict(list)
        self._reverse_adjacency: Dict[str, list[str]] = defaultdict(list)
        
        for edge in edges.values():
            self._adjacency[edge.source_id].append(edge.target_id)
            self._reverse_adjacency[edge.target_id].append(edge.source_id)
        
        # Build edge caches symmetrically (O(k) lookups for both directions)
        self._edge_cache: Dict[str, list[PressureEdge]] = defaultdict(list)
        self._outbound_edge_cache: Dict[str, list[PressureEdge]] = defaultdict(list)
        
        for edge in edges.values():
            self._edge_cache[edge.target_id].append(edge)
            self._outbound_edge_cache[edge.source_id].append(edge)
        
        # Freeze after initialization
        self._frozen = True
    
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
                # Calculate inbound pressure
                inbound_pressure = 0.0
                inbound_edges = self._get_inbound_edges(node_id)
                
                for edge in inbound_edges:
                    source_pressure = pressures.get(edge.source_id, 0.0)
                    # Multiply by edge confidence for evidence-traceable propagation
                    inbound_pressure += (
                        source_pressure *
                        edge.transfer_factor *
                        edge.confidence
                    )
                
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
        return self._outbound_edge_cache.get(node_id, [])
    
    def _get_inbound_edges(self, node_id: str) -> list[PressureEdge]:
        """
        Optimized version using edge cache.
        O(k) where k is number of inbound edges.
        """
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
        
        NOTE: This method clones nodes to avoid mutating live graph state.
        """
        # Clone nodes to avoid mutating live objects
        from copy import deepcopy
        cloned_nodes = {
            node_id: deepcopy(node)
            for node_id, node in self.nodes.items()
        }
        
        # Create temporary propagator with cloned nodes
        temp_propagator = PressurePropagator(
            cloned_nodes,
            self.edges,
            damping_factor=self.damping_factor,
            epsilon=self.epsilon,
            max_iterations=self.max_iterations
        )
        
        # For each crown jewel, verify pressure doesn't decrease when upstream severity increases
        for cj_id in crown_jewel_ids:
            baseline_pressure = baseline_pressures.get(cj_id, 0.0)
            
            # Try increasing severity of each upstream node
            for node_id, node in cloned_nodes.items():
                if node_id == cj_id:
                    continue
                
                # Increase severity on cloned node (safe)
                node.severity = min(10.0, node.severity + 1.0)
                
                # Recompute base pressure
                node.base_pressure = (
                    node.severity *
                    node.exposure *
                    node.exploitability *
                    node.privilege_gain *
                    node.asset_value
                )
                
                # Propagate new pressures using cloned propagator
                new_pressures = temp_propagator.propagate(crown_jewel_ids)
                new_cj_pressure = new_pressures.get(cj_id, 0.0)
                
                # Check invariant
                if new_cj_pressure < baseline_pressure - self.epsilon:
                    return False  # Violation detected
        
        return True  # Invariant holds
    
    def _check_mutable(self) -> None:
        """
        Ensure propagator is not frozen.
        
        Raises:
            RuntimeError: If propagator has been frozen
        """
        if self._frozen:
            raise RuntimeError(
                "PressurePropagator is immutable after initialization. "
                "Create a new instance for modified graphs."
            )
    
    def explain_pressure(self,
                        crown_jewel_id: str,
                        top_n: int = 3) -> Dict:
        """
        Explain why a crown jewel has its current pressure.
        
        Traces back through incoming edges to identify top contributors.
        
        Args:
            crown_jewel_id: The crown jewel node to explain
            top_n: Number of top contributors to return (default 3)
        
        Returns:
            Dict with:
                - crown_jewel_id: str
                - total_pressure: float
                - top_contributors: List of dicts explaining each contributor
        
        Example:
            {
                "crown_jewel_id": "db_prod",
                "total_pressure": 8.5,
                "top_contributors": [
                    {
                        "source_id": "vuln_123",
                        "pressure_contribution": 4.2,
                        "transfer_chain": [...]
                    }
                ]
            }
        """
        # Get current pressures
        pressures = self.propagate({crown_jewel_id})
        total_pressure = pressures.get(crown_jewel_id, 0.0)
        
        # Get inbound edges
        inbound_edges = self._get_inbound_edges(crown_jewel_id)
        
        # Calculate contributions from each inbound edge
        contributors = []
        for edge in inbound_edges:
            source_pressure = pressures.get(edge.source_id, 0.0)
            contribution = (
                source_pressure *
                edge.transfer_factor *
                edge.confidence
            )
            
            # Trace back the transfer chain
            transfer_chain = self._trace_transfer_chain(
                edge.source_id,
                crown_jewel_id,
                pressures,
                max_depth=5
            )
            
            contributors.append({
                "source_id": edge.source_id,
                "pressure_contribution": contribution,
                "transfer_chain": transfer_chain
            })
        
        # Sort by contribution (descending)
        contributors.sort(key=lambda x: x["pressure_contribution"], reverse=True)
        
        return {
            "crown_jewel_id": crown_jewel_id,
            "total_pressure": total_pressure,
            "top_contributors": contributors[:top_n]
        }
    
    def _trace_transfer_chain(self,
                             start_node: str,
                             end_node: str,
                             pressures: Dict[str, float],
                             max_depth: int = 5) -> List[Dict]:
        """
        Trace the transfer chain from start_node to end_node.
        
        Returns a list of (node, edge) tuples showing the pressure flow.
        """
        if max_depth <= 0 or start_node == end_node:
            return []
        
        # Find edge from start_node to its next hop toward end_node
        chain = []
        
        # Get outbound edges
        outbound_edges = self.get_outbound_edges(start_node)
        
        # Find edge that leads toward end_node (BFS heuristic)
        for edge in outbound_edges:
            # If this edge connects to end_node directly
            if edge.target_id == end_node:
                chain.append({
                    "node_id": start_node,
                    "pressure": pressures.get(start_node, 0.0),
                    "edge_id": edge.id,
                    "transfer_factor": edge.transfer_factor,
                    "confidence": edge.confidence
                })
                chain.append({
                    "node_id": end_node,
                    "pressure": pressures.get(end_node, 0.0),
                    "edge_id": None,
                    "transfer_factor": None,
                    "confidence": None
                })
                break
            
            # Otherwise, recurse
            sub_chain = self._trace_transfer_chain(
                edge.target_id,
                end_node,
                pressures,
                max_depth - 1
            )
            
            if sub_chain:
                chain.append({
                    "node_id": start_node,
                    "pressure": pressures.get(start_node, 0.0),
                    "edge_id": edge.id,
                    "transfer_factor": edge.transfer_factor,
                    "confidence": edge.confidence
                })
                chain.extend(sub_chain)
                break
        
        return chain