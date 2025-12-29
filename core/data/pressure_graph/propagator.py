"""
The Solver.

Implements Iterative Relaxation with Weight Normalization guarantees.
"""

from typing import Dict, Set, Optional
from collections import defaultdict

from .models import PressureNode, PressureEdge


class PressurePropagator:
    """
    Immutable Graph Solver.
    
    Solves the system (I - dW)P = (1-d)B.
    Enforces normalization to guarantee spectral radius convergence.
    """
    
    def __init__(self, 
                 nodes: Dict[str, PressureNode],
                 edges: Dict[str, PressureEdge],
                 damping_factor: float = 0.85,
                 epsilon: float = 1e-6,
                 max_iterations: int = 1000):
        self.nodes = nodes
        self.edges = edges
        self.damping_factor = damping_factor
        self.epsilon = epsilon
        self.max_iterations = max_iterations
        
        # Immutability Lock
        self._frozen = False
        
        # Optimization: Pre-compute adjacency lists
        # _outbound: Node -> List[Edge]
        # _inbound: Node -> List[Edge]
        self._outbound_cache: Dict[str, List[PressureEdge]] = defaultdict(list)
        self._inbound_cache: Dict[str, List[PressureEdge]] = defaultdict(list)
        
        self._build_graph_structure()
        
        # Optimization: Weight Normalization
        # Ensures sum of inbound transfers for any node <= 1.0 * damping_factor
        # This guarantees convergence.
        self._normalize_weights()
        
        # Freeze
        self._frozen = True
    
    def __setattr__(self, name, value):
        if getattr(self, "_frozen", False):
            raise RuntimeError(
                f"Cannot mutate {name}. PressurePropagator is immutable."
            )
        super().__setattr__(name, value)
    
    def _build_graph_structure(self):
        """Populates adjacency caches."""
        for edge in self.edges.values():
            self._outbound_cache[edge.source_id].append(edge)
            self._inbound_cache[edge.target_id].append(edge)
    
    def _normalize_weights(self):
        """
        Enforces Convergence Invariant.
        
        For every node, normalizes inbound edge weights so their sum is 1.0,
        then applies the damping factor.
        """
        for target_id, inbound_edges in self._inbound_cache.items():
            # Calculate raw sum
            raw_sum = sum(
                e.transfer_factor * e.confidence for e in inbound_edges
            )
            
            if raw_sum > 0:
                # Normalize to 1.0 then damp
                # w_norm = (w / sum) * damping
                for edge in inbound_edges:
                    # We mutate the edge's private cache slot.
                    # Since edges are frozen, we use object.__setattr__ on the edge object.
                    # This is safe because it happens only once at init and doesn't break hash/eq.
                    w = edge.transfer_factor * edge.confidence
                    w_norm = (w / raw_sum) * self.damping_factor
                    object.__setattr__(edge, '_normalized_transfer_factor', w_norm)
            else:
                # No inbound pressure sources
                for edge in inbound_edges:
                    object.__setattr__(edge, '_normalized_transfer_factor', 0.0)
    
    def propagate(self, 
                crown_jewel_ids: Set[str],
                initial_pressures: Optional[Dict[str, float]] = None) -> Dict[str, float]:
        """
        Computes the fixed point pressure vector P.
        
        P_new = (1-d) * Base + Normalized_Inbound_Contribution
        """
        # Init Vector
        if initial_pressures is None:
            pressures = {nid: n.base_pressure for nid, n in self.nodes.items()}
        else:
            pressures = dict(initial_pressures)
        
        # Iterate
        for _ in range(self.max_iterations):
            max_delta = 0.0
            new_pressures = dict(pressures) # Copy-on-write for vector
            
            for node_id, node in self.nodes.items():
                # Base term (intrinsic)
                base_term = (1 - self.damping_factor) * node.base_pressure
                
                # Inbound term (propagated)
                inbound_pressure = 0.0
                inbound_edges = self._inbound_cache.get(node_id, [])
                
                for edge in inbound_edges:
                    # Check: Is the source a Crown Jewel?
                    # If so, it is a Sink. It absorbs pressure but does not forward.
                    # This is enforced at the transfer boundary.
                    if edge.source_id in crown_jewel_ids:
                        continue
                    
                    source_p = pressures.get(edge.source_id, 0.0)
                    # Use pre-normalized transfer factor (already includes damping)
                    # Confidence is baked into effective_transfer via normalization
                    inbound_pressure += source_p * edge.effective_transfer
                
                total_pressure = base_term + inbound_pressure
                
                # Physics: Pressure cannot be negative
                total_pressure = max(0.0, total_pressure)
                
                # Convergence Check
                delta = abs(total_pressure - pressures[node_id])
                max_delta = max(max_delta, delta)
                
                new_pressures[node_id] = total_pressure
            
            pressures = new_pressures
            
            if max_delta < self.epsilon:
                break
                
        return pressures
    
    def get_inbound_edges(self, node_id: str):
        return self._inbound_cache.get(node_id, [])
        
    def get_outbound_edges(self, node_id: str):
        return self._outbound_cache.get(node_id, [])