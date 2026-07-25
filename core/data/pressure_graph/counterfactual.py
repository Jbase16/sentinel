"""
Fast counterfactual analysis with dirty subgraph optimization.

Exposes clean properties for external query, hiding internal state.
"""

from typing import Dict, Set, Optional, Tuple
from collections import deque

from .models import PressureNode, PressureEdge, Remediation
from .propagator import PressurePropagator


class CounterfactualEngine:
    """
    Fast remediation impact simulator.
    
    Uses 'Dirty Subgraph' optimization to recompute only affected components.
    """
    
    def __init__(self, 
                 nodes: Dict[str, PressureNode],
                 edges: Dict[str, PressureEdge],
                 propagator: PressurePropagator):
        self.nodes = nodes
        self.edges = edges
        self.propagator = propagator
        
        self._baseline_pressures: Dict[str, float] = {}
        self._crown_jewel_ids: Set[str] = set()
    
    def set_baseline(self, 
                    crown_jewel_ids: Set[str],
                    baseline_pressures: Optional[Dict[str, float]] = None):
        self._crown_jewel_ids = crown_jewel_ids
        if baseline_pressures is None:
            self._baseline_pressures = self.propagator.propagate(crown_jewel_ids)
        else:
            self._baseline_pressures = dict(baseline_pressures)
    
    # --- Public API (Clean Interfaces) ---
    
    @property
    def baseline_pressures(self) -> Dict[str, float]:
        """Returns the cached baseline pressure vector."""
        return self._baseline_pressures
    
    @property
    def crown_jewel_ids(self) -> Set[str]:
        return self._crown_jewel_ids
    
    @property
    def has_baseline(self) -> bool:
        return bool(self._baseline_pressures)
    
    # --- Core Logic ---
    
    def simulate_remediation(self, remediation: Remediation) -> Dict[str, float]:
        dirty_nodes = self._identify_dirty_nodes(remediation)
        shadow_nodes, shadow_edges = self._create_shadow_graph(remediation, dirty_nodes)
        
        # Create a NEW solver for the modified topology
        shadow_propagator = PressurePropagator(
            shadow_nodes,
            shadow_edges,
            damping_factor=self.propagator.damping_factor,
            epsilon=self.propagator.epsilon,
            max_iterations=self.propagator.max_iterations
        )
        
        # Initialize dirty nodes to 0.0 to force re-evaluation
        initial_p = dict(self._baseline_pressures)
        for nid in dirty_nodes:
            if nid in shadow_nodes:
                initial_p[nid] = 0.0
        
        new_pressures = shadow_propagator.propagate(self._crown_jewel_ids, initial_p)
        
        # Merge back
        for nid, base_p in self._baseline_pressures.items():
            if nid not in new_pressures:
                new_pressures[nid] = base_p
                
        return new_pressures

    def compute_deltas(self, remediation: Remediation) -> Dict[str, float]:
        if not self.has_baseline:
            raise ValueError("Baseline not set.")
        
        new_pressures = self.simulate_remediation(remediation)
        return {
            nid: new_pressures.get(nid, 0.0) - base_p 
            for nid, base_p in self._baseline_pressures.items()
        }

    def _identify_dirty_nodes(self, remediation: Remediation) -> Set[str]:
        """Finds reachable nodes from modified nodes."""
        dirty = set(remediation.nodes_to_remove)
        dirty.update(remediation.node_pressure_reductions.keys())
        
        # BFS from dirty nodes
        visited = set(dirty)
        queue = deque(dirty)
        
        while queue:
            nid = queue.popleft()
            
            # Stop at CJs (Sinks)
            if nid in self._crown_jewel_ids:
                continue
                
            for edge in self.propagator.get_outbound_edges(nid):
                if edge.id in remediation.edges_to_remove:
                    continue
                if edge.effective_transfer == 0.0:
                    continue # Dead edge
                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    queue.append(edge.target_id)
        
        return visited
    
    def _create_shadow_graph(self, 
                            remediation: Remediation, 
                            dirty_nodes: Set[str]) -> Tuple[Dict, Dict]:
        # Deep copy only dirty nodes
        s_nodes = {}
        for nid in dirty_nodes:
            orig = self.nodes[nid]
            mod = remediation.apply_to_node(orig)
            if mod:
                s_nodes[nid] = mod
        
        # Copy relevant edges
        s_edges = {}
        for eid, edge in self.edges.items():
            if edge.source_id not in dirty_nodes and edge.target_id not in dirty_nodes:
                continue
            mod = remediation.apply_to_edge(edge)
            if mod:
                s_edges[eid] = mod
            
        return s_nodes, s_edges