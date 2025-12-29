"""
Module explanation: Causal explanation engine for Pressure Graph.

PURPOSE:
Answer "Why is this node under pressure?" in one hop.
Provides top-N causal chains contributing to a node's pressure.

Ensures the "Crown Jewel" stress can be instantly understood by the user.
"""

from dataclasses import dataclass
from typing import List, Dict, Set, Optional
import heapq

from core.data.pressure_graph.models import NodeId, PressureNode, PressureEdge

@dataclass
class PressurePath:
    """A causal chain explaining pressure contribution."""
    path: List[NodeId]  # [source, ..., target]
    contribution: float # Amount of pressure delivered by this path
    
    def __lt__(self, other):
        # Reverse logic for max-heap (we want highest pressure)
        return self.contribution > other.contribution

class CausalExplainer:
    """
    Engine for generating causal pressure explanations.
    """
    
    def __init__(self, nodes: Dict[NodeId, PressureNode], edges: Dict[NodeId, List[PressureEdge]]):
        """
        Args:
            nodes: Map of NodeId -> PressureNode
            edges: Adjacency list (incoming edges per node) for backward traversal
                   Map[TargetId, List[IncomingEdge]]
        """
        self.nodes = nodes
        self.incoming_edges = edges
        
    def explain_pressure(self, target_id: NodeId, max_paths: int = 3) -> List[PressurePath]:
        """
        Trace back high-pressure flows to their origin.
        
        Algorithm:
        Dijkstra-like backward search (or just recursive DFS with memoization if DAG)
        to find paths with highest multiplicative transfer * source base pressure.
        
        For V2 MVP, we use a simplified greedy backtracking strategy:
        At each hop, follow the edge delivering the most pressure.
        """
        if target_id not in self.nodes:
            return []
            
        target = self.nodes[target_id]
        paths: List[PressurePath] = []
        
        # Simple implementation: Find top contributing neighbors, then recurse?
        # Better: Priority Queue search for highest-weight paths.
        
        # We want to find paths [S, A, B, T] such that:
        # P(S) * Transfer(S->A) * ... * Transfer(B->T) is maximized.
        
        # Let's verify if we have infinite loops (shouldn't with DAG).
        # We will limit depth to avoid issues.
        
        self._find_top_paths(target_id, current_path=[], current_weight=1.0, results=paths, limit=max_paths)
        
        # Sort by contribution descending
        paths.sort(key=lambda x: x.contribution, reverse=True)
        return paths[:max_paths]

    def _find_top_paths(self, 
                       current_node_id: NodeId, 
                       current_path: List[NodeId], 
                       current_weight: float, 
                       results: List[PressurePath],
                       limit: int,
                       depth: int = 0):
        
        # Safety break
        if depth > 10:
            return
            
        # Add current node to path (building backwards: [Target, B, A, Source])
        # Wait, let's build logic: 
        # Path total pressure = Source.base_pressure * Path_Transfer
        
        # We are traversing backwards.
        # Current weight tracks the cumulative transfer from Target back to here.
        
        print(f"DEBUG: Visiting {current_node_id}, weight: {current_weight}, depth: {depth}")
        node = self.nodes.get(current_node_id)
        if not node:
            print("DEBUG: Node not found")
            return

        # If this node has base pressure, it's a source candidate.
        if node.base_pressure > 0.01:
            total_contribution = node.base_pressure * current_weight
            full_path = [current_node_id] + list(reversed(current_path))
            print(f"DEBUG: Found path: {full_path}, contrib: {total_contribution}")
            results.append(PressurePath(path=full_path, contribution=total_contribution))
            
        # Recurse to parents (incoming edges)
        incoming = self.incoming_edges.get(current_node_id, [])
        print(f"DEBUG: Incoming edges for {current_node_id}: {len(incoming)}")
        
        # Optimization: Only follow top 3 heaviest incoming edges to prevent explosion
        top_incoming = sorted(incoming, key=lambda e: e.effective_transfer, reverse=True)[:3]
        
        for edge in top_incoming:
            # Prevent cycles
            if edge.source_id in current_path or edge.source_id == current_node_id:
                continue
                
            new_weight = current_weight * edge.effective_transfer
            print(f"DEBUG: Traversing edge {edge.source_id}->{edge.target_id} (transfer {edge.effective_transfer}), new weight {new_weight}")
            # Cutoff if contribution is negligible
            if new_weight < 0.01:
                continue
                
            self._find_top_paths(
                edge.source_id,
                current_path + [current_node_id],
                new_weight,
                results,
                limit,
                depth + 1
            )
