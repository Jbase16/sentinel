# ============================================================================
# core/cortex/pathfinder.py
# Cartographer Engine: Graph Algorithms & Strategy
# ============================================================================
#
# PURPOSE:
# The tactical brain of the graph. Uses network theory to find:
# 1. Attack Paths: Shortest route from Internet -> Critical Asset.
# 2. Critical Nodes: "Bridges" that connect disparate clusters.
# 3. Blast Radius: What gets owned if Node X acts as a pivot.
#
# DEPENDENCIES:
# - networkx: For graph algorithms.
#
# ============================================================================

import networkx as nx
from typing import List, Dict, Any, Optional, Set, Tuple

class GraphAnalyzer:
    """
    Wraps NetworkX to provide security-specific graph insights.
    """

    def __init__(self, nodes: List[Dict], edges: List[Dict]):
        """
        Builds the graph from raw nodes and edges.
        """
        self.graph = nx.DiGraph()
        
        for node in nodes:
            self.graph.add_node(node["id"], **node.get("attributes", {}), type=node.get("type", "unknown"))
            
        for edge in edges:
            # Directed graph: source -> target
            # Weight defaults to 1.0. Lower weight = "easier" path usually, 
            # but for hop-count, 1 is fine.
            # If we modeled difficulty, exploit edges might be "costly" (high weight)
            # or "easy" (low weight). Let's assume weight=1 for now (hop count).
            self.graph.add_edge(
                edge["source"], 
                edge["target"], 
                type=edge.get("type", "unknown"),
                weight=edge.get("weight", 1.0)
            )
            
    def find_attack_path(self, source: str, target: str) -> Optional[List[str]]:
        """
        Finds the shortest operational path from source to target.
        Returns list of node IDs or None.
        """
        try:
            return nx.shortest_path(self.graph, source=source, target=target, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def find_critical_bridges(self, to_k: int = 5) -> List[Tuple[str, float]]:
        """
        Identifies nodes with high "Betweenness Centrality".
        These are bridges that control flow between clusters.
        """
        # Betweenness can be slow on massive graphs. 
        # For < 10k nodes it's fine.
        centrality = nx.betweenness_centrality(self.graph, weight="weight")
        # Sort by score desc
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return sorted_nodes[:to_k]

    def calculate_blast_radius(self, node: str, depth: int = 2) -> List[str]:
        """
        Returns all nodes reachable from `node` within `depth` hops.
        Simulates lateral movement potential.
        """
        if node not in self.graph:
            return []
            
        # Ego graph returns the node itself + neighbors.
        # radius=depth
        try:
            subgraph = nx.ego_graph(self.graph, node, radius=depth)
            results = list(subgraph.nodes())
            if node in results:
                results.remove(node) # Exclude self usually? Or keep. Let's keep self in ego, but list implies victims.
            return results
        except Exception:
            return []

    def detect_communities(self) -> Dict[str, int]:
        """
        Detects clusters/communities.
        Note: Community detection on directed graphs is complex.
        Using simple weakly connected components as a proxy for clusters.
        """
        components = list(nx.weakly_connected_components(self.graph))
        # Map node_id -> component_id
        partition = {}
        for idx, comp in enumerate(components):
            for node in comp:
                partition[node] = idx
        return partition
