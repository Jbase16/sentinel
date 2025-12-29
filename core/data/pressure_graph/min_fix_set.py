"""
Minimal fix set computation using node-splitting min-cut.

Uses Dinic's max-flow algorithm to find optimal remediation sets
that break all attack paths to crown jewels.
"""

from typing import Dict, Set, List, Tuple
from collections import deque, defaultdict

from .models import PressureNode, PressureEdge, Remediation
from .propagator import PressurePropagator


class MinimalFixSetEngine:
    """
    Computes minimal sets of remediations that protect crown jewels.
    
    Uses node-splitting min-cut:
    - Split every node V into V_in and V_out
    - Connect V_in → V_out with capacity = remediation cost
    - Entry points → super-source, Crown jewels → super-sink
    - Min-cut = minimal cost to block all paths
    
    LIMITATIONS:
    - Currently returns only the single minimum-cost min-cut
    - Does not enumerate alternative min-cuts with same cost
    - Future enhancement: Use Gomory-Hu tree or min-cut enumeration
      to generate multiple disjoint fix sets
    """
    
    def __init__(self, 
                 nodes: Dict[str, PressureNode],
                 edges: Dict[str, PressureEdge],
                 propagator: PressurePropagator):
        """
        Initialize minimal fix set engine.
        
        Args:
            nodes: Dict of node_id -> PressureNode
            edges: Dict of edge_id -> PressureEdge
            propagator: PressurePropagator instance
        """
        self.nodes = nodes
        self.edges = edges
        self.propagator = propagator
    
    def compute_minimal_fix_sets(self,
                                 crown_jewel_ids: Set[str],
                                 max_sets: int = 5) -> List[List[Remediation]]:
        """
        Compute top N minimal fix sets that protect crown jewels.
        
        Each fix set is a list of remediations that, together,
        break all viable attack paths to crown jewels.
        
        Args:
            crown_jewel_ids: Set of crown jewel node IDs
            max_sets: Number of fix sets to return
        
        Returns:
            List of fix sets, each containing remediations.
            Sorted by total cost (ascending).
        """
        # Build flow network with node splitting
        flow_network = self._build_flow_network(crown_jewel_ids)
        
        # Compute min-cut using Dinic's algorithm
        min_cut_edges = self._dinic_min_cut(flow_network)
        
        # Map min-cut edges to remediations
        fix_sets: List[List[Remediation]] = []
        for cut_edges in min_cut_edges:
            remediations = self._edges_to_remediations(cut_edges)
            if remediations:
                fix_sets.append(remediations)
        
        # Remove duplicates and sort by cost
        unique_fix_sets = self._deduplicate_fix_sets(fix_sets)
        unique_fix_sets.sort(key=lambda rs: sum(r.cost for r in rs))
        
        return unique_fix_sets[:max_sets]
    
    def _build_flow_network(self, crown_jewel_ids: Set[str]) -> Dict:
        """
        Build flow network for max-flow algorithm using node splitting.
        
        Node splitting technique:
        - For each node V, create V_in and V_out
        - Add edge V_in → V_out with capacity = remediation cost
        - This allows us to "cut" a node by cutting this internal edge
        
        Flow network structure:
        - Entry points → super-source
        - Crown jewels → super-sink
        - All other nodes are split (V_in → V_out)
        """
        # Assign numeric IDs to split nodes
        node_to_in_id: Dict[str, int] = {}
        node_to_out_id: Dict[str, int] = {}
        
        next_id = 0
        for node_id in self.nodes.keys():
            node_to_in_id[node_id] = next_id
            next_id += 1
            node_to_out_id[node_id] = next_id
            next_id += 1
        
        # Create super-source and super-sink
        super_source = next_id
        super_sink = next_id + 1
        
        # Build adjacency list and capacity matrix
        capacity: Dict[Tuple[int, int], float] = defaultdict(float)
        adj: Dict[int, List[int]] = defaultdict(list)
        
        # Connect entry points to super-source (infinite capacity)
        entry_points = self._find_entry_points()
        for entry_id in entry_points:
            entry_in = node_to_in_id[entry_id]
            capacity[(super_source, entry_in)] = float('inf')
            adj[super_source].append(entry_in)
            adj[entry_in].append(super_source)
        
        # Connect crown jewels (out) to super-sink (infinite capacity)
        for cj_id in crown_jewel_ids:
            if cj_id not in node_to_out_id:
                continue
            
            cj_out = node_to_out_id[cj_id]
            capacity[(cj_out, super_sink)] = float('inf')
            adj[cj_out].append(super_sink)
            adj[super_sink].append(cj_out)
        
        # Add node-splitting edges (V_in → V_out)
        for node_id, node in self.nodes.items():
            node_in = node_to_in_id[node_id]
            node_out = node_to_out_id[node_id]
            
            # Capacity = remediation cost (default 1.0, could be from metadata)
            # Crown jewels have infinite cost (we don't want to cut them)
            if node_id in crown_jewel_ids:
                cap = float('inf')
            else:
                cap = 1.0  # Default unit cost
            
            capacity[(node_in, node_out)] = cap
            adj[node_in].append(node_out)
            adj[node_out].append(node_in)
        
        # Add graph edges
        for edge in self.edges.values():
            if (edge.source_id not in node_to_out_id or 
                edge.target_id not in node_to_in_id):
                continue
            
            source_out = node_to_out_id[edge.source_id]
            target_in = node_to_in_id[edge.target_id]
            
            # Capacity = 1 (or could use transfer factor)
            cap = 1.0
            
            capacity[(source_out, target_in)] = cap
            adj[source_out].append(target_in)
            adj[target_in].append(source_out)
        
        return {
            "node_to_in_id": node_to_in_id,
            "node_to_out_id": node_to_out_id,
            "super_source": super_source,
            "super_sink": super_sink,
            "capacity": dict(capacity),
            "adj": dict(adj)
        }
    
    def _dinic_min_cut(self, flow_network: Dict) -> List[List[Tuple[str, str]]]:
        """
        Compute min-cut using Dinic's max-flow algorithm.
        
        Returns list of min-cuts (each cut is list of edges).
        For now, returns single min-cut.
        """
        # Run Dinic's to compute max flow
        max_flow, flow_network = self._dinic_max_flow(flow_network)
        
        # Extract min-cut edges from residual graph
        min_cut_edges = self._extract_min_cut(flow_network)
        
        return [min_cut_edges] if min_cut_edges else []
    
    def _dinic_max_flow(self, flow_network: Dict) -> Tuple[float, Dict]:
        """
        Dinic's algorithm for max-flow.
        
        Returns (max_flow_value, updated_flow_network).
        """
        # Extract components
        super_source = flow_network["super_source"]
        super_sink = flow_network["super_sink"]
        capacity = flow_network["capacity"]
        adj = flow_network["adj"]
        
        # Flow matrix
        flow: Dict[Tuple[int, int], float] = defaultdict(float)
        
        total_flow = 0.0
        
        # Main loop: construct level graph and send blocking flow
        while True:
            # Build level graph using BFS
            level = self._dinic_bfs(super_source, super_sink, capacity, flow, adj)
            
            if level.get(super_sink, -1) == -1:
                # No augmenting path
                break
            
            # Send blocking flow using DFS
            it: Dict[int, int] = defaultdict(int)
            while True:
                pushed = self._dinic_dfs(
                    super_source, super_sink, float('inf'),
                    level, it, capacity, flow, adj
                )
                
                if pushed <= 0:
                    break
                
                total_flow += pushed
        
        # Update flow network with actual flow values
        flow_network["flow"] = dict(flow)
        
        return total_flow, flow_network
    
    def _dinic_bfs(self,
                   source: int,
                   sink: int,
                   capacity: Dict[Tuple[int, int], float],
                   flow: Dict[Tuple[int, int], float],
                   adj: Dict[int, List[int]]) -> Dict[int, int]:
        """
        BFS to construct level graph.
        
        Returns level dict where level[node] = distance from source.
        """
        level: Dict[int, int] = {}
        level[source] = 0
        
        queue = deque([source])
        
        while queue:
            u = queue.popleft()
            
            for v in adj.get(u, []):
                # Only consider edges with remaining capacity
                if capacity.get((u, v), 0.0) - flow.get((u, v), 0.0) > 0:
                    if v not in level:
                        level[v] = level[u] + 1
                        queue.append(v)
        
        return level
    
    def _dinic_dfs(self,
                   u: int,
                   sink: int,
                   pushed: float,
                   level: Dict[int, int],
                   it: Dict[int, int],
                   capacity: Dict[Tuple[int, int], float],
                   flow: Dict[Tuple[int, int], float],
                   adj: Dict[int, List[int]]) -> float:
        """
        DFS to send flow in level graph.
        
        Returns amount of flow pushed.
        """
        if u == sink:
            return pushed
        
        while it[u] < len(adj.get(u, [])):
            v = adj[u][it[u]]
            
            # Check if edge is in level graph
            if level.get(v, -1) != level.get(u, -1) + 1:
                it[u] += 1
                continue
            
            # Check if edge has remaining capacity
            remaining = capacity.get((u, v), 0.0) - flow.get((u, v), 0.0)
            if remaining <= 0:
                it[u] += 1
                continue
            
            # Recursively push flow
            pushed_flow = self._dinic_dfs(
                v, sink, min(pushed, remaining),
                level, it, capacity, flow, adj
            )
            
            if pushed_flow > 0:
                flow[(u, v)] += pushed_flow
                flow[(v, u)] -= pushed_flow
                return pushed_flow
            
            it[u] += 1
        
        return 0.0
    
    def _extract_min_cut(self, flow_network: Dict) -> List[Tuple[str, str]]:
        """
        Extract min-cut edges from residual graph.
        
        Min-cut = edges from reachable nodes to non-reachable nodes
        in the residual graph.
        """
        # Extract components
        super_source = flow_network["super_source"]
        super_sink = flow_network["super_sink"]
        capacity = flow_network["capacity"]
        flow = flow_network.get("flow", {})
        adj = flow_network["adj"]
        
        # BFS on residual graph to find reachable nodes
        reachable = set()
        queue = deque([super_source])
        
        while queue:
            u = queue.popleft()
            if u in reachable:
                continue
            
            reachable.add(u)
            
            for v in adj.get(u, []):
                # Edge exists in residual graph if it has remaining capacity
                if capacity.get((u, v), 0.0) - flow.get((u, v), 0.0) > 0:
                    if v not in reachable:
                        queue.append(v)
        
        # Find edges crossing from reachable to non-reachable
        min_cut_edges: List[Tuple[str, str]] = []
        
        node_to_in_id = flow_network["node_to_in_id"]
        node_to_out_id = flow_network["node_to_out_id"]
        
        # Build reverse mapping
        in_id_to_node = {v: k for k, v in node_to_in_id.items()}
        out_id_to_node = {v: k for k, v in node_to_out_id.items()}
        
        for (u, v), cap in capacity.items():
            if cap == float('inf'):
                continue
            
            if u in reachable and v not in reachable:
                # Edge is in min-cut
                
                # Check if this is a node-splitting edge (V_in → V_out)
                if u in in_id_to_node and v in out_id_to_node:
                    node_id = in_id_to_node[u]
                    if node_id == out_id_to_node[v]:
                        # This is a node split edge
                        min_cut_edges.append((node_id, node_id))
                
                # Check if this is a graph edge
                elif u in out_id_to_node and v in in_id_to_node:
                    source_id = out_id_to_node[u]
                    target_id = in_id_to_node[v]
                    min_cut_edges.append((source_id, target_id))
        
        return min_cut_edges
    
    def _edges_to_remediations(self, cut_edges: List[Tuple[str, str]]) -> List[Remediation]:
        """
        Map cut edges back to remediations.
        
        Node-split edges → Node removal remediation
        Graph edges → Edge removal remediation
        """
        remediations: List[Remediation] = []
        
        for source_id, target_id in cut_edges:
            # Node-split edge (source == target)
            if source_id == target_id:
                # Create remediation: remove this node
                node = self.nodes.get(source_id)
                if node:
                    remediation = Remediation(
                        id=f"remove_node_{source_id}",
                        name=f"Remove {node.type} {source_id}",
                        nodes_to_remove={source_id},
                        effort=0.5,
                        cost=1.0
                    )
                    remediations.append(remediation)
            
            # Graph edge
            else:
                # Find edge
                edge = None
                for e in self.edges.values():
                    if e.source_id == source_id and e.target_id == target_id:
                        edge = e
                        break
                
                if edge:
                    # Create remediation: remove this edge
                    remediation = Remediation(
                        id=f"remove_edge_{edge.id}",
                        name=f"Block {edge.type.value} from {source_id} to {target_id}",
                        edges_to_remove={edge.id},
                        effort=0.3,
                        cost=0.5
                    )
                    remediations.append(remediation)
        
        return remediations
    
    def _deduplicate_fix_sets(self, fix_sets: List[List[Remediation]]) -> List[List[Remediation]]:
        """
        Remove duplicate fix sets (same set of remediations).
        """
        unique: List[List[Remediation]] = []
        seen: Set[Tuple[str, ...]] = set()
        
        for fix_set in fix_sets:
            remediation_ids = tuple(sorted(r.id for r in fix_set))
            if remediation_ids not in seen:
                seen.add(remediation_ids)
                unique.append(fix_set)
        
        return unique
    
    def _find_entry_points(self) -> List[str]:
        """
        Find entry points (nodes with no inbound edges).
        """
        all_node_ids = set(self.nodes.keys())
        nodes_with_inbound = set()
        
        for edge in self.edges.values():
            nodes_with_inbound.add(edge.target_id)
        
        entry_points = list(all_node_ids - nodes_with_inbound)
        return entry_points