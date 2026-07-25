import unittest
import asyncio
import json
from core.cortex.graph_analyzer import GraphAnalyzer, _calculate_fingerprint, _serialize_graph_input
from core.cortex.models import TopologyRequest, AnalysisCaps

class TestGraphAnalyzer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Initialize analyzer with 2 workers
        self.analyzer = GraphAnalyzer(max_workers=2)

    async def test_fingerprint_determinism(self):
        graph_a = {"nodes": [{"id": "a"}, {"id": "b"}], "edges": [{"source": "a", "target": "b"}]}
        graph_b = {"edges": [{"target": "b", "source": "a"}], "nodes": [{"id": "b"}, {"id": "a"}]}
        
        fp_a = _calculate_fingerprint(_serialize_graph_input(graph_a))
        fp_b = _calculate_fingerprint(_serialize_graph_input(graph_b))
        
        self.assertEqual(fp_a, fp_b, "Fingerprint should be order-independent")

    async def test_simple_pathfinding(self):
        # A -> B -> C
        graph = {
            "nodes": [{"id": "A"}, {"id": "B"}, {"id": "C"}],
            "edges": [
                {"source": "A", "target": "B"},
                {"source": "B", "target": "C"}
            ]
        }
        
        req = TopologyRequest(
            graph_data=graph,
            entry_nodes=["A"],
            critical_assets=["C"],
            caps=AnalysisCaps(max_paths=5)
        )
        
        result = await self.analyzer.analyze(req)
        
        self.assertEqual(len(result.critical_paths), 1)
        self.assertEqual(result.critical_paths[0].path, ["A", "B", "C"])
        self.assertFalse(result.limits_applied.get("path_capped", False))

    async def test_centrality_small_graph(self):
        # Star graph: Center 'C' connected to L1, L2, L3
        graph = {
            "nodes": [{"id": "C"}, {"id": "L1"}, {"id": "L2"}, {"id": "L3"}],
            "edges": [
                {"source": "L1", "target": "C"},
                {"source": "L2", "target": "C"},
                {"source": "L3", "target": "C"},
            ]
        }
        
        req = TopologyRequest(
            graph_data=graph,
            entry_nodes=[],
            critical_assets=[],
            caps=AnalysisCaps(approximation_threshold=10) # High threshold -> Exact
        )
        
        result = await self.analyzer.analyze(req)
        
        # C should have highest centrality
        # In star graph (undirected), center has high betweenness. 
        # In directed L->C, flow stops at C. Betweenness might be 0 if no paths *through* C.
        # Let's make it flow through: L1 -> C -> R1
        
        # New Graph: L1 -> C -> R1
        graph_flow = {
             "nodes": [{"id": "L1"}, {"id": "C"}, {"id": "R1"}],
             "edges": [{"source": "L1", "target": "C"}, {"source": "C", "target": "R1"}]
        }
        req.graph_data = graph_flow
        
        result = await self.analyzer.analyze(req)
        # C is on the path L1->R1. It should have betweenness > 0
        self.assertGreater(result.centrality.get("C", 0), 0.0)
        self.assertEqual(result.centrality.get("L1", 0), 0.0)

    async def test_limits_capped(self):
        # Create a graph with many parallel paths to ensure we hit the cap.
        # Start -> [M1...M10] -> End
        # This creates 10 distinct paths of length 2.
        
        nodes = [{"id": "Start"}, {"id": "End"}]
        edges = []
        for i in range(10):
            mid_id = f"M{i}"
            nodes.append({"id": mid_id})
            edges.append({"source": "Start", "target": mid_id})
            edges.append({"source": mid_id, "target": "End"})
            
        graph = {"nodes": nodes, "edges": edges}
        
        # Set max_paths to 3, significantly lower than the 10 available paths
        req = TopologyRequest(
            graph_data=graph,
            entry_nodes=["Start"],
            critical_assets=["End"],
            caps=AnalysisCaps(max_paths=3)
        )
        
        result = await self.analyzer.analyze(req)
        
        # Verify we only got 3 paths
        self.assertEqual(len(result.critical_paths), 3)
        # Verify the capped flag was set
        self.assertTrue(result.limits_applied.get("path_capped", False), 
                       "Should report 'path_capped' when paths exceed limit")

if __name__ == '__main__':
    unittest.main()
