
import unittest
from core.data.pressure_graph.models import PressureNode, PressureEdge, EdgeType, Remediation, PressureSource, RemediationState
from core.data.pressure_graph.explanation import CausalExplainer, PressurePath
from core.data.pressure_graph.counterfactual import CounterfactualEngine
from core.data.pressure_graph.propagator import PressurePropagator

class TestV2Logic(unittest.TestCase):
    def setUp(self):
        # Create a simple chain: Source -> Middle -> Target (Crown Jewel)
        self.source = PressureNode("source", "vuln", 10.0, 1.0, 1.0, 1.0, 5.0)
        self.middle = PressureNode("middle", "asset", 1.0, 1.0, 1.0, 1.0, 5.0)
        # Low severity/exploitability locally, but high asset value
        self.target = PressureNode("target", "crown_jewel", 0.1, 1.0, 0.1, 1.0, 100.0) # Base = 0.1*1*0.1*1*100 = 1.0
        
        self.nodes = {
            "source": self.source,
            "middle": self.middle,
            "target": self.target
        }
        
        self.edge1 = PressureEdge("e1", "source", "middle", EdgeType.ENABLES, 0.8, 1.0)
        self.edge2 = PressureEdge("e2", "middle", "target", EdgeType.AMPLIFIES, 0.9, 1.0)
        
        self.edges = {
            "e1": self.edge1,
            "e2": self.edge2
        }
        
        # Build reverse index for explainer
        self.reverse_edges = {
            "middle": [self.edge1],
            "target": [self.edge2]
        }

    def test_causal_explanation(self):
        explainer = CausalExplainer(self.nodes, self.reverse_edges)
        paths = explainer.explain_pressure("target", max_paths=1)
        
        self.assertTrue(len(paths) > 0)
        path = paths[0]
        # Should be [Target, Middle, Source] (reverse order in path logic? let's check implementation)
        # Implementation says: full_path = [current_node_id] + list(reversed(current_path))
        # If traversal is Target -> Middle -> Source
        # At Source: current_path is [Target, Middle]. Reversed: [Middle, Target]. 
        # Full path = [Source, Middle, Target].
        # Let's verify explanation.py logic:
        # _find_top_paths(target_id ... current_path=[])
        #  recurse(edge.source_id, current_path + [current_node_id])
        #  Target -> Middle (current_path=[Target])
        #   recurse(Source, current_path=[Target, Middle])
        #    At Source: Full path = [Source] + reversed([Target, Middle]) = [Source, Middle, Target].
        
        print(f"Path found: {path.path}")
        self.assertEqual(path.path, ["source", "middle", "target"])
        self.assertTrue(path.contribution > 0)

    def test_remediation_revision(self):
        remediation = Remediation(
            id="fix_source",
            name="Patch Source",
            state=RemediationState.PROPOSED,
            nodes_to_remove={"source"}
        )
        
        # Test helper method
        modified_node = remediation.apply_to_node(self.source)
        self.assertIsNone(modified_node)
        
        remediation_reduce = Remediation(
            id="dampen_source",
            name="Mitigate Source",
            state=RemediationState.APPLIED,
            node_pressure_reductions={"source": 0.5}
        )
        
        mod_node = remediation_reduce.apply_to_node(self.source)
        self.assertIsNotNone(mod_node)
        self.assertEqual(mod_node.revision, 2)
        self.assertEqual(mod_node.remediation_state, RemediationState.APPLIED)
        self.assertLess(mod_node.severity, self.source.severity)

if __name__ == "__main__":
    unittest.main()
