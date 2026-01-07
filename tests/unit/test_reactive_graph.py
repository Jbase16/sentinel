import unittest
from unittest.mock import MagicMock
from core.cortex.causal_graph import CausalGraphBuilder
# Mocking EpistemicEvent to avoid importing the real one (which might need config)
from dataclasses import dataclass

@dataclass
class MockEvent:
    event_type: str
    entity_id: str
    payload: dict

class TestReactiveGraph(unittest.TestCase):
    
    def test_update_from_promoted_event(self):
        builder = CausalGraphBuilder()
        
        # Simulate a PROMOTED event from the ledger
        payload = {
            "title": "Open Port 22", 
            "severity": "medium",
            "metadata": {"type": "Open Port", "target": "192.168.1.1"}
        }
        event = MockEvent("promoted", "find-123", payload)
        
        # Action
        builder.update_from_event(event) # Duck typing should work
        
        # Verify
        self.assertIn("find-123", builder.findings_map)
        self.assertTrue(builder.graph.has_node("find-123"))
        node = builder.graph.nodes["find-123"]
        self.assertEqual(node["title"], "Open Port 22")
        self.assertEqual(node["target"], "192.168.1.1")

    def test_incremental_inference(self):
        # Test that adding a vulnerability connects to an existing port
        builder = CausalGraphBuilder()
        
        # 1. Add Port (Existing)
        port_event = MockEvent("promoted", "port-22", {
            "title": "SSH Port",
            "metadata": {"type": "Open Port", "target": "10.0.0.1"}
        })
        builder.update_from_event(port_event)
        
        # 2. Add Vuln (New Event)
        vuln_event = MockEvent("promoted", "vuln-ssh", {
            "title": "SSH RCE",
            "metadata": {"type": "Remote Code Execution (RCE)", "target": "10.0.0.1"}
        })
        builder.update_from_event(vuln_event)
        
        # Verify Edge: Port -> Vuln (enables)
        self.assertTrue(builder.graph.has_edge("port-22", "vuln-ssh"))

if __name__ == '__main__':
    unittest.main()
