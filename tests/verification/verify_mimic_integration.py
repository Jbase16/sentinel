"""
Verification Script for Project MIMIC Integration.
Scenario:
1. Instantiate GhostAddon (wiring check).
2. Simulate a proxy request (Ghost Intercept).
3. Assert that ShadowSpec (MIMIC) learned the route.
"""
import sys
from unittest.mock import MagicMock
# Mock mitmproxy package hierarchy explicitly
mock_mitmproxy = MagicMock()
sys.modules['mitmproxy'] = mock_mitmproxy
sys.modules['mitmproxy.http'] = MagicMock()
sys.modules['mitmproxy.options'] = MagicMock()
sys.modules['mitmproxy.tools'] = MagicMock()
sys.modules['mitmproxy.tools.dump'] = MagicMock()

from core.ghost.proxy import GhostAddon
from core.base.session import ScanSession

class MockFlow:
    def __init__(self, method, url, host):
        self.request = MagicMock()
        self.request.pretty_url = url
        self.request.method = method
        self.request.host = host
        self.request.query = {}
        self.response = MagicMock()
        self.response.headers = {}

def run_test():
    print("🔌 Initializing MIMIC Integration Test...")
    
    # 1. Setup
    session = MagicMock(spec=ScanSession)
    session.log = MagicMock()
    session.findings = MagicMock()
    # Mocking strategy to avoid AI calls
    from core.ai.strategy import StrategyEngine
    StrategyEngine.propose_attacks = MagicMock()
    
    addon = GhostAddon(session)
    
    # Check Wiring
    assert addon.shadow_spec is not None
    print("✅ ShadowSpec Wired to GhostAddon")
    assert addon.strategy.shadow_spec is not None
    print("✅ ShadowSpec Wired to StrategyEngine")
    
    # 2. Simulate User Traffic
    # Request 1: /api/users/1
    flow1 = MockFlow("GET", "http://target.com/api/users/1", "target.com")
    addon.request(flow1)
    
    # Request 2: /api/users/2
    flow2 = MockFlow("GET", "http://target.com/api/users/2", "target.com")
    addon.request(flow2)
    
    print("🚀 Simulated Traffic Ingested")
    
    # 3. Verify MIMIC learned the structure
    # We expect /api/users/{id}
    # We need to dig into the miner state
    # Root -> "api" -> "users" -> "{id}"
    
    miner = addon.shadow_spec.miner
    root = miner.root
    
    # Traverse
    # Empty root -> "api"
    api_node = root.get_child("api")
    assert api_node is not None
    
    users_node = api_node.get_child("users")
    assert users_node is not None
    
    # The magic: "1" and "2" should be clustered into "{id}"
    id_node = users_node.get_child("{id}")
    if not id_node:
        # Debug output if fail
        print(f"FAILED: Children of 'users': {users_node.children.keys()}")
    
    assert id_node is not None
    assert id_node.is_parameter == True
    
    # Check Endpoint
    endpoint = id_node.endpoints.get("GET")
    assert endpoint is not None
    print(f"✅ Learned Endpoint: {endpoint.method} {endpoint.path_template}")
    assert endpoint.path_template == "/api/users/{id}"
    
    print("\n🎉 MIMIC Integration Verified!")

if __name__ == "__main__":
    run_test()
