"""
Integration Test: The Golden Run (System Loop).
Verifies the full pipeline:
Ghost (Traffic) -> MIMIC (Structure), with Strategy deferred offline
"""
import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
import sys

# Mock mitmproxy hierarchy BEFORE importing Ghost
sys.modules['mitmproxy'] = MagicMock()
sys.modules['mitmproxy.http'] = MagicMock()
sys.modules['mitmproxy.options'] = MagicMock()
sys.modules['mitmproxy.tools'] = MagicMock()
sys.modules['mitmproxy.tools.dump'] = MagicMock()

from core.ghost.proxy import GhostAddon
from core.base.context import ScopeContext
from core.base.scope import AssetType, ScopeDecision, ScopeRegistry, ScopeRule
from core.base.session import ScanSession

@pytest.fixture
def mock_ai():
    with patch("core.ai.ai_engine.AIEngine.instance") as mock:
        engine = MagicMock()
        # Mock analyze method to return a dummy attack vector
        # But Strategy uses propose_attacks which calls analyze_traffic which calls AI
        # We need to mock StrategyEngine.propose_attacks or deeper.
        # Let's mock StrategyEngine.propose_attacks directly to avoid complex AI mocking
        mock.return_value = engine
        yield engine

@pytest.fixture
def mock_session():
    s = MagicMock(spec=ScanSession)
    s.findings = MagicMock()
    s.ghost = MagicMock()
    s.ghost._task = MagicMock() # Ensure truthy for task check
    s.log = MagicMock()
    s.knowledge = {}
    registry = ScopeRegistry()
    registry.add_rule(ScopeRule(AssetType.DOMAIN, "target.com", ScopeDecision.ALLOW))
    s.scope_context = ScopeContext(registry=registry)
    return s

class MockFlow:
    def __init__(self, method, url, host):
        self.request = MagicMock()
        self.request.pretty_url = url
        self.request.method = method
        self.request.host = host
        self.request.query = {"user": "admin"} # Simulate params
        self.response = MagicMock()
        self.response.headers = {}

@pytest.mark.asyncio
async def test_system_loop_integration(mock_session, mock_ai):
    """
    Scenario:
    1. User browses to http://target.com/login?user=admin
    2. Ghost intercepts.
    3. MIMIC learns /login.
    4. Live interception does not invoke Strategy or grant proposal authority.
    """
    
    # 1. Setup
    addon = GhostAddon(mock_session)
    
    # Attach a strategy mock to prove live interception never calls it.
    async def fake_propose(flow_data):
        # The wiring contract only needs to prove that Ghost hands the captured
        # flow to Strategy; epistemic promotion is covered by canonical-ledger tests.
        pass

    mock_strategy = MagicMock()
    mock_strategy.propose_attacks = AsyncMock(side_effect=fake_propose)
    addon.strategy = mock_strategy
    
    # 2. Simulate Traffic
    flow = MockFlow("GET", "http://target.com/login?user=admin", "target.com")
    addon.request(flow)
    
    # 3. Verify MIMIC (Synchronous update)
    # Should have learned /login
    # Miner root -> "" -> "login"
    ep = addon.shadow_spec.miner.ingest("GET", "/login") # Check what it learned
    assert ep.path_template == "/login"
    assert ep.observation_count >= 2 # 1 from ingest in test, 1 from request
    
    # 4. Strategy analysis is intentionally offline; the live proxy must not
    # schedule an AI task for each parameterized request.
    await asyncio.sleep(0.1)
    mock_strategy.propose_attacks.assert_not_called()
    
    print("✅ System Loop Configured Correctly")
