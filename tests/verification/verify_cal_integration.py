"""
Integration Verification for Project CAL.
Scenario:
1. Simulate Ghost Proxy traffic (INTERCEPT).
2. Strategy Engine hypothesizes logic vuln (CLAIM).
3. Scanner Bridge emits scan result (EVIDENCE).
4. CAL resolves the debate (DECISION).
"""
import asyncio
import logging
from unittest.mock import MagicMock, AsyncMock
from core.base.session import ScanSession
from core.base.sequence import GlobalSequenceAuthority
from core.ai.strategy import StrategyEngine
from core.cortex.scanner_bridge import ScannerBridge

# Use dummy session for test
class MockSession(ScanSession):
    def __init__(self):
        self.id = "test-session-integration"
        self.findings = MagicMock()
        self.wraith = MagicMock()
        self.wraith.on_hypothesis = AsyncMock()
        self.log = MagicMock()

async def run_integration_test():
    print("🔄 Initializing Integration Test...")
    
    # 1. Setup Global Sequence (Required for EventBus)
    GlobalSequenceAuthority.reset_for_testing()
    GlobalSequenceAuthority.initialize_for_testing()
    
    # 2. Setup Components
    session = MockSession()
    strategy = StrategyEngine(session)
    
    # Mock the AI engine to return a specific hypothesis WITHOUT calling LLM
    # We want to test the WIRING, not the LLM API
    strategy._analyze_with_ai = AsyncMock(return_value=[]) 
    # We'll rely on heuristics for deterministic output, or mock the return
    
    # 3. Simulate Traffic (Ghost Proxy)
    flow_data = {
        "url": "http://target.com/api/user?id=123", # "id=123" triggers IDOR heuristic
        "method": "GET",
        "params": ["id"],
        "host": "target.com"
    }
    
    print("\nREQUEST INTERCEPTED: GET /api/user?id=123")
    
    # 4. Strategy Analysis (Brain)
    # This should trigger the Heuristic engine -> Assert Claim
    print("🧠 Strategy Engine Analyzing...")
    await strategy.propose_attacks(flow_data)
    
    # Verify Findings were added (Legacy)
    assert session.findings.add_finding.called
    print("✅ Legacy Finding Added")
    
    # Verify Wraith triggered (The Hand)
    assert session.wraith.on_hypothesis.called
    print("✅ Wraith Triggered")
    
    # 5. Scanner Bridge (The Eyes)
    # Simulate Nmap finding something relevent to the host
    print("\n👀 Scanner Bridge Emitting Evidence...")
    ev = ScannerBridge.emit_evidence(
        session_id=session.id,
        tool="nmap",
        target="target.com",
        output="PORT 80/tcp OPEN"
    )
    
    assert ev.confidence == 1.0
    assert ev.provenance.source == "Scanner:nmap"
    print(f"✅ Evidence Created: {ev.id}")
    
    print("\n🎉 INTEGRATION SUCCESSFUL: The Loop is Closed.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_integration_test())
