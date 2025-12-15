# ============================================================================
# tests/verification/verify_neural_loop.py
# Verify Neural Loop Module
# ============================================================================
#
# PURPOSE:
# This module is part of the verification package in SentinelForge.
# [Specific purpose based on module name: verify_neural_loop]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#
# ============================================================================

"""
tests/verify_neural_loop.py
Verifies that the StrategyEngine correctly processes traffic and creates Hypotheses Findings.
Includes a Mock for the AI Engine to ensure test reliability.
"""

import asyncio
import os
import sys
import json
from unittest.mock import MagicMock

sys.path.append(os.getcwd())
from core.base.session import ScanSession
from core.ai.strategy import StrategyEngine
from core.ai.ai_engine import AIEngine

# Mock Response mimicking Gemma 9B output
MOCK_AI_RESPONSE = json.dumps({
    "vectors": [
        {
            "vuln_class": "IDOR",
            "parameter": "user_id",
            "hypothesis": "Sequential integer ID. High likelihood of unauthorized access.",
            "suggested_payloads": ["1", "0", "-1", "99999"]
        }
    ]
})

async def test_neural_pipeline():
    print("[*] Init Neural Pipeline Test")
    session = ScanSession("target-api.com")
    
    # Initialize Strategy Engine
    strategy = StrategyEngine(session)
    
    # Mock the AI Client to return our synthetic "Gemma" thought
    print("    Mocking AI Brain...")
    strategy.ai.client = MagicMock()
    strategy.ai.client.generate.return_value = MOCK_AI_RESPONSE
    
    # Simulate Traffic Flow from Ghost
    flow_data = {
        "url": "http://target-api.com/profile?user_id=500",
        "method": "GET",
        "host": "target-api.com",
        "params": ["user_id"]
    }
    
    print(f"    Feeding Traffic: {flow_data['url']}")
    await strategy.propose_attacks(flow_data)
    
    # Allow async DB write
    await asyncio.sleep(0.5)
    
    # Check Findings
    print("[*] Inspecting Mindmap (FindingsStore)...")
    findings = session.findings.get_all()
    
    found_hypothesis = False
    for f in findings:
        if f['type'] == 'hypothesis::idor':
            print(f"    [SUCCESS] AI Generated Hypothesis Found!")
            print(f"    - Reasoning: {f['value']}")
            print(f"    - Payloads: {f['metadata']['payloads']}")
            found_hypothesis = True
            break
            
    if not found_hypothesis:
        print("[FAILED] No hypothesis generated.")
        print(findings)
        sys.exit(1)
        
    print("\n[SUCCESS] Neural Loop Verified. The system can dream of attacks.")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(test_neural_pipeline())
