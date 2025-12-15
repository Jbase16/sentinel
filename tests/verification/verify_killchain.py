# ============================================================================
# tests/verification/verify_killchain.py
# Verify Killchain Module
# ============================================================================
#
# PURPOSE:
# This module is part of the verification package in SentinelForge.
# [Specific purpose based on module name: verify_killchain]
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
tests/verify_killchain.py
Verifies the complete loop: Traffic -> AI -> Hypothesis -> Wraith -> Vulnerability.
"""

import asyncio
import os
import sys
import json
from unittest.mock import MagicMock

sys.path.append(os.getcwd())
from core.base.session import ScanSession
from core.ai.strategy import StrategyEngine

# Mock AI Response with a "Success" payload
MOCK_AI_RESPONSE = json.dumps({
    "vectors": [
        {
            "vuln_class": "IDOR",
            "parameter": "user_id",
            "hypothesis": "Sequential ID detected.",
            "suggested_payloads": ["1"] # "1" is a magic payload in our mock Wraith
        }
    ]
})

async def test_full_killchain():
    print("[*] Init Full Killchain Test")
    session = ScanSession("target-bank.com")
    
    # Initialize Strategy Engine
    strategy = StrategyEngine(session)
    
    # Mock AI
    print("    Mocking AI Brain...")
    strategy.ai.client = MagicMock()
    strategy.ai.client.generate.return_value = MOCK_AI_RESPONSE
    
    # Stimulate Traffic
    flow_data = {
        "url": "http://target-bank.com/api/transact?id=500",
        "method": "POST",
        "host": "target-bank.com",
        "params": ["id"]
    }
    
    print(f"    Feeding Traffic: {flow_data['url']}")
    await strategy.propose_attacks(flow_data)
    
    # Wait for Wraith (Simulated delay + processing)
    print("    Waiting for Wraith Automator...")
    for i in range(4):
        print(f"    ... {3-i}")
        await asyncio.sleep(1)
    
    # Check Logs
    print("[*] Inspecting Logs...")
    hit_confirmed = False
    for log in session.logs:
        if "TARGET HIT" in log:
            print(f"    [LOG] {log}")
            hit_confirmed = True
            
    if not hit_confirmed:
        print("[FAILED] Wraith did not report a hit.")
        print("Logs:", session.logs)
        sys.exit(1)
        
    # Check Mindmap (FindingsStore)
    print("[*] Inspecting DB for High-Sev Vuln...")
    findings = session.findings.get_all()
    found_vuln = False
    for f in findings:
        if f['type'] == 'vuln::idor':
            print(f"    [SUCCESS] Confirmed Vulnerability Found!")
            print(f"    - Severity: {f['severity']}")
            print(f"    - Details: {f['value']}")
            found_vuln = True
            break
            
    if found_vuln:
        print("\n[SUCCESS] Killchain Verified. Autonomous Hacking is Live.")
    else:
        print("[FAILED] Vulnerability not found in DB.")
        sys.exit(1)

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(test_full_killchain())
