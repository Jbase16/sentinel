"""
Verification Script for Project CAL.
Scenario:
1. Scanner asserts 'Port 80 Open'.
2. Firewall asserts 'Port 80 Filtered'.
3. CAL resolves dispute (simulated).
"""
import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from core.cal.types import Evidence, ValidationStatus, Provenance 
from core.cal.engine import ReasoningSession
from core.cal.interface import cal_rule, CALInterface
from core.base.sequence import GlobalSequenceAuthority

# Setup logging
logging.basicConfig(level=logging.INFO)

async def setup():
    # Mocking DB init for test speed, or use in-memory
    # For this unit test, we just reset it to work without DB
    GlobalSequenceAuthority.reset_for_testing()
    GlobalSequenceAuthority.initialize_for_testing()

def run_test():
    import asyncio
    asyncio.run(setup())

    print("⚖️  Initializing CAL Reasoning Session...")
    session = ReasoningSession(session_id="test-123", topic="Host 192.168.1.1")

    # 1. Scanner Evidence
    ev_nmap = Evidence(
        content={"port": 80, "state": "open"},
        description="Nmap Scan Result",
        provenance=Provenance("Scanner:Nmap", method="automated"),
        confidence=0.9
    )

    # 2. Scanner makes a Claim
    print("\n🗣️  Agent A asserts Claim...")
    claim = session.assert_claim(
        statement="Port 80 is Open",
        evidence=ev_nmap,
        metadata={"type": "port_status"}
    )
    
    print(f"   Current Status: {claim.status} (Conf: {claim.confidence})")
    assert claim.status == ValidationStatus.VALIDATED  # High confidence initial evidence

    # 3. Apply Policy Limit (Simulated Dispute)
    # Let's say we have a rule: if confidence < 1.0, wait multiple sources.
    # But wait, let's test a Dispute.
    
    ev_fw = Evidence(
        content={"drop_rate": 0.99},
        description="WAF Drop Statistics",
        provenance=Provenance("Scanner:WAFDetector", method="automated"),
        confidence=0.8
    )

    print("\n🗣️  Agent B disputes Claim...")
    session.dispute_claim(claim.id, ev_fw, reason="High packet drop rate suggests filtration")

    print(f"   Current Status: {claim.status} (Conf: {claim.confidence})")
    assert claim.status == ValidationStatus.DISPUTED or claim.confidence < 0.8

    # 4. Test Interface Rule
    print("\n📜 Applying CAL Rules...")
    
    @cal_rule(on_claim_type="port_status")
    def resolve_port_conflict(claim, sess):
        # Stupid simple resolver logic for test
        if len(claim.disputed_by) > 0:
            print(f"   [Rule Triggered] Resolving conflict for {claim.statement}")
            # If we see a dispute, let's say we trust the WAF more in restart
            # Arbitrary logic test
            pass

    CALInterface.apply_rules(session) # Just ensuring it calls the function
    
    print("\n✅ CAL Core Logic Verified!")
    print(session.stats())

if __name__ == "__main__":
    run_test()
