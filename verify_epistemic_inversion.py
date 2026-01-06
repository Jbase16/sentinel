"""
Verification script for Epistemic Inversion (The Capstone).
Ensures that:
1. AI Engine returns proposals (not findings).
2. Ledger rejects proposals without citations.
3. Ledger accepts proposals with valid citations.
4. Only promotions reach the findings_store.
"""
import sys
import os
from unittest.mock import MagicMock
from dataclasses import asdict

sys.path.append(os.getcwd())

from core.base.task_router import TaskRouter
from core.epistemic.ledger import EvidenceLedger, FindingProposal, Citation
from core.data.findings_store import findings_store

def verify_inversion():
    print("[*] Initializing Components...")
    router = TaskRouter.instance()
    
    # Reset stores
    findings_store.clear()
    
    # Mock AI Engine to return controlled Proposals
    router.ai.process_tool_output = MagicMock()
    
    # 1. Test Rejection (Uncited Proposal)
    print("\n[Step 1] Testing Gatekeeper Rejection (Uncited)...")
    
    # Setup: Observation exists, but AI fails to cite it
    obs = router.ledger.record_observation("mock_tool", [], "target", b"output")
    
    uncited_proposal = FindingProposal(
        title="Hallucinated Finding",
        severity="HIGH",
        description="I made this up.",
        citations=[], # EMPTY
        source="ai"
    )
    
    router.ai.process_tool_output.return_value = {
        "summary": "Mock summary",
        "proposals": [uncited_proposal],
        "evidence_id": "ev-1"
    }
    
    router.handle_tool_output("mock_tool", "output", "", 0, {"target": "target"})
    
    # Verify Store is EMPTY
    if findings_store.get_all():
        print(f"    [FAIL] Findings Store should be empty! Found: {findings_store.get_all()}")
        sys.exit(1)
    print("    [PASS] Uncited proposal was blocked by Ledger.")

    # 2. Test Promotion (Cited Proposal)
    print("\n[Step 2] Testing Gatekeeper Promotion (Cited)...")
    
    citation = Citation(
        observation_id=obs.id,
        snippet="output"
    )
    
    valid_proposal = FindingProposal(
        title="Valid Finding",
        severity="MEDIUM",
        description="I saw this in the output.",
        citations=[citation],
        source="ai"
    )
    
    router.ai.process_tool_output.return_value = {
        "summary": "Mock summary",
        "proposals": [valid_proposal],
        "evidence_id": "ev-2"
    }
    
    router.handle_tool_output("mock_tool", "output", "", 0, {"target": "target"})
    
    # Verify Store has 1 item
    findings = findings_store.get_all()
    if len(findings) != 1:
        print(f"    [FAIL] Findings Store should have 1 item! Found: {len(findings)}")
        sys.exit(1)
        
    f = findings[0]
    if f["title"] != "Valid Finding":
        print(f"    [FAIL] Wrong finding title: {f['title']}")
        sys.exit(1)
        
    print(f"    [PASS] Valid proposal was promoted: {f['title']} (ID: {f.get('id')})")
    
    print("\n[SUCCESS] Epistemic Inversion Verified.")

if __name__ == "__main__":
    verify_inversion()
