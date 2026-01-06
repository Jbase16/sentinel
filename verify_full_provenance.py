"""
Verification script for Full Epistemic Provenance.
Tests the integration of TaskRouter -> EvidenceLedger -> AIEngine.
"""
import sys
import os
import time
from unittest.mock import MagicMock

# Ensure we can import core modules
sys.path.append(os.getcwd())

from core.base.task_router import TaskRouter
from core.epistemic.ledger import EvidenceLedger

def verify_provenance():
    print("[*] Initializing TaskRouter...")
    router = TaskRouter.instance()
    
    # Mock the AI engine to avoid making real Ollama calls (and to check args)
    # We want to verify that process_tool_output receives the observation_id
    real_process = router.ai.process_tool_output
    router.ai.process_tool_output = MagicMock(return_value={
        "summary": "Mock summary",
        "findings": [],
        "evidence_id": "ev-123"
    })
    
    print("\n[Step 1] Simulating Tool Execution...")
    tool_name = "provenance_test_tool"
    stdout = "CRITICAL DATA: SECRET_KEY=12345"
    metadata = {"target": "localhost", "args": ["--scan"]}
    
    router.handle_tool_output(
        tool_name=tool_name,
        stdout=stdout,
        stderr="",
        rc=0,
        metadata=metadata
    )
    
    # Verify AI was called with observation_id
    call_args = router.ai.process_tool_output.call_args
    if not call_args:
        print("    [FAIL] AI Engine was not called!")
        sys.exit(1)
        
    _, kwargs = call_args
    obs_id = kwargs.get("observation_id")
    print(f"    -> AI called with observation_id: {obs_id}")
    
    if not obs_id:
        print("    [FAIL] observation_id was None!")
        sys.exit(1)
        
    if not obs_id.startswith("obs-"):
        print(f"    [FAIL] Invalid observation ID format: {obs_id}")
        sys.exit(1)

    # Verify Ledger has the data
    print("\n[Step 2] Verifying Ledger Data...")
    obs = router.ledger.get_observation(obs_id)
    if not obs:
        print("    [FAIL] Observation not found in Ledger index!")
        sys.exit(1)
        
    print(f"    -> Blob Hash: {obs.blob_hash}")
    
    # Verify CAS content
    print("\n[Step 3] Verifying CAS Content...")
    blob_content = router.ledger.get_blob(obs_id)
    if blob_content.decode() == stdout:
        print("    [PASS] CAS content matches original tool output.")
    else:
        print(f"    [FAIL] CAS content mismatch! Got: {blob_content}")
        sys.exit(1)

    print("\n[SUCCESS] Full provenance chain verified.")

if __name__ == "__main__":
    verify_provenance()
