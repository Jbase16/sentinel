"""
Verification script for Temporal Epistemics.
Tests state reconstruction, replay, and invalidation.
"""
import time
from unittest.mock import MagicMock
import sys

# Mock findings_store to avoid DB async issues
sys.modules['core.data.findings_store'] = MagicMock()
from core.data.findings_store import findings_store
findings_store.add_finding = MagicMock()

from core.epistemic.ledger import EvidenceLedger, LifecycleState, FindingProposal, Citation

def verify_temporal_replay():
    print("[*] Initializing Evidence Ledger (Event Sourced)...")
    ledger = EvidenceLedger()
    
    # T1: Record Observation
    print("\n[T1] Recording Observation...")
    obs = ledger.record_observation("nmap", ["-p80"], "target", b"80/tcp open")
    t1 = time.time()
    time.sleep(0.1)
    
    # T2: Promote Finding
    print("\n[T2] Promoting Finding...")
    proposal = FindingProposal(
        title="Open Port 80",
        severity="MEDIUM",
        description="Port 80 is open",
        citations=[Citation(obs.id, snippet="open")]
    )
    finding = ledger.evaluate_and_promote(proposal)
    t2 = time.time()
    time.sleep(0.1)
    
    # T3: Invalidate Finding
    print("\n[T3] Invalidating Finding (e.g. Service Stop)...")
    ledger.invalidate_finding(finding.id, "Service stopped")
    t3 = time.time()
    
    # --- VERIFICATION ---
    
    # 1. Current State (Should be INVALIDATED)
    print("\n[Verify] Current State...")
    state = ledger.get_state(finding.id)
    print(f"    -> Current State: {state.state}")
    if state.state != LifecycleState.INVALIDATED:
        print(f"[FAIL] Expected INVALIDATED, got {state.state}")
        exit(1)
        
    # 2. Replay at T2 (Should be PROMOTED)
    print(f"\n[Verify] Replay at T2 ({t2})...")
    state_t2, events_t2 = ledger.replay(t2)
    
    if finding.id not in state_t2:
        print("[FAIL] Finding not found in T2 replay.")
        exit(1)
        
    record_t2 = state_t2[finding.id]
    print(f"    -> State at T2: {record_t2.state}")
    
    if record_t2.state != LifecycleState.PROMOTED:
        print(f"[FAIL] At T2, finding should be PROMOTED. Got {record_t2.state}")
        exit(1)
        
    # 3. Replay at T1 (Should not exist or be Unknown)
    # The finding ID didn't exist at T1 (was created at T2).
    # But the Observation should exist.
    print(f"\n[Verify] Replay at T1 ({t1})...")
    state_t1, events_t1 = ledger.replay(t1)
    
    if finding.id in state_t1:
        print("[FAIL] Finding shouldn't exist at T1.")
        exit(1)
        
    if obs.id not in state_t1:
        print("[FAIL] Observation SHOULD exist at T1.")
        exit(1)
        
    obs_record_t1 = state_t1[obs.id]
    print(f"    -> Obs State at T1: {obs_record_t1.state}")
    
    print("\n[SUCCESS] Temporal Epistemics Verified.")

if __name__ == "__main__":
    verify_temporal_replay()
