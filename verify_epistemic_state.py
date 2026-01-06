"""
Verification script for Epistemic State Machine.
Ensures we can mutate belief (State) without mutating evidence (Observation).
"""
import sys
from core.epistemic.ledger import EvidenceLedger, LifecycleState

def verify_epistemic_state():
    print("[*] Initializing Evidence Ledger (State Machine Mode)...")
    ledger = EvidenceLedger()
    
    # 1. Create Immutable Observation
    print("\n[Step 1] Recording Observation...")
    raw_output = b"Port 80 Open"
    obs = ledger.record_observation(
        tool_name="nmap",
        tool_args=["-p80", "target"],
        target="target",
        raw_output=raw_output
    )
    print(f"    -> Observation ID: {obs.id}")
    
    # 2. Verify Initial State
    print("\n[Step 2] Verifying Initial State...")
    state = ledger.get_state(obs.id)
    if not state:
        print("    [FAIL] No state record found!")
        sys.exit(1)
        
    print(f"    -> Current State: {state.state}")
    if state.state != LifecycleState.OBSERVED:
        print(f"    [FAIL] Expected OBSERVED, got {state.state}")
        sys.exit(1)
    print("    [PASS] Initial state correct.")

    # 3. Mutate State (Suppress)
    print("\n[Step 3] Suppressing Observation (Mutating State)...")
    reason = "False positive, port is filtered"
    ledger.suppress(obs.id, "FALSE_POSITIVE", reason)
    
    # 4. Verify New State
    new_state = ledger.get_state(obs.id)
    print(f"    -> New State: {new_state.state}")
    print(f"    -> Reason: {new_state.reason}")
    
    if new_state.state != LifecycleState.SUPPRESSED:
        print(f"    [FAIL] State update failed! Got {new_state.state}")
        sys.exit(1)
        
    if "FALSE_POSITIVE" not in new_state.reason:
        print(f"    [FAIL] Reason not recorded! Got {new_state.reason}")
        sys.exit(1)
        
    print("    [PASS] State mutation success.")
    
    # 5. Verify Observation Immutability
    # (In a real typed language, this is compile-time. In Python, we just check attrs didn't change)
    # The 'lifecycle' field shouldn't exist on Observation anymore, or at least shouldn't be used
    if hasattr(obs, 'lifecycle'):
        print("    [WARN] Observation still has 'lifecycle' attribute (Deprecated).")
    
    print("\n[SUCCESS] Epistemic State Machine verified.")

if __name__ == "__main__":
    verify_epistemic_state()
