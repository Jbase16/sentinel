"""
Verification script for Epistemic Conflicts.
Ensures we can register disagreements between observations.
"""
from core.epistemic.ledger import EvidenceLedger, LifecycleState

def verify_conflicts():
    print("[*] Initializing Evidence Ledger (Conflict Mode)...")
    ledger = EvidenceLedger()
    
    # 1. Register Source A (e.g. Nmap says Open)
    obs_a = ledger.record_observation("nmap", ["-p80"], "target", b"80/tcp open")
    print(f"    -> Source A: {obs_a.id}")
    
    # 2. Register Source B (e.g. Curl says Connection Refused)
    obs_b = ledger.record_observation("curl", ["target"], "target", b"Connection refused")
    print(f"    -> Source B: {obs_b.id}")
    
    # 3. Register Conflict
    print("\n[Step 2] Registering Conflict...")
    conflict = ledger.register_conflict(
        source_a_id=obs_a.id,
        source_b_id=obs_b.id,
        description="Nmap reports open, Curl reports closed.",
        conflict_type="direct_contradiction"
    )
    print(f"    -> Conflict ID: {conflict.id}")
    
    # 4. Verify
    if len(ledger._conflicts) != 1:
        print("[FAIL] Conflict not stored.")
        exit(1)
        
    stored = ledger._conflicts[0]
    if stored.source_a_id != obs_a.id or stored.source_b_id != obs_b.id:
        print("[FAIL] Stored conflict has wrong IDs.")
        exit(1)
        
    print("[PASS] Conflict registered successfully.")

if __name__ == "__main__":
    verify_conflicts()
