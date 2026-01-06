"""
Verification script for Epistemic Grounding.
Ensures we cannot lie (cite non-existent evidence) and cannot forget (WhyNot).
"""
import sys
import shutil
from core.epistemic.ledger import EvidenceLedger, Citation

def verify_epistemic_system():
    print("[*] Initializing Evidence Ledger...")
    ledger = EvidenceLedger()
    
    # 1. Test CAS & Observation
    print("\n[Step 1] Recording Raw Observation (CAS)...")
    raw_output = b"HTTP/1.1 403 Forbidden\nServer: nginx\n"
    obs = ledger.record_observation(
        tool_name="curl",
        tool_args=["-I", "http://target.local"],
        target="http://target.local",
        raw_output=raw_output
    )
    print(f"    -> Observation ID: {obs.id}")
    print(f"    -> Blob Hash: {obs.blob_hash}")
    
    # Verify we can read it back
    loaded_bytes = ledger.get_blob(obs.id)
    if loaded_bytes == raw_output:
        print("    [PASS] Blob retrieval verified (Match).")
    else:
        print("    [FAIL] Blob mismatch!")
        sys.exit(1)

    # 2. Test Citation Enforcement
    print("\n[Step 2] Testing Citation Enforcement...")
    try:
        ledger.promote_finding(
            title="Fake WAF Detected",
            severity="High",
            citations=[],  # EMPTY CITATIONS -> MUST FAIL
            description="I hallucinated this."
        )
        print("    [FAIL] Ledger allowed uncited finding!")
        sys.exit(1)
    except ValueError as e:
        print(f"    [PASS] Ledger rejected uncited finding: {e}")

    # 3. Test Valid Finding
    print("\n[Step 3] Promoting Valid Finding...")
    citation = Citation(
        observation_id=obs.id,
        line_start=1,
        snippet="403 Forbidden"
    )
    finding = ledger.promote_finding(
        title="Access Denied",
        severity="Info",
        citations=[citation],
        description="Target returned 403."
    )
    print(f"    [PASS] Finding {finding.id} promoted.")

    # 4. Test WhyNot/Suppression
    print("\n[Step 4] Testing Suppression (The 403 Case)...")
    whynot = ledger.suppress(
        related_id=obs.id,
        reason_code="NO_EXPLOIT_PATH",
        notes="403 is expected for unauthenticated root."
    )
    print(f"    [PASS] Recorded WhyNot: {whynot.id} - {whynot.notes}")
    
    print("\n[SUCCESS] Epistemic Grounding verified.")

if __name__ == "__main__":
    verify_epistemic_system()
