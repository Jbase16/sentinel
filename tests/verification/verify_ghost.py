# ============================================================================
# tests/verification/verify_ghost.py
# Verify Ghost Module
# ============================================================================
#
# PURPOSE:
# This module is part of the verification package in SentinelForge.
# [Specific purpose based on module name: verify_ghost]
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
tests/verify_ghost.py
Verifies the Ghost Protocol Interceptor.
"""
import asyncio
import os
import sys
import time

sys.path.append(os.getcwd())
from core.base.session import ScanSession

async def test_ghost_protocol():
    print("[*] Initializing Ghost Protocol...")
    session = ScanSession("example.com")
    
    try:
        session.start_ghost(port=8082)
        print("    Proxy Start Task Created.")
    except Exception as e:
        print(f"    [ERROR] Start failed: {e}")
        return

    await asyncio.sleep(5) # Generous warmup
    
    print("[*] Sending Traffic through Proxy (127.0.0.1:8082)...")
    try:
        # Use short timeout
        proc = await asyncio.create_subprocess_exec(
            "curl", "-x", "http://127.0.0.1:8082", "http://example.com/?test_param=ghost_injection", 
            "-s", "-o", "/dev/null", "--max-time", "5"
        )
        rc = await proc.wait()
        print(f"    Curl exited with {rc}")
    except Exception as e:
        print(f"[!] Curl failed: {e}")
    
    print("[*] Checking Evidence/Findings...")
    findings = session.findings.get_all()
    found_ghost = False
    for f in findings:
        if f.get("tool") == "ghost_proxy":
            print(f"    [FOUND] Ghost Intercepted: {f}")
            if "test_param" in str(f):
                print("    [SUCCESS] Parameter captured!")
                found_ghost = True
    
    session.stop_ghost()
    
    if found_ghost:
        print("\n[SUCCESS] Ghost Protocol Verified.")
    else:
        print("\n[FAILED] No Ghost findings found.")
        # Print logs
        print("Logs:", session.logs)
        sys.exit(1)

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(test_ghost_protocol())
