#
# PURPOSE:
# This module is part of the verification package in SentinelForge.
# [Specific purpose based on module name: verify_assemblage]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
tests/verify_assemblage.py
Verifies that Phase 7 components are in place.
"""
import os
import sys

def check_file(path, description):
    """Function check_file."""
    # Conditional branch.
    if os.path.exists(path):
        print(f"[PASS] {description} found at {os.path.basename(path)}")
        return True
    else:
        print(f"[FAIL] {description} MISSING at {path}")
        return False

def main():
    """Function main."""
    print("[*] Verifying Phase 7: Assemblage...")
    
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    
    # 1. Check Swift Services
    swift_services = os.path.join(root, "ui/Sources/SentinelForgeUI/Services")
    check_file(os.path.join(swift_services, "CortexStream.swift"), "Cortex Stream (Metal)")
    check_file(os.path.join(swift_services, "PTYClient.swift"), "PTY Client (Terminal)")
    check_file(os.path.join(swift_services, "SentinelAPIClient.swift"), "API Client")
    
    # 2. Check App State
    app_state = os.path.join(root, "ui/Sources/SentinelForgeUI/Models/HelixAppState.swift")
    # Conditional branch.
    if check_file(app_state, "HelixAppState"):
        with open(app_state, 'r') as f:
            content = f.read()
            if "CortexStream()" in content and "PTYClient()" in content:
                print("[PASS] Services injected into AppState")
            else:
                print("[FAIL] Services NOT injected into AppState")

if __name__ == "__main__":
    main()
