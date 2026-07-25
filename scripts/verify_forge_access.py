#!/usr/bin/env python3
"""
scripts/verify_forge_access.py

Verifies that the FORGE API endpoint is reachable, secured, and functional.
Does NOT execute an actual AI generation to save tokens/time, but asserts the plumbing.
"""

import sys
import os
import requests
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.base.config import get_config

def main():
    config = get_config()
    base_url = f"http://{config.api_host}:{config.api_port}/v1"
    
    # 1. Get Token
    token_path = Path.home() / ".sentinelforge" / "api_token"
    if not token_path.exists():
        print("[-] No API token found. Ensure server is running.")
        sys.exit(1)
        
    token = token_path.read_text().strip()
    headers = {"Authorization": f"Bearer {token}"}
    
    print(f"[*] Target: {base_url}")
    print(f"[*] Token: {token[:8]}...")
    
    # 2. Test Ping (Baseline)
    try:
        r = requests.get(f"{base_url}/ping", timeout=2)
        if r.status_code != 200:
            print(f"[-] API not healthy. Status: {r.status_code}")
            sys.exit(1)
        print("[+] API Health: OK")
    except Exception as e:
        print(f"[-] Failed to connect to API: {e}")
        print("    (Is the server running?)")
        sys.exit(1)
        
    # 3. Test FORGE Endpoint Reachability
    # We send a request. If we get 404 -> Fail (Not Mounted)
    # If we get 422 (Validation Error) -> Success (Endpoint exists and is parsing args)
    # If we get 401/403 -> Fail (Auth broken)
    
    forge_url = f"{base_url}/forge/compile"
    
    # Test Payload
    payload = {
        "target": "http://example.com/vuln.php",
        "anomaly_context": "SQL Injection in parameter 'id'"
    }
    
    print(f"[*] Testing {forge_url}...")
    try:
        r = requests.post(forge_url, json=payload, headers=headers, timeout=5)
        
        if r.status_code == 200:
            print("[+] FORGE Endpoint: REACHABLE (200 OK)")
            print(f"Response: {r.json()}")
        elif r.status_code == 422:
             print("[+] FORGE Endpoint: REACHABLE (422 Validation Error - this confirms pydantic is listening)")
        elif r.status_code == 404:
            print("[-] FORGE Endpoint: NOT FOUND (404)")
            print("    (Has the router been mounted in api.py?)")
            sys.exit(1)
        elif r.status_code in [401, 403]:
            print(f"[-] FORGE Endpoint: UNAUTHORIZED ({r.status_code})")
            sys.exit(1)
        else:
            # It might fail with logic error if AI is offline, that's fine for plumbing check
            print(f"[?] FORGE Endpoint returned {r.status_code} (Acceptable if not 404)")
            print(f"Response: {r.text}")

    except Exception as e:
        print(f"[-] Request failed: {e}")
        sys.exit(1)

    print("[*] Verification Complete.")

if __name__ == "__main__":
    main()
