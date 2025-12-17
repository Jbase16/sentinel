"""Module test_scan_flow: inline documentation for /Users/jason/Developer/sentinelforge/tests/integration/test_scan_flow.py."""
#
# PURPOSE:
# This module is part of the integration package in SentinelForge.
# [Specific purpose based on module name: test_scan_flow]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

import requests
import json
import time
import sys

BASE_URL = "http://127.0.0.1:8765"

def stream_events():
    """Function stream_events."""
    print("[*] connecting to SSE stream...")
    try:
        # Connect to SSE
        with requests.get(f"{BASE_URL}/events", stream=True, timeout=30) as resp:
            for line in resp.iter_lines():
                if line:
                    decoded = line.decode()
                    if decoded.startswith("data: "):
                        try:
                            data = json.loads(decoded[6:])
                            if "line" in data:
                                print(f"[LOG] {data['line']}")
                            elif "tool" in data:
                                print(f"[FINDING] {data.get('type')} ({data.get('tool')})")
                        except:
                            pass
    except Exception as e:
        # SSE usually times out or breaks, that's fine for this test
        pass

def run_scan_test():
    """Function run_scan_test."""
    target = "scanme.nmap.org"
    print(f"[*] Starting scan against {target}...")
    
    # 1. Force start scan
    resp = requests.post(f"{BASE_URL}/scan", json={"target": target, "force": True})
    if resp.status_code != 202:
        print(f"!!! Scan start failed: {resp.status_code} {resp.text}")
        return

    print("[*] Scan started. Listening for logs (Press Ctrl+C to stop)...")
    
    # 2. Listen to logs via SSE
    stream_events()

if __name__ == "__main__":
    try:
        run_scan_test()
    except KeyboardInterrupt:
        print("\nTest stopped.")
