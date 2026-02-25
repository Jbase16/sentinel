#!/usr/bin/env python3
import httpx
import base64
import sys

# Deterministic Replay Script for f-4b64ff3a7c8d55d9

def main():
    target_url = 'http://localhost:8081/search?q=test'
    headers = {}
    method = 'GET'
    body_b64 = None
    
    content = base64.b64decode(body_b64) if body_b64 else None
    
    print(f"[*] Replaying {method} {target_url}")
    client = httpx.Client(verify=False, follow_redirects=True)
    try:
        req = client.build_request(method, target_url, headers=headers, content=content)
        resp = client.send(req)
        print(f"[+] Status: {resp.status_code}")
        # In a real replay, you'd assert against the delta or canary here.
        # This V1 stub exits clean if network succeeds.
    except Exception as e:
        print(f"[-] Replay failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
