import requests
import json
import sys
import time

BASE_URL = "http://127.0.0.1:8765"

def test_ping():
    print("[*] Testing /ping...")
    try:
        resp = requests.get(f"{BASE_URL}/ping", timeout=2)
        if resp.status_code == 200 and resp.json().get("status") == "ok":
            print("    SUCCESS")
            return True
    except Exception as e:
        print(f"    FAILED: {e}")
    return False

def test_scan():
    print("[*] Testing /scan (mock target)...")
    try:
        # We use a dummy target to just check if the orchestrator starts
        resp = requests.post(f"{BASE_URL}/scan", json={"target": "127.0.0.1"}, timeout=5)
        if resp.status_code == 202:
            print(f"    SUCCESS: {resp.json()}")
            return True
        else:
            print(f"    FAILED: Status {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"    FAILED: {e}")
    return False

def test_chat():
    print("[*] Testing /chat (mock prompt)...")
    try:
        # We stream the response
        resp = requests.post(f"{BASE_URL}/chat", json={"prompt": "Who are you and what vulnerabilities did you find?"}, stream=True, timeout=120)
        if resp.status_code == 200:
            print("    Streaming started...")
            full_response = ""
            for line in resp.iter_lines():
                if line:
                    decoded = line.decode()
                    if decoded.startswith("data: "):
                        data_str = decoded[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            token_json = json.loads(data_str)
                            token = token_json.get("token", "")
                            full_response += token
                            # Print dot for progress
                            print(".", end="", flush=True)
                        except:
                            pass
            
            print("\n    SUCCESS. Full Response:")
            print(f"    --------------------------------------------------")
            print(f"    {full_response.strip()}")
            print(f"    --------------------------------------------------")
            return True
        else:
            print(f"    FAILED: Status {resp.status_code}")
    except Exception as e:
        print(f"    FAILED: {e}")
    return False

if __name__ == "__main__":
    print(f"Checking backend at {BASE_URL}")
    if not test_ping():
        print("!!! Backend is NOT running or NOT reachable.")
        sys.exit(1)
    
    if not test_scan():
        print("!!! Scan endpoint failed.")
    
    if not test_chat():
        print("!!! Chat endpoint failed.")
