import asyncio
import logging
import httpx
import argparse
from pathlib import Path

logging.basicConfig(level=logging.INFO)

API_URL = "http://127.0.0.1:8765/v1/driver/start_capture"
STOP_URL = "http://127.0.0.1:8765/v1/driver/stop_capture"


def _auth_headers():
    token_path = Path.home() / ".sentinelforge" / "api_token"
    try:
        token = token_path.read_text().strip()
    except OSError:
        return {}
    return {"Authorization": f"Bearer {token}"} if token else {}

async def run_capture(target_url: str):
    headers = _auth_headers()
    try:
        print(f"Requesting backend to start capture for {target_url} (will wait for Swift node)...")
        async with httpx.AsyncClient() as client:
            response = await client.post(
                API_URL,
                json={"url": target_url},
                headers=headers,
                timeout=30.0,
            )
            if response.status_code != 200:
                print(f"Error: backend returned HTTP {response.status_code}: {response.text}")
                return
            data = response.json()
            if data.get("status") != "ok":
                print(f"Backend error: {data}")
                return
            print("=== SYSTEM READY ===")
            print("Navigation complete. The UI is now listening for network traffic.")
            print(f"Capture file: {data.get('capture_file', 'unknown')}")
            print("Press Ctrl+C to stop and flush the capture.")
            try:
                while True:
                    await asyncio.sleep(1)
            finally:
                await client.post(STOP_URL, headers=headers, timeout=30.0)
    except KeyboardInterrupt:
        print("\nStopping capture...")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelForge Capture Script")
    parser.add_argument("--url", default="https://www.whatnot.com/", help="The target URL to capture")
    args = parser.parse_args()
    asyncio.run(run_capture(args.url))
