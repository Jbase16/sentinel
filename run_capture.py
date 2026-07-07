import asyncio
import logging
import httpx
import sys
import argparse

logging.basicConfig(level=logging.INFO)

API_URL = "http://127.0.0.1:8765/v1/driver/start_capture"

async def run_capture(target_url: str):
    try:
        print(f"Requesting backend to start capture for {target_url} (will wait for Swift node)...")
        async with httpx.AsyncClient() as client:
            response = await client.post(API_URL, json={"url": target_url}, timeout=30.0)
        if response.status_code != 200:
            print(f"Error: backend returned HTTP {response.status_code}")
            return
        data = response.json()
        if data.get("status") != "ok":
            msg = data.get("message", "unknown error")
            print(f"Backend error: {msg}")
            return
        print("=== SYSTEM READY ===")
        print("Navigation complete. The UI is now listening for GraphQL traffic.")
        print("Please log in as Alice and click around the app to populate the capture file.")
        print("Captured data will be appended to data/graphql_capture.jsonl")
        print("Press Ctrl+C to exit this script when you're done.")
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping capture...")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelForge Capture Script")
    parser.add_argument("--url", default="https://www.whatnot.com/", help="The target URL to capture")
    args = parser.parse_args()
    asyncio.run(run_capture(args.url))
