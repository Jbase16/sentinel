
import asyncio
import os
import aiohttp

async def test_connect():
    token_path = os.path.expanduser("~/.sentinelforge/api_token")
    if not os.path.exists(token_path):
        print("No token file found!")
        return

    with open(token_path, "r") as f:
        token = f.read().strip()

    print(f"Token: {token[:5]}...")

    url = f"ws://127.0.0.1:8765/v1/ws/events?token={token}"
    print(f"Connecting to {url}")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(url) as ws:
                print("Connected successfully!")
                await ws.close()
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_connect())
