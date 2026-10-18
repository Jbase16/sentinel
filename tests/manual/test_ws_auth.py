
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

    url = "ws://127.0.0.1:8765/v1/ws/events"
    print(f"Connecting to {url}")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(url, headers={"Authorization": f"Bearer {token}"}) as ws:
                print("Connected successfully!")
                await ws.close()
    except Exception as e:
        print(f"Connection failed: {type(e).__name__}")

if __name__ == "__main__":
    asyncio.run(test_connect())
