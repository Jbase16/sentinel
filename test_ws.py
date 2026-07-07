import asyncio
from websockets.client import connect

async def hello():
    try:
        async with connect("ws://127.0.0.1:8765/v1/driver/bridge") as websocket:
            print("Connected to WebSocket bridge.")
    except Exception as e:
        print(f"Failed to connect: {e}")

asyncio.run(hello())
