import asyncio
import websockets
import json

async def monitor_cortex():
    uri = "ws://127.0.0.1:8765/ws/graph"
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected! Listening for graph updates...")
            while True:
                message = await websocket.recv()
                data = json.loads(message)
                node_count = len(data.get("nodes", []))
                print(f"Update received: {node_count} nodes")
                if node_count > 0:
                    print("- Sample Node:", data["nodes"][0])
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(monitor_cortex())
    except KeyboardInterrupt:
        print("\nStopping monitor.")
