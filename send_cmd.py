import asyncio
from websockets.client import connect
import json
import uuid

async def send_cmd():
    try:
        async with connect("ws://127.0.0.1:8765/v1/driver/bridge") as websocket:
            print("Connected to WebSocket bridge.")
            
            # Start network capture
            req_id = str(uuid.uuid4())
            payload = {
                "request_id": req_id,
                "command": "start_network_capture",
                "session_id": "manual",
                "args": {}
            }
            await websocket.send(json.dumps(payload))
            print("Sent network capture command.")
            
            # Wait for response
            response = await websocket.recv()
            print(f"Response: {response}")
            
    except Exception as e:
        print(f"Failed to connect: {e}")

asyncio.run(send_cmd())
