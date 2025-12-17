"""Module debug_cortex: inline documentation for /Users/jason/Developer/sentinelforge/scripts/debug_cortex.py."""
#
# PURPOSE:
# This module is part of the scripts package in SentinelForge.
# [Specific purpose based on module name: debug_cortex]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

import asyncio
import websockets
import json

async def monitor_cortex():
    """AsyncFunction monitor_cortex."""
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
