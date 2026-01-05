import asyncio
import aiohttp
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VERIFIER")

async def check_api():
    async with aiohttp.ClientSession() as session:
        async with session.get('http://127.0.0.1:8765/v1/graph') as resp:
            data = await resp.json()
            logger.info(f"API /v1/graph Status: {resp.status}")
            logger.info(f"API Nodes: {len(data.get('nodes', []))}, Edges: {len(data.get('edges', []))}")
            if data.get('nodes'):
                logger.info(f"First Node Label: {data['nodes'][0].get('label')}")

async def check_ws():
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect('ws://127.0.0.1:8765/ws/graph') as ws:
            logger.info("Connected to WS /ws/graph")
            # Read first message
            msg = await ws.receive_json()
            logger.info(f"WS Nodes: {len(msg.get('nodes', []))}, Edges: {len(msg.get('edges', []))}")
            if msg.get('nodes'):
                logger.info(f"First Node Label: {msg['nodes'][0].get('label')}")

async def main():
    await check_api()
    await check_ws()

if __name__ == "__main__":
    asyncio.run(main())
