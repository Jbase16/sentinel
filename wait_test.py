import asyncio
from curl_cffi import requests
async def wait_for_ui():
    print("Test running. It waits for UI...")
asyncio.run(wait_for_ui())
