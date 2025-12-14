#!/usr/bin/env python3
"""Quick test for the tools install API endpoint"""
import asyncio
import json
import sys
sys.path.insert(0, '.')

async def test_install():
    # Import and call our new function directly
    from core.toolkit.tools import install_tools
    
    # Test installing a tool you don't have (e.g., wafw00f)
    results = await install_tools(["wafw00f"])
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(test_install())
