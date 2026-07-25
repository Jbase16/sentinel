#
# PURPOSE:
# This module is part of the scripts package in SentinelForge.
# [Specific purpose based on module name: test_tools_install]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

#!/usr/bin/env python3
"""Quick test for the tools install API endpoint"""
import asyncio
import json
import sys
sys.path.insert(0, '.')

async def test_install():
    # Import and call our new function directly
    """AsyncFunction test_install."""
    from core.toolkit.tools import install_tools
    
    # Test installing a tool you don't have (e.g., wafw00f)
    results = await install_tools(["wafw00f"])
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(test_install())
