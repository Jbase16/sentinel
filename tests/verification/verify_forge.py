#
# PURPOSE:
# This module is part of the verification package in SentinelForge.
# [Specific purpose based on module name: verify_forge]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
tests/verify_forge.py
Verifies the JIT Exploit Forge (Mocked LLM).
"""
import sys
import os
import asyncio
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# MOCK Dependencies
sys.modules["networkx"] = MagicMock()
sys.modules["httpx"] = MagicMock()

from core.forge.compiler import ExploitCompiler
from core.forge.sandbox import SandboxRunner
from core.ai.ai_engine import AIEngine

async def test_forge():
    """AsyncFunction test_forge."""
    print("[*] Testing JIT Forge...")
    
    compiler = ExploitCompiler.instance()
    
    # Mock AIEngine to return a python script
    mock_ai = MagicMock()
    mock_ai.client.generate.return_value = '```python\\nimport sys\\nprint("EXPLOIT SUCCESS")\\n```'
    compiler.ai = mock_ai
    
    # 1. Compile
    target = "http://example.com"
    anomaly = "Weird header found"
    script_path = compiler.compile_exploit(target, anomaly)
    print(f"    > Compiled exploit to: {script_path}")
    
    if os.path.exists(script_path):
        print("    [SUCCESS] Script file created.")
    else:
        print("    [FAIL] Script file not found.")
        return

    # 2. Execute
    print("    > Executing in Sandbox...")
    result = await SandboxRunner.run(script_path)
    
    if result.get("success_flag"):
        print("    [SUCCESS] Sandbox captured 'EXPLOIT SUCCESS'")
    else:
        print(f"    [FAIL] Sandbox output: {result.get('output')}")

if __name__ == "__main__":
    asyncio.run(test_forge())
