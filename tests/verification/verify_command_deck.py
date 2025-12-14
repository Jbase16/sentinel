"""
tests/verify_command_deck.py
Verifies the Chat and Orchestrator.
"""
import sys
import os
import asyncio
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# MOCK Dependencies
sys.modules["networkx"] = MagicMock()
sys.modules["httpx"] = MagicMock()
sys.modules["aiosqlite"] = MagicMock()

from core.chat.chat_engine import GraphAwareChat
from core.engine.orchestrator import Orchestrator

def test_chat():
    print("[*] Testing GraphAwareChat...")
    chat = GraphAwareChat.instance()
    
    # Mock AI response
    chat.ai = MagicMock()
    chat.ai.client.generate.return_value = "Verified RAG Response."
    
    response = chat.query("What is the status of target A?")
    print(f"    > AI Response: {response}")
    
    if response == "Verified RAG Response.":
        print("    [SUCCESS] Chat Engine Functional.")
    else:
        print("    [FAIL] Chat Engine Error.")

async def test_orchestrator():
    print("\n[*] Testing Orchestrator (One-Click)...")
    orch = Orchestrator.instance()
    
    # Start Mission
    mission_id = await orch.start_mission("example.com")
    print(f"    > Mission Started: {mission_id}")
    
    if mission_id.startswith("mission_example.com"):
        print("    [SUCCESS] Orchestrator running.")
    else:
        print("    [FAIL] Mission ID invalid.")
        
    # Wait briefly for async loop
    await asyncio.sleep(0.1)

if __name__ == "__main__":
    test_chat()
    asyncio.run(test_orchestrator())
