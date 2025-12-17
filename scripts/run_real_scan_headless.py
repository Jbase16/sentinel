# ============================================================================
# scripts/run_real_scan_headless.py
# True Headless Scan Runner (No UI, No Chat, No Memory)
# ============================================================================

import asyncio
from typing import List, Dict
from core.scheduler.strategos import Strategos
from core.scheduler.modes import ScanMode
from core.cortex.events import EventBus
from core.cortex.narrator import NarratorEngine
from core.scheduler.decisions import DecisionLedger

async def mock_tool_execution(tool: str) -> List[Dict]:
    """
    Simulates tool execution since we are headless and might not have tools installed.
    """
    print(f"    [EXEC] Running {tool}...")
    await asyncio.sleep(0.5)
    return [{"type": "mock_finding", "tool": tool, "target": "example.com"}]

async def main():
    print("\n--- REAL HEADLESS SCAN TEST ---\n")

    # Core plumbing
    event_bus = EventBus()
    ledger = DecisionLedger()
    # Narrator needs to be kept alive
    narrator = NarratorEngine(event_bus=event_bus)

    # Subscribe to events (terminal visibility)
    def print_event(event):
        try:
            print(f"[EVENT] {event.type.value}: {event.payload}")
        except:
            print(f"[EVENT] {event}")

    event_bus.subscribe(print_event)

    # Strategos ONLY (no API, no chat)
    strategos = Strategos(
        event_bus=event_bus,
        decision_ledger=ledger,
        narrator=narrator
    )

    # Kick off scan (using correct run_mission API)
    # providing a selection of "installed" tools
    await strategos.run_mission(
        target="example.com",
        available_tools=["subfinder", "httpx", "nmap"],
        mode=ScanMode.STANDARD,
        dispatch_tool=mock_tool_execution
    )

    print("\n--- HEADLESS SCAN COMPLETE ---\n")

if __name__ == "__main__":
    asyncio.run(main())
