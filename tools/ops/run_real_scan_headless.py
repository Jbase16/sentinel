"""Module run_real_scan_headless: inline documentation for /Users/jason/Developer/sentinelforge/scripts/run_real_scan_headless.py."""
import asyncio
import sys
from pathlib import Path
from typing import List, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.scheduler.strategos import Strategos  # noqa: E402
from core.scheduler.modes import ScanMode  # noqa: E402
from core.cortex.events import EventBus  # noqa: E402
from core.cortex.narrator import NarratorEngine  # noqa: E402
from core.scheduler.decisions import DecisionLedger  # noqa: E402

async def mock_tool_execution(tool: str) -> List[Dict]:
    """
    Simulates tool execution since we are headless and might not have tools installed.
    """
    print(f"    [EXEC] Running {tool}...")
    await asyncio.sleep(0.5)
    return [{"type": "mock_finding", "tool": tool, "target": "example.com"}]

async def main():
    """AsyncFunction main."""
    print("\n--- REAL HEADLESS SCAN TEST ---\n")

    # Core plumbing
    event_bus = EventBus()
    ledger = DecisionLedger()
    # Narrator needs to be kept alive
    narrator = NarratorEngine(event_bus=event_bus)

    # Subscribe to events (terminal visibility)
    def print_event(event):
        """Function print_event."""
        # Error handling block.
        try:
            print(f"[EVENT] {event.type.value}: {event.payload}")
        except (AttributeError, TypeError):
            print(f"[EVENT] {event}")

    event_bus.subscribe_sync(print_event)

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
