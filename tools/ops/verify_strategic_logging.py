"""Module verify_strategic_logging: inline documentation for /Users/jason/Developer/sentinelforge/scripts/verify_strategic_logging.py."""

import asyncio
import logging
import sys
from pathlib import Path
from typing import List, Dict

# Ensure core matches
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cortex.events import get_event_bus, GraphEventType  # noqa: E402
from core.cortex.event_store import get_event_store  # noqa: E402
from core.scheduler.strategos import Strategos  # noqa: E402
from core.scheduler.modes import ScanMode  # noqa: E402

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("Verification")

async def mock_dispatch_tool(tool: str) -> List[Dict]:
    """Simulate tool execution."""
    await asyncio.sleep(0.1)
    logger.info(f"   [Mock] Tool '{tool}' running...")
    return [{"type": "issue", "message": "Simulated finding"}]

async def main():
    """AsyncFunction main."""
    print("--- Verifying Strategic Logging ---")
    
    # 1. Setup Event Bus
    store = get_event_store()
    bus = get_event_bus()
    
    # 2. Setup Strategos with EventBus
    brain = Strategos(
        log_fn=lambda msg: print(f"   [LogFn] {msg}"),
        event_bus=bus
    )
    
    # 3. Start Listener for Events
    async def event_listener():
        """AsyncFunction event_listener."""
        print("--- Listening for Events ---")
        # Async loop over items.
        async for stored_event in store.subscribe():
            event = stored_event.event
            if event.type == GraphEventType.DECISION_MADE:
                intent = event.payload.get("intent")
                reason = event.payload.get("reason")
                print(f"✅ [EVENT: DECISION] {intent} -> {reason}")
            elif event.type == GraphEventType.SCAN_PHASE_CHANGED:
                phase = event.payload.get("phase")
                print(f"✅ [EVENT: PHASE] Transitioned to {phase}")
            elif event.type == GraphEventType.LOG:
                 # Too noisy, ignore for now or print
                 pass
    
    listener_task = asyncio.create_task(event_listener())
    
    # 4. Run Mission (Short)
    print("--- Starting Mission ---")
    # Error handling block.
    try:
        await brain.run_mission(
            target="http://testphp.vulnweb.com",
            available_tools=["whois", "nmap_fast"],
            mode=ScanMode.STANDARD,
            dispatch_tool=mock_dispatch_tool
        )
    except Exception as e:
        print(f"Mission ended: {e}")
    
    # Give time for events to flush
    await asyncio.sleep(2.0)
    listener_task.cancel()
    
    print(f"--- Event Store Dump ({len(store._events)} events) ---")
    # Loop over items.
    for e in store.get_latest(len(store._events)):
        print(f"Stored Event: {e.type} | {e.payload}")

    print("--- Verification Complete ---")

if __name__ == "__main__":
    asyncio.run(main())
