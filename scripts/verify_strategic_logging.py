
import asyncio
import logging
import sys
import os
import time
from typing import List, Dict

# Ensure core matches
sys.path.append(os.getcwd())

from core.cortex.events import EventBus, EventStore, GraphEventType
from core.scheduler.strategos import Strategos
from core.scheduler.modes import ScanMode

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("Verification")

async def mock_dispatch_tool(tool: str) -> List[Dict]:
    """Simulate tool execution."""
    await asyncio.sleep(0.1)
    logger.info(f"   [Mock] Tool '{tool}' running...")
    return [{"type": "issue", "message": "Simulated finding"}]

async def main():
    print("--- Verifying Strategic Logging ---")
    
    # 1. Setup Event Bus
    store = EventStore()
    bus = EventBus(store)
    
    # 2. Setup Strategos with EventBus
    brain = Strategos(
        log_fn=lambda msg: print(f"   [LogFn] {msg}"),
        event_bus=bus
    )
    
    # 3. Start Listener for Events
    async def event_listener():
        print("--- Listening for Events ---")
        async for event in store.subscribe():
            if event.type == GraphEventType.DECISION_MADE:
                intent = event.payload.get("intent")
                reason = event.payload.get("reason")
                print(f"✅ [EVENT: DECISION] {intent} -> {reason}")
            elif event.type == GraphEventType.SCAN_PHASE_CHANGED:
                phase = event.payload.get("phase")
                print(f"✅ [EVENT: PHASE] Transitioned to {phase}")
            elif event.type == GraphEventType.LOG_EMITTED:
                 # Too noisy, ignore for now or print
                 pass
    
    listener_task = asyncio.create_task(event_listener())
    
    # 4. Run Mission (Short)
    print("--- Starting Mission ---")
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
    for e in store._events:
        print(f"Stored Event: {e.type} | {e.payload}")

    print("--- Verification Complete ---")

if __name__ == "__main__":
    asyncio.run(main())
