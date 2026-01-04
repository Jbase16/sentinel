import asyncio
import logging
from core.system.orchestrator import SystemOrchestrator

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
log = logging.getLogger("verify_orchestrator")

async def test_lifecycle():
    log.info("--- Testing System Orchestrator Lifecycle ---")
    
    cortex = SystemOrchestrator()
    
    # 1. Boot
    await cortex.boot()
    log.info("✅ Boot successful.")
    
    # 2. Mock Loop
    await cortex.run_autonomous_loop()
    log.info("✅ Run loop accessed.")
    
    # 3. Shutdown
    await cortex.shutdown()
    log.info("✅ Shutdown successful.")

    # 4. Verify Logs
    import os
    if os.path.exists("logs/system_events.jsonl"):
        with open("logs/system_events.jsonl", "r") as f:
            lines = f.readlines()
            log.info(f"✅ Log file captured {len(lines)} events.")
            # Expect at least STARTUP and SHUTDOWN events

if __name__ == "__main__":
    asyncio.run(test_lifecycle())
    
    # Cleanup
    import shutil
    # shutil.rmtree("logs") # Optional, maybe keep for inspection
