"""Module manual_scan: inline documentation for /Users/jason/Developer/sentinelforge/scripts/manual_scan.py."""
#
# PURPOSE:
# This module is part of the scripts package in SentinelForge.
# [Specific purpose based on module name: manual_scan]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#


import asyncio
import logging
import sys
from pathlib import Path

# Ensure core matches
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.engine.scanner_engine import ScannerEngine  # noqa: E402
from core.base.session import ScanSession  # noqa: E402
from core.data.db import Database  # noqa: E402
from core.data.blackbox import BlackBox  # noqa: E402

# Configure Logging to Stdout
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

async def main():
    """AsyncFunction main."""
    target = "testphp.vulnweb.com"
    print(f"--- Starting Manual Scan on {target} ---")
    
    # Init DB
    await Database.instance().init()
    
    # Init Session
    session = ScanSession(target)
    
    # Init Engine
    engine = ScannerEngine(session=session)
    
    # Error handling block.
    try:
        # Use run_all to consume generator and get results
        # Note: run_all signature in ScannerEngine: run_all(target) -> List[dict]
        # But we want to see logs too. 
        # Actually proper usage is: async for line in scan(): print(line)
        # But to match signature mismatch let's just use run_all for validity check.
        results_list = await engine.run_all(target)
        results = {"findings": results_list}
        print("--- Scan Complete ---")
        print("Findings:", len(results.get("findings", [])))
        print(results)
        print(results)
    except Exception as e:
        print(f"--- CRITICAL ERROR: {e} ---")
        import traceback
        traceback.print_exc()
    finally:
        # CRITICAL: Drain the write queue
        print("--- Draining Persistence Queue ---")
        await BlackBox.instance().shutdown()
        print("--- Closing Database Connection ---")
        await Database.instance().close()
        print("--- Shutdown Complete ---")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
