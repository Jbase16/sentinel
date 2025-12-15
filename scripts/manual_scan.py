# ============================================================================
# scripts/manual_scan.py
# Manual Scan Module
# ============================================================================
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
# ============================================================================


import asyncio
import logging
import sys
import os

# Ensure core matches
sys.path.append(os.getcwd())

from core.engine.scanner_engine import ScannerEngine
from core.base.session import ScanSession
from core.data.db import Database

# Configure Logging to Stdout
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

async def main():
    target = "testphp.vulnweb.com"
    print(f"--- Starting Manual Scan on {target} ---")
    
    # Init DB
    await Database.instance().init()
    
    # Init Session
    session = ScanSession(target)
    
    # Init Engine
    engine = ScannerEngine(session=session)
    
    # Run
    # mocking cancel flag
    cancel_event = asyncio.Event()
    
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
    except Exception as e:
        print(f"--- CRITICAL ERROR: {e} ---")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
