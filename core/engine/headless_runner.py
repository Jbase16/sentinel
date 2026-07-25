"""Module headless_runner: inline documentation for /Users/jason/Developer/sentinelforge/core/engine/headless_runner.py."""
#
# PURPOSE:
# This module is part of the engine package in SentinelForge.
# [Specific purpose based on module name: headless_runner]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

# core/headless_runner.py
# Controller for running AraUltra without a GUI.

import asyncio
import logging
import sys

from core.ai.reporting import create_report_bundle

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class HeadlessRunner:
    """Class HeadlessRunner."""
    def __init__(self):
        """Function __init__."""
        raise RuntimeError(
            "HeadlessRunner has been superseded by the canonical scan lifecycle. "
            "Start the backend (or use POST /scan) so all scan activity emits EventBus "
            "events for /events/stream."
        )

    def _log_callback(self, msg: str):
        """Function _log_callback."""
        print(msg)

    async def run(self, target: str):
        """AsyncFunction run."""
        print(f"[*] Starting Headless Scan against: {target}")
        print("[*] Press Ctrl+C to stop.")
        
        # Error handling block.
        try:
            # Run the orchestrator
            # The orchestrator runs the scanner, which runs tools and yields logs
            # It also handles autonomous actions internally via TaskRouter/ActionDispatcher
            context = await self.orchestrator.run(target)
            
            print("\n[*] Scan Complete.")
            print(f"[*] Findings: {len(context.findings)}")
            print(f"[*] Issues: {len(context.issues)}")
            
            # Generate Report
            print("[*] Generating AI Report...")
            bundle = await create_report_bundle()
            print(f"[+] Report saved to: {bundle.markdown_path}")
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            import traceback
            traceback.print_exc()

    def start(self, target: str):
        """Entry point for synchronous execution"""
        asyncio.run(self.run(target))
