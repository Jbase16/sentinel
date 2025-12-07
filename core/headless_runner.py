# core/headless_runner.py
# Controller for running AraUltra without a GUI.

import asyncio
import logging
import sys
from typing import List

from core.scan_orchestrator import ScanOrchestrator
from core.reporting import create_report_bundle

# Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class HeadlessRunner:
    def __init__(self):
        self.orchestrator = ScanOrchestrator(log_fn=self._log_callback)

    def _log_callback(self, msg: str):
        print(msg)

    async def run(self, target: str):
        print(f"[*] Starting Headless Scan against: {target}")
        print("[*] Press Ctrl+C to stop.")
        
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
            bundle = create_report_bundle()
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
