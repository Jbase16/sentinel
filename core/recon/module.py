#
# PURPOSE:
# This module is part of the recon package in SentinelForge.
# [Specific purpose based on module name: module]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
Simple recon module entry point.

This wraps the PassiveReconEngine from recon.py so the orchestrator/UI have
one place to call for recon work. It keeps a tiny, well-commented surface so
new contributors can read it quickly.
"""

from __future__ import annotations

import asyncio
from typing import Callable, List

from core.recon.behavioral import PassiveReconEngine

LogFn = Callable[[str], None]


class ReconModule:
    """
    Runs passive recon (httpx, dnsx, sslscan where available).
    Use run() from async contexts or run_sync() from sync callers.
    """

    def __init__(self, log_fn: LogFn | None = None):
        """Function __init__."""
        self.log = log_fn or (lambda msg: None)
        self.engine = PassiveReconEngine()

    async def run(self, target: str) -> List[dict]:
        """AsyncFunction run."""
        self.log(f"[recon] starting passive recon for {target}")
        findings = await self.engine.run_all(target)
        self.log(f"[recon] finished passive recon ({len(findings)} findings)")
        return findings

    def run_sync(self, target: str) -> List[dict]:
        """
        Convenience wrapper to run in sync contexts (e.g., tests or scripts).
        """
        return asyncio.run(self.run(target))
