"""
core/engine/scan_orchestrator.py
Lightweight orchestrator that wraps ScannerEngine with session management.
Accepts mode parameter for Strategos integration.
"""

import asyncio
import logging
from typing import List, Optional, Callable
from dataclasses import dataclass, field

from core.engine.scanner_engine import ScannerEngine

logger = logging.getLogger(__name__)

@dataclass
class ScanContext:
    """Result context from a scan run."""
    target: str
    modules: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)


class ScanOrchestrator:
    """
    Orchestrates a scan using ScannerEngine.
    Provides session management and mode support.
    """
    
    def __init__(self, session=None, log_fn: Callable[[str], None] = None):
        """
        Args:
            session: Optional ScanSession for result isolation.
            log_fn: Optional callback for logging.
        """
        self.session = session
        self.log_fn = log_fn or (lambda msg: logger.info(msg))
        self.engine = ScannerEngine(session=session)
        self._queued_tasks: List[str] = []
    
    def _detect_installed(self):
        """Detect installed tools."""
        return self.engine._detect_installed()
    
    def queue_task(self, tool: str, args: List[str] = None):
        """Queue a tool task for execution."""
        self._queued_tasks.append(tool)
    
    async def run(
        self, 
        target: str, 
        modules: Optional[List[str]] = None,
        cancel_flag=None,
        mode: str = "standard"
    ) -> ScanContext:
        """
        Run a scan against the target.
        
        Args:
            target: Target URL or domain.
            modules: List of tools to run. If empty, runs all installed.
            cancel_flag: Threading event to signal cancellation.
            mode: Strategos mode (standard, bug_bounty, stealth).
        
        Returns:
            ScanContext with findings and logs.
        """
        self.log_fn(f"[ScanOrchestrator] Starting scan: {target} (mode={mode})")
        
        context = ScanContext(target=target, modules=modules or [])
        
        # Determine tools to run
        tools_to_run = modules if modules else None
        
        # If queued tasks exist, use those instead
        if self._queued_tasks:
            tools_to_run = self._queued_tasks
            self._queued_tasks = []
        
        try:
            async for log_line in self.engine.scan(target, selected_tools=tools_to_run, cancel_flag=cancel_flag):
                self.log_fn(log_line)
                context.logs.append(log_line)
        except asyncio.CancelledError:
            self.log_fn("[ScanOrchestrator] Scan cancelled.")
            raise
        except Exception as e:
            self.log_fn(f"[ScanOrchestrator] Scan error: {e}")
            raise
        
        # Collect findings from engine
        findings = self.engine.get_last_results() or []
        context.findings = findings
        
        self.log_fn(f"[ScanOrchestrator] Scan complete. Findings: {len(findings)}")
        
        return context
