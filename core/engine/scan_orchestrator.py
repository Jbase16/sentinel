# ============================================================================
# core/engine/scan_orchestrator.py
# Scan Orchestrator Module
# ============================================================================
#
# PURPOSE:
# This module is part of the engine package in SentinelForge.
# [Specific purpose based on module name: scan_orchestrator]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#
# ============================================================================

"""
core/engine/scan_orchestrator.py
Lightweight orchestrator that wraps ScannerEngine with Strategos integration.
This is the bridge between the API and the intelligent scheduler.

DEPRECATED:
The canonical, UI-visible scan lifecycle now lives in `core/server/api.py` under
POST `/scan` (and `/mission/start` is an alias). That path is responsible for:
- Emitting EventBus events into `/events/stream`
- Streaming logs, graph mutations, and tool lifecycle to the UI

This module is kept only as a compatibility stub to prevent split-brain scan execution.
"""

import logging
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result context from a scan run."""
    target: str
    mode: str
    modules: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    status: str = "completed"
    reason: str = ""


class ScanOrchestrator:
    """
    Orchestrates a scan using Strategos (the intelligent scheduler).
    
    This class serves as the bridge between:
    - The API layer (core/server/api.py)
    - The intelligent planner (Strategos)
    - The actual tool runner (ScannerEngine)
    """
    
    def __init__(self, session=None, log_fn: Callable[[str], None] = None):
        """
        Args:
            session: Optional ScanSession for result isolation.
            log_fn: Optional callback for logging.
        """
        self.session = session
        self.log_fn = log_fn or (lambda msg: logger.info(msg))
        self._last_result: Optional[ScanResult] = None
    
    def _detect_installed(self) -> Dict[str, str]:
        """Detect installed tools. Returns dict of tool_name -> path."""
        raise RuntimeError(
            "ScanOrchestrator is deprecated. Use GET /tools/status (API) or POST /scan."
        )
    
    async def run(
        self, 
        target: str, 
        modules: Optional[List[str]] = None,
        cancel_flag=None,
        mode: str = "standard"
    ) -> ScanResult:
        """
        Run a scan against the target using Strategos for intelligent scheduling.
        
        Args:
            target: Target URL or domain.
            modules: List of tools to run. If empty, Strategos decides.
            cancel_flag: Threading event to signal cancellation.
            mode: Strategos mode (standard, bug_bounty, stealth).
        
        Returns:
            ScanResult with findings and logs.
        """
        raise RuntimeError(
            "ScanOrchestrator has been superseded by the canonical scan lifecycle. "
            "Use POST /scan (core/server/api.py) so all scan activity emits EventBus "
            "events for /events/stream."
        )
