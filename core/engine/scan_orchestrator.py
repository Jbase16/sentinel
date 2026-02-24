"""
core/engine/scan_orchestrator.py
---------------------------------
DEPRECATED MODULE — kept as a documented stub to prevent confusion.

The ScanOrchestrator class was the original bridge between the API and the
scan engine. It has been fully superseded. If you are looking for the scan
entry point, it is NOT here.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTUAL SCAN LIFECYCLE (as of current codebase):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  UI / API Client
      │
      ▼
  POST /v1/scans/start
      │
      ▼
  core/server/routers/scans.py  →  begin_scan_logic()
      │
      ▼
  core/cortex/reasoning_engine.py  →  ReasoningEngine.start_scan()
      │
      ▼
  core/scheduler/strategos.py  →  Strategos.run_mission()
      │
      ▼
  core/engine/scanner_engine.py  →  ScannerEngine._run_tool_task()
      │
      ▼
  asyncio.create_subprocess_exec()  ←  Real tool processes here

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tool detection:  GET /v1/tools/status
Scan status:     GET /v1/scans/{scan_id}
Findings:        GET /v1/findings
Events stream:   GET /v1/events/stream  (SSE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This file is kept to avoid import errors in any code that still references
ScanOrchestrator. All methods log a deprecation warning and return safe
no-op results — they do NOT raise RuntimeError, which would cause silent
crashes in callers that don't catch exceptions.

To remove this file entirely: search the codebase for 'ScanOrchestrator'
and 'scan_orchestrator' imports. If no callers exist, delete this file.
"""

import logging
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DEPRECATION_MSG = (
    "[ScanOrchestrator] DEPRECATED: This class is a no-op stub. "
    "Use POST /v1/scans/start (core/server/routers/scans.py → begin_scan_logic) "
    "to initiate scans. See this module's docstring for the full call chain."
)


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
    DEPRECATED stub.

    This class previously bridged the API → Strategos → ScannerEngine.
    That responsibility now lives in core/server/routers/scans.py.
    All methods here are safe no-ops that emit a deprecation warning.

    See this module's docstring for the actual scan call chain.
    """

    def __init__(self, session=None, log_fn: Callable[[str], None] = None):
        logger.warning(_DEPRECATION_MSG)
        self.session = session
        self.log_fn = log_fn or (lambda msg: logger.info(msg))
        self._last_result: Optional[ScanResult] = None

    def _detect_installed(self) -> Dict[str, str]:
        """
        DEPRECATED. Use GET /v1/tools/status instead.

        Returns an empty dict — does not raise, to avoid crashing callers.
        """
        logger.warning(
            "[ScanOrchestrator] _detect_installed() called on deprecated stub. "
            "Use GET /v1/tools/status for installed tool detection."
        )
        return {}

    async def run(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        cancel_flag=None,
        mode: str = "standard",
    ) -> ScanResult:
        """
        DEPRECATED. Use POST /v1/scans/start instead.

        Returns an empty ScanResult with status='deprecated' — does not raise,
        to avoid crashing callers that have not been updated.
        """
        logger.warning(
            "[ScanOrchestrator] run() called on deprecated stub for target=%s. "
            "Use POST /v1/scans/start (begin_scan_logic) to initiate scans with "
            "full EventBus / SSE / UI integration.",
            target,
        )
        return ScanResult(
            target=target,
            mode=mode,
            modules=modules or [],
            findings=[],
            logs=["[DEPRECATED] ScanOrchestrator.run() is a no-op. See scan_orchestrator.py docstring."],
            status="deprecated",
            reason="ScanOrchestrator has been superseded by begin_scan_logic(). No scan was executed.",
        )
