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
"""

import asyncio
import logging
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass, field

from core.engine.scanner_engine import ScannerEngine
from core.scheduler.strategos import Strategos
from core.scheduler.modes import ScanMode

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
        self.engine = ScannerEngine(session=session)
        self._last_result: Optional[ScanResult] = None
    
    def _detect_installed(self) -> Dict[str, str]:
        """Detect installed tools. Returns dict of tool_name -> path."""
        return self.engine._detect_installed()
    
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
        # Convert string mode to ScanMode enum
        scan_mode = ScanMode.STANDARD
        if mode == "bug_bounty":
            scan_mode = ScanMode.BUG_BOUNTY
        elif mode == "stealth":
            scan_mode = ScanMode.STEALTH
        
        self.log_fn(f"[ScanOrchestrator] Starting scan: {target} (mode={scan_mode.value})")
        
        result = ScanResult(target=target, mode=mode, modules=modules or [])
        
        # Detect available tools
        installed_tools = list(self._detect_installed().keys())
        self.log_fn(f"[ScanOrchestrator] Detected {len(installed_tools)} installed tools")
        
        # If specific modules requested, filter to only those
        if modules:
            available_tools = [t for t in modules if t in installed_tools]
            self.log_fn(f"[ScanOrchestrator] Using {len(available_tools)} requested tools")
        else:
            available_tools = installed_tools
        
        # Create Strategos brain
        brain = Strategos()
        
        # Define the dispatch callback - this is how Strategos runs tools
        async def dispatch_tool(tool: str) -> List[Dict]:
            """
            Runs a single tool via ScannerEngine.
            Returns findings list for Strategos to ingest.
            """
            self.log_fn(f"[ScanOrchestrator] Dispatching: {tool}")
            
            try:
                # Run the tool
                async for log_line in self.engine.scan(target, selected_tools=[tool], cancel_flag=cancel_flag):
                    self.log_fn(log_line)
                    result.logs.append(log_line)
                
                # Get findings from this tool run
                tool_findings = self.engine.get_last_results() or []
                return tool_findings
                
            except asyncio.CancelledError:
                self.log_fn(f"[ScanOrchestrator] Tool {tool} cancelled")
                return []
            except Exception as e:
                self.log_fn(f"[ScanOrchestrator] Tool {tool} error: {e}")
                return []
        
        # Run the Strategos mission
        try:
            mission_result = await brain.run_mission(
                target=target,
                available_tools=available_tools,
                mode=scan_mode,
                dispatch_tool=dispatch_tool
            )
            
            result.status = "completed"
            result.reason = mission_result.reason
            result.findings = brain.context.findings if brain.context else []
            
            self.log_fn(f"[ScanOrchestrator] Mission complete: {mission_result.reason}")
            
        except asyncio.CancelledError:
            result.status = "cancelled"
            result.reason = "User cancelled"
            self.log_fn("[ScanOrchestrator] Scan cancelled by user")
            raise
        except Exception as e:
            result.status = "error"
            result.reason = str(e)
            self.log_fn(f"[ScanOrchestrator] Scan error: {e}")
            raise
        
        self._last_result = result
        self.log_fn(f"[ScanOrchestrator] Scan complete. Findings: {len(result.findings)}")
        
        return result

