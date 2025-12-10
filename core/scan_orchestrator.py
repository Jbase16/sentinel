# core/scan_orchestrator.py
# High-level orchestrator that runs tool scans, recon phases, and correlation.

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from core.scanner_engine import ScannerEngine
from core.runner import PhaseRunner
from core.issues_store import issues_store
from core.killchain_store import killchain_store
from core.findings import findings_store
from core.action_dispatcher import ActionDispatcher
from core.task_router import TaskRouter


LogCallback = Callable[[str], None]


@dataclass
class ScanContext:
    target: str
    findings: List[dict]
    issues: List[dict]
    killchain_edges: List[dict]
    phase_results: Dict[str, List[dict]]
    logs: List[str]


class ScanOrchestrator:
    """Wrapper that sequences the end-to-end pipeline for a target."""

    def __init__(self, log_fn: Optional[LogCallback] = None):
        self.log = log_fn or (lambda msg: None)
        self.scanner = ScannerEngine()
        self.dispatcher = ActionDispatcher.instance()
        
        # We need to listen to TaskRouter events to trigger new scans
        self.router = TaskRouter.instance()
        self.router.ui_event.connect(self._on_router_event)
        
        # Listen for approved actions (both auto and manual)
        self.dispatcher.action_approved.connect(self._on_action_approved)
        
        self.current_target = ""

    def _on_action_approved(self, action: dict):
        """
        Executed when an action is greenlit (either auto or by user).
        """
        tool = action["tool"]
        args = action["args"]
        reason = action.get("reason", "")
        self.log(f"[AUTONOMOUS] Executing approved action: {tool} ({reason})")
        self.scanner.queue_task(tool, args)

    def _on_router_event(self, event_type: str, payload: dict):
        if event_type == "findings_update":
            self._handle_autonomous_actions(payload)

    def _handle_autonomous_actions(self, payload: dict):
        """
        Callback triggered when AI finds something.
        """
        next_steps = payload.get("next_steps", [])
        if not next_steps:
            return

        for step in next_steps:
            # Request action - dispatcher will either auto-approve (emitting action_approved)
            # or hold it in pending (emitting action_needed)
            status = self.dispatcher.request_action(step, self.current_target)
            if status == "PENDING":
                self.log(f"[AUTONOMOUS] Action paused for approval: {step.get('tool')}")

    async def run(self, target: str, modules: Optional[List[str]] = None, cancel_flag=None) -> ScanContext:
        self.current_target = target
        logs: List[str] = []
        
        # Note: We do NOT reset dispatcher history here anymore, 
        # so duplicates are remembered across scans in the same session.
        # If per-scan dedupe is desired, we'd add a method to clear history.

        async for line in self.scanner.scan(target, selected_tools=modules, cancel_flag=cancel_flag):
            logs.append(line)
            self.log(line)

        phase_runner = PhaseRunner(target, lambda msg: self._log(msg, logs))
        phase_results = await phase_runner.run_all_phases()

        findings = self.scanner.get_last_results()
        issues = issues_store.get_all()
        edges = killchain_store.get_all()

        return ScanContext(
            target=target,
            findings=findings,
            issues=issues,
            killchain_edges=edges,
            phase_results=phase_results,
            logs=logs,
        )

    def run_sync(self, target: str, modules: Optional[List[str]] = None, cancel_flag=None) -> ScanContext:
        """Convenience wrapper to run orchestrator in a synchronous context."""
        return asyncio.run(self.run(target, modules=modules, cancel_flag=cancel_flag))

    def _log(self, msg: str, logs: List[str]):
        logs.append(msg)
        self.log(msg)
