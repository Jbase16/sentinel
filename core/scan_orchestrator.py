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
        self.dispatcher = ActionDispatcher()
        
        # We need to listen to TaskRouter events to trigger new scans
        self.router = TaskRouter.instance()
        self.router.register_ui_callback("findings_update", self._handle_autonomous_actions)
        self.current_target = ""

    def _handle_autonomous_actions(self, payload: dict):
        """
        Callback triggered when AI finds something.
        """
        next_steps = payload.get("next_steps", [])
        if not next_steps:
            return

        for step in next_steps:
            validated = self.dispatcher.validate_action(step, self.current_target)
            if validated:
                tool = validated["tool"]
                args = validated["args"]
                reason = validated["reason"]
                self.log(f"[AUTONOMOUS] AI suggests: {tool} ({reason}). Queueing...")
                self.scanner.queue_task(tool, args)

    async def run(self, target: str) -> ScanContext:
        self.current_target = target
        logs: List[str] = []
        
        # Reset dispatcher history for new scan
        self.dispatcher = ActionDispatcher()

        async for line in self.scanner.scan(target):
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

    def run_sync(self, target: str) -> ScanContext:
        """Convenience wrapper to run orchestrator in a synchronous context."""
        return asyncio.run(self.run(target))

    def _log(self, msg: str, logs: List[str]):
        logs.append(msg)
        self.log(msg)
