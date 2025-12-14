# core/scan_orchestrator.py
# High-level orchestrator that runs tool scans, recon phases, and correlation.

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from core.engine.scanner_engine import ScannerEngine
from core.engine.runner import PhaseRunner
from core.data.issues_store import issues_store
from core.data.killchain_store import killchain_store
from core.data.findings import findings_store
from core.base.action_dispatcher import ActionDispatcher
from core.base.task_router import TaskRouter
from core.cortex.reasoning import ReasoningEngine


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

    def __init__(self, session=None, log_fn: Optional[LogCallback] = None):
        self.session = session
        self._external_log = log_fn or (lambda msg: None)
        
        # If we have a session, create a combined log function that logs to both session and external log
        if self.session:
            def session_and_external_log(msg: str):
                # Log to session
                self.session.log(msg)
                # Log to external callback
                self._external_log(msg)
            self.log = session_and_external_log
        else:
            self.log = self._external_log
        
        # Initialize queues before any event handlers can call queue_task
        self._pending_tasks_initialized = False
        
        # Pass session to engine for isolated data storage
        self.scanner = ScannerEngine(session=session)
        self.dispatcher = ActionDispatcher.instance()
        
        # We need to listen to TaskRouter events to trigger new scans
        self.router = TaskRouter.instance()
        self.router.ui_event.connect(self._on_router_event)
        
        # Listen for approved actions (both auto and manual)
        self.dispatcher.action_approved.connect(self._on_action_approved)
        
        self.current_target = session.target if session else ""

    def _on_action_approved(self, action: dict):
        """
        Executed when an action is greenlit (either auto or by user).
        CRITICAL: Filter by session target to avoid cross-talk.
        """
        target = action.get("target") or self.current_target
        
        # Safety check: Is this action for 'us'?
        # If we have a session, ensure the action targets our scope.
        if self.session and target != self.session.target:
             # This event belongs to another concurrent scan
             return
        
        tool = action["tool"]
        args = action["args"]
        reason = action.get("reason", "")
        
        # CRITICAL FIX: Only queue task if scanner is running and queues are initialized
        if not self._pending_tasks_initialized:
            self.log(f"[AUTONOMOUS] Action received outside of active scan: {tool}")
            return
        
        self.log(f"[AUTONOMOUS] Executing approved action: {tool} ({reason})")
        self.scanner.queue_task(tool, args)

    def _on_router_event(self, event_type: str, payload: dict):
        if event_type == "findings_update":
            # If session is active, ensure this update relates to our findings
            # (optimization: strictly we should check payload origin, currently implicit)
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
        
        # Initialize task queues before scanner runs
        self._pending_tasks_initialized = True
        
        # Note: We do NOT reset dispatcher history here anymore, 
        # so duplicates are remembered across scans in the same session.
        # If per-scan dedupe is desired, we'd add a method to clear history.

        try:
            async for line in self.scanner.scan(target, selected_tools=modules, cancel_flag=cancel_flag):
                logs.append(line)
                self.log(line)
        finally:
            # Reset flag when scan is complete
            self._pending_tasks_initialized = False

        phase_runner = PhaseRunner(target, lambda msg: self._log(msg, logs))
        phase_results = await phase_runner.run_all_phases()

        # Analyze knowledge graph and dispatch opportunities as actions
        await self._analyze_and_dispatch_opportunities()

        findings = self.scanner.get_last_results()
        # Use session-scoped stores when available; fallback to global singletons
        if self.session:
            issues = self.session.issues.get_all()
            edges = self.session.killchain.get_all()
        else:
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

    async def _analyze_and_dispatch_opportunities(self):
        """
        Run the ReasoningEngine to analyze the knowledge graph
        and dispatch derived opportunities to the ActionDispatcher.
        """
        try:
            reasoning = ReasoningEngine()
            analysis = reasoning.analyze()
            
            opportunities = analysis.get("opportunities", [])
            risks = analysis.get("risks", [])
            graph_summary = analysis.get("graph_summary", {})
            
            self.log(f"[REASONING] Graph: {graph_summary.get('nodes', 0)} nodes, {graph_summary.get('edges', 0)} edges")
            self.log(f"[REASONING] Derived {len(opportunities)} opportunities, {len(risks)} high-risk findings")
            
            # Emit risks to UI via TaskRouter
            if risks:
                self.router.emit("risk_assessment", {
                    "risks": risks,
                    "target": self.current_target
                })
            
            # Dispatch each opportunity as an action request
            for opp in opportunities:
                tool = opp.get("tool")
                target = opp.get("target", self.current_target)
                args = opp.get("args", [])
                reason = opp.get("reason", "Derived from knowledge graph analysis")
                
                action = {
                    "tool": tool,
                    "target": target,
                    "args": args,
                    "reason": reason,
                    "source": "reasoning_engine"
                }
                
                status = self.dispatcher.request_action(action, target)
                if status == "APPROVED":
                    self.log(f"[REASONING] Auto-approved action: {tool}")
                elif status == "PENDING":
                    self.log(f"[REASONING] Action queued for approval: {tool} - {reason}")
                else:
                    self.log(f"[REASONING] Action rejected or duplicate: {tool}")
                    
        except Exception as e:
            self.log(f"[REASONING] Analysis failed: {e}")
