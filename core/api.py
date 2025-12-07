"""
Sentinel Core API (Python side)

This file is the “bridge” the SwiftUI app will talk to. Keep it tiny and
beginner-friendly:
  - expose functions Swift can call (start_scan, stream_logs, latest_results)
  - ONLY pass JSON-serializable data across the process boundary
  - hide engine complexity behind this façade so UI changes stay simple

Think of this as the contract between the macOS app and the AraUltra-derived
engine. The goal is to wire AraUltra pieces here without leaking internals.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional


class CoreAPI:
    """
    Lightweight façade over the scanner/orchestrator layers.

    TODO: Replace placeholders with actual AraUltra engines:
      - ScanOrchestrator for running tools
      - AIEngine for summarization + next steps
      - ReasoningEngine for attack-path graphs
    """

    def __init__(self):
        # In a later pass, create ScanOrchestrator() and keep a reference here.
        # For now, we stub it out so Swift has something to call.
        self._orchestrator = None

    def ping(self) -> Dict[str, str]:
        """Basic health check callable from Swift."""
        return {"status": "ok"}

    def start_scan(self, target: str, modules: Optional[Iterable[str]] = None) -> None:
        """
        Entry point for launching a scan from the UI.

        Expected flow once wired:
          1) kick off orchestrator.run(target)
          2) capture live log lines into an internal buffer/queue
          3) stream findings back through TaskRouter callbacks
        """
        raise NotImplementedError("Hook up AraUltra ScanOrchestrator here")

    def stream_logs(self) -> Iterable[str]:
        """
        Yield log lines for UI consumption.

        Implement by exposing a generator that yields from the orchestrator's
        log queue, or by reading from a multiprocessing Pipe/Queue.
        """
        raise NotImplementedError("Connect to orchestrator log stream")

    def latest_results(self) -> Dict[str, Any]:
        """
        Provide a snapshot of findings/issues/killchain edges.

        Shape (proposed):
        {
            "findings": [...],
            "issues": [...],
            "killchain_edges": [...],
            "phase_results": {...}
        }
        """
        raise NotImplementedError("Return structured results for the UI")
