"""
Cronus Session: The Time Machine's Cockpit
Enforces budget constraints and tracks temporal consumption.
"""
import time
import logging
from typing import Dict, Optional
from core.contracts.events import EventType, EventContract
from core.contracts.budget import Budget, BudgetOverrun

logger = logging.getLogger(__name__)

class CronusSession:
    """
    Per-scan session for Cronus.
    
    Responsibilities:
    1. Holds the immutable Budget.
    2. Tracks "Time Spent" (wall clock + simulated).
    3. Authorizes or Denies actions based on remaining budget.
    """
    
    def __init__(self, session_id: str, budget: Budget):
        self.session_id = session_id
        self.budget = budget
        self.start_time = time.time()
        self.active_tools: Dict[str, float] = {} # Tool -> StartTime
        
        # Snapshot of consumption at varying intervals
        self._last_check_time = self.start_time

    def check_budget_precondition(self, cost_findings: int = 0) -> bool:
        """
        Check if we can proceed. Raises BudgetOverrun if not.
        """
        # 1. Update Time Consumption
        now = time.time()
        elapsed_ms = (now - self._last_check_time) * 1000
        if elapsed_ms > 0:
            self.budget.consume("time_ms", elapsed_ms)
            self._last_check_time = now

        # 2. Check proposed cost
        if cost_findings > 0:
            self.budget.consume("findings", cost_findings)
            
        return True

    def on_tool_started(self, tool: str):
        """Register tool start time."""
        # Check if we have time budget to even start
        self.check_budget_precondition()
        self.active_tools[tool] = time.time()

    def on_tool_completed(self, tool: str, findings_count: int):
        """Register tool completion and cost."""
        start_time = self.active_tools.pop(tool, None)
        
        # 1. Consume Time
        self.check_budget_precondition()
        
        # 2. Consume Findings Budget
        if findings_count > 0:
            try:
                self.budget.consume("findings", findings_count)
            except BudgetOverrun as e:
                logger.warning(f"Scan {self.session_id} exceeded finding budget: {e}")
                raise

    def shutdown(self):
        """Cleanup and final accounting."""
        try:
            self.check_budget_precondition()
        except BudgetOverrun:
            pass # We are shutting down anyway
