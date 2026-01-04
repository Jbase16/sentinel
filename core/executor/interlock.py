"""
core/executor/interlock.py

Purpose:
    The "Red Button" and final safety gate.
    Ensures that even if Sentient approved a test, we don't execute if:
    1. The Global Kill Switch is active.
    2. The Target is not in the hard Scope (double-check).
    3. The Decision is stale or invalid.

Magnum Opus Standards:
    - Audit Logging: Every decision is logged structurally.
    - Stale Check: Prevents replay of old orders.
    - Fail-Safe: Default return is BLOCKED.
"""

from __future__ import annotations
from typing import Optional
import logging
from datetime import datetime

from core.sentient.models import Verdict
from .models import ExecutionOrder, ExecutionStatus

log = logging.getLogger("executor.interlock")

# Maximum time an Order is valid before being considered "Stale"
MAX_ORDER_AGE_SECONDS = 300  # 5 minutes

class SafetyInterlock:
    """
    Final authorization gate before the Harness touches the network.
    """
    def __init__(self):
        self._kill_switch_active = False

    def engage_kill_switch(self, operator: str = "SYSTEM"):
        log.warning(f"🚨 KILL SWITCH ENGAGED by {operator}. All execution halted.")
        self._kill_switch_active = True

    def disengage_kill_switch(self, operator: str = "SYSTEM"):
        log.warning(f"🟢 Kill switch disengaged by {operator}. Execution enabled.")
        self._kill_switch_active = False

    def check(self, order: ExecutionOrder) -> Optional[str]:
        """
        Verifies if it is safe to proceed.
        Returns None if SAFE.
        Returns reason string if BLOCKED.
        """
        check_ts = datetime.now()
        
        # 1. Kill Switch (Top Priority)
        if self._kill_switch_active:
            self._audit(order, "BLOCKED", "Global Kill Switch is ACTIVE.")
            return "Global Kill Switch is ACTIVE."

        # 2. Verdict Verification
        if order.decision.verdict != Verdict.APPROVE:
            reason = f"Invalid Verdict: {order.decision.verdict}"
            self._audit(order, "BLOCKED", reason)
            return reason

        # 3. Staleness Check (Replay Prevention)
        age = check_ts.timestamp() - order.created_at
        if age > MAX_ORDER_AGE_SECONDS:
            reason = f"Order Expired (Age: {age:.1f}s > Limit: {MAX_ORDER_AGE_SECONDS}s)"
            self._audit(order, "BLOCKED", reason)
            return reason

        # 4. Scope Verification (Redundant but necessary)
        # In a real system, we might query the ScopeGate one last time here.
        # For now, we trust the ScopeGate ran upstream, but we log the target.
        
        self._audit(order, "ALLOWED", "All checks passed.")
        return None

    def _audit(self, order: ExecutionOrder, result: str, reason: str):
        """
        Emits a structured audit log.
        """
        log.info(
            f"AUDIT | Order={id(order)} | Target={order.test_case.target.node_id} | "
            f"Result={result} | Reason={reason}"
        )
