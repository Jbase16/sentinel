"""
core/executor/models.py

Purpose:
    Defines the data structures for Pillar VI (The Harness).
    These models encapsulate the "Active" phase of the security pipeline.

Semantics:
    - ExecutionOrder: A signed command to execute a LogicTestCase.
      Requires a valid SentientDecision(APPROVE) to be constructed.
    - ExecutionResult: The outcome of the attempt.
      Captures raw signals (HTTP response, logs) and the final
      safety/success status.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime

from core.thanatos.models import LogicTestCase
from core.sentient.models import SentientDecision, Verdict

class ExecutionStatus(str, Enum):
    EXECUTED = "EXECUTED"  # Harness ran successfully
    ERROR = "ERROR"        # Harness crashed or network failed
    SKIPPED = "SKIPPED"    # Interlock blocked execution

class BreachStatus(str, Enum):
    BREACH = "BREACH"      # Invariant violated (Vulnerability)
    SECURE = "SECURE"      # Invariant held
    ANOMALY = "ANOMALY"    # Unexpected State (Crash/Timeout)
    UNKNOWN = "UNKNOWN"    # Could not determine


@dataclass(frozen=True)
class ExecutionOrder:
    """
    The envelope that authorizes a test.
    Immutable. Must be constructed with a valid Decision.
    """
    test_case: LogicTestCase
    decision: SentientDecision
    idempotency_token: str
    auth_headers: Optional[Dict[str, str]] = None
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())

    def __post_init__(self):
        """
        Runtime invariant: Verification is mandatory.
        """
        if self.decision.verdict != Verdict.APPROVE:
             raise ValueError(f"Cannot create ExecutionOrder with Verdict {self.decision.verdict}. Must be APPROVE.")


@dataclass(frozen=True)
class ExecutionResult:
    """
    The outcome of an execution.
    """
    order_id: str
    status: ExecutionStatus
    signals: Dict[str, Any]  # Raw evidence (status_code, body, logs)
    duration_ms: float
    metrics: Dict[str, float] = field(default_factory=dict) # Telemetry (ttfb, dns, retries)
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    error_message: Optional[str] = None
