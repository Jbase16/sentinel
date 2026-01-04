from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional
from datetime import datetime

from core.thanatos.models import LogicTestCase
from core.sentient.models import SentientDecision, Verdict


class ExecutionStatus(str, Enum):
    EXECUTED = "EXECUTED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class BreachStatus(str, Enum):
    BREACH = "BREACH"
    SECURE = "SECURE"
    ANOMALY = "ANOMALY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ExecutionOrder:
    """
    Immutable envelope that authorizes a test.
    """
    test_case: LogicTestCase
    decision: SentientDecision
    idempotency_token: str

    # Identity context (Doppelganger)
    auth_headers: Optional[Dict[str, str]] = None
    auth_cookies: Optional[Dict[str, str]] = None

    # Useful for 401 heal / re-login without guessing
    target_base_url: Optional[str] = None

    created_at: float = field(default_factory=lambda: datetime.now().timestamp())

    def __post_init__(self) -> None:
        if self.decision.verdict != Verdict.APPROVE:
            raise ValueError(
                f"Cannot create ExecutionOrder with Verdict {self.decision.verdict}. Must be APPROVE."
            )


@dataclass(frozen=True)
class ExecutionResult:
    """
    The outcome of an execution.
    """
    order_id: str
    status: ExecutionStatus
    signals: Dict[str, Any]
    duration_ms: float
    metrics: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    error_message: Optional[str] = None
