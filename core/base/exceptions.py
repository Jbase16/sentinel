from typing import Any, List, Optional

class SentinelError(Exception):
    """Base exception for all SentinelForge errors."""

class ScopePolicyViolationError(SentinelError):
    """Raised when a request violates the defined Scope Domain Model."""
    def __init__(self, message: str, decision: Any = None):
        super().__init__(message)
        self.decision = decision

class ExecutionPolicyViolationError(SentinelError):
    """Raised when a request violates the Execution Policy (methods, headers, rate, destructiveness)."""
    def __init__(self, message: str, violations: Optional[List[str]] = None):
        super().__init__(message)
        self.violations = violations or []
