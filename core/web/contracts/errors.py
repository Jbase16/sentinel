from __future__ import annotations


class WebEngineError(Exception):
    """Base exception for web exploitation engine."""


class PolicyViolation(WebEngineError):
    """Raised when an action would violate ExecutionPolicy or Scope."""


class ScopeViolation(PolicyViolation):
    """Raised when a URL/navigation is out of scope."""


class BudgetExceeded(PolicyViolation):
    """Raised when mission ceilings are exceeded."""


class ContractViolation(WebEngineError):
    """Raised when an internal component violates a data contract or invariant."""
