"""
core/scope
Scope enforcement for bug bounty safety.

Usage:
    from core.scope import ScopeEnforcer, ScopePolicy, OutOfScopeError

    policy = ScopePolicy.from_lines([
        "*.example.com",
        "api.other.com/v2",
        "!staging.example.com",  # explicit exclusion
        "10.0.0.0/24",
    ])
    enforcer = ScopeEnforcer(policy)
    enforcer.assert_in_scope("https://app.example.com/login")  # OK
    enforcer.assert_in_scope("https://evil.com")               # raises OutOfScopeError
"""

from core.scope.models import ScopeRule, ScopePolicy, ScopeViolation, ScopeRuleKind
from core.scope.enforcer import ScopeEnforcer, OutOfScopeError

__all__ = [
    "ScopeEnforcer",
    "OutOfScopeError",
    "ScopePolicy",
    "ScopeRule",
    "ScopeViolation",
    "ScopeRuleKind",
]
