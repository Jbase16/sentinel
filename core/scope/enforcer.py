"""
core/scope/enforcer.py
ScopeEnforcer — runtime gate for all outbound URLs.

Design:
  - Instantiated once per scan session with a ScopePolicy.
  - Called at every point a URL leaves the system (tool dispatch, HTTP probes,
    WAF bypass retries, OOB payloads, redirect follows).
  - Thread-safe; all state is read-only after construction.

Evaluation order (first match wins):
  1. Exclusion rules  (!staging.example.com)  → reject
  2. Inclusion rules  (*.example.com)          → allow
  3. Strict mode: no match                     → reject
  4. Permissive mode (default): no match       → allow

Edge cases handled:
  - Redirects that change the host
  - Ports (example.com:8080 treated as example.com for domain rules)
  - Subdomains discovered during scan (api.example.com)
  - IPv4/IPv6 literals in URLs
  - Path-scoped rules (example.com/api only)
  - Missing scheme (treated as https)
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from core.scope.models import ScopePolicy, ScopeRule, ScopeViolation

logger = logging.getLogger(__name__)


class OutOfScopeError(Exception):
    """Raised when a URL violates the scope policy."""

    def __init__(self, violation: ScopeViolation):
        self.violation = violation
        super().__init__(str(violation))


class ScopeEnforcer:
    """
    Enforces a ScopePolicy against URLs at runtime.

    Thread-safe after construction (all internal state is immutable).

    Example:
        policy = ScopePolicy.from_lines([
            "*.example.com",
            "!staging.example.com",
            "10.0.0.0/8",
        ], strict=True)
        enforcer = ScopeEnforcer(policy)

        enforcer.is_in_scope("https://app.example.com/login")  # True
        enforcer.is_in_scope("https://staging.example.com")    # False (excluded)
        enforcer.is_in_scope("https://evil.com")               # False (strict)
        enforcer.assert_in_scope("https://evil.com")           # raises OutOfScopeError
    """

    def __init__(self, policy: ScopePolicy):
        self._policy = policy
        self._exclusions: List[ScopeRule] = policy.exclusion_rules()
        self._inclusions: List[ScopeRule] = policy.inclusion_rules()
        logger.debug("[ScopeEnforcer] Loaded %s", policy.summary())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def permissive(cls) -> "ScopeEnforcer":
        """Return a no-op enforcer that allows everything (for non-bounty scans)."""
        return cls(ScopePolicy(rules=[], strict=False))

    @classmethod
    def from_lines(
        cls,
        lines: List[str],
        *,
        label: str = "",
        strict: bool = False,
    ) -> "ScopeEnforcer":
        """Convenience constructor — parse lines directly into an enforcer."""
        policy = ScopePolicy.from_lines(lines, label=label, strict=strict)
        return cls(policy)

    def is_in_scope(self, url: str) -> bool:
        """
        Return True if the URL is within scope, False otherwise.

        Never raises; suitable for conditional checks.
        """
        _, violation = self._evaluate(url)
        return violation is None

    def assert_in_scope(self, url: str) -> None:
        """
        Raise OutOfScopeError if the URL is out of scope.

        Call this at every point a URL leaves the system.
        """
        _, violation = self._evaluate(url)
        if violation is not None:
            logger.warning("[ScopeEnforcer] BLOCKED %s — %s", url, violation.reason)
            raise OutOfScopeError(violation)

    def check(self, url: str) -> Tuple[bool, Optional[ScopeViolation]]:
        """
        Return (in_scope, violation_or_None).

        Use this when you need both the boolean and the reason.
        """
        return self._evaluate(url)

    def filter_urls(self, urls: List[str]) -> Tuple[List[str], List[ScopeViolation]]:
        """
        Split a list of URLs into (in_scope, violations).

        Useful for batch-filtering discovered subdomains or redirect chains.
        """
        ok: List[str] = []
        bad: List[ScopeViolation] = []
        for u in urls:
            in_scope, violation = self._evaluate(u)
            if in_scope:
                ok.append(u)
            else:
                bad.append(violation)  # type: ignore[arg-type]
        return ok, bad

    @property
    def policy(self) -> ScopePolicy:
        return self._policy

    @property
    def is_permissive(self) -> bool:
        """True if the policy has no rules (allow-all)."""
        return self._policy.is_empty

    def describe(self) -> str:
        """Human-readable description of the active policy."""
        if self.is_permissive:
            return "ScopeEnforcer: permissive (no rules, all targets allowed)"
        return f"ScopeEnforcer: {self._policy.summary()}"

    # ------------------------------------------------------------------
    # Internal evaluation
    # ------------------------------------------------------------------

    def _evaluate(self, url: str) -> Tuple[bool, Optional[ScopeViolation]]:
        """Core evaluation logic. Returns (in_scope, violation_or_None)."""
        # Empty policy: allow everything
        if self._policy.is_empty:
            return True, None

        host, path = self._parse_url(url)
        if not host:
            violation = ScopeViolation(
                url=url, host="", path="",
                reason="Could not parse host from URL",
            )
            return False, violation

        # Step 1: Check exclusions first (they always win)
        for rule in self._exclusions:
            if rule.matches_host(host, path):
                violation = ScopeViolation(
                    url=url, host=host, path=path,
                    reason=f"Matched exclusion rule: {rule.raw!r}",
                    matched_exclusion=rule.raw,
                )
                return False, violation

        # Step 2: Check inclusions
        for rule in self._inclusions:
            if rule.matches_host(host, path):
                return True, None  # Explicitly in scope

        # Step 3: No inclusion rule matched.
        # If there are any inclusion rules defined, failing to match any of them
        # means the URL is out of scope — regardless of strict mode.
        # Strict mode only affects the case where the policy has NO inclusions at all.
        if self._inclusions:
            violation = ScopeViolation(
                url=url, host=host, path=path,
                reason="No inclusion rule matched",
                unmatched=True,
            )
            return False, violation

        # No inclusion rules defined + no exclusion matched → strict controls
        if self._policy.strict:
            violation = ScopeViolation(
                url=url, host=host, path=path,
                reason="No inclusion rule matched (strict mode)",
                unmatched=True,
            )
            return False, violation

        # Exclusion-only policy in permissive mode: not explicitly excluded → allow
        return True, None

    @staticmethod
    def _parse_url(url: str) -> Tuple[str, str]:
        """
        Extract (hostname_without_port, path) from a URL.

        Returns ("", "") if unparseable.
        """
        # Add a scheme if missing so urlparse works correctly
        if "://" not in url:
            url = "https://" + url
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            path = parsed.path or "/"
            return host, path
        except Exception:
            return "", ""
