"""
core/scope/models.py
Data models for scope policy.

ScopeRule    — A single in-scope or out-of-scope rule entry.
ScopePolicy  — The full policy (list of rules + metadata).
ScopeViolation — Carries detail about why a URL was rejected.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from urllib.parse import urlparse


class ScopeRuleKind(str, Enum):
    WILDCARD_DOMAIN = "wildcard_domain"   # *.example.com
    EXACT_DOMAIN    = "exact_domain"      # api.example.com
    DOMAIN_PREFIX   = "domain_prefix"     # api.example.com/v2/...
    CIDR            = "cidr"              # 10.0.0.0/24
    EXACT_IP        = "exact_ip"          # 192.168.1.5
    REGEX           = "regex"             # /^.*\.example\.com$/


@dataclass
class ScopeRule:
    """One rule entry in the scope policy."""

    raw: str                       # Original string as entered by user
    kind: ScopeRuleKind
    is_exclusion: bool = False     # True if prefixed with "!" (out-of-scope)

    # Pre-parsed internals (set by ScopePolicy.from_lines)
    _hostname: str = field(default="", repr=False)
    _path_prefix: str = field(default="", repr=False)
    _wildcard_base: str = field(default="", repr=False)   # for *.example.com → "example.com"
    _cidr_network: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default=None, repr=False
    )
    _regex: Optional[re.Pattern] = field(default=None, repr=False)

    def matches_host(self, host: str, path: str = "") -> bool:
        """Return True if host (+optional path) satisfies this rule."""
        host = host.lower().rstrip(".")

        if self.kind == ScopeRuleKind.WILDCARD_DOMAIN:
            # *.example.com matches foo.example.com and bar.baz.example.com
            # but NOT example.com itself (use EXACT_DOMAIN for that)
            base = self._wildcard_base.lower()
            return host == base or host.endswith("." + base)

        if self.kind == ScopeRuleKind.EXACT_DOMAIN:
            return host == self._hostname.lower()

        if self.kind == ScopeRuleKind.DOMAIN_PREFIX:
            if host != self._hostname.lower():
                return False
            # Path must start with the specified prefix
            norm_path = ("/" + path.lstrip("/")) if path else "/"
            prefix = self._path_prefix or "/"
            return norm_path.startswith(prefix)

        if self.kind in (ScopeRuleKind.EXACT_IP, ScopeRuleKind.CIDR):
            # Resolve the host to an IP for comparison
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                # host is a name, not an IP; can't match an IP rule
                return False
            if self.kind == ScopeRuleKind.EXACT_IP:
                return addr == ipaddress.ip_address(self._hostname)
            # CIDR
            return addr in self._cidr_network  # type: ignore[operator]

        if self.kind == ScopeRuleKind.REGEX:
            return bool(self._regex and self._regex.search(host))

        return False


@dataclass
class ScopePolicy:
    """
    Ordered list of scope rules.

    Evaluation is ordered: the first matching rule wins.
    Exclusion rules (prefixed with !) shadow inclusion rules — place them first
    or rely on the fact that exclusions are checked before inclusions in
    ScopeEnforcer.is_in_scope().

    If no rules are defined (empty policy), everything is considered in-scope
    (permissive default — suitable for non-bounty scans where scope isn't set).
    """

    rules: List[ScopeRule] = field(default_factory=list)
    label: str = ""           # Optional human-readable label (program name)
    strict: bool = False      # If True, unknown/unmatched URLs are rejected

    # ---------- Factory ----------

    @classmethod
    def from_lines(cls, lines: List[str], label: str = "", strict: bool = False) -> "ScopePolicy":
        """
        Parse a list of scope strings into a ScopePolicy.

        Supported formats:
            *.example.com            — wildcard domain
            example.com              — exact domain
            example.com/api/v2       — domain + path prefix
            !staging.example.com     — explicit exclusion (prefix with !)
            192.168.1.0/24           — CIDR block
            192.168.1.5              — exact IP
            /regex/                  — regex (surrounded by slashes)

        Lines starting with # are comments. Empty lines are ignored.
        """
        rules: List[ScopeRule] = []
        for raw in lines:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            rule = cls._parse_line(raw)
            if rule:
                rules.append(rule)
        return cls(rules=rules, label=label, strict=strict)

    @classmethod
    def _parse_line(cls, raw: str) -> Optional[ScopeRule]:
        """Parse one line into a ScopeRule. Returns None on parse failure."""
        is_exclusion = raw.startswith("!")
        token = raw[1:].strip() if is_exclusion else raw

        # Regex rule: /pattern/
        if token.startswith("/") and token.endswith("/") and len(token) > 2:
            pattern = token[1:-1]
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error:
                return None
            rule = ScopeRule(raw=raw, kind=ScopeRuleKind.REGEX, is_exclusion=is_exclusion)
            rule._regex = compiled
            return rule

        # CIDR block: e.g. 10.0.0.0/24
        if "/" in token and not token.startswith("*."):
            # Could be CIDR or domain+path — disambiguate
            maybe_cidr, _, _ = token.partition("/")
            try:
                net = ipaddress.ip_network(token, strict=False)
                rule = ScopeRule(raw=raw, kind=ScopeRuleKind.CIDR, is_exclusion=is_exclusion)
                rule._cidr_network = net
                return rule
            except ValueError:
                pass  # Not a CIDR, fall through to domain+path

        # Wildcard domain: *.example.com
        if token.startswith("*."):
            base = token[2:]
            rule = ScopeRule(raw=raw, kind=ScopeRuleKind.WILDCARD_DOMAIN, is_exclusion=is_exclusion)
            rule._wildcard_base = base.lower()
            return rule

        # Exact IP: 192.168.1.5
        try:
            ipaddress.ip_address(token)
            rule = ScopeRule(raw=raw, kind=ScopeRuleKind.EXACT_IP, is_exclusion=is_exclusion)
            rule._hostname = token
            return rule
        except ValueError:
            pass

        # Domain + optional path prefix: example.com  OR  example.com/api/v2
        # Strip scheme if user accidentally included it
        stripped = re.sub(r"^https?://", "", token)
        if "/" in stripped:
            hostname, _, path_prefix = stripped.partition("/")
            rule = ScopeRule(raw=raw, kind=ScopeRuleKind.DOMAIN_PREFIX, is_exclusion=is_exclusion)
            rule._hostname = hostname.lower()
            rule._path_prefix = "/" + path_prefix.lstrip("/")
            return rule
        else:
            hostname = stripped
            rule = ScopeRule(raw=raw, kind=ScopeRuleKind.EXACT_DOMAIN, is_exclusion=is_exclusion)
            rule._hostname = hostname.lower()
            return rule

    # ---------- Helpers ----------

    @property
    def is_empty(self) -> bool:
        return len(self.rules) == 0

    def inclusion_rules(self) -> List[ScopeRule]:
        return [r for r in self.rules if not r.is_exclusion]

    def exclusion_rules(self) -> List[ScopeRule]:
        return [r for r in self.rules if r.is_exclusion]

    def summary(self) -> str:
        inc = len(self.inclusion_rules())
        exc = len(self.exclusion_rules())
        return f"ScopePolicy(label={self.label!r}, {inc} inclusions, {exc} exclusions, strict={self.strict})"


@dataclass
class ScopeViolation:
    """Describes why a URL was rejected by the scope enforcer."""

    url: str
    host: str
    path: str
    reason: str                         # Human-readable explanation
    matched_exclusion: Optional[str] = None   # The exclusion rule that matched
    unmatched: bool = False             # True if strict mode + no rule matched

    def __str__(self) -> str:
        return f"OutOfScope: {self.url!r} — {self.reason}"
