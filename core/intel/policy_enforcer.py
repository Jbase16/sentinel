"""
policy_enforcer — translate restrictions.json into runtime config.

The policy_gate compiler (Phase 2C) emits a restrictions.json file
that describes WHAT to enforce (kind + enforcement strategy). This
module reads that file and produces a ``PolicyEnforcement`` config
describing HOW: concrete tool names to disable, the max capability
tier allowed, the rate-limit value, etc.

Separation of concerns:

    restrictions.json     —  "WHAT: no DoS, no bruteforce, max 5 rps"
    PolicyEnforcement     —  "HOW: disable [nuclei_mutating, gobuster,
                              feroxbuster], cap tier T2a_SAFE_VERIFY,
                              set rate_limit_rps=5.0"
    Strategos / engine    —  consumes PolicyEnforcement via existing
                              parameters (disabled tools, tier gate, etc.)

That intent vs implementation split means a tool rename or category
expansion only changes this module, not every cached restrictions.json
on disk.

This module also surfaces:

  - ``required_attestations``: list of attestation prompts the operator
    must acknowledge before scan-time (REQUIRES_PRIOR_APPROVAL maps here).
  - ``scan_blocked``: True if a hard restriction makes the scan refuse
    to run at all (NO_AUTOMATED_SCAN hard).
  - ``warnings``: human-readable messages the CLI surfaces to the operator.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.intel.compilers.policy_gate import SCHEMA_VERSION as _CURRENT_SCHEMA

logger = logging.getLogger(__name__)


# Category → tool-name mapping. Lives here (in code, not the schema)
# so a tool rename only touches this file. Categories are stable; tool
# names are not.
_CATEGORY_TO_TOOLS: Dict[str, List[str]] = {
    # DoS — exclude high-volume / mutating tools. nuclei_safe is
    # info-only and stays allowed; nuclei_mutating and unprofiled
    # nuclei runs can include DoS templates so they're gated.
    "dos": ["nuclei_mutating", "nuclei"],
    "stress-test": ["nuclei_mutating", "nuclei"],
    "volumetric": ["nuclei_mutating", "nuclei", "masscan"],
    # Bruteforce — directory and path-enumeration tools.
    "bruteforce": ["gobuster", "feroxbuster", "nikto"],
    # Social engineering — Sentinel ships no SE tools today; empty
    # list keeps the entry future-compatible.
    "social-engineering": [],
    "phishing": [],
}

# Max-tier strings map to ordinal positions so we can do "less than or
# equal to" comparisons. These mirror ``CapabilityTier`` in
# ``core/cortex/capability_tiers.py``.
_TIER_ORDER: Dict[str, int] = {
    "T0_OBSERVE": 0,
    "T1_PROBE": 1,
    "T2a_SAFE_VERIFY": 2,
    "T2b_MUTATING_VERIFY": 3,
    "T3_EXPLOIT": 4,
    "T4_DESTRUCTIVE": 5,
}


@dataclass
class PolicyEnforcement:
    """Runtime-applicable enforcement config derived from restrictions.json.

    All fields use sensible defaults — an empty enforcement config means
    "no restrictions; scan freely." The fields are designed to map
    directly onto Strategos's existing parameters or the scan request:

      disabled_tools           → ExecutionPolicy.banned_tools
      max_capability_tier      → CapabilityGate ceiling
      rate_limit_rps           → ExecutionPolicy.max_rps_per_host
      scan_blocked             → scan request rejected before start
      scope_strict             → ScopeContext.scope_strict
      required_attestations    → operator must confirm each
      warnings                 → surfaced to operator at scan start
    """
    disabled_tools: Set[str] = field(default_factory=set)
    max_capability_tier: Optional[str] = None
    rate_limit_rps: Optional[float] = None
    scan_blocked: bool = False
    scan_blocked_reason: Optional[str] = None
    scope_strict: bool = False
    required_attestations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """True if no enforcement actions are required at all."""
        return not (
            self.disabled_tools
            or self.max_capability_tier
            or self.rate_limit_rps is not None
            or self.scan_blocked
            or self.scope_strict
            or self.required_attestations
            or self.warnings
        )

    def apply_to_execution_policy(self, policy) -> None:
        """Mutate an ``ExecutionPolicy`` in-place so its parameters reflect
        the enforcement state.

        This is the bridge from Phase 2 intent ("respect policy X") to
        scan-time enforcement (Strategos / ScopeContext / tool registry).
        Each field maps:

          disabled_tools  → policy.banned_tools (union with existing)
          rate_limit_rps  → policy.max_rps_per_host (lowest wins)

        ``scope_strict``, ``scan_blocked``, ``required_attestations``,
        and ``max_capability_tier`` are NOT applied here — they require
        action at a different layer of the engine (ScopeContext, scan-
        gate, CLI prompt, CapabilityGate respectively) and are inspected
        directly by their consumers.

        The signature accepts ``Any`` so this module doesn't have to
        import ``ExecutionPolicy`` (which would create a circular
        dependency with core.base). Duck-typed contract: ``policy``
        must have attributes ``banned_tools`` (optional Set[str]) and
        ``max_rps_per_host`` (int).
        """
        # Banned tools: union the enforcement's disabled set with any
        # tools already banned on the policy. Both reflect "do not run."
        if self.disabled_tools:
            existing = policy.banned_tools or set()
            policy.banned_tools = set(existing) | self.disabled_tools

        # Rate limit: take the more-restrictive (smaller) value if the
        # policy already has one set. Restrictions tighten policy; they
        # never loosen it.
        if self.rate_limit_rps is not None and self.rate_limit_rps > 0:
            limit_int = max(1, int(self.rate_limit_rps))
            current = getattr(policy, "max_rps_per_host", None)
            if current is None or limit_int < current:
                policy.max_rps_per_host = limit_int


def enforce(restrictions_data: Dict[str, Any]) -> PolicyEnforcement:
    """Translate a restrictions.json dict into a ``PolicyEnforcement`` config.

    The input ``restrictions_data`` is the parsed dict from
    ``policy_gate.compile_restrictions_json``. Returns the enforcement
    config; callers apply it to their scan-startup logic.

    Schema-mismatched input (wrong version, missing fields) emits
    warnings but doesn't raise — better to enforce what we can than
    refuse to scan because of a config-format drift.
    """
    result = PolicyEnforcement()

    schema_version = restrictions_data.get("schema_version", "")
    if schema_version != _CURRENT_SCHEMA:
        result.warnings.append(
            f"Restrictions schema_version mismatch: file has {schema_version!r}, "
            f"enforcer expects {_CURRENT_SCHEMA!r}. Enforcement may be incomplete."
        )

    restrictions = restrictions_data.get("restrictions", [])
    if not isinstance(restrictions, list):
        result.warnings.append(
            "restrictions field is not a list — skipping all restrictions."
        )
        return result

    for r in restrictions:
        if not isinstance(r, dict):
            result.warnings.append(f"Skipping malformed restriction: {r!r}")
            continue
        _apply_restriction(r, result)

    return result


def enforce_from_file(path: str | Path) -> PolicyEnforcement:
    """Convenience: read restrictions.json from disk and enforce.

    Returns an empty ``PolicyEnforcement`` (with a warning) if the file
    is missing or unparseable — same "fail open with surface" philosophy
    as ``enforce`` itself.
    """
    p = Path(path)
    if not p.exists():
        result = PolicyEnforcement()
        result.warnings.append(f"Restrictions file not found: {path}")
        return result

    try:
        data = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError) as e:
        result = PolicyEnforcement()
        result.warnings.append(f"Could not parse restrictions file {path}: {e}")
        return result

    return enforce(data)


# ─────────────────────────── Per-strategy handlers ─────────────────

# Maps an applies_to scope label to the tool categories it governs. Used
# when a block_scan rule is scoped to something narrower than "all" — we
# downgrade it from "block the whole scan" to "disable these categories".
_SCOPE_TO_TOOL_CATEGORIES: Dict[str, List[str]] = {
    "dos": ["dos", "stress-test", "volumetric"],
    "bruteforce": ["bruteforce"],
    "social_eng": ["social-engineering", "phishing"],
    "social-engineering": ["social-engineering", "phishing"],
}


def _apply_restriction(r: Dict[str, Any], result: PolicyEnforcement) -> None:
    """Dispatch a single restriction by its ``enforcement`` strategy."""
    strategy = r.get("enforcement", "warn")
    severity = r.get("severity", "soft")
    description = r.get("description", "")
    kind = r.get("kind", "unknown")
    args = r.get("enforcement_args", {}) or {}
    # applies_to defaults to ["all"] for any pre-1.1 restriction lacking it.
    applies_to = r.get("applies_to") or ["all"]

    if strategy == "disable_tool_categories":
        _apply_disable_categories(args, severity, result, kind=kind, description=description)
    elif strategy == "cap_capability_tier":
        _apply_cap_tier(args, severity, result, kind=kind, description=description)
    elif strategy == "set_rate_limit":
        _apply_rate_limit(args, severity, result, kind=kind, description=description)
    elif strategy == "block_scan":
        _apply_block_scan(severity, result, kind=kind, description=description,
                          applies_to=applies_to)
    elif strategy == "enforce_strict_scope":
        _apply_strict_scope(severity, result, kind=kind, description=description)
    elif strategy == "require_attestation":
        _apply_require_attestation(severity, result, kind=kind, description=description)
    elif strategy == "warn":
        result.warnings.append(f"[{kind}] {description}")
    else:
        # Unknown strategy — surface as a warning so the operator knows
        # something in the restrictions file wasn't enforced.
        result.warnings.append(
            f"Unknown enforcement strategy {strategy!r} for kind={kind!r}. "
            "This restriction was NOT enforced."
        )


def _apply_disable_categories(
    args: Dict[str, Any], severity: str, result: PolicyEnforcement,
    *, kind: str, description: str,
) -> None:
    """Add each category's tools to result.disabled_tools.

    Hard restrictions disable the tools outright; soft restrictions
    surface a warning + still disable (the operator opted into the
    program knowing the restriction was there)."""
    categories = args.get("categories", [])
    if not isinstance(categories, list):
        result.warnings.append(
            f"[{kind}] expected categories list, got {type(categories).__name__}"
        )
        return

    added: Set[str] = set()
    unknown: List[str] = []
    for category in categories:
        tools = _CATEGORY_TO_TOOLS.get(category)
        if tools is None:
            unknown.append(category)
            continue
        added.update(tools)

    if added:
        result.disabled_tools.update(added)
        if severity == "soft":
            result.warnings.append(
                f"[{kind}] disabled tools (soft restriction): {sorted(added)}"
            )

    if unknown:
        result.warnings.append(
            f"[{kind}] unknown tool categories (not enforced): {unknown}"
        )


def _apply_cap_tier(
    args: Dict[str, Any], severity: str, result: PolicyEnforcement,
    *, kind: str, description: str,
) -> None:
    """Set the capability-tier ceiling. Takes the *lowest* (most
    restrictive) cap if multiple restrictions cap the tier."""
    requested = args.get("max_tier")
    if not requested or requested not in _TIER_ORDER:
        result.warnings.append(
            f"[{kind}] invalid max_tier={requested!r}; expected one of {list(_TIER_ORDER)}"
        )
        return

    if result.max_capability_tier is None:
        result.max_capability_tier = requested
    else:
        # Multiple restrictions cap the tier — keep the most restrictive
        # (lowest ordinal). E.g. one restriction caps at T3_EXPLOIT,
        # another at T2a_SAFE_VERIFY → final cap is T2a_SAFE_VERIFY.
        if _TIER_ORDER[requested] < _TIER_ORDER[result.max_capability_tier]:
            result.max_capability_tier = requested


def _apply_rate_limit(
    args: Dict[str, Any], severity: str, result: PolicyEnforcement,
    *, kind: str, description: str,
) -> None:
    """Set the rate limit. Takes the lowest rps if multiple restrictions
    set one (most restrictive wins)."""
    rps = args.get("rps")
    if not isinstance(rps, (int, float)) or rps <= 0:
        result.warnings.append(
            f"[{kind}] invalid rate-limit rps={rps!r}; must be positive number"
        )
        return

    if result.rate_limit_rps is None:
        result.rate_limit_rps = float(rps)
    else:
        result.rate_limit_rps = min(result.rate_limit_rps, float(rps))


def _apply_block_scan(
    severity: str, result: PolicyEnforcement,
    *, kind: str, description: str, applies_to: List[str],
) -> None:
    """Mark the scan as blocked — but ONLY when the rule is globally scoped.

    This is the Calibration Run #17 fix. A ``block_scan`` rule should
    halt the entire scan only when ``applies_to`` includes ``"all"`` —
    i.e. the program forbids automated testing program-wide. When the
    rule is scoped to a specific testing category (e.g. ``["dos"]`` — "no
    automated tools" appearing in a DoS-testing section), we downgrade
    it: disable that category's tools and let the rest of the scan run.

    Soft severity always just warns, regardless of scope.
    """
    scopes = [s.strip().lower() for s in (applies_to or ["all"])]

    if severity != "hard":
        result.warnings.append(
            f"[{kind}] soft restriction (not blocking): {description}"
        )
        return

    if "all" in scopes:
        # Genuine program-wide ban — halt the scan.
        result.scan_blocked = True
        result.scan_blocked_reason = description or kind
        return

    # Scoped block — downgrade to disabling the named categories' tools.
    downgraded: Set[str] = set()
    unmapped: List[str] = []
    for scope in scopes:
        categories = _SCOPE_TO_TOOL_CATEGORIES.get(scope)
        if categories is None:
            unmapped.append(scope)
            continue
        for category in categories:
            tools = _CATEGORY_TO_TOOLS.get(category, [])
            downgraded.update(tools)

    if downgraded:
        result.disabled_tools.update(downgraded)
    result.warnings.append(
        f"[{kind}] scoped to {scopes} (not program-wide) — downgraded from "
        f"scan-block to disabling tools {sorted(downgraded) or '[none mapped]'}. "
        f"{description}"
    )
    if unmapped:
        result.warnings.append(
            f"[{kind}] could not map applies_to scopes {unmapped} to tool "
            f"categories — those aspects are NOT enforced."
        )


def _apply_strict_scope(
    severity: str, result: PolicyEnforcement,
    *, kind: str, description: str,
) -> None:
    """Set scope_strict=True. Even soft restrictions enable this — the
    cost (denying ambiguous targets) is low; the benefit (no accidental
    out-of-scope hits) is high."""
    result.scope_strict = True
    if severity == "soft":
        result.warnings.append(
            f"[{kind}] enabled scope_strict (soft restriction): {description}"
        )


def _apply_require_attestation(
    severity: str, result: PolicyEnforcement,
    *, kind: str, description: str,
) -> None:
    """Queue an operator attestation prompt."""
    result.required_attestations.append(
        f"[{kind}] {description} — confirm you have done this before scanning."
    )
