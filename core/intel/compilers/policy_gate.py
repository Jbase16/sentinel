"""
policy_gate — emit Sentinel's restrictions config from a ProgramScope.

Restrictions are *operational* constraints (rate limit, no DoS, no
bruteforce) that Strategos must enforce at scan-time. They live in a
separate file from the scope rules because they're a different kind of
config: scope answers "which targets," restrictions answer "what
techniques."

Output format (new in Phase 2C — there's no existing format):

  {
    "schema_version": "sentinelforge-restrictions-v1",
    "program": {
      "handle": "gitlab",
      "platform": "hackerone",
      "name": "GitLab"
    },
    "rate_limit_rps": 5.0,
    "restrictions": [
      {
        "kind": "no_dos",
        "severity": "hard",
        "description": "No DoS or load testing.",
        "raw_quote": "DoS is strictly prohibited.",
        "enforcement": "disable_tool_categories",
        "enforcement_args": {
          "categories": ["dos", "stress-test", "volumetric"]
        }
      },
      {
        "kind": "rate_limited",
        "severity": "soft",
        "description": "Rate-limit to 5 rps.",
        "enforcement": "set_rate_limit",
        "enforcement_args": {"rps": 5.0}
      }
    ]
  }

Phase 2E wires Strategos to read this file and apply each restriction's
``enforcement`` strategy. For Phase 2C we just produce the file — the
enforcement logic comes later.

Enforcement strategy reference:

  +------------------------+--------------------------------------------+
  | RestrictionKind        | Enforcement strategy                       |
  +========================+============================================+
  | NO_DOS                 | disable_tool_categories                    |
  |                        |   args: {categories: [dos, stress-test]}   |
  +------------------------+--------------------------------------------+
  | NO_AUTOMATED_SCAN      | block_scan (if hard) or warn (if soft)     |
  +------------------------+--------------------------------------------+
  | NO_BRUTEFORCE          | disable_tool_categories                    |
  |                        |   args: {categories: [bruteforce]}         |
  +------------------------+--------------------------------------------+
  | NO_DATA_DESTRUCTION    | cap_capability_tier                        |
  |                        |   args: {max_tier: "T2a_SAFE_VERIFY"}      |
  +------------------------+--------------------------------------------+
  | NO_SOCIAL_ENG          | disable_tool_categories                    |
  |                        |   args: {categories: [social-engineering]} |
  +------------------------+--------------------------------------------+
  | NO_THIRD_PARTY         | enforce_strict_scope                       |
  +------------------------+--------------------------------------------+
  | RATE_LIMITED           | set_rate_limit                             |
  |                        |   args: {rps: <rate_limit_rps>}            |
  +------------------------+--------------------------------------------+
  | BUSINESS_HOURS_ONLY    | warn  (we don't enforce time-of-day)       |
  +------------------------+--------------------------------------------+
  | REGION_RESTRICTED      | warn  (we don't enforce geo)               |
  +------------------------+--------------------------------------------+
  | REQUIRES_PRIOR_APPROVAL| require_attestation                        |
  +------------------------+--------------------------------------------+
  | OTHER                  | warn                                       |
  +------------------------+--------------------------------------------+

Hard restrictions are enforced; soft restrictions are surfaced as
warnings to the operator and otherwise pass through.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from core.intel.program_scope import (
    ProgramScope,
    Restriction,
    RestrictionKind,
)

SCHEMA_VERSION = "sentinelforge-restrictions-v1"


# Enforcement strategy mapping. The values here are the literal strings
# Strategos's enforcement layer (Phase 2E) reads. Changing one of these
# is a schema break — bump SCHEMA_VERSION above if you do.
_ENFORCEMENT_STRATEGY: Dict[RestrictionKind, str] = {
    RestrictionKind.NO_DOS: "disable_tool_categories",
    RestrictionKind.NO_AUTOMATED_SCAN: "block_scan",
    RestrictionKind.NO_BRUTEFORCE: "disable_tool_categories",
    RestrictionKind.NO_DATA_DESTRUCTION: "cap_capability_tier",
    RestrictionKind.NO_SOCIAL_ENG: "disable_tool_categories",
    RestrictionKind.NO_THIRD_PARTY: "enforce_strict_scope",
    RestrictionKind.RATE_LIMITED: "set_rate_limit",
    RestrictionKind.BUSINESS_HOURS_ONLY: "warn",
    RestrictionKind.REGION_RESTRICTED: "warn",
    RestrictionKind.REQUIRES_PRIOR_APPROVAL: "require_attestation",
    RestrictionKind.OTHER: "warn",
}


def compile_restrictions_json(scope: ProgramScope, *, indent: int = 2) -> str:
    """Render ``ProgramScope.restrictions`` (plus rate-limit) as JSON.

    Returns a JSON document, trailing-newline-terminated. The caller is
    responsible for writing it to ``<program>-restrictions.json``.

    Schema version: see ``SCHEMA_VERSION`` module constant. Bumped if
    the document shape or any enforcement strategy name changes.
    """
    rendered: List[Dict[str, Any]] = []
    for r in scope.restrictions:
        rendered.append(_render_restriction(r))

    # Auto-emit a RATE_LIMITED restriction if scope.rate_limit_rps was
    # extracted but no explicit RATE_LIMITED restriction is in the list.
    # This handles the common case where the LLM caught "rate limit 5 rps"
    # as a structured field but missed cataloging it under restrictions.
    if scope.rate_limit_rps is not None and not any(
        r["kind"] == RestrictionKind.RATE_LIMITED.value for r in rendered
    ):
        rendered.append(_synthesize_rate_limit_restriction(scope.rate_limit_rps))

    payload = {
        "schema_version": SCHEMA_VERSION,
        "program": {
            "handle": scope.handle,
            "platform": scope.platform.value,
            "name": scope.name,
        },
        "rate_limit_rps": scope.rate_limit_rps,
        "restrictions": rendered,
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False) + "\n"


# ─────────────────────────── Internals ─────────────────────────────

def _render_restriction(r: Restriction) -> Dict[str, Any]:
    """Render one ``Restriction`` to its JSON shape, including the
    enforcement strategy lookup."""
    strategy = _ENFORCEMENT_STRATEGY.get(r.kind, "warn")
    enforcement_args = _enforcement_args_for(r)

    out: Dict[str, Any] = {
        "kind": r.kind.value,
        "severity": r.severity,
        "description": r.description,
        "enforcement": strategy,
        # applies_to is the rule's scope — the policy_enforcer reads it to
        # decide whether a block_scan rule actually blocks (only when
        # "all" is present) or just disables its specific categories.
        "applies_to": list(r.applies_to) if r.applies_to else ["all"],
    }
    if enforcement_args:
        out["enforcement_args"] = enforcement_args
    if r.raw_quote:
        out["raw_quote"] = r.raw_quote
    return out


def _enforcement_args_for(r: Restriction) -> Dict[str, Any]:
    """Build the per-strategy args. Each enforcement strategy has its own
    expected args shape — kept centralized here for easy review."""
    if r.kind == RestrictionKind.NO_DOS:
        return {"categories": ["dos", "stress-test", "volumetric"]}
    if r.kind == RestrictionKind.NO_BRUTEFORCE:
        return {"categories": ["bruteforce"]}
    if r.kind == RestrictionKind.NO_SOCIAL_ENG:
        return {"categories": ["social-engineering", "phishing"]}
    if r.kind == RestrictionKind.NO_DATA_DESTRUCTION:
        # Cap at SAFE_VERIFY — no mutating actions, no exploit attempts.
        return {"max_tier": "T2a_SAFE_VERIFY"}
    # All other strategies either take no args (warn, block_scan,
    # enforce_strict_scope, require_attestation) or get their args at
    # the top level (RATE_LIMITED gets rps from scope.rate_limit_rps).
    return {}


def _synthesize_rate_limit_restriction(rps: float) -> Dict[str, Any]:
    """Build a RATE_LIMITED restriction entry from a top-level rps value.

    Used when ``scope.rate_limit_rps`` is set but no explicit
    ``Restriction`` of kind RATE_LIMITED exists — common when the LLM
    extracted the rate limit as a structured field via the
    ``rate_limit_rps`` slot.
    """
    return {
        "kind": RestrictionKind.RATE_LIMITED.value,
        "severity": "soft",
        "description": f"Rate-limit automated traffic to {rps} requests per second.",
        "enforcement": _ENFORCEMENT_STRATEGY[RestrictionKind.RATE_LIMITED],
        "enforcement_args": {"rps": rps},
        "applies_to": ["all"],  # a rate limit governs all traffic
    }
