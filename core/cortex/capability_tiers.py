"""
Capability Tier System for SentinelForge.

Implements dual execution modes (Research/Bounty) with five capability tiers
(T0-T4) that gate scanner actions through Strategos policy evaluation.

Tier definitions:
  T0 OBSERVE  - Passive data collection (DNS, WHOIS, certificate parsing)
  T1 PROBE    - Active but non-intrusive (port scanning, directory brute, header analysis)
  T2 VERIFY   - Payload-based testing split into:
                 T2a SAFE_VERIFY - Non-mutating (time-based blind, error-based, boolean blind)
                 T2b MUTATING_VERIFY - Potentially mutating (INSERT/UPDATE payloads, file writes)
  T3 EXPLOIT  - Full exploitation for proof (data extraction, RCE proof, auth bypass)
  T4 DESTRUCTIVE - Destructive actions (never auto-approved)

Gate formula evaluated by Strategos:
  (scope_ok) AND (tier_allowed_in_mode) AND (risk_budget_ok) AND (approval_if_required)
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# Capability Tiers
class CapabilityTier(enum.IntEnum):
    """Scanner capability tiers ordered by risk/intrusiveness."""
    T0_OBSERVE = 0
    T1_PROBE = 1
    T2a_SAFE_VERIFY = 2
    T2b_MUTATING_VERIFY = 3
    T3_EXPLOIT = 4
    T4_DESTRUCTIVE = 5


# Execution Modes
class ExecutionMode(str, enum.Enum):
    """Top-level scanner execution mode."""
    RESEARCH = "research"   # Defensive: safe by default, no exploitation
    BOUNTY = "bounty"       # Offensive: opt-in, per-target, scope-attested


# Tier policies per mode - which tiers are allowed and which need approval
@dataclass(frozen=True)
class TierPolicy:
    """Policy for a single tier within an execution mode."""
    allowed: bool                    # Is this tier permitted at all?
    auto_approve: bool = False       # Can Strategos auto-approve without operator?
    budget_cost: int = 0             # Budget tokens consumed per action
    requires_scope_attestation: bool = False  # Must operator attest scope?


# Default tier policies per execution mode
MODE_TIER_POLICIES: Dict[ExecutionMode, Dict[CapabilityTier, TierPolicy]] = {
    ExecutionMode.RESEARCH: {
        CapabilityTier.T0_OBSERVE:         TierPolicy(allowed=True, auto_approve=True, budget_cost=0),
        CapabilityTier.T1_PROBE:           TierPolicy(allowed=True, auto_approve=True, budget_cost=0),
        CapabilityTier.T2a_SAFE_VERIFY:    TierPolicy(allowed=True, auto_approve=True, budget_cost=1),
        CapabilityTier.T2b_MUTATING_VERIFY:TierPolicy(allowed=False),  # Not allowed in research
        CapabilityTier.T3_EXPLOIT:         TierPolicy(allowed=False),
        CapabilityTier.T4_DESTRUCTIVE:     TierPolicy(allowed=False),
    },
    ExecutionMode.BOUNTY: {
        CapabilityTier.T0_OBSERVE:         TierPolicy(allowed=True, auto_approve=True, budget_cost=0),
        CapabilityTier.T1_PROBE:           TierPolicy(allowed=True, auto_approve=True, budget_cost=0),
        CapabilityTier.T2a_SAFE_VERIFY:    TierPolicy(allowed=True, auto_approve=True, budget_cost=1),
        CapabilityTier.T2b_MUTATING_VERIFY:TierPolicy(allowed=True, auto_approve=False, budget_cost=5),
        CapabilityTier.T3_EXPLOIT:         TierPolicy(allowed=True, auto_approve=False, budget_cost=10, requires_scope_attestation=True),
        CapabilityTier.T4_DESTRUCTIVE:     TierPolicy(allowed=False),  # Never auto-approved
    },
}


# Map existing tool names/categories to their capability tier
TOOL_TIER_CLASSIFICATION: Dict[str, CapabilityTier] = {
    # T0: Passive observation
    "dns_lookup": CapabilityTier.T0_OBSERVE,
    "whois": CapabilityTier.T0_OBSERVE,
    "certificate_parse": CapabilityTier.T0_OBSERVE,
    "passive_recon": CapabilityTier.T0_OBSERVE,
    "subfinder": CapabilityTier.T0_OBSERVE,
    # T1: Active probing
    "nmap": CapabilityTier.T1_PROBE,
    "httpx": CapabilityTier.T1_PROBE,
    "feroxbuster": CapabilityTier.T1_PROBE,
    "gobuster": CapabilityTier.T1_PROBE,
    "dirsearch": CapabilityTier.T1_PROBE,
    "nuclei_info": CapabilityTier.T1_PROBE,
    "header_analysis": CapabilityTier.T1_PROBE,
    "wappalyzer": CapabilityTier.T1_PROBE,
    # T2a: Safe verification (non-mutating)
    "nuclei_low": CapabilityTier.T2a_SAFE_VERIFY,
    "sqli_blind_time": CapabilityTier.T2a_SAFE_VERIFY,
    "sqli_blind_boolean": CapabilityTier.T2a_SAFE_VERIFY,
    "sqli_error_based": CapabilityTier.T2a_SAFE_VERIFY,
    "xss_reflected_check": CapabilityTier.T2a_SAFE_VERIFY,
    "ssrf_dns_only": CapabilityTier.T2a_SAFE_VERIFY,
    # T2b: Mutating verification
    "nuclei_medium": CapabilityTier.T2b_MUTATING_VERIFY,
    "nuclei_high": CapabilityTier.T2b_MUTATING_VERIFY,
    "sqli_union": CapabilityTier.T2b_MUTATING_VERIFY,
    "file_upload_test": CapabilityTier.T2b_MUTATING_VERIFY,
    # T3: Exploitation
    "nuclei_critical": CapabilityTier.T3_EXPLOIT,
    "rce_proof": CapabilityTier.T3_EXPLOIT,
    "sqli_extract": CapabilityTier.T3_EXPLOIT,
    "auth_bypass": CapabilityTier.T3_EXPLOIT,
    "ssrf_exploit": CapabilityTier.T3_EXPLOIT,
    # T4: Destructive (never auto-approved)
    "data_exfil": CapabilityTier.T4_DESTRUCTIVE,
    "persistence": CapabilityTier.T4_DESTRUCTIVE,
}


# Budget management per target
@dataclass
class TargetBudget:
    """Per-target budget for controlling action costs.
    
    Attributes:
        target: The target identifier (domain, IP, etc.)
        max_tokens: Maximum token budget for this target.
        remaining_tokens: Current remaining tokens.
        max_time_seconds: Maximum execution time per target (default 1 hour).
        start_time: Unix timestamp when budget was created.
        actions_taken: Total number of actions executed for this target.
        actions_by_tier: Count of actions per capability tier.
    """
    target: str
    max_tokens: int = 100
    remaining_tokens: int = 100
    max_time_seconds: float = 3600.0     # 1 hour per target
    start_time: float = field(default_factory=time.time)
    actions_taken: int = 0
    actions_by_tier: Dict[CapabilityTier, int] = field(default_factory=lambda: {t: 0 for t in CapabilityTier})
    
    @property
    def elapsed(self) -> float:
        """Return elapsed time in seconds since budget creation."""
        return time.time() - self.start_time
    
    @property
    def time_remaining(self) -> float:
        """Return remaining time budget in seconds (minimum 0.0)."""
        return max(0.0, self.max_time_seconds - self.elapsed)
    
    @property
    def is_exhausted(self) -> bool:
        """Return True if either token or time budget is exhausted."""
        return self.remaining_tokens <= 0 or self.time_remaining <= 0
    
    def can_afford(self, cost: int) -> bool:
        """Check if there is sufficient token and time budget for a cost.
        
        Args:
            cost: Number of tokens required.
            
        Returns:
            True if cost can be afforded without exceeding budget.
        """
        return self.remaining_tokens >= cost and self.time_remaining > 0
    
    def consume(self, cost: int, tier: CapabilityTier) -> bool:
        """Consume budget tokens for an action.
        
        Args:
            cost: Number of tokens to consume.
            tier: Capability tier of the action being consumed.
            
        Returns:
            True if budget was successfully consumed, False if insufficient.
        """
        if not self.can_afford(cost):
            return False
        self.remaining_tokens -= cost
        self.actions_taken += 1
        self.actions_by_tier[tier] = self.actions_by_tier.get(tier, 0) + 1
        return True
    
    def summary(self) -> Dict:
        """Return a dictionary summary of budget status.
        
        Returns:
            Dictionary with tokens, time, action counts, and exhaustion status.
        """
        return {
            "target": self.target,
            "tokens_remaining": self.remaining_tokens,
            "tokens_max": self.max_tokens,
            "time_remaining_s": round(self.time_remaining, 1),
            "actions_taken": self.actions_taken,
            "actions_by_tier": {t.name: c for t, c in self.actions_by_tier.items() if c > 0},
            "is_exhausted": self.is_exhausted,
        }


@dataclass(frozen=True)
class GateResult:
    """Result of evaluating capability tier gate.
    
    Attributes:
        approved: Whether the action was approved.
        tier: The capability tier being evaluated.
        mode: The execution mode in effect.
        reason: Human-readable explanation of the decision.
        budget_cost: Token cost of the action (0 if not approved).
        requires_operator_approval: Whether operator sign-off is needed for approval.
    """
    approved: bool
    tier: CapabilityTier
    mode: ExecutionMode
    reason: str
    budget_cost: int = 0
    requires_operator_approval: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary representation.
        
        Returns:
            Dictionary with all fields, tiers/modes converted to string names.
        """
        return {
            "approved": self.approved,
            "tier": self.tier.name,
            "mode": self.mode.value,
            "reason": self.reason,
            "budget_cost": self.budget_cost,
            "requires_operator_approval": self.requires_operator_approval,
        }


class CapabilityGate:
    """
    Central gate that evaluates whether an action is permitted.
    
    Implements the gate formula:
        (scope_ok) AND (tier_allowed_in_mode) AND (risk_budget_ok) AND (approval_if_required)
    
    Manages:
      - Execution mode (RESEARCH or BOUNTY)
      - Target scope (which domains/IPs are in-scope)
      - Per-target token budgets
      - Operator approval cache
      - Tier policies per mode
    
    Attributes:
        mode: Current execution mode.
        scope_targets: Frozenset of approved target identifiers.
        policies: Tier policies per execution mode.
    """
    
    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.RESEARCH,
        scope_targets: Optional[FrozenSet[str]] = None,
        custom_policies: Optional[Dict[ExecutionMode, Dict[CapabilityTier, TierPolicy]]] = None,
    ):
        """Initialize the capability gate.
        
        Args:
            mode: Execution mode (RESEARCH or BOUNTY). Defaults to RESEARCH.
            scope_targets: Frozenset of approved target identifiers. If None, created empty.
            custom_policies: Custom tier policies. If None, uses default MODE_TIER_POLICIES.
        """
        self.mode = mode
        self.scope_targets: FrozenSet[str] = scope_targets or frozenset()
        self.policies = custom_policies or MODE_TIER_POLICIES
        self._budgets: Dict[str, TargetBudget] = {}
        self._approval_cache: Set[Tuple[str, CapabilityTier]] = set()  # (target, tier) pairs approved by operator
    
    def get_budget(self, target: str) -> TargetBudget:
        """Get or create budget for target.
        
        Args:
            target: Target identifier.
            
        Returns:
            TargetBudget object for this target (creates new if not exists).
        """
        if target not in self._budgets:
            self._budgets[target] = TargetBudget(target=target)
        return self._budgets[target]
    
    def set_mode(self, mode: ExecutionMode) -> None:
        """Switch execution mode. Clears operator approval cache.
        
        Args:
            mode: New execution mode.
        """
        self.mode = mode
        self._approval_cache.clear()
    
    def add_scope_target(self, target: str) -> None:
        """Add target to approved scope.
        
        Args:
            target: Target identifier to add.
        """
        self.scope_targets = self.scope_targets | frozenset([target])
    
    def record_operator_approval(self, target: str, tier: CapabilityTier) -> None:
        """Record that operator has approved this (target, tier) combination.
        
        Args:
            target: Target identifier.
            tier: Capability tier being approved.
        """
        self._approval_cache.add((target, tier))
    
    def classify_tool(self, tool_name: str) -> CapabilityTier:
        """Classify a tool into its capability tier.
        
        Args:
            tool_name: Name of the tool to classify.
            
        Returns:
            CapabilityTier, defaults to T1_PROBE if tool not found in classification map.
        """
        return TOOL_TIER_CLASSIFICATION.get(tool_name, CapabilityTier.T1_PROBE)
    
    def evaluate(
        self,
        target: str,
        tier: CapabilityTier,
        tool_name: Optional[str] = None,
    ) -> GateResult:
        """
        Evaluate the capability gate for a proposed action.
        
        Checks in order:
          1. Scope: Is target in approved scope?
          2. Tier Policy: Is tier allowed in current mode?
          3. Budget: Are tokens and time available?
          4. Approval: Does tier require operator sign-off?
          5. Attestation: Does tier require explicit scope attestation?
        
        If all checks pass, budget is consumed and action is approved.
        
        Args:
            target: Target identifier being tested against.
            tier: Capability tier of the proposed action.
            tool_name: Optional tool name for logging/classification.
            
        Returns:
            GateResult with approval status and reasoning.
        """
        # 1. Scope check — target must be in approved scope (if scope is defined)
        if self.scope_targets and target not in self.scope_targets:
            return GateResult(
                approved=False,
                tier=tier,
                mode=self.mode,
                reason=f"Target '{target}' not in approved scope",
            )
        
        # 2. Tier allowed in mode?
        mode_policies = self.policies.get(self.mode, {})
        policy = mode_policies.get(tier)
        
        if policy is None or not policy.allowed:
            return GateResult(
                approved=False,
                tier=tier,
                mode=self.mode,
                reason=f"Tier {tier.name} not allowed in {self.mode.value} mode",
            )
        
        # 3. Budget check
        budget = self.get_budget(target)
        if budget.is_exhausted:
            return GateResult(
                approved=False,
                tier=tier,
                mode=self.mode,
                reason=f"Budget exhausted for target '{target}' ({budget.remaining_tokens} tokens, {budget.time_remaining:.0f}s remaining)",
                budget_cost=policy.budget_cost,
            )
        
        if not budget.can_afford(policy.budget_cost):
            return GateResult(
                approved=False,
                tier=tier,
                mode=self.mode,
                reason=f"Insufficient budget: need {policy.budget_cost} tokens, have {budget.remaining_tokens}",
                budget_cost=policy.budget_cost,
            )
        
        # 4. Approval check — does this tier require operator sign-off?
        if not policy.auto_approve:
            if (target, tier) not in self._approval_cache:
                return GateResult(
                    approved=False,
                    tier=tier,
                    mode=self.mode,
                    reason=f"Tier {tier.name} requires operator approval for '{target}'",
                    budget_cost=policy.budget_cost,
                    requires_operator_approval=True,
                )
        
        # 5. Scope attestation check for T3+
        if policy.requires_scope_attestation and not self.scope_targets:
            return GateResult(
                approved=False,
                tier=tier,
                mode=self.mode,
                reason=f"Tier {tier.name} requires explicit scope attestation (no scope targets defined)",
                budget_cost=policy.budget_cost,
            )
        
        # All gates passed — consume budget and approve
        budget.consume(policy.budget_cost, tier)
        
        return GateResult(
            approved=True,
            tier=tier,
            mode=self.mode,
            reason=f"Approved: {tier.name} in {self.mode.value} mode (cost: {policy.budget_cost} tokens)",
            budget_cost=policy.budget_cost,
        )
    
    def evaluate_tool(self, target: str, tool_name: str) -> GateResult:
        """Convenience: classify tool and evaluate in one call.
        
        Args:
            target: Target identifier.
            tool_name: Name of tool to classify and evaluate.
            
        Returns:
            GateResult from evaluate() with classified tier.
        """
        tier = self.classify_tool(tool_name)
        return self.evaluate(target, tier, tool_name=tool_name)
    
    def get_allowed_tiers(self, target: str) -> List[CapabilityTier]:
        """Return list of tiers currently available for a target.
        
        Evaluates each tier as a dry-run query and reverses budget consumption
        since this is introspection, not an actual action.
        
        Args:
            target: Target identifier to check.
            
        Returns:
            List of CapabilityTier enums that are currently available.
        """
        allowed = []
        for tier in CapabilityTier:
            result = self.evaluate(target, tier)
            # Re-add consumed budget since this is a dry-run query
            if result.approved:
                budget = self.get_budget(target)
                budget.remaining_tokens += result.budget_cost
                budget.actions_taken -= 1
                budget.actions_by_tier[tier] -= 1
                allowed.append(tier)
        return allowed
    
    def status(self) -> Dict:
        """Return current gate status for all targets.
        
        Returns:
            Dictionary containing mode, scope, budgets, and operator approvals.
        """
        return {
            "mode": self.mode.value,
            "scope_targets": sorted(self.scope_targets),
            "budgets": {t: b.summary() for t, b in self._budgets.items()},
            "operator_approvals": [(t, tier.name) for t, tier in sorted(self._approval_cache)],
        }


# Module-level singleton (lazily replaced by Strategos on startup)
_default_gate: Optional[CapabilityGate] = None


def get_capability_gate() -> CapabilityGate:
    """Get or create the global capability gate.
    
    Returns:
        The global CapabilityGate instance (creates with defaults if not set).
    """
    global _default_gate
    if _default_gate is None:
        _default_gate = CapabilityGate()
    return _default_gate


def set_capability_gate(gate: CapabilityGate) -> None:
    """Replace the global capability gate (called by Strategos on init).
    
    Args:
        gate: New CapabilityGate instance to use globally.
    """
    global _default_gate
    _default_gate = gate
