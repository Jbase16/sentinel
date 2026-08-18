"""Module arbitration: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/arbitration.py."""
#
# PURPOSE:
# The "Cortex" acts as the Supreme Court.
# It does not originate decisions (Strategos does that).
# It reviews decisions for compliance, safety, and strategy alignment.
#
# LOGIC:
# - Decision is proposed.
# - All Policies enforce their rules.
# - If ANY policy dictates VETO, the decision is blocked.
# - If policies conflict (one approves, one vetoes), VETO wins (Safety First).
#

from __future__ import annotations

import logging
from typing import List, Dict, Any

from core.scheduler.decisions import DecisionPoint
from core.cortex.policy import Policy, Judgment, Verdict

logger = logging.getLogger(__name__)

class ArbitrationEngine:
    """Class ArbitrationEngine."""
    def __init__(self):
        """Function __init__."""
        self._policies: List[Policy] = []

    def register_policy(self, policy: Policy):
        """
        Register a single Policy instance.

        Args:
            policy: A typed Policy object
        """
        self._policies.append(policy)
        logger.debug(f"[Arbitration] Registered policy: {policy.name}")

    def unregister_policy(self, policy_name: str) -> bool:
        """
        Remove a policy by name.

        Args:
            policy_name: The policy.name to remove

        Returns:
            True if removed, False if not found
        """
        for i, policy in enumerate(self._policies):
            if policy.name == policy_name:
                removed = self._policies.pop(i)
                logger.info(f"[Arbitration] Unregistered policy: {removed.name}")
                return True
        return False

    def list_policies(self) -> List[str]:
        """
        Get names of all registered policies.

        Returns:
            List of policy names
        """
        return [p.name for p in self._policies]

    def review(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        """
        Review a proposed decision.

        Policies are evaluated in priority order (higher priority first).
        Returns a single Judgment: APPROVE, VETO, or MODIFY.

        Arbitration Rules:
        - VETO always wins (fail-closed for safety)
        - MODIFY suggestions are collected and returned if approved
        - APPROVE is default consensus
        """
        vetoes: List[Judgment] = []
        approvals: List[Judgment] = []
        modifications: List[Judgment] = []

        # Sort policies by priority (higher = evaluated first)
        # Python policies default to priority 50 if no priority property
        sorted_policies = sorted(
            self._policies,
            key=lambda p: getattr(p, 'priority', 50),
            reverse=True  # Higher priority first
        )

        # 1. Collect Judgments in priority order
        for policy in sorted_policies:
            try:
                judgment = policy.evaluate(decision, context)

                if judgment.verdict == Verdict.VETO:
                    vetoes.append(judgment)
                    # Early exit on veto for performance (veto always wins)
                    break
                elif judgment.verdict == Verdict.APPROVE:
                    approvals.append(judgment)
                elif judgment.verdict == Verdict.MODIFY:
                    modifications.append(judgment)
                    logger.debug(f"[Arbitration] MODIFY requested by {policy.name}: {judgment.reason}")

            except Exception as e:
                # Fail Closed: Policy crash = VETO for safety
                logger.error(f"[Arbitration] Policy {policy.name} crashed: {e}")
                vetoes.append(Judgment(Verdict.VETO, policy.name, f"Policy Crashed: {e}"))
                break

        # 2. Arbitrate
        if vetoes:
            # Veto wins (fail-closed)
            reasons = "; ".join([f"{j.policy_name}: {j.reason}" for j in vetoes])
            return Judgment(
                verdict=Verdict.VETO,
                policy_name="ArbitrationEngine",
                reason=f"Blocked by {len(vetoes)} policies. [{reasons}]"
            )

        # 3. Handle modifications
        if modifications:
            # Collect all modification suggestions
            all_modifications = {}
            reasons = []
            for mod_judgment in modifications:
                if mod_judgment.modifications:
                    all_modifications.update(mod_judgment.modifications)
                reasons.append(f"{mod_judgment.policy_name}: {mod_judgment.reason}")

            return Judgment(
                verdict=Verdict.MODIFY,
                policy_name="ArbitrationEngine",
                reason=f"Approved with modifications from {len(modifications)} policies. [{'; '.join(reasons)}]",
                modifications=all_modifications
            )

        # 4. Consensus (all approved or no policies matched)
        return Judgment(
            verdict=Verdict.APPROVE,
            policy_name="ArbitrationEngine",
            reason="Consensus: Approved"
        )
