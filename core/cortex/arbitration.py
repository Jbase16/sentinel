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
from typing import List, Dict, Any, Optional

from core.scheduler.decisions import DecisionPoint
from core.cortex.policy import Policy, Judgment, Verdict

logger = logging.getLogger(__name__)

class ArbitrationEngine:
    """Class ArbitrationEngine."""
    def __init__(self):
        """Function __init__."""
        self._policies: List[Policy] = []

    def register_policy(self, policy: Policy):
        """Function register_policy."""
        self._policies.append(policy)
        logger.debug(f"[Arbitration] Registered policy: {policy.name}")

    def review(self, decision: DecisionPoint, context: Dict[str, Any]) -> Judgment:
        """
        Review a proposed decision.
        Returns a single Judgment: APPROVE or VETO.
        """
        vetoes: List[Judgment] = []
        approvals: List[Judgment] = []
        
        # 1. Collect Judgments
        for policy in self._policies:
            try:
                judgment = policy.evaluate(decision, context)
                if judgment.verdict == Verdict.VETO:
                    vetoes.append(judgment)
                elif judgment.verdict == Verdict.APPROVE:
                    approvals.append(judgment)
                # MODIFY is treated as VETO for now in strict mode
                elif judgment.verdict == Verdict.MODIFY:
                     logger.warning(f"[Arbitration] MODIFY requested by {policy.name} but not supported yet. Treating as INFO.")
                     approvals.append(judgment) # Treat as allow-with-modification-request (soft allow)
            except Exception as e:
                # Fail Closed: If a policy crashes, we default to VETO for safety? 
                # Or Log and Ignore? 
                # "Fail Safe" usually means Fail Open in non-critical, Fail Closed in critical.
                # Let's Fail Closed for safety.
                logger.error(f"[Arbitration] Policy {policy.name} crashed: {e}")
                vetoes.append(Judgment(Verdict.VETO, policy.name, f"Policy Crashed: {e}"))
        
        # 2. Arbitrate
        if vetoes:
            # Veto wins
            reasons = "; ".join([f"{j.policy_name}: {j.reason}" for j in vetoes])
            return Judgment(
                verdict=Verdict.VETO,
                policy_name="ArbitrationEngine",
                reason=f"Blocked by {len(vetoes)} policies. [{reasons}]"
            )
            
        # 3. Consensus
        return Judgment(
            verdict=Verdict.APPROVE,
            policy_name="ArbitrationEngine",
            reason="Consensus: Approved"
        )
