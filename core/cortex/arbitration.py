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
from pathlib import Path

from core.scheduler.decisions import DecisionPoint
from core.cortex.policy import Policy, Judgment, Verdict, CALCompiledPolicy

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
            policy: A Policy object (Python or CAL-compiled)
        """
        self._policies.append(policy)
        logger.debug(f"[Arbitration] Registered policy: {policy.name}")

    def load_cal_policy(self, cal_source: str) -> List[Policy]:
        """
        Parse CAL source string and register all laws as policies.

        Args:
            cal_source: CAL DSL string containing one or more Law definitions

        Returns:
            List of registered CALCompiledPolicy instances

        Example:
            >>> cal = '''
            ... Law BlockProduction {
            ...     When: context.target == "prod.example.com"
            ...     Then: DENY "Production scans require approval"
            ... }
            ... '''
            >>> engine.load_cal_policy(cal)
        """
        from core.cal.parser import CALParser

        parser = CALParser()
        laws = parser.parse_string(cal_source)

        policies = []
        for law in laws:
            policy = CALCompiledPolicy(law)
            self.register_policy(policy)
            policies.append(policy)
            logger.info(f"[Arbitration] Loaded CAL policy: {policy.name}")

        return policies

    def load_cal_file(self, file_path: str) -> List[Policy]:
        """
        Load CAL policies from a file.

        Args:
            file_path: Path to .cal file (absolute or relative to cwd)

        Returns:
            List of registered CALCompiledPolicy instances

        Example:
            >>> engine.load_cal_file("assets/laws/constitution.cal")
        """
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"[Arbitration] CAL file not found: {file_path}")
            return []

        cal_source = path.read_text()
        logger.info(f"[Arbitration] Loading CAL policies from {file_path}")
        return self.load_cal_policy(cal_source)

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
