"""Module risk: inline documentation for /Users/jason/Developer/sentinelforge/core/data/risk.py."""
#
# PURPOSE:
# Automatically calculates a risk score for each target based on discovered issues.
# Helps prioritize which assets need immediate attention.
#
# HOW SCORING WORKS:
# - Each confirmed issue has a severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
# - Severities have numeric weights (CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1, INFO=0.5)
# - An asset's score = sum of all issue weights for that asset
# - Higher score = more/worse vulnerabilities = higher priority
#
# EXAMPLE:
# example.com has:
#   - 1 CRITICAL issue (10 points)
#   - 2 HIGH issues (6 × 2 = 12 points)
#   - 3 MEDIUM issues (3 × 3 = 9 points)
#   Total score: 31 points (needs urgent attention!)
#
# WHY AUTOMATIC SCORING:
# - Objective prioritization (not just gut feel)
# - Helps focus on highest-impact targets first
# - Provides quantitative risk metrics for reports
# - Updates automatically as new issues are discovered
#
# KEY CONCEPTS:
# - Observable Pattern: Emits signal when scores change (UI can update automatically)
# - Reactive Updates: Recalculates whenever new issues are added
# - Asset Aggregation: Groups issues by target to compute per-asset scores
#

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Any

from core.utils.observer import Observable, Signal
from core.data.issues_store import issues_store


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0.5,
}

from core.data.constants import CONFIRMATION_MULTIPLIERS


class RiskEngine(Observable):
    """Class RiskEngine."""
    scores_changed = Signal()

    def __init__(self):
        """Function __init__."""
        super().__init__()
        self._scores: Dict[str, float] = {}
        issues_store.issues_changed.connect(self.recalculate)
        self.recalculate()

    def recalculate(self):
        """Function recalculate."""
        raw = issues_store.get_all()
        scores = defaultdict(float)
        # Loop over items.
        for issue in raw:
            asset = issue.get("target") or issue.get("asset") or "unknown"
            severity = str(issue.get("severity", "INFO")).upper()
            weight = SEVERITY_WEIGHTS.get(severity, 0.5)
            # Confirmation-weighted scoring
            # COMPOUND MULTIPLIER NOTE:
            # This multiplier applies to ASSET-LEVEL ranking (which target needs
            # attention first). VulnRule.apply() applies a SEPARATE multiplier to
            # ISSUE-LEVEL ranking. Both are needed — see note in VulnRule.apply().
            confirmation = issue.get("confirmation_level")
            multiplier = CONFIRMATION_MULTIPLIERS.get(confirmation, 1.0) if confirmation else 1.0
            scores[asset] += weight * multiplier
        self._scores = dict(scores)
        self.scores_changed.emit()

    def get_scores(self) -> Dict[str, float]:
        """Function get_scores."""
        return dict(self._scores)

    def compute_three_axis_priority(self, issue: Dict[str, Any]) -> Dict[str, float]:
        """
        Compute read-only three-axis priority for an issue.

        This method does not mutate self._scores and does not emit signals.
        """
        from core.base.config import get_config

        capability_model = get_config().capability_model
        confirmation = str(issue.get("confirmation_level", "confirmed")).strip().lower()

        raw_capability_types = issue.get("capability_types", ["execution"])
        if isinstance(raw_capability_types, str):
            capability_types: List[str] = [raw_capability_types]
        elif isinstance(raw_capability_types, list):
            capability_types = [str(cap).strip().lower() for cap in raw_capability_types if str(cap).strip()]
        else:
            capability_types = ["execution"]
        if not capability_types:
            capability_types = ["execution"]

        # Axis 1: Time-to-impact
        time_to_impact = self._compute_time_to_impact(confirmation, capability_types)

        # Axis 2: Uncertainty reduction (read-only, metadata-driven).
        uncertainty_reduction = min(10.0, float(issue.get("enablement_score", 0.0)))

        # Axis 3: Effort eliminated from configured table.
        enablement_class = str(issue.get("enablement_class", "partial_info")).strip()
        effort_eliminated = float(
            capability_model.effort_eliminated_by_capability.get(enablement_class, 2.0)
        )

        priority_composite = (
            capability_model.time_to_impact_weight * time_to_impact
            + capability_model.uncertainty_reduction_weight * uncertainty_reduction
            + capability_model.effort_eliminated_weight * effort_eliminated
        )

        return {
            "time_to_impact": round(time_to_impact, 2),
            "uncertainty_reduction": round(uncertainty_reduction, 2),
            "effort_eliminated": round(effort_eliminated, 2),
            "priority_composite": round(priority_composite, 2),
        }

    @staticmethod
    def _compute_time_to_impact(
        confirmation: str,
        capability_types: List[str],
    ) -> float:
        """Score how quickly an attacker can act on a finding."""
        if confirmation == "confirmed":
            if "access" in capability_types:
                return 10.0
            if "execution" in capability_types:
                return 9.0
            if "information" in capability_types:
                return 8.0
            return 8.0
        if confirmation == "probable":
            if "execution" in capability_types:
                return 6.0
            return 5.0
        if confirmation == "hypothesized":
            if "execution" in capability_types:
                return 3.0
            return 2.0
        return 5.0


risk_engine = RiskEngine()
