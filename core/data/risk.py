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
from typing import Dict

from core.utils.observer import Observable, Signal
from core.data.issues_store import issues_store


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0.5,
}


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
            scores[asset] += weight
        self._scores = dict(scores)
        self.scores_changed.emit()

    def get_scores(self) -> Dict[str, float]:
        """Function get_scores."""
        return dict(self._scores)


risk_engine = RiskEngine()
