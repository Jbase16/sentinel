# core/risk.py — simple asset risk scoring engine

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
    scores_changed = Signal()

    def __init__(self):
        super().__init__()
        self._scores: Dict[str, float] = {}
        issues_store.issues_changed.connect(self.recalculate)
        self.recalculate()

    def recalculate(self):
        raw = issues_store.get_all()
        scores = defaultdict(float)
        for issue in raw:
            asset = issue.get("target") or issue.get("asset") or "unknown"
            severity = str(issue.get("severity", "INFO")).upper()
            weight = SEVERITY_WEIGHTS.get(severity, 0.5)
            scores[asset] += weight
        self._scores = dict(scores)
        self.scores_changed.emit()

    def get_scores(self) -> Dict[str, float]:
        return dict(self._scores)


risk_engine = RiskEngine()
