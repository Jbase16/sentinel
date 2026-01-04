"""
core/sentient/ethics.py

Purpose:
    The "Superego" of the system. Enforces hard constraints that cannot be bought/bribed
    by high ROI. If a Constraint fails, the verdict is REJECT or DEFER, regardless of value.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, time
from typing import Any, Dict, List

from .models import Constraint


@dataclass
class TimeWindowConstraint:
    """
    Blocks execution during prohibited hours (e.g., Critical Business Hours).
    Returns DEFER if blocked, implying it can run later.
    """
    name: str = "TimeWindow"
    start_time: time = time(9, 0)  # 09:00
    end_time: time = time(17, 0)   # 17:00
    timezone_offset: int = 0       # Simplified for now

    def check(self, context: Dict[str, Any]) -> bool:
        """
        Returns False (BLOCK) if current time is within the prohibited window.
        Returns True (PASS) otherwise.
        """
        now = datetime.now().time()
        # Simple blocking window: if start <= now <= end, we block.
        # Ideally this logic handles crossing midnight, but keeping it simple for V1.
        if self.start_time <= now <= self.end_time:
            return False
        return True


@dataclass
class ValueCeilingConstraint:
    """
    Blocks execution if the target's business value exceeds a safety ceiling 
    without explicit override.
    """
    name: str = "ValueCeiling"
    max_value: float = 9.0  # Cap at 9.0; 10.0 (Crown Jewels) requires manual approval.

    def check(self, context: Dict[str, Any]) -> bool:
        """
        Context expects 'target_value' (float).
        """
        val = context.get("target_value", 0.0)
        return val <= self.max_value


class EthicalGuard:
    """
    Aggregator for all active constraints.
    """
    def __init__(self):
        self.constraints: List[Constraint] = [
            # Default policy:
            # 1. Respect business hours (don't break prod when users are awake)
            # 2. Don't touch Crown Jewels (value > 9.0) automatically
            TimeWindowConstraint(),
            ValueCeilingConstraint()
        ]

    def evaluate(self, context: Dict[str, Any]) -> List[str]:
        """
        Returns a list of FAILED constraint names.
        If empty, all passed.
        """
        failed = []
        for c in self.constraints:
            if not c.check(context):
                failed.append(c.name)
        return failed
