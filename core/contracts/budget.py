"""
core/contracts/budget.py
The Economic Constitution of SentinelForge.

Defines the Budget model which acts as the authoritative resource limit
for all scan phases.

DESIGN PRINCIPLES:
1. Budgets are explicit contracts, not vague guidelines.
2. Consumption is transaction-based (consume() raises on overdraft).
3. Used by ResourceGuard to enforce "God-Mode" safety limits.
"""

from typing import Dict, Optional
from pydantic import BaseModel, Field, PrivateAttr

class BudgetOverrun(Exception):
    """Raised when a budget limit is exceeded."""
    def __init__(self, metric: str, limit: float, current: float):
        self.metric = metric
        self.limit = limit
        self.current = current
        super().__init__(f"Budget overrun for {metric}: current {current} > limit {limit}")

class Budget(BaseModel):
    """
    Canonical resource budget for a scan or phase.
    
    This object flows through the system and tracks consumption against
    hard limits. It is the "currency" of the scan economy.
    """
    # Time Limits
    max_time_ms: int = Field(..., description="Maximum duration in milliseconds")
    
    # Discovery Limits
    max_findings: int = Field(500, description="Max findings before aborting to prevent db flood")
    max_urls: int = Field(1000, description="Max URLs to discover/crawl")
    max_snapshots: int = Field(50, description="Max historical snapshots to process (Cronus)")
    
    # Execution Limits
    max_depth: int = Field(2, description="Max crawl recursion depth")
    max_concurrency: int = Field(10, description="Max concurrent tasks")
    
    # Internal Tracking (Private to prevent direct mutation)
    _usage: Dict[str, float] = PrivateAttr(default_factory=dict)

    def consume(self, metric: str, amount: float = 1.0) -> float:
        """
        Consume resources from the budget.
        
        Args:
            metric: The name of the metric (must match a field name or be a tracked custom metric)
            amount: Amount to consume
            
        Returns:
            The new total usage for this metric.
            
        Raises:
            BudgetOverrun: If the consumption exceeds the limit.
        """
        current = self._usage.get(metric, 0.0)
        new_total = current + amount
        
        # Check against defined limits if they exist
        # Convention: limit field is "max_{metric}"
        limit_field = f"max_{metric}"
        limit = None
        
        if hasattr(self, limit_field):
            limit = getattr(self, limit_field)
        elif hasattr(self, metric):
            limit = getattr(self, metric)
            
        if limit is not None:
            if new_total > limit:
                raise BudgetOverrun(metric, limit, new_total)
        
        self._usage[metric] = new_total
        return new_total

    def remaining(self, metric: str) -> float:
        """Return remaining budget for a metric (or infinity if no limit)."""
        if not hasattr(self, metric):
            return float('inf')
            
        limit = getattr(self, metric)
        usage = self._usage.get(metric, 0.0)
        return max(0.0, limit - usage)

    def usage_report(self) -> Dict[str, Dict[str, float]]:
        """Return a snapshot of limits vs usage."""
        report = {}
        for field in self.model_fields:
            limit = getattr(self, field)
            # Only include numeric limits in the report
            if isinstance(limit, (int, float)):
                used = self._usage.get(field, 0.0)
                report[field] = {
                    "limit": limit,
                    "used": used,
                    "remaining": max(0, limit - used),
                    "percent": (used / limit) * 100 if limit > 0 else 0
                }
        return report
