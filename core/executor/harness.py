"""
core/executor/harness.py

Purpose:
    The Abstract Interface for "The Hands".
    Defines how an ExecutionOrder is converted into reality.
"""

from __future__ import annotations
from typing import Protocol, runtime_checkable

from .models import ExecutionOrder, ExecutionResult

@runtime_checkable
class Harness(Protocol):
    """
    Interface for execution strategies.
    Implementations might include:
    - LocalHttpHarness (Uses httpx)
    - BrowserHarness (Uses Playwright)
    - ReplayHarness (Uses recorded traffic)
    """

    async def execute(self, order: ExecutionOrder) -> ExecutionResult:
        """
        Executes the Mutation defined in the Order.
        Must handle its own exceptions and return an ExecutionResult(ERROR) on crash.
        """
        ...
