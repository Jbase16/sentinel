"""Module test_strategos_edge_conditions: inline documentation for /Users/jason/Developer/sentinelforge/tests/unit/test_strategos_edge_conditions.py."""
#
# PURPOSE:
# This module is part of the unit package in SentinelForge.
# [Specific purpose based on module name: test_strategos_edge_conditions]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

import asyncio

import pytest

from core.scheduler.intents import INTENT_PASSIVE_RECON
from core.scheduler.modes import ScanMode
from core.scheduler.registry import PHASE_3_SURFACE
from core.scheduler.strategos import ScanContext, Strategos


@pytest.mark.asyncio
async def test_tool_cancellation_does_not_deadlock_intent_completion():
    """AsyncFunction test_tool_cancellation_does_not_deadlock_intent_completion."""
    brain = Strategos(event_queue_maxsize=8)

    async def dispatch_tool(_: str):
        """AsyncFunction dispatch_tool."""
        await asyncio.sleep(10)
        return []

    mission_task = asyncio.create_task(
        brain.run_mission(
            target="example.com",
            available_tools=["subfinder"],
            mode=ScanMode.STANDARD,
            dispatch_tool=dispatch_tool,
        )
    )

    # Loop over items.
    for _ in range(200):
        if brain._tool_tasks.get("subfinder"):
            break
        await asyncio.sleep(0.01)

    assert brain._tool_tasks.get("subfinder") is not None
    brain._tool_tasks["subfinder"].cancel()

    await asyncio.wait_for(mission_task, timeout=2.0)
    assert brain.context is not None
    assert brain.context.active_tools == 0
    assert not brain.context.running_tools


@pytest.mark.asyncio
async def test_completed_tools_are_not_redispatched_for_same_intent():
    """AsyncFunction test_completed_tools_are_not_redispatched_for_same_intent."""
    brain = Strategos(event_queue_maxsize=8)

    async def dispatch_tool(_: str):
        """AsyncFunction dispatch_tool."""
        return []

    brain.context = ScanContext(target="example.com")
    brain.context.knowledge["mode"] = ScanMode.STANDARD
    brain._dispatch_callback = dispatch_tool
    brain._tool_tasks = {}
    brain._tool_semaphore = asyncio.Semaphore(brain.context.max_concurrent)

    await brain._dispatch_tools_async(["subfinder"], intent=INTENT_PASSIVE_RECON)
    await brain._wait_for_intent_completion()

    assert "subfinder" in brain.context.completed_tools_per_intent.get(INTENT_PASSIVE_RECON, set())
    assert brain.context.active_tools == 0
    assert not brain.context.running_tools
    assert not brain._tool_tasks

    await brain._dispatch_tools_async(["subfinder"], intent=INTENT_PASSIVE_RECON)
    await asyncio.sleep(0)

    assert brain.context.active_tools == 0
    assert not brain.context.running_tools
    assert not brain._tool_tasks


@pytest.mark.asyncio
async def test_bounded_event_queue_does_not_block_tool_cleanup():
    """AsyncFunction test_bounded_event_queue_does_not_block_tool_cleanup."""
    brain = Strategos(event_queue_maxsize=1)

    async def dispatch_tool(_: str):
        """AsyncFunction dispatch_tool."""
        return []

    brain.context = ScanContext(target="example.com")
    brain.context.knowledge["mode"] = ScanMode.STANDARD
    brain._dispatch_callback = dispatch_tool
    brain._tool_tasks = {}
    brain._tool_semaphore = asyncio.Semaphore(2)

    await brain._dispatch_tools_async(["tool_a", "tool_b"], intent=INTENT_PASSIVE_RECON)
    await asyncio.wait_for(brain._wait_for_intent_completion(), timeout=2.0)

    assert brain.context.active_tools == 0
    assert not brain.context.running_tools
    assert brain.event_queue.qsize() == 1


@pytest.mark.asyncio
async def test_bug_bounty_walk_away_uses_surface_delta():
    """AsyncFunction test_bug_bounty_walk_away_uses_surface_delta."""
    brain = Strategos(event_queue_maxsize=8)

    async def dispatch_tool(tool: str):
        """AsyncFunction dispatch_tool."""
        # Conditional branch.
        if tool == "subfinder":
            return [
                {
                    "tool": "subfinder",
                    "type": "subdomain_enum",
                    "target": "example.com",
                    "severity": "INFO",
                    "message": "example.com",
                    "tags": [],
                    "metadata": {"original_target": "example.com"},
                }
            ]
        # Conditional branch.
        if tool == "nmap":
            return [
                {
                    "tool": "nmap",
                    "type": "basic_scan",
                    "target": "example.com",
                    "severity": "INFO",
                    "message": "example.com",
                    "tags": [],
                    "metadata": {"original_target": "example.com"},
                }
            ]
        return []

    await asyncio.wait_for(
        brain.run_mission(
            target="example.com",
            available_tools=["subfinder", "nmap"],
            mode=ScanMode.BUG_BOUNTY,
            dispatch_tool=dispatch_tool,
        ),
        timeout=2.0,
    )

    assert brain.context is not None
    assert brain.context.phase_index == PHASE_3_SURFACE

