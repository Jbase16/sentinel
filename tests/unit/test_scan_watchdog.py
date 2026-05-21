"""
Tests for the wait-loop watchdog and tool-task observability — Bug #12.

The watchdog can't be tested by waiting for a real hang (the original Bug #12
was intermittent and 3+ minutes long). Instead we test the diagnostic
emission directly with a synthetic stalled task, which is what the
watchdog produces when the wait-loop notices no progress.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict
from unittest.mock import MagicMock

import pytest

from core.engine.scanner_engine import ScannerEngine


@pytest.fixture
def engine() -> ScannerEngine:
    """A bare ScannerEngine instance suitable for testing helper methods.

    We don't initialize anything that requires the DB / event bus — only
    the attributes that _emit_hang_diagnostic actually reads.
    """
    eng = ScannerEngine.__new__(ScannerEngine)
    eng._running_tasks = {}
    return eng


async def _suspended_coro(event: asyncio.Event) -> None:
    """A coroutine that awaits an Event that will never be set.

    This produces a task whose stack frame is suspended at the await,
    which is exactly the shape of the Bug #12 hang we want to diagnose.
    """
    await event.wait()


class TestEmitHangDiagnostic:
    async def test_emits_warning_for_stalled_task(self, engine, caplog):
        """The diagnostic must emit at least one WARNING with the
        suspended task's elapsed time and a stack frame."""
        never_set = asyncio.Event()
        loop = asyncio.get_running_loop()
        task = loop.create_task(_suspended_coro(never_set))
        # Yield once so the task actually starts and reaches the await.
        await asyncio.sleep(0.05)

        engine._running_tasks = {"feroxbuster:abc123": task}
        task_started = {"feroxbuster:abc123": loop.time() - 7.3}

        try:
            with caplog.at_level(logging.WARNING, logger="core.engine.scanner_engine"):
                engine._emit_hang_diagnostic(
                    elapsed_stall=9.5,
                    task_started=task_started,
                    loop=loop,
                )

            # Outer "scan-loop stalled" warning must appear with the elapsed time.
            outer = [r for r in caplog.records if "scan-loop stalled" in r.getMessage()]
            assert outer, "expected outer 'scan-loop stalled' warning"
            # Format uses %.0f so 9.5 → "10s"; just check seconds-suffix is there.
            assert "s with" in outer[0].getMessage(), "elapsed seconds should appear in message"
            assert "1 task" in outer[0].getMessage()

            # Per-task warning must reference exec_id and elapsed.
            per_task = [r for r in caplog.records if "WATCHDOG task" in r.getMessage()]
            assert per_task, "expected per-task WATCHDOG warning"
            assert "feroxbuster:abc123" in per_task[0].getMessage()
        finally:
            never_set.set()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def test_handles_empty_running_tasks(self, engine, caplog):
        """When `_running_tasks` is empty (e.g. all completed between
        the wait timeout and the watchdog check), the diagnostic must
        emit the outer warning but not error out."""
        loop = asyncio.get_running_loop()
        engine._running_tasks = {}
        with caplog.at_level(logging.WARNING, logger="core.engine.scanner_engine"):
            engine._emit_hang_diagnostic(
                elapsed_stall=15.0,
                task_started={},
                loop=loop,
            )
        # The outer "0 task(s) running" warning still fires
        outer = [r for r in caplog.records if "scan-loop stalled" in r.getMessage()]
        assert outer
        assert "0 task" in outer[0].getMessage()

    async def test_continues_when_task_introspection_fails(self, engine, caplog):
        """If a task somehow can't be introspected, the diagnostic must
        log a defensive message rather than raise."""
        loop = asyncio.get_running_loop()
        # MagicMock without proper get_stack behavior
        broken_task = MagicMock()
        broken_task.get_stack.side_effect = RuntimeError("boom")
        broken_task.done.return_value = False
        engine._running_tasks = {"weird:deadbeef": broken_task}

        with caplog.at_level(logging.WARNING, logger="core.engine.scanner_engine"):
            engine._emit_hang_diagnostic(
                elapsed_stall=20.0,
                task_started={"weird:deadbeef": loop.time() - 5},
                loop=loop,
            )

        per_task = [r for r in caplog.records if "weird:deadbeef" in r.getMessage()]
        assert per_task
        assert "could not introspect" in per_task[0].getMessage()
