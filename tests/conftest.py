"""Pytest configuration for SentinelForge."""
from __future__ import annotations

import asyncio
import os
import sys
import warnings

import pytest

# Ensure application modules resolve from repo root, not tests/* shadow packages.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


def pytest_configure(config):
    # Register the marker used by the pinned pytest-asyncio runtime.
    config.addinivalue_line("markers", "asyncio: run async test via pytest-asyncio")

    # Enable development mode for tests so loopback port wildcards are allowed.
    os.environ.setdefault("SENTINEL_DEBUG", "true")
    # Keep test writes inside a writable sandbox path (avoid $HOME restrictions).
    os.environ.setdefault("SENTINEL_DATA_DIR", "/tmp/sentinelforge_test")
    
    # Suppress known deprecation warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")

    # Many subsystems (EventBus, DecisionLedger) require the global sequence
    # authority to be initialized. For unit tests we bypass DB startup to keep
    # tests hermetic and avoid initialization order pitfalls (migrations, IO).
    try:
        from core.base.sequence import GlobalSequenceAuthority

        GlobalSequenceAuthority.reset_for_testing()
        GlobalSequenceAuthority.initialize_for_testing(start=1)
    except Exception:
        # Tests that don't emit events/decisions shouldn't fail hard here.
        pass


def _reset_event_runtime() -> None:
    """Reset process-wide event state that must share the sequence epoch."""
    import core.cortex.event_store as event_store_module
    import core.cortex.events as events_module

    event_store_module._store = None
    events_module._event_bus = None
    events_module.reset_run_id()
    events_module.reset_contract_state()


def _close_persistence_runtime() -> None:
    """Close loop-bound persistence resources before the next test starts."""
    from core.data.blackbox import BlackBox
    from core.data.db import Database

    db = Database._instance
    blackbox = BlackBox._instance

    if db is not None and db._db_connection is not None:
        preferred_loop = db._loop
        owns_loop = (
            preferred_loop is None
            or preferred_loop.is_closed()
            or preferred_loop.is_running()
        )
        loop = asyncio.new_event_loop() if owns_loop else preferred_loop

        async def close_runtime() -> None:
            worker = getattr(db.blackbox, "_worker_task", None)
            if (
                worker is not None
                and not worker.done()
                and worker.get_loop() is asyncio.get_running_loop()
            ):
                await db.blackbox.shutdown()
            await db.close()

        try:
            loop.run_until_complete(close_runtime())
        finally:
            if owns_loop:
                loop.close()

    if db is not None:
        db._db_connection = None
        db._initialized = False
        db._init_lock = None
        db._db_lock = None
        db._loop = None

    if blackbox is not None:
        blackbox._draining = True
        blackbox._stopped = True

    fresh_blackbox = BlackBox()
    BlackBox._instance = fresh_blackbox
    if db is not None:
        db.blackbox = fresh_blackbox


@pytest.fixture(autouse=True)
def isolate_process_runtime():
    """Give every test fresh sequence, event, and persistence runtimes."""
    from core.base.sequence import GlobalSequenceAuthority

    _reset_event_runtime()
    GlobalSequenceAuthority.reset_for_testing()
    GlobalSequenceAuthority.initialize_for_testing(start=1)
    try:
        yield
    finally:
        _close_persistence_runtime()
        _reset_event_runtime()
        GlobalSequenceAuthority.reset_for_testing()


def pytest_unconfigure(config):
    """Clean up process-wide test runtimes after pytest finishes."""
    try:
        _close_persistence_runtime()
    except Exception:
        pass

    try:
        _reset_event_runtime()
    except Exception:
        pass
