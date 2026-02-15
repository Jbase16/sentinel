"""Pytest configuration for SentinelForge."""
from __future__ import annotations

import asyncio
import inspect
import os
import sys
import warnings
import atexit

# Ensure application modules resolve from repo root, not tests/* shadow packages.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


def pytest_configure(config):
    # Register markers referenced across the suite even when optional plugins
    # (like pytest-asyncio) aren't installed.
    config.addinivalue_line("markers", "asyncio: run async test via built-in asyncio runner")

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


def pytest_pyfunc_call(pyfuncitem):
    """
    Minimal asyncio runner for async tests.

    The repo's test suite uses `async def` tests and `@pytest.mark.asyncio`,
    but the environment running these tests may not have `pytest-asyncio`
    installed. This hook runs coroutine tests via `asyncio.run()` so unit
    tests remain executable without extra dependencies.
    """
    testfunction = pyfuncitem.obj
    if not inspect.iscoroutinefunction(testfunction):
        return None

    # Only pass fixtures that are explicit arguments to the test function.
    argnames = getattr(pyfuncitem, "_fixtureinfo", None)
    argnames = getattr(argnames, "argnames", ()) if argnames is not None else ()
    kwargs = {name: pyfuncitem.funcargs[name] for name in argnames}

    asyncio.run(testfunction(**kwargs))
    return True


def pytest_unconfigure(config):
    """
    Clean up after pytest finishes.
    
    Python 3.14 has stricter asyncio shutdown that can cause
    'Bad file descriptor' errors during pytest-asyncio teardown.
    We suppress these by forcing cleanup of known singletons.
    """
    # Force cleanup of async singletons that may hold file descriptors
    try:
        from core.data.db import Database
        if Database._instance is not None and Database._instance._db_connection:
            import asyncio
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(Database._instance.close())
                loop.close()
            except Exception:
                pass
            Database._instance = None
    except Exception:
        pass
    
    try:
        from core.data.blackbox import BlackBox
        if BlackBox._instance is not None:
            BlackBox._instance._stopped = True
            BlackBox._instance._draining = True
            BlackBox._instance = None
    except Exception:
        pass
