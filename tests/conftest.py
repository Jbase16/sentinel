"""Pytest configuration for SentinelForge."""
import os
import sys
import warnings
import atexit


def pytest_configure():
    # Enable development mode for tests so loopback port wildcards are allowed.
    os.environ.setdefault("SENTINEL_DEBUG", "true")
    # Keep test writes inside a writable sandbox path (avoid $HOME restrictions).
    os.environ.setdefault("SENTINEL_DATA_DIR", "/tmp/sentinelforge_test")
    
    # Suppress known deprecation warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")

    # Many subsystems (EventBus, DecisionLedger) require the global sequence
    # authority to be initialized. In production this happens during startup;
    # tests should mirror that invariant.
    try:
        import asyncio
        from core.base.sequence import GlobalSequenceAuthority

        loop = asyncio.new_event_loop()
        loop.run_until_complete(GlobalSequenceAuthority.initialize_from_db())
        loop.close()
    except Exception:
        # Tests that don't emit events/decisions shouldn't fail hard here.
        pass


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
