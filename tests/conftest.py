"""Pytest configuration for SentinelForge."""
import os
import pytest


def pytest_configure():
    # Enable development mode for tests so loopback port wildcards are allowed.
    os.environ.setdefault("SENTINEL_DEBUG", "true")


@pytest.fixture(autouse=True)
def reset_constitution():
    """Reset Constitution singleton between tests to prevent state leakage."""
    from core.scheduler.laws import Constitution
    Constitution._instance = None
    yield
    Constitution._instance = None


def pytest_sessionfinish(session, exitstatus):
    """
    Clean up async resources after all tests complete.
    
    This prevents the 'Bad file descriptor' error on Python 3.14 by ensuring
    all async resources are properly closed before the event loop shuts down.
    """
    import asyncio
    
    async def cleanup():
        # Close Database connection if open
        try:
            from core.data.db import Database
            if Database._instance is not None:
                if Database._instance._db_connection:
                    await Database._instance.close()
                Database._instance = None
        except Exception:
            pass
        
        # Stop BlackBox worker
        try:
            from core.data.blackbox import BlackBox
            if BlackBox._instance is not None:
                BlackBox._instance._stopped = True
                BlackBox._instance._draining = True
                if BlackBox._instance._worker_task and not BlackBox._instance._worker_task.done():
                    BlackBox._instance._worker_task.cancel()
                    try:
                        await BlackBox._instance._worker_task
                    except asyncio.CancelledError:
                        pass
                BlackBox._instance = None
        except Exception:
            pass
    
    # Run cleanup in a fresh event loop
    try:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(cleanup())
        loop.close()
    except Exception:
        pass
