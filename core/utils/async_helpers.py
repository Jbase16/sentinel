# core/utils/async_helpers.py
"""
Async utilities for safe task management.
"""

import asyncio
import logging
from typing import Coroutine, Any, Optional

logger = logging.getLogger(__name__)


def create_safe_task(
    coro: Coroutine[Any, Any, Any],
    name: Optional[str] = None,
    log_errors: bool = True
) -> asyncio.Task:
    """
    Create an asyncio task with automatic error handling.
    
    This prevents fire-and-forget tasks from silently swallowing exceptions.
    
    Args:
        coro: The coroutine to run as a task
        name: Optional name for the task (for logging)
        log_errors: Whether to log errors (default True)
        
    Returns:
        The created asyncio.Task
        
    Example:
        # Instead of: asyncio.create_task(some_coro())
        # Use: create_safe_task(some_coro(), name="save_finding")
    """
    task = asyncio.create_task(coro, name=name)
    
    def _handle_exception(t: asyncio.Task):
        try:
            exc = t.exception()
            if exc and log_errors:
                task_name = name or t.get_name()
                logger.error(f"[AsyncTask:{task_name}] Unhandled exception: {exc}", exc_info=exc)
        except asyncio.CancelledError:
            pass  # Task was cancelled, not an error
        except asyncio.InvalidStateError:
            pass  # Task not done yet (shouldn't happen in callback)
    
    task.add_done_callback(_handle_exception)
    return task


async def run_with_timeout(
    coro: Coroutine[Any, Any, Any],
    timeout: float,
    default: Any = None,
    name: Optional[str] = None
) -> Any:
    """
    Run a coroutine with a timeout, returning a default value on timeout.
    
    Args:
        coro: The coroutine to run
        timeout: Timeout in seconds
        default: Value to return if timeout occurs
        name: Optional name for logging
        
    Returns:
        The coroutine result, or default if timeout occurred
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        task_name = name or "unknown"
        logger.warning(f"[AsyncTask:{task_name}] Timed out after {timeout}s")
        return default
    except Exception as e:
        task_name = name or "unknown"
        logger.error(f"[AsyncTask:{task_name}] Error: {e}")
        return default


def fire_and_forget(coro: Coroutine[Any, Any, Any], name: Optional[str] = None) -> None:
    """
    Schedule a coroutine to run without waiting for the result.
    
    Unlike raw asyncio.create_task, this logs any exceptions that occur.
    
    Args:
        coro: The coroutine to run
        name: Optional name for logging
    """
    try:
        loop = asyncio.get_running_loop()
        create_safe_task(coro, name=name)
    except RuntimeError:
        # No running event loop - try to run in new loop
        logger.warning(f"[fire_and_forget:{name or 'unknown'}] No running loop, scheduling in new thread")
        import threading
        def run_in_thread():
            asyncio.run(coro)
        t = threading.Thread(target=run_in_thread, daemon=True)
        t.start()
