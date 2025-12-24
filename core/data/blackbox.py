"""Module blackbox: inline documentation for /Users/jason/Developer/sentinelforge/core/data/blackbox.py."""

import asyncio
import logging
from typing import Callable, Any, Optional, Awaitable

logger = logging.getLogger(__name__)

class BlackBox:
    """
    The Flight Recorder (Persistence Actor).
    
    Responsibilities:
    1.  Serialize all database writes into a single "funnel".
    2.  Prevent "database is locked" by ensuring only one writer exists.
    3.  Manage lifecycle: Ensure all pending writes are flushed to disk before shutdown.
    
    This acts as a barrier:
    - Callers (Scanner) fire-and-forget (mostly) or await enqueue.
    - Worker loop drains the queue and executes the writes.
    - On shutdown, we refuse to die until the queue is empty.
    """
    _instance = None
    
    @staticmethod
    def instance():
        """Function instance."""
        # Conditional branch.
        if BlackBox._instance is None:
            BlackBox._instance = BlackBox()
        return BlackBox._instance

    def __init__(self):
        """Function __init__."""
        self._queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        self._draining = False
        self._stopped = False

    def start(self):
        """Start the writer loop if not already running."""
        # Conditional branch.
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._writer_loop(), name="BlackBox-Writer")
            logger.info("[BlackBox] Writer loop started.")

    async def _writer_loop(self):
        """Forever loop consuming write tasks."""
        logger.debug("[BlackBox] Loop active.")
        # While loop.
        while not self._stopped:
            try:
                # Get a task
                # We fetch one by one, but typically SQLite works best if we commit often 
                # or batch. For now, strict serialization is the goal.
                item = await self._queue.get()
                
                if item is None:
                    # Sentinel for shutdown signal inside the queue
                    self._queue.task_done()
                    break

                func, args, kwargs, future = item
                
                try:
                    # Execute the write
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)
                        
                    # If the caller is waiting on a result (rare for logging, but possible)
                    if future and not future.done():
                        future.set_result(result)
                        
                except Exception as e:
                    logger.error(f"[BlackBox] Write failure: {e}", exc_info=True)
                    if future and not future.done():
                        future.set_exception(e)
                finally:
                    self._queue.task_done()
                    
            except asyncio.CancelledError:
                logger.info("[BlackBox] Loop cancelled.")
                break
            except Exception as e:
                logger.critical(f"[BlackBox] Critical loop error: {e}", exc_info=True)
                await asyncio.sleep(1) # Anti-spin

    async def enqueue(self, func: Callable[..., Awaitable[Any]], *args, **kwargs) -> Any:
        """
        Schedule a write operation.
        Returns a Future that resolves when the write is COMPLETE.
        Use this if you need backpressure or confirmation.
        """
        # Conditional branch.
        if self._draining or self._stopped:
             raise RuntimeError("[BlackBox] Cannot write: System is shutting down.")
             
        # Conditional branch.
        if self._worker_task is None:
            self.start()
            
        future = asyncio.get_running_loop().create_future()
        await self._queue.put((func, args, kwargs, future))
        return await future

    def fire_and_forget(self, func: Callable[..., Awaitable[Any]], *args, **kwargs) -> None:
        """
        Schedule a write without waiting for it.
        """
        # Conditional branch.
        if self._draining or self._stopped:
             logger.warning(f"[BlackBox] Drop write to {func.__name__}: draining/stopped.")
             return
             
        # Conditional branch.
        if self._worker_task is None:
            self.start()

        # We push to queue synchronously? No, queue.put is async if full.
        # But queue is unbounded by default.
        try:
             self._queue.put_nowait((func, args, kwargs, None))
        except asyncio.QueueFull:
             # Should not happen with unbounded
             logger.error("[BlackBox] Queue full! Dropping write.")

    async def shutdown(self):
        """
        Graceful shutdown protocol.
        1. Mark as draining (no new writes).
        2. Wait for queue to empty.
        3. Stop worker.
        """
        logger.info(f"[BlackBox] Initiating Shutdown. Pending writes: {self._queue.qsize()}")
        self._draining = True
        
        # Insert sentinel to wake up loop if it's idle
        await self._queue.put(None)
        
        # Wait for all tasks to be marked done
        if self._queue.qsize() > 0:
            logger.info("[BlackBox] Waiting for queue drain...")
            await self._queue.join()
        
        self._stopped = True
        
        # Conditional branch.
        if self._worker_task:
            # It should have exited due to None sentinel, but ensure it
            try:
                await asyncio.wait_for(self._worker_task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("[BlackBox] Writer loop timed out during shutdown. Force cancelling.")
                self._worker_task.cancel()
        
        logger.info("[BlackBox] Shutdown Complete.")
