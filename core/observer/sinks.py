"""
core/observer/sinks.py

Purpose:
    Destinations for telemetry.
    Sinks persist or display the events flowing through the bus.

Magnum Opus Standards:
    - Performance: File writes allow batched, non-blocking I/O.
    - Concurrency: Uses asyncio queues to decouple emission from writing.
    - Safety: Ensures flushing on shutdown.
"""

import logging
import asyncio
from pathlib import Path
from typing import TextIO, Optional

from .events import TelemetryEvent, EventLevel

log = logging.getLogger("observer.sinks")

class FileSink:
    """
    Writes events as NDJSON (Newline Delimited JSON).
    Uses a background worker to prevent I/O blocking the main loop.
    """
    def __init__(self, filepath: str):
        self.path = Path(filepath)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._queue: asyncio.Queue[TelemetryEvent] = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._keep_running = False
        
    async def start(self):
        """Start the background writer task."""
        self._keep_running = True
        self._worker_task = asyncio.create_task(self._process_queue())
        log.info(f"FileSink writer started for {self.path}")

    async def stop(self):
        """Flush and stop the writer."""
        self._keep_running = False
        if self._worker_task:
            await self._queue.join() # Wait for pending items
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        log.info("FileSink writer stopped.")

    async def handle(self, event: TelemetryEvent):
        """Subscriber callback (Async)."""
        await self._queue.put(event)

    async def _process_queue(self):
        """
        Background loop to consume queue and write to disk.
        """
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                while self._keep_running or not self._queue.empty():
                    # Batch fetch could be optimized here
                    try:
                        # Wait for an item, but wake up periodically to check stop flag
                        event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                        f.write(event.to_json() + "\n")
                        f.flush() # Explicit flush for durability, or optimize to flush less often
                        self._queue.task_done()
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        log.error(f"FileSink Write Error: {e}")
                        # If queue error, mark done to prevent hang
                        self._queue.task_done()
        except Exception as e:
            log.critical(f"FileSink Worker Crashed: {e}")

class ConsoleSink:
    """
    Human-readable console output.
    Sync is fine for stdout usually, but we make it async compatible.
    """
    async def handle(self, event: TelemetryEvent):
        # We run this directly. Stdout blocking is minimal for reasonable volumes,
        # but for massive logs, this should also be queued.
        if event.level in (EventLevel.ERROR, EventLevel.CRITICAL):
            icon = "🚨"
        elif event.level == EventLevel.WARNING:
            icon = "⚠️"
        else:
            icon = "ℹ️"
            
        print(f"{icon} [{event.timestamp:.3f}] {event.source} -> {event.type.value}: {event.payload}")
