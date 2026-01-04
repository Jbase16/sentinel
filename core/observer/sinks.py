"""
core/observer/sinks.py

Purpose:
    Destinations for telemetry.
    Sinks persist or display the events flowing through the bus.

Magnum Opus Standards:
    - Fault Tolerance: File writing errors handled gracefully.
    - Performance: Buffered writing (future).
"""

import logging
import sys
from pathlib import Path
from typing import TextIO, Optional

from .events import TelemetryEvent, EventLevel

log = logging.getLogger("observer.sinks")

class FileSink:
    """
    Writes events as NDJSON (Newline Delimited JSON).
    """
    def __init__(self, filepath: str):
        self.path = Path(filepath)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file: Optional[TextIO] = None
        
    def open(self):
        self._file = open(self.path, "a", encoding="utf-8")
        
    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def handle(self, event: TelemetryEvent):
        """Subscriber callback."""
        if not self._file:
            # Auto-open if not managed externally
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(event.to_json() + "\n")
            except Exception as e:
                log.error(f"FileSink Write Error: {e}")
        else:
            try:
                self._file.write(event.to_json() + "\n")
                self._file.flush() # Ensure durability
            except Exception as e:
                log.error(f"FileSink Stream Error: {e}")

class ConsoleSink:
    """
    Human-readable console output.
    """
    def handle(self, event: TelemetryEvent):
        if event.level in (EventLevel.ERROR, EventLevel.CRITICAL):
            icon = "🚨"
        elif event.level == EventLevel.WARNING:
            icon = "⚠️"
        else:
            icon = "ℹ️"
            
        print(f"{icon} [{event.timestamp:.3f}] {event.source} -> {event.type.value}: {event.payload}")
