"""
core/scheduler/events.py
Event Types for the Agent Loop.
Strategos listens for these events from the Worker.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
import time

@dataclass
class ToolStartedEvent:
    """Emitted when a tool starts execution."""
    tool: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class ToolCompletedEvent:
    """Emitted when a tool finishes execution."""
    tool: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = True
    duration_seconds: float = 0.0
    timestamp: float = field(default_factory=time.time)

@dataclass
class MissionTerminatedEvent:
    """Emitted when Strategos decides to stop."""
    reason: str
    timestamp: float = field(default_factory=time.time)
