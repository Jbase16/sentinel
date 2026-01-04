"""
core/observer/events.py

Purpose:
    Defines the "nervous signals" of the system.
    Strictly typed, immutable, and serializable events.

Magnum Opus Standards:
    - Immutability: Events are facts; they cannot change.
    - Serde: Native support for JSON serialization.
    - Typing: Strict Enums for discoverability.
"""

from __future__ import annotations
from enum import Enum, auto
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, Optional
import json
import uuid

class EventLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class EventType(str, Enum):
    # System Lifecycle
    SYSTEM_STARTUP = "SYSTEM_STARTUP"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"
    
    # Aegis (Reasoning)
    PRESSURE_UPDATED = "PRESSURE_UPDATED"
    ASSET_DISCOVERED = "ASSET_DISCOVERED"
    
    # Thanatos (Planning)
    HYPOTHESIS_FORMED = "HYPOTHESIS_FORMED"
    TEST_CASE_GENERATED = "TEST_CASE_GENERATED"
    
    # Sentient (Decision)
    DECISION_MADE = "DECISION_MADE"
    
    # Executor (Action)
    EXECUTION_STARTED = "EXECUTION_STARTED"
    EXECUTION_COMPLETED = "EXECUTION_COMPLETED" # payload: {status, duration}
    
    # Oracle (Evaluation)
    BREACH_DETECTED = "BREACH_DETECTED"         # payload: {severity, target}
    ATTACK_DEFLECTED = "ATTACK_DEFLECTED"       # payload: {target}

@dataclass(frozen=True)
class TelemetryEvent:
    """
    An immutable atom of system behavior.
    """
    type: EventType
    source: str         # Component Name (e.g., "Executor")
    level: EventLevel
    payload: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    trace_id: Optional[str] = None # For correlating chains of events

    def to_json(self) -> str:
        data = asdict(self)
        # Convert Enum to string for serialization
        data['type'] = self.type.value
        data['level'] = self.level.value
        return json.dumps(data)

    @classmethod
    def from_json(cls, json_str: str) -> TelemetryEvent:
        data = json.loads(json_str)
        data['type'] = EventType(data['type'])
        data['level'] = EventLevel(data['level'])
        return cls(**data)
