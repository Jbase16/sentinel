"""
System Self-Audit Schema
Defines the structure of the post-scan audit artifact.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

class SubsystemStats(BaseModel):
    """
    Statistics for a specific subsystem.
    Structure is rigid and numeric to ensure easier diffing and thresholding.
    """
    exercised: bool = Field(..., description="Whether the subsystem performed any active work.")
    counters: Dict[str, int] = Field(default_factory=dict, description="Numeric counters of activity (decisions, blocks, executions).")

class SystemSelfAudit(BaseModel):
    """
    The authoritative record of what Sentinel actually exercised during a scan.
    This artifact is deterministic and must be reproducible from the event stream.
    """
    scan_id: str
    completed_at: float = Field(..., description="Timestamp of completion.")
    event_sequence_end: int = Field(..., description="The final event sequence number this audit was derived from.")
    source_epoch: str = Field(..., description="Stable identifier for the execution run (e.g. session UUID).")
    
    subsystems: Dict[str, SubsystemStats] = Field(..., description="Stats per subsystem (strategos, policies, tools, graph, etc).")
    idle_subsystems: List[str] = Field(default_factory=list, description="List of subsystems explicitly determined to be idle.")
    anomalies: List[str] = Field(default_factory=list, description="Detected anomalies (e.g. churn, high block rate).")
    confidence: float = Field(..., description="Confidence in the audit's completeness (0.0 - 1.0).")
