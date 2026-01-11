"""
core/omega/models.py
Omega Data Models.

This file defines the strict schema for Omega artifacts stored in the findings/results DB.
"""

from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class CronusResult(BaseModel):
    snapshots_analyzed: int = 0
    zombies_found: int = 0
    zombies_confirmed: int = 0

class MimicResult(BaseModel):
    traffic_observed_count: int = 0
    secrets_redacted_count: int = 0
    shadow_routes_found: int = 0

class NexusResult(BaseModel):
    hypotheses_generated: int = 0
    insights_formed: int = 0

class OmegaScanResult(BaseModel):
    """
    The versioned 'omega' block in scan results.
    """
    schema_version: int = Field(1, const=True)
    scan_id: str
    
    # Per-Phase Summaries
    cronus: CronusResult = Field(default_factory=CronusResult)
    mimic: MimicResult = Field(default_factory=MimicResult)
    nexus: NexusResult = Field(default_factory=NexusResult)
    
    # Governance Stats
    budget_consumed: Dict[str, float] = Field(default_factory=dict)
    contract_violations: int = 0
