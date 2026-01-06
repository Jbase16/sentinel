"""
Evidence Ledger (The Truth Store).

This module defines the authoritative record of all observations and findings.
It distinguishes between:
1. Observation (Immutable raw fact, stored in CAS)
2. Fact (Normalized data derived from Observation)
3. Finding (Actionable intelligence citing Observations)
4. WhyNot (Reasoning for discarded/suppressed findings)
"""

import logging
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Union
from enum import Enum

from core.epistemic.cas import ContentAddressableStorage
from core.base.config import SentinelConfig

logger = logging.getLogger(__name__)


class LifecycleState(str, Enum):
    OBSERVED = "observed"       # Raw data ingested
    PROMOTED = "promoted"       # Became a Finding
    SUPPRESSED = "suppressed"   # Ignored (with WhyNot)
    REJECTED = "rejected"       # Proven false (e.g. sensor glitch)


@dataclass(frozen=True)
class ToolContext:
    name: str
    args: List[str]
    version: Optional[str] = None
    exit_code: int = 0


@dataclass(frozen=True)
class Observation:
    """
    Atomic, immutable capture of raw tool output.
    Identified by a deterministic hash of its content.
    """
    id: str  # Deterministic hash (e.g. sha256 of tool+args+blob)
    timestamp: float
    tool: ToolContext
    target: str
    blob_hash: str  # Pointer to CAS content
    
    # Metadata for quick filtering
    lifecycle: LifecycleState = field(default=LifecycleState.OBSERVED)


@dataclass
class Citation:
    """
    A strict link to evidence.
    """
    observation_id: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    snippet: Optional[str] = None  # Short quote for verification


@dataclass
class Finding:
    """
    Actionable intelligence derived from Observations.
    MUST have citations.
    """
    id: str
    title: str
    severity: str
    citations: List[Citation]
    description: str
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WhyNot:
    """
    Explanation for why an Observation was NOT promoted to a Finding.
    """
    id: str
    related_id: str  # Observation ID or Finding ID
    decision: str    # "deprioritized", "false_positive"
    reason_code: str # "NO_EXPLOIT_PATH", "WAF_BLOCK"
    notes: str
    timestamp: float = field(default_factory=time.time)


class EvidenceLedger:
    """
    Authoritative store for Sentinel's epistemic state.
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig.from_env()
        self.cas = ContentAddressableStorage(self.config)
        
        # In-memory indices (backed by DB in production, currently simplistic)
        self._observations: Dict[str, Observation] = {}
        self._findings: Dict[str, Finding] = {}
        self._whynots: Dict[str, WhyNot] = {}

    def record_observation(self, tool_name: str, tool_args: List[str], target: str, 
                          raw_output: bytes, exit_code: int = 0) -> Observation:
        """
        Ingest raw tool output.
        1. Store raw data in CAS -> Get blob_hash
        2. Create Observation record
        3. Index it locally
        """
        # 1. Store in CAS
        blob_hash = self.cas.store(raw_output)
        
        # 2. Generate Deterministic ID
        # Hashing stable fields ensures idempotency
        # If we run same tool on same target and get same output -> Same Obs ID
        unique_string = f"{tool_name}:{target}:{blob_hash}"
        obs_id = f"obs-{uuid.uuid5(uuid.NAMESPACE_DNS, unique_string).hex[:12]}"
        
        obs = Observation(
            id=obs_id,
            timestamp=time.time(),
            tool=ToolContext(name=tool_name, args=tool_args, exit_code=exit_code),
            target=target,
            blob_hash=blob_hash,
            lifecycle=LifecycleState.OBSERVED
        )
        
        # 3. Index
        if obs_id not in self._observations:
            self._observations[obs_id] = obs
            logger.info(f"[EvidenceLedger] Recorded Observation {obs_id}: {tool_name} -> {blob_hash[:8]}")
        else:
            logger.debug(f"[EvidenceLedger] Idempotent observation seen: {obs_id}")
            
        return obs

    def promote_finding(self, title: str, severity: str, citations: List[Citation], 
                       description: str, **kwargs) -> Finding:
        """
        Create a valid finding.
        Enforces: Must have citations.
        """
        if not citations:
            raise ValueError(f"CRITICAL: Finding '{title}' rejected. No citations provided.")
            
        # Verify valid citations
        for c in citations:
            if c.observation_id not in self._observations:
                logger.warning(f"[EvidenceLedger] Cite check warning: Observation {c.observation_id} not found in this runtime.")
        
        find_id = f"find-{uuid.uuid4().hex[:8]}"
        finding = Finding(
            id=find_id,
            title=title,
            severity=severity,
            citations=citations,
            description=description,
            metadata=kwargs
        )
        
        self._findings[find_id] = finding
        logger.info(f"[EvidenceLedger] Promoted Finding {find_id}: {title} (Cited {len(citations)} sources)")
        return finding

    def suppress(self, related_id: str, reason_code: str, notes: str) -> WhyNot:
        """
        Record a decision to ignore/deprioritize something.
        """
        # Updates lifecycle state if it's an observation
        if related_id in self._observations:
            # We treat Observation as immutable, but we can update a separate "State Table"
            # For now, simplistic override (real implementation needs DB updates)
            # obj = self._observations[related_id]
            # object.__setattr__(obj, 'lifecycle', LifecycleState.SUPPRESSED) 
            pass # Keep it immutable for now
            
        wn_id = f"wn-{uuid.uuid4().hex[:8]}"
        whynot = WhyNot(
            id=wn_id,
            related_id=related_id,
            decision="suppressed",
            reason_code=reason_code,
            notes=notes
        )
        self._whynots[wn_id] = whynot
        logger.info(f"[EvidenceLedger] Suppressed {related_id}: {reason_code} - {notes}")
        return whynot

    def get_observation(self, obs_id: str) -> Optional[Observation]:
        return self._observations.get(obs_id)
        
    def get_blob(self, obs_id: str) -> Optional[bytes]:
        """Retrieve raw content for an observation."""
        obs = self.get_observation(obs_id)
        if not obs:
            return None
        return self.cas.load(obs.blob_hash)
