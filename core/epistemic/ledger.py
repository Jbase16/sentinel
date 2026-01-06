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
    NO MUTABLE STATE IN THIS CLASS.
    """
    id: str  # Deterministic hash (e.g. sha256 of tool+args+blob)
    timestamp: float
    tool: ToolContext
    target: str
    blob_hash: str  # Pointer to CAS content


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


@dataclass(frozen=True)
class StateRecord:
    """
    Mutable state wrapper for any epistemic entity (Observation or Finding).
    """
    entity_id: str
    state: LifecycleState
    reason: Optional[str] = None
    decider: str = "system"
    timestamp: float = field(default_factory=time.time)

from core.epistemic.events import EpistemicConflict

@dataclass
class WhyNot:
    """
    Explanation for why an Observation was NOT promoted to a Finding.
    Now just a specialized view of a 'SUPPRESSED' state record.
    """
    id: str
    related_id: str  # Observation ID or Finding ID
    decision: str    # "deprioritized", "false_positive"
    reason_code: str # "NO_EXPLOIT_PATH", "WAF_BLOCK"
    notes: str
    timestamp: float = field(default_factory=time.time)



@dataclass
class FindingProposal:
    """
    Proposed finding from an AI or heuristic source.
    Subject to validation by the Ledger before becoming a Finding.
    """
    title: str
    severity: str
    description: str
    citations: List[Citation]
    source: str = "ai"
    metadata: Dict[str, Any] = field(default_factory=dict)


class EvidenceLedger:
    """
    Authoritative store for Sentinel's epistemic state.
    Manages:
    1. Immutable Evidence (CAS + Observations)
    2. Mutable Beliefs (StateTable)
    3. Epistemic Conflicts (Disagreements)
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig.from_env()
        self.cas = ContentAddressableStorage(self.config)
        
        # 1. Immutable Stores
        self._observations: Dict[str, Observation] = {}
        self._findings: Dict[str, Finding] = {}
        self._conflicts: List[EpistemicConflict] = []
        
        # 2. Mutable State Table (The Belief System)
        # Maps entity_id -> StateRecord
        self._state_table: Dict[str, StateRecord] = {}

    def record_observation(self, tool_name: str, tool_args: List[str], target: str, 
                          raw_output: bytes, exit_code: int = 0) -> Observation:
        """
        Ingest raw tool output.
        1. Store raw data in CAS -> Get blob_hash
        2. Create Observation record
        3. Index it locally
        4. Initialize State as OBSERVED
        """
        # 1. Store in CAS
        blob_hash = self.cas.store(raw_output)
        
        # 2. Generate Deterministic ID
        unique_string = f"{tool_name}:{target}:{blob_hash}"
        obs_id = f"obs-{uuid.uuid5(uuid.NAMESPACE_DNS, unique_string).hex[:12]}"
        
        # 3. Create Immutable Record
        obs = Observation(
            id=obs_id,
            timestamp=time.time(),
            tool=ToolContext(name=tool_name, args=tool_args, exit_code=exit_code),
            target=target,
            blob_hash=blob_hash
        )
        
        # 4. Index & Initialize State
        if obs_id not in self._observations:
            self._observations[obs_id] = obs
            self._set_state(obs_id, LifecycleState.OBSERVED, reason="Initial ingestion")
            logger.info(f"[EvidenceLedger] Recorded Observation {obs_id}: {tool_name} -> {blob_hash[:8]}")
        else:
            logger.debug(f"[EvidenceLedger] Idempotent observation seen: {obs_id}")
            
        return obs

    def evaluate_and_promote(self, proposal: FindingProposal) -> Optional[Finding]:
        """
        Gatekeeper Logic: Validates a proposal and promotes it to a Finding.
        Enforces:
        1. Must have citations.
        2. Citations must point to known observations.
        3. Citations must not be SUPPRESSED (unless override?).
        
        Returns promoted Finding or None if rejected.
        """
        # 1. Check Citations Existence
        if not proposal.citations:
            logger.warning(f"[EvidenceLedger] Rejected proposal '{proposal.title}': No citations.")
            # We could record a 'REJECTED' state record for the *proposal* if we had IDs for them.
            return None
            
        valid_citations = []
        for c in proposal.citations:
            if c.observation_id in self._observations:
                obs_state = self.get_state(c.observation_id)
                if obs_state and obs_state.state == LifecycleState.SUPPRESSED:
                    logger.info(f"[EvidenceLedger] Proposal cites SUPPRESSED evidence {c.observation_id}. Proceeding with caution.")
                valid_citations.append(c)
            else:
                logger.warning(f"[EvidenceLedger] Proposal cites unknown observation {c.observation_id}.")
        
        if not valid_citations:
            logger.warning(f"[EvidenceLedger] Rejected proposal '{proposal.title}': No valid citations found.")
            return None
            
        # 2. Promote
        # Note: We use valid_citations, effectively filtering out hallucinations
        return self.promote_finding(
            title=proposal.title,
            severity=proposal.severity,
            citations=valid_citations,
            description=proposal.description,
            **proposal.metadata
        )

    def promote_finding(self, title: str, severity: str, citations: List[Citation], 
                       description: str, **kwargs) -> Finding:
        """
        Internal promotion logic.
        """
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
        self._set_state(find_id, LifecycleState.PROMOTED, reason="AI/Human promotion")
        
        logger.info(f"[EvidenceLedger] Promoted Finding {find_id}: {title}")
        
        # PROJECTION: Update global findings store (Read-model)
        # Ideally this would be an event listener, but for now we push.
        from core.data.findings_store import findings_store
        
        # Convert to dict format expected by findings_store
        finding_dict = {
            "id": finding.id,
            "title": finding.title, # Store expects 'type' or 'title' usually? Check legacy schema.
            "type": kwargs.get("type", "General"), # Legacy field
            "severity": finding.severity,
            "value": finding.description, # Legacy field mapping
            "description": finding.description,
            "citations": [asdict(c) for c in citations],
            "metadata": kwargs
        }
        findings_store.add_finding(finding_dict)
        
        return finding

    def suppress(self, related_id: str, reason_code: str, notes: str) -> StateRecord:
        """
        Move an entity to SUPPRESSED state.
        This provides the "WhyNot" reasoning.
        """
        if related_id not in self._observations and related_id not in self._findings:
            logger.warning(f"[EvidenceLedger] Suppressing unknown entity {related_id}")

        # Update the State Table
        reason = f"{reason_code}: {notes}"
        return self._set_state(related_id, LifecycleState.SUPPRESSED, reason=reason)

    def register_conflict(self, source_a_id: str, source_b_id: str, 
                         description: str, conflict_type: str = "direct_contradiction"):
        """
        Record an epistemic conflict between two observations.
        """
        conflict_id = f"conflict-{uuid.uuid4().hex[:8]}"
        conflict = EpistemicConflict(
            id=conflict_id,
            source_a_id=source_a_id,
            source_b_id=source_b_id,
            conflict_type=conflict_type,
            description=description
        )
        self._conflicts.append(conflict)
        logger.warning(f"[EvidenceLedger] Conflict Registered: {source_a_id} vs {source_b_id} ({description})")
        return conflict

    def _set_state(self, entity_id: str, state: LifecycleState, reason: Optional[str] = None) -> StateRecord:
        """Internal helper to update state table."""
        record = StateRecord(
            entity_id=entity_id,
            state=state,
            reason=reason,
            timestamp=time.time()
        )
        self._state_table[entity_id] = record
        return record

    def get_state(self, entity_id: str) -> Optional[StateRecord]:
        """Retrieve the current belief state of an entity."""
        return self._state_table.get(entity_id)

    def get_observation(self, obs_id: str) -> Optional[Observation]:
        return self._observations.get(obs_id)
        
    def get_blob(self, obs_id: str) -> Optional[bytes]:
        """Retrieve raw content for an observation."""
        obs = self.get_observation(obs_id)
        if not obs:
            return None
        return self.cas.load(obs.blob_hash)
