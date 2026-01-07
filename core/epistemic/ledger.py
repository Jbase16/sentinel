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
from core.replay.merkle import MerkleEngine

logger = logging.getLogger(__name__)


class LifecycleState(str, Enum):
    OBSERVED = "observed"       # Raw data ingested
    PROMOTED = "promoted"       # Became a Finding
    SUPPRESSED = "suppressed"   # Ignored (with WhyNot)
    REJECTED = "rejected"       # Proven false (e.g. sensor glitch)
    INVALIDATED = "invalidated" # Was Promoted, now false (Time travel)



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


from core.epistemic.events import EpistemicConflict, EpistemicEvent, EventType, ConflictType


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
    2. Event Log (The Source of Truth)
    3. Derived View (StateTable, Findings)
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig.from_env()
        self.cas = ContentAddressableStorage(self.config)
        
        # 1. Immutable Stores (The "What")
        self._observations: Dict[str, Observation] = {}
        # Technically 'findings' map is also a view now, but we keep it for fast lookup
        self._findings: Dict[str, Finding] = {}
        self._conflicts: List[EpistemicConflict] = []
        
        # 2. Event Log (The "When" and "Why")
        self._event_log: List[EpistemicEvent] = []
        
        # 2b. Audit Persistence
        self._audit_path = self.config.storage.base_dir / "audit.jsonl"
        # Ensure header exists
        if not self._audit_path.exists():
            with open(self._audit_path, "a") as f:
                f.write(json.dumps({"type": "header", "version": "1.0", "created": time.time()}) + "\n")
        
        # 2c. Reactive Listeners
        self._listeners: List[Callable[[EpistemicEvent], None]] = []

        # 3. Derived Views (The "Now")

        
        # 3. Derived Views (The "Now")
        self._state_table: Dict[str, StateRecord] = {}

    def _generate_deterministic_id(self, prefix: str, content: Any) -> str:
        """Generate a deterministic ID based on content hash."""
        # Use first 12 chars of SHA256 (48 bits of entropy is enough for local collision resistance)
        # We rely on MerkleEngine for canonicalization.
        return f"{prefix}-{MerkleEngine.compute_hash(content)[:12]}"

    # ------------------------------------------------------------------
    # Reactivity
    # ------------------------------------------------------------------
    def subscribe(self, callback) -> Callable[[], None]:
        """
        Register a listener for ledger events.
        Returns: A callable that removes the subscription when invoked.
        """
        self._listeners.append(callback)
        
        def unsubscribe():
            if callback in self._listeners:
                self._listeners.remove(callback)
        return unsubscribe

    def record_observation(self, tool_name: str, tool_args: List[str], target: str, 
                          raw_output: bytes, exit_code: int = 0, 
                          timestamp_override: Optional[float] = None) -> Observation:
        """
        Ingest raw tool output.
        """
        # 1. Store in CAS
        blob_hash = self.cas.store(raw_output)
        
        unique_string = f"{tool_name}:{target}:{blob_hash}"
        obs_id = f"obs-{uuid.uuid5(uuid.NAMESPACE_DNS, unique_string).hex[:12]}"
        
        # 2. Create Immutable Record
        obs = Observation(
            id=obs_id,
            timestamp=timestamp_override or time.time(),
            tool=ToolContext(name=tool_name, args=tool_args, exit_code=exit_code),
            target=target,
            blob_hash=blob_hash
        )
        
        # 3. Index locally (Optimization: Don't need event for existence of blob/obs definition)
        if obs_id not in self._observations:
            self._observations[obs_id] = obs
            
            # Emit OBSERVED event
            self._emit_event(
                event_type=EventType.OBSERVED,
                entity_id=obs_id,
                payload={"tool": tool_name, "target": target, "blob_hash": blob_hash},
                timestamp_override=timestamp_override
            )
            
            logger.info(f"[EvidenceLedger] Recorded Observation {obs_id}: {tool_name} -> {blob_hash[:8]}")
        else:
            logger.debug(f"[EvidenceLedger] Idempotent observation seen: {obs_id}")
            
        return obs

    def evaluate_and_promote(self, proposal: FindingProposal) -> Optional[Finding]:
        """
        Gatekeeper Logic: Validates a proposal and promotes it to a Finding.
        """
        # 1. Check Citations Existence
        if not proposal.citations:
            logger.warning(f"[EvidenceLedger] Rejected proposal '{proposal.title}': No citations.")
            return None
            
        valid_citations = []
        for c in proposal.citations:
            if c.observation_id in self._observations:
                obs_state = self.get_state(c.observation_id)
                if obs_state and obs_state.state == LifecycleState.SUPPRESSED:
                    logger.info(f"[EvidenceLedger] Proposal cites SUPPRESSED evidence {c.observation_id}. Proceeding with caution.")
                elif obs_state and obs_state.state in [LifecycleState.INVALIDATED, LifecycleState.REJECTED]:
                    logger.warning(f"[EvidenceLedger] Proposal cites INVALIDATED evidence {c.observation_id}.")
                    continue # Skip invalid evidence
                    
                valid_citations.append(c)
            else:
                logger.warning(f"[EvidenceLedger] Proposal cites unknown observation {c.observation_id}.")
        
        if not valid_citations:
            logger.warning(f"[EvidenceLedger] Rejected proposal '{proposal.title}': No valid citations found.")
            return None
            
        # 2. Promote
        return self.promote_finding(
            title=proposal.title,
            severity=proposal.severity,
            citations=valid_citations,
            description=proposal.description,
            **proposal.metadata
        )

    def promote_finding(self, title: str, severity: str, citations: List[Citation], 
                       description: str, timestamp_override: Optional[float] = None, **kwargs) -> Finding:
        """
        Internal promotion logic.
        """
        # Deterministic ID generation based on immutable attributes
        content_hash_input = {
            "title": title,
            "severity": severity,
            "description": description,
            "citations": [asdict(c) for c in citations],
            # Metadata might contain timestamps, so be careful. 
            # But Finding ID should be content-based.
            "metadata": kwargs
        }
        find_id = self._generate_deterministic_id("find", content_hash_input)
        
        finding = Finding(
            id=find_id,
            title=title,
            severity=severity,
            citations=citations,
            description=description,
            metadata=kwargs
        )
        
        self._findings[find_id] = finding
        
        # Emit PROMOTED event
        self._emit_event(
            event_type=EventType.PROMOTED,
            entity_id=find_id,
            payload={
                "title": title,
                "severity": severity,
                "citations": [asdict(c) for c in citations],
                "description": description,
                "metadata": kwargs
            },
            timestamp_override=timestamp_override
        )
        
        # Push to findings_store (Read Model)
        self._update_findings_store(finding)
        
        logger.info(f"[EvidenceLedger] Promoted Finding {find_id}: {title}")
        return finding

    def suppress(self, related_id: str, reason_code: str, notes: str, 
                 timestamp_override: Optional[float] = None) -> StateRecord:
        """
        Move an entity to SUPPRESSED state.
        """
        if related_id not in self._observations and related_id not in self._findings:
            logger.warning(f"[EvidenceLedger] Suppressing unknown entity {related_id}")
            
        # Emit SUPPRESSED event
        event = self._emit_event(
            event_type=EventType.SUPPRESSED,
            entity_id=related_id,
            payload={
                "reason_code": reason_code,
                "notes": notes
            },
            timestamp_override=timestamp_override
        )
        
        # Return the new state record
        return self.get_state(related_id)

    def invalidate_finding(self, finding_id: str, reason: str, timestamp_override: Optional[float] = None):
        """
        Transition a finding to INVALIDATED state.
        Triggered by conflicting evidence or manual review.
        """
        if finding_id not in self._findings:
            logger.error(f"[EvidenceLedger] Cannot invalidate unknown finding {finding_id}")
            return
            
        self._emit_event(
            event_type=EventType.INVALIDATED,
            entity_id=finding_id,
            payload={"reason": reason},
            timestamp_override=timestamp_override
        )
        logger.info(f"[EvidenceLedger] Invalidated Finding {finding_id}: {reason}")

    def register_conflict(self, source_a_id: str, source_b_id: str, 
                         description: str, conflict_type: str = "direct_contradiction",
                         timestamp_override: Optional[float] = None):
        """
        Record an epistemic conflict between two observations.
        """
        content_hash_input = {
            "source_a": source_a_id,
            "source_b": source_b_id,
            "type": conflict_type,
            "desc": description
        }
        conflict_id = self._generate_deterministic_id("conflict", content_hash_input)
        
        # Emit CONFLICT event
        self._emit_event(
            event_type=EventType.CONFLICT,
            entity_id=conflict_id, # Conflict is an entity itself? Or just an event?
            timestamp_override=timestamp_override
        )
        
        conflict = EpistemicConflict(
            id=conflict_id,
            source_a_id=source_a_id,
            source_b_id=source_b_id,
            conflict_type=conflict_type,
            description=description
        )
        self._conflicts.append(conflict) # We still keep this list for easy access, or rebuild it?
        
        logger.warning(f"[EvidenceLedger] Conflict Registered: {source_a_id} vs {source_b_id} ({description})")
        return conflict

    # ------------------------------------------------------------------
    # Event Sourcing Core
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: EventType, entity_id: str, payload: Dict[str, Any], 
                   timestamp_override: Optional[float] = None) -> EpistemicEvent:
        """
        Create, Log, and Apply an event.
        """
        # Event ID should be deterministic based on its contents + timestamp
        # This ensures that replaying the same actions at the same time yields same Event IDs
        timestamp = timestamp_override or time.time()
        
        event_content = {
            "type": event_type,
            "entity": entity_id,
            "payload": payload,
            "time": timestamp
        }
        event_id = self._generate_deterministic_id("evt", event_content)
        
        from core.base.sequence import GlobalSequenceAuthority
        event = EpistemicEvent(
            id=event_id,
            event_type=event_type,
            entity_id=entity_id,
            payload=payload,
            timestamp=timestamp,
            run_id=GlobalSequenceAuthority.instance().run_id
        )
        
        self._event_log.append(event)
        
        # Persist to Audit Log
        try:
            with open(self._audit_path, "a") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        except Exception as e:
            logger.error(f"[EvidenceLedger] Failed to persist event {event_id}: {e}")
            
        self._apply_event(event) # Update in-memory view
        
        # Notify Listeners (Reactive Graph etc)
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as e:
                logger.error(f"[EvidenceLedger] Listener exception: {e}")
                
        return event

    def _apply_event(self, event: EpistemicEvent):
        """
        The Reducer. Updates derived state based on event.
        """
        if event.event_type == EventType.OBSERVED:
            self._set_state(event.entity_id, LifecycleState.OBSERVED, reason="Observed")
            
        elif event.event_type == EventType.PROMOTED:
            self._set_state(event.entity_id, LifecycleState.PROMOTED, reason="Promoted")
            
        elif event.event_type == EventType.SUPPRESSED:
            reason = f"{event.payload.get('reason_code')}: {event.payload.get('notes')}"
            self._set_state(event.entity_id, LifecycleState.SUPPRESSED, reason=reason)
            
        elif event.event_type == EventType.INVALIDATED:
            reason = event.payload.get("reason", "Invalidated")
            self._set_state(event.entity_id, LifecycleState.INVALIDATED, reason=reason)
            
            # If finding is invalidated, maybe remove from findings_store view?
            # Or update its status there? 
            # Current findings_store doesn't support 'update status' well, but we can assume
            # the UI handles it if we had a proper sync mechanism. 
            pass

    def _set_state(self, entity_id: str, state: LifecycleState, reason: Optional[str] = None) -> StateRecord:
        """Internal helper to update state table view."""
        record = StateRecord(
            entity_id=entity_id,
            state=state,
            reason=reason,
            timestamp=time.time()
        )
        self._state_table[entity_id] = record
        return record

    def replay(self, until_timestamp: float) -> Tuple[Dict[str, StateRecord], List[EpistemicEvent]]:
        """
        Reconstruct the state table as it was at `until_timestamp`.
        Returns: (Constructed State Table, List of Events up to T)
        """
        reconstructed_state = {}
        relevant_events = []
        
        # Simple helper for the reducer used within replay
        def apply(table, ev):
            reason = None
            new_state = None
            
            if ev.event_type == EventType.OBSERVED:
                new_state = LifecycleState.OBSERVED
            elif ev.event_type == EventType.PROMOTED:
                new_state = LifecycleState.PROMOTED
            elif ev.event_type == EventType.SUPPRESSED:
                new_state = LifecycleState.SUPPRESSED
                reason = f"{ev.payload.get('reason_code')}: {ev.payload.get('notes')}"
            elif ev.event_type == EventType.INVALIDATED:
                new_state = LifecycleState.INVALIDATED
                reason = ev.payload.get("reason")
            
            if new_state:
                table[ev.entity_id] = StateRecord(
                    entity_id=ev.entity_id,
                    state=new_state,
                    reason=reason or ev.payload.get("reason"),
                    timestamp=ev.timestamp
                )

        for event in self._event_log:
            if event.timestamp <= until_timestamp:
                relevant_events.append(event)
                apply(reconstructed_state, event)
            else:
                break # Assumes log is sorted by time (append-only)
                
        return reconstructed_state, relevant_events

    def get_state(self, entity_id: str) -> Optional[StateRecord]:
        """Retrieve the current belief state of an entity."""
        return self._state_table.get(entity_id)

    def get_observation(self, obs_id: str) -> Optional[Observation]:
        return self._observations.get(obs_id)
        
    def get_blob(self, obs_id: str) -> Optional[bytes]:
        return self.get_observation(obs_id) and self.cas.load(self.get_observation(obs_id).blob_hash)

    def _update_findings_store(self, finding: Finding):
        """Push finding to the read-model store."""
        from core.data.findings_store import findings_store
        
        # Convert to dict format expected by findings_store
        finding_dict = {
            "id": finding.id,
            "title": finding.title, 
            "type": finding.metadata.get("type", "General"), 
            "severity": finding.severity,
            "value": finding.description, 
            "description": finding.description,
            "citations": [asdict(c) for c in finding.citations],
            "metadata": finding.metadata
        }
        findings_store.add_finding(finding_dict)
