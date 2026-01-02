"""
Time-Travel Debugging - Scan Timeline Navigation

PURPOSE:
Enable debugging of scan sessions by navigating through decision timeline,
inspecting state at any point, and understanding why decisions were made.

WHY THIS MATTERS:
1. **Debug Failed Scans**: "Why did it stop at step 5?"
2. **Understand Decisions**: "Why did it choose tool X over Y?"
3. **Forensic Analysis**: "What was the state when finding X was discovered?"
4. **Learning**: "How did the scan progress from start to finish?"

KEY CONCEPTS:
- **Snapshot**: Complete state of scan at a specific decision point
- **Timeline**: Ordered sequence of events/decisions (uses GlobalSequenceAuthority)
- **Scrubbing**: Moving backward/forward through timeline
- **State Reconstruction**: Replaying events to recreate past state

DESIGN PATTERN:
This is an "Event Sourcing + Memento" pattern - we use the event log to reconstruct
past states, with periodic snapshots for performance.

EXAMPLE:
Timeline: [Event 1, Decision 1, Event 2, Decision 2, Tool Execution, Event 3]
Scrub to Decision 2 → See: findings so far, tool outputs, decisions made
"""

import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TimelineEntryType(str, Enum):
    """Types of entries in the scan timeline."""
    EVENT = "event"
    DECISION = "decision"
    TOOL_EXECUTION = "tool_execution"
    FINDING = "finding"
    ISSUE = "issue"


@dataclass
class TimelineEntry:
    """A single entry in the scan timeline."""

    sequence: int  # Global sequence number (from GlobalSequenceAuthority)
    timestamp: float
    entry_type: TimelineEntryType

    # Type-specific data
    data: Dict[str, Any]

    # Human-readable description
    description: str


@dataclass
class ScanSnapshot:
    """
    Complete state of a scan at a specific point in time.

    This is like a savestate in an emulator - you can restore to this
    exact point and inspect everything that was known at that time.
    """

    # When this snapshot was taken
    sequence: int
    timestamp: float

    # Session context
    session_id: str
    target: str

    # Accumulated findings so far
    findings: List[Dict[str, Any]] = field(default_factory=list)
    issues: List[Dict[str, Any]] = field(default_factory=list)

    # Decisions made so far
    decisions: List[Dict[str, Any]] = field(default_factory=list)

    # Tool executions completed so far
    tool_executions: List[Dict[str, Any]] = field(default_factory=list)

    # Events emitted so far
    events: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    tools_run: int = 0
    findings_count: int = 0
    issues_count: int = 0
    last_decision_type: Optional[str] = None
    last_tool: Optional[str] = None


class TimeTravelDebugger:
    """
    Navigate through scan timeline and inspect state at any point.

    This lets you "rewind" a scan to see what was happening at any moment,
    understand why decisions were made, and debug failures.
    """

    def __init__(self, session_id: str):
        """
        Initialize debugger for a scan session.

        Args:
            session_id: Session UUID to debug
        """
        self.session_id = session_id

        # Timeline (ordered by sequence)
        self.timeline: List[TimelineEntry] = []

        # Periodic snapshots for fast seeking
        self.snapshots: Dict[int, ScanSnapshot] = {}

        # Current position in timeline
        self.current_sequence: int = 0

        logger.info(f"[TimeTravelDebugger] Initialized for session {session_id}")

    async def load_timeline(self):
        """
        Load complete timeline from database.

        This fetches all events, decisions, tool executions, and findings
        for the session, sorted by sequence number.
        """
        from core.data.db import Database
        from core.cortex.event_store import get_event_store
        from core.scheduler.decisions import get_decision_ledger

        logger.info(f"[TimeTravelDebugger] Loading timeline for {self.session_id}")

        db = Database.instance()
        await db.init()

        # Get session data
        session_data = await db.get_session(self.session_id)
        if not session_data:
            raise ValueError(f"Session {self.session_id} not found")

        self.target = session_data.get('target', 'unknown')

        # Build timeline from multiple sources
        timeline_entries = []

        # 1. Events from EventStore
        event_store = get_event_store()
        all_events, _ = event_store.get_since(0)

        for stored_event in all_events:
            event = stored_event.event
            # Filter by session
            if event.payload.get('session_id') == self.session_id:
                timeline_entries.append(TimelineEntry(
                    sequence=stored_event.sequence,
                    timestamp=event.timestamp,
                    entry_type=TimelineEntryType.EVENT,
                    data={
                        'type': event.type.value,
                        'payload': event.payload
                    },
                    description=f"Event: {event.type.value}"
                ))

        # 2. Decisions from DecisionLedger
        decision_ledger = get_decision_ledger()
        all_decisions = decision_ledger.get_all()

        for decision in all_decisions:
            # Filter by session
            if decision.context.get('session_id') == self.session_id:
                timeline_entries.append(TimelineEntry(
                    sequence=decision.sequence,
                    timestamp=decision.timestamp,
                    entry_type=TimelineEntryType.DECISION,
                    data={
                        'type': decision.type.value,
                        'chosen': decision.chosen,
                        'reason': decision.reason,
                        'alternatives': decision.alternatives,
                        'context': decision.context
                    },
                    description=f"Decision: {decision.type.value} → {decision.chosen}"
                ))

        # 3. Tool executions from evidence
        evidence_records = await db.get_evidence(self.session_id)

        for evidence in evidence_records:
            # Evidence doesn't have sequence numbers, estimate from timestamp
            # We'll use a separate timeline for these
            timeline_entries.append(TimelineEntry(
                sequence=0,  # Will be sorted by timestamp
                timestamp=float(evidence.get('timestamp', 0)),
                entry_type=TimelineEntryType.TOOL_EXECUTION,
                data={
                    'tool': evidence.get('tool', 'unknown'),
                    'output': evidence.get('raw_output', ''),
                    'metadata': evidence.get('metadata', {})
                },
                description=f"Tool: {evidence.get('tool', 'unknown')}"
            ))

        # 4. Findings
        findings = await db.get_findings(self.session_id)

        for finding in findings:
            timeline_entries.append(TimelineEntry(
                sequence=0,  # Will be sorted by timestamp
                timestamp=float(finding.get('timestamp', 0)) if 'timestamp' in finding else 0,
                entry_type=TimelineEntryType.FINDING,
                data=finding,
                description=f"Finding: {finding.get('type', 'unknown')}"
            ))

        # Sort by sequence (then timestamp for entries without sequence)
        self.timeline = sorted(
            timeline_entries,
            key=lambda e: (e.sequence, e.timestamp)
        )

        logger.info(f"[TimeTravelDebugger] Loaded timeline: {len(self.timeline)} entries")

        # Create snapshots at decision points (for fast seeking)
        await self._create_snapshots()

    async def _create_snapshots(self):
        """
        Create periodic snapshots at decision points for fast seeking.

        Snapshots are created every N decisions to avoid replaying
        entire timeline when seeking.
        """
        SNAPSHOT_INTERVAL = 5  # Create snapshot every 5 decisions

        current_snapshot = ScanSnapshot(
            sequence=0,
            timestamp=0,
            session_id=self.session_id,
            target=self.target
        )

        decisions_since_snapshot = 0

        for entry in self.timeline:
            # Accumulate state
            if entry.entry_type == TimelineEntryType.EVENT:
                current_snapshot.events.append(entry.data)

            elif entry.entry_type == TimelineEntryType.DECISION:
                current_snapshot.decisions.append(entry.data)
                current_snapshot.last_decision_type = entry.data.get('type')
                decisions_since_snapshot += 1

                # Create snapshot at intervals
                if decisions_since_snapshot >= SNAPSHOT_INTERVAL:
                    self.snapshots[entry.sequence] = ScanSnapshot(
                        sequence=entry.sequence,
                        timestamp=entry.timestamp,
                        session_id=self.session_id,
                        target=self.target,
                        findings=list(current_snapshot.findings),
                        issues=list(current_snapshot.issues),
                        decisions=list(current_snapshot.decisions),
                        tool_executions=list(current_snapshot.tool_executions),
                        events=list(current_snapshot.events),
                        tools_run=current_snapshot.tools_run,
                        findings_count=len(current_snapshot.findings),
                        issues_count=len(current_snapshot.issues),
                        last_decision_type=current_snapshot.last_decision_type,
                        last_tool=current_snapshot.last_tool
                    )
                    decisions_since_snapshot = 0

            elif entry.entry_type == TimelineEntryType.TOOL_EXECUTION:
                current_snapshot.tool_executions.append(entry.data)
                current_snapshot.tools_run += 1
                current_snapshot.last_tool = entry.data.get('tool')

            elif entry.entry_type == TimelineEntryType.FINDING:
                current_snapshot.findings.append(entry.data)
                current_snapshot.findings_count += 1

            elif entry.entry_type == TimelineEntryType.ISSUE:
                current_snapshot.issues.append(entry.data)
                current_snapshot.issues_count += 1

        logger.info(f"[TimeTravelDebugger] Created {len(self.snapshots)} snapshots")

    def get_timeline(self) -> List[Tuple[int, str, str]]:
        """
        Get the complete timeline as a list of (sequence, type, description).

        Returns:
            List of timeline entries for display
        """
        return [
            (entry.sequence, entry.entry_type.value, entry.description)
            for entry in self.timeline
        ]

    def get_state_at(self, target_sequence: int) -> ScanSnapshot:
        """
        Get the scan state at a specific sequence number.

        This finds the nearest snapshot and replays events up to the target.

        Args:
            target_sequence: Sequence number to seek to

        Returns:
            ScanSnapshot at that point in time
        """
        logger.info(f"[TimeTravelDebugger] Seeking to sequence {target_sequence}")

        # Find nearest snapshot before target
        nearest_snapshot_seq = 0
        for snapshot_seq in sorted(self.snapshots.keys()):
            if snapshot_seq <= target_sequence:
                nearest_snapshot_seq = snapshot_seq
            else:
                break

        # Start from snapshot (or beginning if no snapshot)
        if nearest_snapshot_seq in self.snapshots:
            state = ScanSnapshot(
                sequence=self.snapshots[nearest_snapshot_seq].sequence,
                timestamp=self.snapshots[nearest_snapshot_seq].timestamp,
                session_id=self.session_id,
                target=self.target,
                findings=list(self.snapshots[nearest_snapshot_seq].findings),
                issues=list(self.snapshots[nearest_snapshot_seq].issues),
                decisions=list(self.snapshots[nearest_snapshot_seq].decisions),
                tool_executions=list(self.snapshots[nearest_snapshot_seq].tool_executions),
                events=list(self.snapshots[nearest_snapshot_seq].events),
                tools_run=self.snapshots[nearest_snapshot_seq].tools_run,
                last_decision_type=self.snapshots[nearest_snapshot_seq].last_decision_type,
                last_tool=self.snapshots[nearest_snapshot_seq].last_tool
            )
            start_idx = self._find_entry_index(nearest_snapshot_seq)
        else:
            # No snapshot, start from beginning
            state = ScanSnapshot(
                sequence=0,
                timestamp=0,
                session_id=self.session_id,
                target=self.target
            )
            start_idx = 0

        # Replay events from snapshot to target
        for entry in self.timeline[start_idx:]:
            if entry.sequence > target_sequence:
                break

            # Update state based on entry type
            if entry.entry_type == TimelineEntryType.EVENT:
                state.events.append(entry.data)
                state.sequence = entry.sequence
                state.timestamp = entry.timestamp

            elif entry.entry_type == TimelineEntryType.DECISION:
                state.decisions.append(entry.data)
                state.last_decision_type = entry.data.get('type')
                state.sequence = entry.sequence
                state.timestamp = entry.timestamp

            elif entry.entry_type == TimelineEntryType.TOOL_EXECUTION:
                state.tool_executions.append(entry.data)
                state.tools_run += 1
                state.last_tool = entry.data.get('tool')

            elif entry.entry_type == TimelineEntryType.FINDING:
                state.findings.append(entry.data)
                state.findings_count += 1

            elif entry.entry_type == TimelineEntryType.ISSUE:
                state.issues.append(entry.data)
                state.issues_count += 1

        logger.info(
            f"[TimeTravelDebugger] State at {target_sequence}: "
            f"{state.findings_count} findings, {state.tools_run} tools, "
            f"{len(state.decisions)} decisions"
        )

        return state

    def _find_entry_index(self, sequence: int) -> int:
        """Find the index of the first entry with given sequence."""
        for idx, entry in enumerate(self.timeline):
            if entry.sequence >= sequence:
                return idx
        return len(self.timeline)

    def next(self) -> Optional[ScanSnapshot]:
        """Move forward one entry in timeline."""
        if not self.timeline:
            return None

        current_idx = self._find_entry_index(self.current_sequence)
        if current_idx < len(self.timeline) - 1:
            next_entry = self.timeline[current_idx + 1]
            self.current_sequence = next_entry.sequence
            return self.get_state_at(self.current_sequence)

        return None

    def previous(self) -> Optional[ScanSnapshot]:
        """Move backward one entry in timeline."""
        if not self.timeline:
            return None

        current_idx = self._find_entry_index(self.current_sequence)
        if current_idx > 0:
            prev_entry = self.timeline[current_idx - 1]
            self.current_sequence = prev_entry.sequence
            return self.get_state_at(self.current_sequence)

        return None


# ============================================================================
# Module-level helpers
# ============================================================================

_debuggers: Dict[str, TimeTravelDebugger] = {}


async def get_debugger(session_id: str) -> TimeTravelDebugger:
    """
    Get or create a time-travel debugger for a session.

    Args:
        session_id: Session UUID

    Returns:
        TimeTravelDebugger instance with timeline loaded
    """
    if session_id not in _debuggers:
        debugger = TimeTravelDebugger(session_id)
        await debugger.load_timeline()
        _debuggers[session_id] = debugger

    return _debuggers[session_id]
