"""
Deterministic Replay Capsules - Complete Scan State Preservation

PURPOSE:
Save complete scan state (events, decisions, tool outputs, findings) in a portable,
verifiable format that enables perfect replay and forensic analysis.

WHY THIS MATTERS:
1. **Reproducibility**: Re-run scans deterministically for debugging
2. **Forensics**: Analyze exactly what happened in a scan session
3. **Training Data**: Create labeled datasets for ML model training
4. **Auditing**: Prove what actions were taken and why
5. **Sharing**: Sanitize and share scan results without sensitive data

KEY FEATURES:
- Cryptographic integrity verification (SHA-256 checksums)
- Sanitization to remove secrets/credentials
- Complete event + decision timeline
- Tool output preservation
- Metadata about scan environment

DESIGN PATTERN:
This is an "Immutable Snapshot" pattern - once created, a capsule cannot be modified.
Any changes require creating a new capsule (e.g., sanitized version).
"""

import json
import hashlib
import time
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class CapsuleMetadata:
    """Metadata about the scan environment and capsule creation."""

    # When this capsule was created (Unix timestamp)
    created_at: float

    # Version of SentinelForge that created this capsule
    sentinel_version: str

    # Platform (darwin, linux, etc.)
    platform: str

    # Whether this capsule has been sanitized
    sanitized: bool = False

    # Capsule format version (for future compatibility)
    format_version: str = "1.0"

    # Optional description/notes
    notes: Optional[str] = None


@dataclass
class ToolExecution:
    """Record of a single tool execution."""

    tool_name: str
    tool_version: Optional[str]
    start_time: float
    end_time: Optional[float]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanCapsule:
    """
    Complete, immutable snapshot of a scan session.

    This is the core data structure for replay capsules. It captures:
    - Session metadata (target, timing, status)
    - All events that occurred (from EventStore)
    - All decisions made (from DecisionLedger)
    - All tool executions and outputs
    - All findings and issues
    - Environment context
    - Integrity checksum

    Once created, a capsule is immutable. Sanitization creates a NEW capsule.
    """

    # ========== Session Identity ==========
    session_id: str
    target: str
    status: str
    start_time: float
    end_time: Optional[float]

    # ========== Timeline Data ==========
    events: List[Dict[str, Any]]  # Serialized StoredEvent objects
    decisions: List[Dict[str, Any]]  # Serialized DecisionPoint objects
    tool_executions: List[ToolExecution]

    # ========== Results ==========
    findings: List[Dict[str, Any]]  # Structured findings
    issues: List[Dict[str, Any]]  # Confirmed issues

    # ========== Environment ==========
    environment: Dict[str, Any]  # Tool availability, config settings, etc.
    metadata: CapsuleMetadata

    # ========== Integrity ==========
    checksum: Optional[str] = None  # SHA-256 of all content (excluding checksum itself)

    def __post_init__(self):
        """Calculate checksum after initialization."""
        if self.checksum is None:
            self.checksum = self._calculate_checksum()

    def _calculate_checksum(self) -> str:
        """
        Calculate SHA-256 checksum of all capsule content.

        This creates a tamper-evident seal - any modification to the capsule
        will change the checksum, making tampering detectable.
        """
        # Create a dict of all fields EXCEPT checksum
        data = asdict(self)
        data.pop('checksum', None)

        # Serialize to deterministic JSON (sorted keys)
        json_str = json.dumps(data, sort_keys=True, default=str)

        # Calculate SHA-256 hash
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    def verify(self) -> bool:
        """
        Verify capsule integrity by recalculating checksum.

        Returns:
            True if checksum matches (capsule is intact)
            False if checksum doesn't match (capsule was tampered with)
        """
        if self.checksum is None:
            logger.warning("[ScanCapsule] No checksum found, cannot verify")
            return False

        expected_checksum = self._calculate_checksum()
        is_valid = expected_checksum == self.checksum

        if not is_valid:
            logger.error(
                f"[ScanCapsule] Integrity check FAILED!\n"
                f"  Expected: {expected_checksum}\n"
                f"  Got:      {self.checksum}"
            )

        return is_valid

    def sanitize(self) -> "ScanCapsule":
        """
        Create a sanitized copy with sensitive data removed.

        Removes:
        - API keys, tokens, passwords in tool outputs
        - Private IP addresses (10.x, 172.16.x, 192.168.x)
        - Email addresses
        - Session cookies
        - Authorization headers

        Returns a NEW capsule (original is unchanged).
        """
        logger.info(f"[ScanCapsule] Sanitizing capsule {self.session_id}")

        # Patterns for sensitive data
        PATTERNS = {
            'api_key': re.compile(r'(?i)(api[_-]?key|apikey|key)[\s=:]+[\w\-]{20,}'),
            'token': re.compile(r'(?i)(token|bearer|jwt)[\s=:]+[\w\.\-]{20,}'),
            'password': re.compile(r'(?i)(password|passwd|pwd)[\s=:]+\S+'),
            'private_ip': re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'cookie': re.compile(r'(?i)(cookie|session|phpsessid)[\s=:]+[\w\-]+'),
            'auth_header': re.compile(r'(?i)authorization:\s*(basic|bearer|digest)\s+\S+'),
        }

        def sanitize_string(text: str) -> str:
            """Replace sensitive patterns with redaction markers."""
            for pattern_name, pattern in PATTERNS.items():
                text = pattern.sub(f'[REDACTED:{pattern_name.upper()}]', text)
            return text

        def sanitize_dict(d: Dict) -> Dict:
            """Recursively sanitize dictionary values."""
            result = {}
            for key, value in d.items():
                if isinstance(value, str):
                    result[key] = sanitize_string(value)
                elif isinstance(value, dict):
                    result[key] = sanitize_dict(value)
                elif isinstance(value, list):
                    result[key] = [sanitize_dict(v) if isinstance(v, dict) else
                                   sanitize_string(v) if isinstance(v, str) else v
                                   for v in value]
                else:
                    result[key] = value
            return result

        # Sanitize target (might contain credentials in URL)
        sanitized_target = sanitize_string(self.target)

        # Sanitize tool executions
        sanitized_executions = []
        for tool_exec in self.tool_executions:
            sanitized_executions.append(ToolExecution(
                tool_name=tool_exec.tool_name,
                tool_version=tool_exec.tool_version,
                start_time=tool_exec.start_time,
                end_time=tool_exec.end_time,
                exit_code=tool_exec.exit_code,
                stdout=sanitize_string(tool_exec.stdout),
                stderr=sanitize_string(tool_exec.stderr),
                metadata=sanitize_dict(tool_exec.metadata)
            ))

        # Sanitize events, findings, issues
        sanitized_events = [sanitize_dict(e) for e in self.events]
        sanitized_findings = [sanitize_dict(f) for f in self.findings]
        sanitized_issues = [sanitize_dict(i) for i in self.issues]
        sanitized_decisions = [sanitize_dict(d) for d in self.decisions]
        sanitized_environment = sanitize_dict(self.environment)

        # Create new metadata marking this as sanitized
        new_metadata = CapsuleMetadata(
            created_at=time.time(),
            sentinel_version=self.metadata.sentinel_version,
            platform=self.metadata.platform,
            sanitized=True,
            format_version=self.metadata.format_version,
            notes=f"Sanitized from capsule {self.session_id}"
        )

        # Create new capsule (checksum will be recalculated in __post_init__)
        return ScanCapsule(
            session_id=f"{self.session_id}_sanitized",
            target=sanitized_target,
            status=self.status,
            start_time=self.start_time,
            end_time=self.end_time,
            events=sanitized_events,
            decisions=sanitized_decisions,
            tool_executions=sanitized_executions,
            findings=sanitized_findings,
            issues=sanitized_issues,
            environment=sanitized_environment,
            metadata=new_metadata
        )

    @classmethod
    async def from_session(cls, session_id: str, db=None) -> "ScanCapsule":
        """
        Create a replay capsule from a completed scan session.

        Queries the database to extract all events, decisions, findings,
        tool outputs, and metadata for the given session.

        Args:
            session_id: UUID of the scan session
            db: Database instance (optional, will use singleton if not provided)

        Returns:
            ScanCapsule with complete scan data
        """
        from core.data.db import Database
        from core.cortex.event_store import get_event_store
        from core.scheduler.decisions import get_decision_ledger
        import platform

        if db is None:
            db = Database.instance()
            await db.init()

        logger.info(f"[ScanCapsule] Creating capsule from session {session_id}")

        # ========== Fetch session metadata ==========
        session_data = await db.get_session(session_id)
        if not session_data:
            raise ValueError(f"Session {session_id} not found in database")

        # ========== Fetch timeline data ==========
        # Events from EventStore
        event_store = get_event_store()
        # Filter events for this session (if EventStore supports filtering)
        # For now, we'll get all events and filter by session_id in payload
        all_stored_events, _ = event_store.get_since(0)
        session_events = [
            {
                'sequence': se.sequence,
                'type': se.event.type.value,
                'payload': se.event.payload,
                'timestamp': se.event.timestamp,
            }
            for se in all_stored_events
            if se.event.payload.get('session_id') == session_id
        ]

        # Decisions from DecisionLedger
        decision_ledger = get_decision_ledger()
        # Filter decisions for this session
        session_decisions = [
            {
                'sequence': dp.sequence,
                'type': dp.type.value,
                'chosen': dp.chosen,
                'reason': dp.reason,
                'alternatives': dp.alternatives,
                'timestamp': dp.timestamp,
                'context': dp.context,
            }
            for dp in decision_ledger.get_all()
            if dp.context.get('session_id') == session_id
        ]

        # ========== Fetch tool executions ==========
        evidence_records = await db.get_evidence(session_id)
        tool_executions = []
        for evidence in evidence_records:
            tool_executions.append(ToolExecution(
                tool_name=evidence.get('tool', 'unknown'),
                tool_version=evidence.get('tool_version'),
                start_time=evidence.get('timestamp', 0),
                end_time=evidence.get('timestamp', 0),  # We don't track end_time separately yet
                exit_code=None,  # Not currently stored
                stdout=evidence.get('raw_output', ''),
                stderr='',  # Not currently stored
                metadata=evidence.get('metadata', {})
            ))

        # ========== Fetch results ==========
        findings = await db.get_findings(session_id)
        issues = await db.get_issues(session_id)

        # ========== Environment context ==========
        # Capture tool availability and configuration
        from core.toolkit.registry import ToolRegistry
        registry = ToolRegistry()
        available_tools = {
            name: {
                'available': registry.is_available(name),
                'version': registry.get_version(name)
            }
            for name in registry.list_tools()
        }

        environment = {
            'tools': available_tools,
            'python_version': platform.python_version(),
            'platform': platform.platform(),
        }

        # ========== Create metadata ==========
        metadata = CapsuleMetadata(
            created_at=time.time(),
            sentinel_version="1.0.0",  # TODO: Get from config
            platform=platform.system(),
            sanitized=False,
            format_version="1.0"
        )

        # ========== Create capsule ==========
        return cls(
            session_id=session_id,
            target=session_data.get('target', 'unknown'),
            status=session_data.get('status', 'unknown'),
            start_time=session_data.get('start_time', 0),
            end_time=session_data.get('end_time'),
            events=session_events,
            decisions=session_decisions,
            tool_executions=tool_executions,
            findings=findings,
            issues=issues,
            environment=environment,
            metadata=metadata
        )

    def save(self, path: Path) -> None:
        """
        Save capsule to disk as JSON file.

        Args:
            path: Where to save the capsule (e.g., Path("capsules/scan_123.json"))
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2, default=str)

        logger.info(f"[ScanCapsule] Saved to {path}")

    @classmethod
    def load(cls, path: Path) -> "ScanCapsule":
        """
        Load capsule from disk.

        Args:
            path: Path to capsule JSON file

        Returns:
            ScanCapsule instance
        """
        with open(path, 'r') as f:
            data = json.load(f)

        # Reconstruct nested dataclasses
        data['metadata'] = CapsuleMetadata(**data['metadata'])
        data['tool_executions'] = [ToolExecution(**te) for te in data['tool_executions']]

        capsule = cls(**data)
        logger.info(f"[ScanCapsule] Loaded from {path}")

        # Verify integrity
        if not capsule.verify():
            logger.warning(f"[ScanCapsule] WARNING: Capsule integrity check failed!")

        return capsule

    async def replay(self) -> "ReplayResult":
        """
        Replay this scan from the capsule.

        NOT YET IMPLEMENTED - This is a complex feature that requires:
        1. Mocking tool executions (using captured stdout/stderr)
        2. Replaying events in order
        3. Verifying decisions match
        4. Comparing final findings to ensure determinism

        Returns:
            ReplayResult with comparison data
        """
        from core.ai.ai_engine import AIEngine
        from core.epistemic.ledger import EvidenceLedger

        start = time.time()
        ledger = EvidenceLedger()
        ai = AIEngine.instance()

        replayed_findings = []

        timeline = self._build_replay_timeline()
        for entry in timeline:
            if entry["kind"] != "tool_execution":
                continue

            tool_exec: ToolExecution = entry["data"]
            metadata = dict(tool_exec.metadata or {})
            metadata.setdefault("target", self.target)
            metadata.setdefault("session_id", self.session_id)

            observation = ledger.record_observation(
                tool_name=tool_exec.tool_name,
                tool_args=metadata.get("args", []),
                target=self.target,
                raw_output=tool_exec.stdout.encode("utf-8", errors="replace"),
                exit_code=tool_exec.exit_code or 0,
                timestamp_override=tool_exec.start_time,
                session_id=self.session_id,
            )

            result = await ai.process_tool_output(
                tool_name=tool_exec.tool_name,
                stdout=tool_exec.stdout,
                stderr=tool_exec.stderr,
                rc=tool_exec.exit_code or 0,
                metadata=metadata,
                observation_id=observation.id,
            )

            for proposal in result.get("proposals", []):
                finding = ledger.evaluate_and_promote(proposal)
                if finding:
                    replayed_findings.append(finding)

        replayed_findings_dicts = [self._finding_to_dict(f) for f in replayed_findings]
        differences = self._compare_findings(
            original=self.findings,
            replayed=replayed_findings_dicts,
        )

        return ReplayResult(
            success=len(differences) == 0,
            original_findings_count=len(self.findings),
            replayed_findings_count=len(replayed_findings_dicts),
            differences=differences,
            replay_duration=time.time() - start,
        )

    def _build_replay_timeline(self) -> List[Dict[str, Any]]:
        """
        Merge events, decisions, and tool executions into a single chronological timeline.
        """
        timeline: List[Dict[str, Any]] = []

        for event in self.events:
            timeline.append(
                {
                    "kind": "event",
                    "timestamp": self._extract_timestamp(event),
                    "data": event,
                }
            )

        for decision in self.decisions:
            timeline.append(
                {
                    "kind": "decision",
                    "timestamp": self._extract_timestamp(decision),
                    "data": decision,
                }
            )

        for tool_exec in self.tool_executions:
            timeline.append(
                {
                    "kind": "tool_execution",
                    "timestamp": tool_exec.start_time or tool_exec.end_time or 0.0,
                    "data": tool_exec,
                }
            )

        timeline.sort(key=lambda entry: entry["timestamp"])
        return timeline

    def _extract_timestamp(self, payload: Dict[str, Any]) -> float:
        for key in ("timestamp", "created_at", "time", "start_time"):
            value = payload.get(key)
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value)
                except ValueError:
                    continue
        return 0.0

    def _finding_to_dict(self, finding: Any) -> Dict[str, Any]:
        return {
            "id": getattr(finding, "id", None),
            "title": getattr(finding, "title", ""),
            "severity": getattr(finding, "severity", ""),
            "description": getattr(finding, "description", ""),
        }

    def _compare_findings(
        self,
        original: List[Dict[str, Any]],
        replayed: List[Dict[str, Any]],
    ) -> List[str]:
        def signature(item: Dict[str, Any]) -> str:
            if item.get("id"):
                return str(item["id"])
            return f"{item.get('title')}|{item.get('severity')}|{item.get('description')}"

        original_signatures = {signature(item) for item in original}
        replayed_signatures = {signature(item) for item in replayed}

        missing = original_signatures - replayed_signatures
        unexpected = replayed_signatures - original_signatures

        differences = []
        for item in sorted(missing):
            differences.append(f"Missing finding in replay: {item}")
        for item in sorted(unexpected):
            differences.append(f"Unexpected finding in replay: {item}")
        return differences


@dataclass
class ReplayResult:
    """Result of replaying a scan capsule."""

    success: bool
    original_findings_count: int
    replayed_findings_count: int
    differences: List[str]  # Human-readable differences
    replay_duration: float


# ============================================================================
# Module-level helpers
# ============================================================================

_capsule_store_path: Optional[Path] = None


def set_capsule_store_path(path: Path) -> None:
    """Set the directory where capsules are saved by default."""
    global _capsule_store_path
    _capsule_store_path = path
    path.mkdir(parents=True, exist_ok=True)


def get_capsule_store_path() -> Path:
    """Get the default capsule storage directory."""
    global _capsule_store_path
    if _capsule_store_path is None:
        from core.base.config import get_config
        config = get_config()
        _capsule_store_path = config.storage.base_dir / "capsules"
        _capsule_store_path.mkdir(parents=True, exist_ok=True)
    return _capsule_store_path


async def create_capsule_for_session(session_id: str, sanitize: bool = False) -> ScanCapsule:
    """
    Convenience function to create (and optionally sanitize) a capsule for a session.

    Args:
        session_id: Session UUID
        sanitize: If True, return sanitized capsule

    Returns:
        ScanCapsule (sanitized or raw)
    """
    capsule = await ScanCapsule.from_session(session_id)

    if sanitize:
        capsule = capsule.sanitize()

    # Auto-save to default location
    filename = f"{session_id}_{'sanitized' if sanitize else 'raw'}.json"
    capsule.save(get_capsule_store_path() / filename)

    return capsule
