"""
Evidence Ledger (The Truth Store).

This module defines the authoritative record of all observations and findings.
It distinguishes between:
1. Observation (Immutable raw fact, stored in CAS)
2. Fact (Normalized data derived from Observation)
3. Finding (Actionable intelligence citing Observations)
4. WhyNot (Reasoning for discarded/suppressed findings)
"""

import hashlib
import json
import logging
import math
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from enum import Enum

from core.base.scope import canonical_origin
from core.behavior.compiler import OperationFamily, OperationInstance
from core.behavior.receipts import (
    COMPLETED,
    BehavioralReceiptStore,
    ReceiptStoreError,
)
from core.epistemic.cas import ContentAddressableStorage
from core.epistemic.events import EpistemicConflict, EpistemicEvent, EventType
from core.epistemic.persistence import CanonicalEvidenceRepository
from core.identity import AssessmentIdentityContext
from core.base.config import SentinelConfig
from core.replay.merkle import MerkleEngine
from core.behavior.normalize import stable_hash

logger = logging.getLogger(__name__)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BEHAVIORAL_RECEIPT_ID = re.compile(r"^behavioral-[0-9a-f]{64}$")
_PROVENANCE_ROOT = re.compile(r"^(?:provenance:)?[0-9a-f]{64}$")
_AUDIT_HEADER_MAX_BYTES = 4096


class LifecycleState(str, Enum):
    OBSERVED = "observed"       # Raw data ingested
    PROMOTED = "promoted"       # Became a Finding
    SUPPRESSED = "suppressed"   # Ignored (with WhyNot)
    REJECTED = "rejected"       # Proven false (e.g. sensor glitch)
    INVALIDATED = "invalidated" # Was Promoted, now false (Time travel)


class ConfirmationLevel(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    HYPOTHESIZED = "hypothesized"



@dataclass(frozen=True)
class ToolContext:
    name: str
    args: Tuple[str, ...]
    version: Optional[str] = None
    exit_code: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("tool name is required")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "args", tuple(str(item) for item in self.args))


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


def _observation_envelope_material(
    *,
    tool: ToolContext,
    target: str,
    blob_hash: str,
    identity: AssessmentIdentityContext,
    operation_family: OperationFamily,
    operation_instance: OperationInstance,
) -> Dict[str, Any]:
    return {
        "schema": "evidence_observation_envelope_v1",
        "tool": {
            "name": tool.name,
            "args": list(tool.args),
            "version": tool.version,
            "exit_code": tool.exit_code,
        },
        "target": target,
        "blob_hash": blob_hash,
        "session_id": identity.session_id,
        "identity_digest": identity.digest,
        "operation_family_id": operation_family.family_id,
        "operation_instance_id": operation_instance.instance_id,
        "operation_outcome": operation_instance.outcome.value,
        "operation_source_ref": operation_instance.source_ref,
    }


@dataclass(frozen=True)
class ObservationEnvelope(Observation):
    """Canonical observation bound to one session, identity, and outcome."""

    commitment: str
    identity: AssessmentIdentityContext
    operation_family: OperationFamily
    operation_instance: OperationInstance

    @property
    def session_id(self) -> str:
        return self.identity.session_id

    def __post_init__(self) -> None:
        material = _observation_envelope_material(
            tool=self.tool,
            target=self.target,
            blob_hash=self.blob_hash,
            identity=self.identity,
            operation_family=self.operation_family,
            operation_instance=self.operation_instance,
        )
        expected_commitment = stable_hash("observation_envelope", material)
        expected_id = f"obs-{expected_commitment.rsplit(':', 1)[-1]}"
        target_origin = canonical_origin(self.target)
        expected_world_ref = (
            self.identity.world_id
            if self.identity.world_id.startswith("world:")
            else stable_hash("world", self.identity.world_id)
        )
        if (
            self.id != expected_id
            or self.commitment != expected_commitment
            or self.identity.session_id == "global_scan"
            or target_origin is None
            or target_origin.as_url() != self.identity.target_origin
            or self.operation_instance.family_id != self.operation_family.family_id
            or self.operation_instance.source_ref not in self.operation_family.source_refs
            or self.operation_instance.world_ref != expected_world_ref
            or _SHA256.fullmatch(self.blob_hash) is None
        ):
            raise ValueError("canonical observation envelope is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "tool": {
                "name": self.tool.name,
                "args": list(self.tool.args),
                "version": self.tool.version,
                "exit_code": self.tool.exit_code,
            },
            "target": self.target,
            "blob_hash": self.blob_hash,
            "commitment": self.commitment,
            "session_id": self.identity.session_id,
            "identity": self.identity.to_dict(),
            "operation_family": self.operation_family.to_dict(),
            "operation_instance": self.operation_instance.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObservationEnvelope":
        tool = value["tool"]
        observation = cls(
            id=value["id"],
            timestamp=value["timestamp"],
            tool=ToolContext(
                name=tool["name"],
                args=tuple(tool["args"]),
                version=tool.get("version"),
                exit_code=tool["exit_code"],
            ),
            target=value["target"],
            blob_hash=value["blob_hash"],
            commitment=value["commitment"],
            identity=AssessmentIdentityContext.from_dict(value["identity"]),
            operation_family=OperationFamily.from_dict(value["operation_family"]),
            operation_instance=OperationInstance.from_dict(value["operation_instance"]),
        )
        if value.get("session_id") != observation.session_id:
            raise ValueError("canonical observation session mismatch")
        return observation


@dataclass
class Citation:
    """
    A strict link to evidence.
    """
    observation_id: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    snippet: Optional[str] = None  # Short quote for verification


@dataclass(frozen=True)
class ActiveProofCitation:
    """Binding from one active evidence atom to completed R0 conduct proof."""

    observation_id: str
    receipt_id: str
    provenance_root: str

    def __post_init__(self) -> None:
        if not isinstance(self.observation_id, str) or not self.observation_id.startswith(
            "obs-"
        ):
            raise ValueError("active proof observation citation is invalid")
        if (
            not isinstance(self.receipt_id, str)
            or _BEHAVIORAL_RECEIPT_ID.fullmatch(self.receipt_id) is None
        ):
            raise ValueError("active proof receipt citation is invalid")
        if (
            not isinstance(self.provenance_root, str)
            or _PROVENANCE_ROOT.fullmatch(self.provenance_root) is None
        ):
            raise ValueError("active proof provenance citation is invalid")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ActiveProofCitation":
        if set(value) != {"observation_id", "receipt_id", "provenance_root"}:
            raise ValueError("active proof citation fields are invalid")
        return cls(
            observation_id=value["observation_id"],
            receipt_id=value["receipt_id"],
            provenance_root=value["provenance_root"],
        )


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
    confirmation_level: str = "probable"  # Default preserves existing behavior
    session_id: Optional[str] = None
    commitment: Optional[str] = None
    active_proof: List[ActiveProofCitation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "citations": [asdict(item) for item in self.citations],
            "description": self.description,
            "remediation": self.remediation,
            "metadata": self.metadata,
            "confirmation_level": self.confirmation_level,
            "session_id": self.session_id,
            "commitment": self.commitment,
            "active_proof": [asdict(item) for item in self.active_proof],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Finding":
        finding = cls(
            id=value["id"],
            title=value["title"],
            severity=value["severity"],
            citations=[Citation(**item) for item in value["citations"]],
            description=value["description"],
            remediation=value.get("remediation"),
            metadata=dict(value.get("metadata") or {}),
            confirmation_level=value["confirmation_level"],
            session_id=value.get("session_id"),
            commitment=value.get("commitment"),
            active_proof=[
                ActiveProofCitation.from_dict(item)
                for item in value.get("active_proof", [])
            ],
        )
        if finding.commitment != _canonical_finding_commitment(finding):
            raise ValueError("canonical finding commitment mismatch")
        if finding.id != f"find-{finding.commitment.rsplit(':', 1)[-1]}":
            raise ValueError("canonical finding id mismatch")
        return finding


def _canonical_finding_material(finding: Finding) -> Dict[str, Any]:
    if not finding.session_id or finding.session_id == "global_scan":
        raise ValueError("canonical finding requires an explicit session")
    confirmation = ConfirmationLevel(finding.confirmation_level)
    if confirmation is ConfirmationLevel.HYPOTHESIZED:
        raise ValueError("hypothesized claims cannot be canonical findings")
    if not finding.active_proof:
        raise ValueError("active canonical finding requires proof provenance")
    return {
        "schema": "evidence_finding_v2",
        "session_id": finding.session_id,
        "title": finding.title,
        "severity": finding.severity,
        "citations": [asdict(item) for item in finding.citations],
        "description": finding.description,
        "remediation": finding.remediation,
        "metadata": finding.metadata,
        "confirmation_level": finding.confirmation_level,
        "active_proof": [asdict(item) for item in finding.active_proof],
    }


def _canonical_finding_commitment(finding: Finding) -> str:
    return stable_hash("evidence_finding", _canonical_finding_material(finding))


@dataclass(frozen=True)
class CanonicalSessionReadModel:
    """One immutable, session-scoped projection of current ledger truth."""

    session_id: str
    revision: str
    observations: Tuple[ObservationEnvelope, ...]
    findings: Tuple[Finding, ...]

    def finding_views(self) -> List[Dict[str, Any]]:
        observation_index = {item.id: item for item in self.observations}
        views: List[Dict[str, Any]] = []
        for finding in self.findings:
            cited = [
                observation_index.get(item.observation_id)
                for item in finding.citations
            ]
            first_observation = next(
                (item for item in cited if isinstance(item, ObservationEnvelope)),
                None,
            )
            metadata = json.loads(
                json.dumps(finding.metadata, sort_keys=True, default=str)
            )
            finding_type = str(
                metadata.get("type") or metadata.get("finding_class") or finding.title
            )
            views.append(
                {
                    "id": finding.id,
                    "finding_id": finding.id,
                    "title": finding.title,
                    "type": finding_type,
                    "severity": finding.severity,
                    "description": finding.description,
                    "message": finding.description,
                    "value": finding.description,
                    "remediation": finding.remediation,
                    "target": (
                        first_observation.target if first_observation is not None else ""
                    ),
                    "asset": (
                        first_observation.target if first_observation is not None else ""
                    ),
                    "tool": (
                        first_observation.tool.name
                        if first_observation is not None
                        else ""
                    ),
                    "confirmation_level": finding.confirmation_level,
                    "session_id": finding.session_id,
                    "commitment": finding.commitment,
                    "citations": [asdict(item) for item in finding.citations],
                    "active_proof": [asdict(item) for item in finding.active_proof],
                    "metadata": metadata,
                }
            )
        return views

    def evidence_views(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": observation.id,
                "evidence_id": observation.id,
                "type": "canonical_observation",
                "session_id": observation.session_id,
                "target": observation.target,
                "tool": observation.tool.name,
                "tool_args": list(observation.tool.args),
                "exit_code": observation.tool.exit_code,
                "blob_hash": observation.blob_hash,
                "commitment": observation.commitment,
                "identity_digest": observation.identity.digest,
                "operation_family_id": observation.operation_family.family_id,
                "operation_instance_id": observation.operation_instance.instance_id,
                "operation_outcome": observation.operation_instance.outcome.value,
            }
            for observation in self.observations
        ]

    def filter_cited_issues(
        self, issues: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Keep specialist issue enrichment only when it cites active findings."""

        active_ids = {item.id for item in self.findings}
        output: List[Dict[str, Any]] = []
        for issue in issues:
            supporting = issue.get("supporting_findings")
            if not isinstance(supporting, list):
                continue
            refs: set[str] = set()
            for item in supporting:
                if not isinstance(item, Mapping):
                    continue
                for key in ("id", "finding_id", "canonical_finding_id"):
                    value = item.get(key)
                    if isinstance(value, str):
                        refs.add(value)
                metadata = item.get("metadata")
                if isinstance(metadata, Mapping):
                    value = metadata.get("canonical_finding_id")
                    if isinstance(value, str):
                        refs.add(value)
            if refs & active_ids:
                output.append(dict(issue))
        return output


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
    remediation: Optional[str] = None
    source: str = "ai"
    metadata: Dict[str, Any] = field(default_factory=dict)
    confirmation_level: Optional[str] = None  # Derived by Ledger if not set


class EvidenceLedger:
    """
    Authoritative store for Sentinel's epistemic state.
    Manages:
    1. Immutable Evidence (CAS + Observations)
    2. Event Log (The Source of Truth)
    3. Derived View (StateTable, Findings)
    """

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        *,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ):
        # Use the global singleton when no config is injected.
        # See core/epistemic/cas.py for the historical-bug rationale.
        from core.base.config import get_config
        self.config = config or get_config()
        self.cas = ContentAddressableStorage(self.config)
        self._repository = CanonicalEvidenceRepository(self.config.storage.db_path)
        self._receipt_store = receipt_store or BehavioralReceiptStore()
        
        # 1. Immutable Stores (The "What")
        self._observations: Dict[str, Observation] = {}
        # Technically 'findings' map is also a view now, but we keep it for fast lookup
        self._findings: Dict[str, Finding] = {}
        self._conflicts: List[EpistemicConflict] = []
        
        # 2. Event Log (The "When" and "Why")
        self._event_log: List[EpistemicEvent] = []
        
        # 2b. Audit Persistence
        self._audit_path = self.config.storage.base_dir / "audit.jsonl"
        self._ensure_audit_log()
        
        # 2c. Reactive Listeners
        self._listeners: List[Callable[[EpistemicEvent], None]] = []

        # 3. Derived Views (The "Now")
        self._state_table: Dict[str, StateRecord] = {}
        self._restore_canonical_state()

    def _ensure_audit_log(self) -> None:
        """Atomically publish and validate one durable audit header."""

        directory_descriptor = os.open(
            self._audit_path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        temporary_name = (
            f".{self._audit_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        temporary_descriptor = -1
        final_descriptor = -1
        temporary_exists = False
        try:
            temporary_descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_descriptor,
            )
            temporary_exists = True
            self._validate_audit_descriptor(temporary_descriptor)
            payload = (
                json.dumps(
                    {"type": "header", "version": "1.0", "created": time.time()}
                )
                + "\n"
            ).encode("utf-8")
            self._write_all(temporary_descriptor, payload)
            os.fsync(temporary_descriptor)
            os.close(temporary_descriptor)
            temporary_descriptor = -1

            try:
                os.link(
                    temporary_name,
                    self._audit_path.name,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError:
                pass

            final_descriptor = os.open(
                self._audit_path.name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            self._validate_audit_descriptor(final_descriptor)
            self._validate_audit_header(final_descriptor)
            os.close(final_descriptor)
            final_descriptor = -1

            os.unlink(temporary_name, dir_fd=directory_descriptor)
            temporary_exists = False
            os.fsync(directory_descriptor)
        finally:
            if final_descriptor >= 0:
                os.close(final_descriptor)
            if temporary_descriptor >= 0:
                os.close(temporary_descriptor)
            if temporary_exists:
                try:
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
                except FileNotFoundError:
                    pass
            os.close(directory_descriptor)

    @staticmethod
    def _validate_audit_descriptor(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            raise ValueError("canonical audit path ownership or mode is unsafe")

    @staticmethod
    def _validate_audit_header(descriptor: int) -> None:
        encoded = bytearray()
        while len(encoded) <= _AUDIT_HEADER_MAX_BYTES:
            chunk = os.read(
                descriptor,
                min(1024, _AUDIT_HEADER_MAX_BYTES + 1 - len(encoded)),
            )
            if not chunk:
                break
            encoded.extend(chunk)
            if b"\n" in chunk:
                break
        newline = encoded.find(b"\n")
        if newline < 0 or newline > _AUDIT_HEADER_MAX_BYTES:
            raise ValueError("canonical audit header is missing or incomplete")

        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
            decoded: Dict[str, Any] = {}
            for key, value in pairs:
                if key in decoded:
                    raise ValueError("canonical audit header has duplicate fields")
                decoded[key] = value
            return decoded

        try:
            header = json.loads(
                bytes(encoded[:newline]).decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("canonical audit header is invalid") from exc
        created = header.get("created") if isinstance(header, dict) else None
        if (
            not isinstance(header, dict)
            or set(header) != {"type", "version", "created"}
            or header["type"] != "header"
            or header["version"] != "1.0"
            or isinstance(created, bool)
            or not isinstance(created, (int, float))
            or not math.isfinite(created)
            or created <= 0
        ):
            raise ValueError("canonical audit header is invalid")

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("canonical audit write made no progress")
            offset += written

    def _append_audit_event(self, event: EpistemicEvent) -> None:
        payload = (json.dumps(asdict(event)) + "\n").encode("utf-8")
        descriptor = os.open(
            self._audit_path,
            os.O_WRONLY
            | os.O_APPEND
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            self._validate_audit_descriptor(descriptor)
            self._write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _generate_deterministic_id(self, prefix: str, content: Any) -> str:
        """Generate a deterministic ID based on content hash."""
        # Use first 12 chars of SHA256 (48 bits of entropy is enough for local collision resistance)
        # We rely on MerkleEngine for canonicalization.
        return f"{prefix}-{MerkleEngine.compute_hash(content)[:12]}"

    def _restore_canonical_state(self) -> None:
        entities, event_values = self._repository.load()
        for stored in entities:
            if stored["kind"] == "observation":
                entity = ObservationEnvelope.from_dict(stored["data"])
                blob = self.cas.load(entity.blob_hash)
                if blob is None or hashlib.sha256(blob).hexdigest() != entity.blob_hash:
                    raise ValueError("canonical observation CAS integrity check failed")
                self._observations[entity.id] = entity
            elif stored["kind"] == "finding":
                entity = Finding.from_dict(stored["data"])
                cited = [
                    self._observations.get(item.observation_id)
                    for item in entity.citations
                ]
                if any(
                    not isinstance(item, ObservationEnvelope)
                    or item.session_id != entity.session_id
                    for item in cited
                ):
                    raise ValueError("canonical finding citation index mismatch")
                self._validate_active_proof(
                    evidence_citations=entity.citations,
                    observations=cited,
                    active_proof=entity.active_proof,
                )
                self._validate_capability_replay_finding(entity, cited)
                self._findings[entity.id] = entity
            else:
                raise ValueError("unsupported persisted epistemic entity")
            if (
                stored["id"] != entity.id
                or stored["session_id"] != entity.session_id
                or stored["commitment"] != entity.commitment
            ):
                raise ValueError("canonical evidence index mismatch")

        for value in event_values:
            event = EpistemicEvent(
                id=value["id"],
                event_type=EventType(value["event_type"]),
                entity_id=value["entity_id"],
                payload=dict(value["payload"]),
                timestamp=value["timestamp"],
                run_id=value.get("run_id"),
            )
            expected_id = self._generate_deterministic_id(
                "evt",
                {
                    "type": event.event_type,
                    "entity": event.entity_id,
                    "payload": event.payload,
                    "time": event.timestamp,
                },
            )
            entity = self._observations.get(event.entity_id) or self._findings.get(
                event.entity_id
            )
            if (
                event.id != expected_id
                or entity is None
                or event.payload.get("session_id") != entity.session_id
            ):
                raise ValueError("canonical epistemic event is invalid")
            self._event_log.append(event)
            self._apply_event(event)

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
                          timestamp_override: Optional[float] = None,
                          session_id: Optional[str] = None) -> Observation:
        """
        Ingest raw tool output.
        
        Args:
            tool_name: Name of the tool that generated the output
            tool_args: Arguments passed to the tool
            target: Target being scanned
            raw_output: Raw bytes output from the tool
            exit_code: Tool exit code
            timestamp_override: Optional timestamp override
            session_id: Optional session ID. If None, uses "global_scan"
        
        Returns:
            The recorded Observation object
        """
        # 1. Store in CAS
        blob_hash = self.cas.store(raw_output)
        
        unique_string = f"{tool_name}:{target}:{blob_hash}"
        obs_id = f"obs-{uuid.uuid5(uuid.NAMESPACE_DNS, unique_string).hex[:12]}"
        
        # 2. Create Immutable Record
        obs = Observation(
            id=obs_id,
            timestamp=timestamp_override or time.time(),
            tool=ToolContext(name=tool_name, args=tuple(tool_args), exit_code=exit_code),
            target=target,
            blob_hash=blob_hash
        )
        
        # 3. Index locally (Optimization: Don't need event for existence of blob/obs definition)
        if obs_id not in self._observations:
            self._observations[obs_id] = obs
            
            # Use global_scan session if no session_id provided
            effective_session_id = session_id or "global_scan"
            
            # Emit OBSERVED event
            self._emit_event(
                event_type=EventType.OBSERVED,
                entity_id=obs_id,
                payload={
                    "tool": tool_name, 
                    "target": target, 
                    "blob_hash": blob_hash,
                    "session_id": effective_session_id
                },
                timestamp_override=timestamp_override
            )
            
            logger.info(f"[EvidenceLedger] Recorded Observation {obs_id}: {tool_name} -> {blob_hash[:8]} (session: {effective_session_id})")
        else:
            logger.debug(f"[EvidenceLedger] Idempotent observation seen: {obs_id}")
            
        return obs

    def record_canonical_observation(
        self,
        *,
        tool_name: str,
        tool_args: List[str],
        target: str,
        raw_output: bytes,
        identity: AssessmentIdentityContext,
        operation_family: OperationFamily,
        operation_instance: OperationInstance,
        exit_code: int = 0,
        tool_version: Optional[str] = None,
        timestamp_override: Optional[float] = None,
    ) -> ObservationEnvelope:
        """Admit one exact Stage-1 identity/outcome atom into this ledger."""

        blob_hash = self.cas.store(raw_output)
        tool = ToolContext(
            name=tool_name,
            args=tuple(tool_args),
            version=tool_version,
            exit_code=exit_code,
        )
        material = _observation_envelope_material(
            tool=tool,
            target=target,
            blob_hash=blob_hash,
            identity=identity,
            operation_family=operation_family,
            operation_instance=operation_instance,
        )
        commitment = stable_hash("observation_envelope", material)
        observation = ObservationEnvelope(
            id=f"obs-{commitment.rsplit(':', 1)[-1]}",
            timestamp=(timestamp_override if timestamp_override is not None else time.time()),
            tool=tool,
            target=target,
            blob_hash=blob_hash,
            commitment=commitment,
            identity=identity,
            operation_family=operation_family,
            operation_instance=operation_instance,
        )
        existing = self._observations.get(observation.id)
        if existing is not None:
            if (
                not isinstance(existing, ObservationEnvelope)
                or existing.commitment != observation.commitment
            ):
                raise ValueError("observation commitment collision")
            return existing

        self._observations[observation.id] = observation
        try:
            self._emit_event(
                event_type=EventType.OBSERVED,
                entity_id=observation.id,
                payload=observation.to_dict(),
                timestamp_override=timestamp_override,
                canonical_session_id=identity.session_id,
                durable_entity=("observation", observation.to_dict()),
            )
        except Exception:
            self._observations.pop(observation.id, None)
            raise
        logger.info(
            "[EvidenceLedger] Recorded canonical observation %s "
            "(session=%s family=%s instance=%s)",
            observation.id,
            identity.session_id,
            operation_family.family_id,
            operation_instance.instance_id,
        )
        return observation

    def observations_for_family(self, family_id: str) -> Tuple[ObservationEnvelope, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in self._observations.values()
                    if isinstance(item, ObservationEnvelope)
                    and item.operation_family.family_id == family_id
                ),
                key=lambda item: item.id,
            )
        )

    def assess_proposal(self, proposal: FindingProposal) -> FindingProposal:
        """Bind a proposal to canonical evidence without promoting its claim."""

        if not proposal.citations:
            raise ValueError("proposal requires canonical citations")
        citations = sorted(
            proposal.citations,
            key=lambda item: json.dumps(asdict(item), sort_keys=True, default=str),
        )
        observations = [self._observations.get(item.observation_id) for item in citations]
        if any(not isinstance(item, ObservationEnvelope) for item in observations):
            raise ValueError("proposal citation is not a canonical observation")
        sessions = {
            item.session_id
            for item in observations
            if isinstance(item, ObservationEnvelope)
        }
        if len(sessions) != 1:
            raise ValueError("proposal cannot cross session identities")
        for observation in observations:
            state = self.get_state(observation.id)
            if state is not None and state.state in {
                LifecycleState.INVALIDATED,
                LifecycleState.REJECTED,
            }:
                raise ValueError("proposal cites invalid canonical evidence")

        if proposal.source in {"ai", "neural_strategy"}:
            confirmation = ConfirmationLevel.HYPOTHESIZED.value
        elif proposal.source in {"scanner", "heuristic"}:
            confirmation = ConfirmationLevel.PROBABLE.value
        else:
            confirmation = (
                proposal.confirmation_level or ConfirmationLevel.PROBABLE.value
            )
        metadata = dict(proposal.metadata or {})
        metadata["session_id"] = sessions.pop()
        return FindingProposal(
            title=proposal.title,
            severity=proposal.severity,
            description=proposal.description,
            citations=citations,
            remediation=proposal.remediation,
            source=proposal.source,
            metadata=metadata,
            confirmation_level=confirmation,
        )

    def promote_canonical_finding(
        self,
        *,
        title: str,
        severity: str,
        citations: List[Citation],
        description: str,
        confirmation_level: str,
        remediation: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        active_proof: Optional[List[ActiveProofCitation]] = None,
        timestamp_override: Optional[float] = None,
    ) -> Finding:
        """Promote a non-hypothetical claim grounded only in session evidence."""

        if not citations:
            raise ValueError("canonical finding requires citations")
        normalized_citations = sorted(
            citations,
            key=lambda item: json.dumps(asdict(item), sort_keys=True, default=str),
        )
        observations = [
            self._observations.get(item.observation_id)
            for item in normalized_citations
        ]
        if any(not isinstance(item, ObservationEnvelope) for item in observations):
            raise ValueError(
                "canonical finding citations must resolve to canonical observations"
            )
        sessions = {
            item.session_id
            for item in observations
            if isinstance(item, ObservationEnvelope)
        }
        if len(sessions) != 1:
            raise ValueError("canonical finding cannot cross session identities")
        session_id = sessions.pop()
        if any(
            item.tool.name == "capability_effect_evidence"
            for item in observations
            if isinstance(item, ObservationEnvelope)
        ):
            raise ValueError(
                "capability effect evidence requires typed replay-leak admission"
            )
        normalized_active_proof = sorted(
            active_proof or [],
            key=lambda item: json.dumps(asdict(item), sort_keys=True),
        )
        self._validate_active_proof(
            evidence_citations=normalized_citations,
            observations=observations,
            active_proof=normalized_active_proof,
        )
        finding = Finding(
            id="",
            title=title,
            severity=severity,
            citations=normalized_citations,
            description=description,
            remediation=remediation,
            metadata=dict(metadata or {}),
            confirmation_level=confirmation_level,
            session_id=session_id,
            active_proof=normalized_active_proof,
        )
        finding.commitment = _canonical_finding_commitment(finding)
        finding.id = f"find-{finding.commitment.rsplit(':', 1)[-1]}"
        existing = self._findings.get(finding.id)
        if existing is not None:
            if existing.commitment != finding.commitment:
                raise ValueError("canonical finding commitment collision")
            return existing

        self._findings[finding.id] = finding
        try:
            self._emit_event(
                event_type=EventType.PROMOTED,
                entity_id=finding.id,
                payload=finding.to_dict(),
                timestamp_override=timestamp_override,
                canonical_session_id=session_id,
                durable_entity=("finding", finding.to_dict()),
            )
        except Exception:
            self._findings.pop(finding.id, None)
            raise
        return finding

    def admit_capability_replay_finding(
        self,
        *,
        evidence: Any,
        admission_id: str,
        event_timestamp: float,
        event_run_id: Optional[str],
    ) -> tuple[ObservationEnvelope, Finding]:
        """Atomically admit the R5D10 observation, finding, events, and job result.

        The caller must already have reloaded and validated the completed source
        receipt.  CAS publication intentionally precedes the bounded SQLite
        transaction; a crash may therefore leave an unreferenced immutable blob,
        but can never expose only half of the canonical result.
        """

        from core.behavior.capability_effect_evidence import (
            CapabilityEffectEvidence,
            evaluate_replay_leak,
            replay_leak_finding_material,
        )
        from core.behavior.compiler import OperationFamily, OperationInstance, OperationSafety

        if type(evidence) is not CapabilityEffectEvidence:
            raise TypeError("capability replay admission requires typed evidence")
        evaluation = evaluate_replay_leak(evidence)
        if not evaluation.eligible:
            raise ValueError("capability replay evidence is not eligible")
        if (
            isinstance(event_timestamp, bool)
            or not isinstance(event_timestamp, (int, float))
            or event_timestamp <= 0
        ):
            raise ValueError("capability replay event timestamp is invalid")

        identity = AssessmentIdentityContext.from_dict(evidence.identity_binding)
        raw_evidence = evidence.to_json_bytes()
        blob_hash = self.cas.store(raw_evidence)
        source_ref = stable_hash(
            "source_ref",
            {
                "source_receipt_id": evidence.source_receipt_id,
                "evidence_root": evidence.evidence_root,
            },
        )
        family = OperationFamily.build(
            action_id=stable_hash(
                "action",
                {"kind": "capability_replay_leak_evidence_admission"},
            ),
            label="capability replay-leak evidence admission",
            method="LOCAL",
            requires=(),
            safety=OperationSafety.READ_ONLY,
            source_refs=(source_ref,),
        )
        instance = OperationInstance.build(
            family_id=family.family_id,
            source_ref=source_ref,
            world_ref=(
                identity.world_id
                if identity.world_id.startswith("world:")
                else stable_hash("world", identity.world_id)
            ),
            state_ref=stable_hash(
                "state",
                {
                    "evidence_root": evidence.evidence_root,
                    "source_receipt_id": evidence.source_receipt_id,
                },
            ),
            response_status=200,
            outputs=(),
        )
        tool = ToolContext(
            name="capability_effect_evidence",
            args=(evidence.source_receipt_id,),
            version=evidence.adapter_contract_version,
            exit_code=0,
        )
        observation_material = _observation_envelope_material(
            tool=tool,
            target=evidence.target_origin,
            blob_hash=blob_hash,
            identity=identity,
            operation_family=family,
            operation_instance=instance,
        )
        observation_commitment = stable_hash(
            "observation_envelope",
            observation_material,
        )
        observation = ObservationEnvelope(
            id=f"obs-{observation_commitment.rsplit(':', 1)[-1]}",
            timestamp=evidence.observed_at_epoch,
            tool=tool,
            target=evidence.target_origin,
            blob_hash=blob_hash,
            commitment=observation_commitment,
            identity=identity,
            operation_family=family,
            operation_instance=instance,
        )
        claim = replay_leak_finding_material(evidence)
        citation = Citation(observation_id=observation.id)
        active_proof = ActiveProofCitation(
            observation_id=observation.id,
            receipt_id=evidence.source_receipt_id,
            provenance_root=evidence.evidence_root,
        )
        finding = Finding(
            id="",
            title=claim["title"],
            severity=claim["severity"],
            citations=[citation],
            description=claim["description"],
            remediation=claim["remediation"],
            metadata=claim["metadata"],
            confirmation_level=claim["confirmation_level"],
            session_id=identity.session_id,
            active_proof=[active_proof],
        )
        finding.commitment = _canonical_finding_commitment(finding)
        finding.id = f"find-{finding.commitment.rsplit(':', 1)[-1]}"

        self._validate_active_proof(
            evidence_citations=[citation],
            observations=[observation],
            active_proof=[active_proof],
        )
        self._validate_capability_replay_finding(
            finding,
            [observation],
            require_committed_journal=False,
        )

        def event_for(event_type: EventType, entity: Any) -> EpistemicEvent:
            payload = entity.to_dict()
            content = {
                "type": event_type,
                "entity": entity.id,
                "payload": payload,
                "time": event_timestamp,
            }
            return EpistemicEvent(
                id=self._generate_deterministic_id("evt", content),
                event_type=event_type,
                entity_id=entity.id,
                payload=payload,
                timestamp=float(event_timestamp),
                run_id=event_run_id,
            )

        observation_event = event_for(EventType.OBSERVED, observation)
        finding_event = event_for(EventType.PROMOTED, finding)
        journal = self._repository.load_capability_effect_admission(admission_id)
        if journal is None:
            raise ValueError("capability replay admission journal is missing")

        def event_value(event: EpistemicEvent) -> Dict[str, Any]:
            return {
                "id": event.id,
                "event_type": event.event_type.value,
                "entity_id": event.entity_id,
                "payload": event.payload,
                "timestamp": event.timestamp,
                "run_id": event.run_id,
            }

        _committed, created = self._repository.commit_capability_effect_promotion(
            admission_id=admission_id,
            session_id=identity.session_id,
            observation_id=observation.id,
            observation_commitment=observation.commitment,
            observation=observation.to_dict(),
            observation_event=event_value(observation_event),
            finding_id=finding.id,
            finding_commitment=finding.commitment,
            finding=finding.to_dict(),
            finding_event=event_value(finding_event),
            evidence_root=evidence.evidence_root,
            cas_blob_hash=blob_hash,
            source_receipt_id=evidence.source_receipt_id,
            source_fingerprint=evidence.source_receipt_id.removeprefix(
                "behavioral-"
            ),
            identity=evidence.identity_binding,
            operation=journal["operation_data"],
            producer=evidence.producer_identity,
        )

        if not created:
            return observation, finding

        existing_observation = self._observations.get(observation.id)
        if existing_observation is not None and existing_observation != observation:
            raise ValueError("capability observation in-memory collision")
        existing_finding = self._findings.get(finding.id)
        if existing_finding is not None and existing_finding != finding:
            raise ValueError("capability finding in-memory collision")
        self._observations[observation.id] = observation
        self._findings[finding.id] = finding
        existing_event_ids = {item.id for item in self._event_log}
        for event in (observation_event, finding_event):
            if event.id in existing_event_ids:
                continue
            self._event_log.append(event)
            try:
                self._append_audit_event(event)
            except OSError:
                logger.exception("failed to append canonical capability audit event")
            self._apply_event(event)
            for listener in self._listeners:
                try:
                    listener(event)
                except Exception:
                    logger.exception("capability promotion listener failed")
        return observation, finding

    @staticmethod
    def _contains_provenance_root(value: Any, expected: str) -> bool:
        if value == expected:
            return True
        if isinstance(value, Mapping):
            return any(
                EvidenceLedger._contains_provenance_root(item, expected)
                for item in value.values()
            )
        if isinstance(value, (list, tuple)):
            return any(
                EvidenceLedger._contains_provenance_root(item, expected)
                for item in value
            )
        return False

    def _validate_active_proof(
        self,
        *,
        evidence_citations: List[Citation],
        observations: List[Optional[Observation]],
        active_proof: List[ActiveProofCitation],
    ) -> None:
        if not active_proof:
            raise ValueError(
                "active canonical finding requires a completed behavioral receipt "
                "and safety provenance"
            )
        cited_ids = {item.observation_id for item in evidence_citations}
        observation_index = {
            item.id: item
            for item in observations
            if isinstance(item, ObservationEnvelope)
        }
        if len(active_proof) != len(set(active_proof)):
            raise ValueError("active proof citations must be unique")

        for proof in active_proof:
            observation = observation_index.get(proof.observation_id)
            if proof.observation_id not in cited_ids or observation is None:
                raise ValueError("active proof must bind a cited canonical observation")
            fingerprint = proof.receipt_id.removeprefix("behavioral-")
            try:
                receipt = self._receipt_store.load(fingerprint)
            except (OSError, ReceiptStoreError) as exc:
                raise ValueError("active proof receipt could not be verified") from exc
            if receipt is None or receipt.state != COMPLETED or receipt.outcome is None:
                raise ValueError("active proof receipt is not completed")

            identity = observation.identity
            expected_target = stable_hash(
                "behavioral_receipt_target", identity.target_origin
            )
            expected_envelope = stable_hash(
                "behavioral_receipt_envelope", identity.authorization_envelope_id
            )
            expected_persona = stable_hash(
                "behavioral_receipt_persona", identity.persona_id
            )
            if (
                receipt.context.target_ref != expected_target
                or receipt.context.envelope_ref != expected_envelope
                or expected_persona
                not in {
                    receipt.context.source_persona_ref,
                    receipt.context.peer_persona_ref,
                }
            ):
                raise ValueError("active proof receipt identity does not match evidence")
            if observation.tool.name == "capability_effect_evidence":
                from core.behavior.capability_effect_evidence import (
                    CapabilityEffectEvidence,
                    evaluate_replay_leak,
                )

                evidence_value = receipt.outcome.get("capability_effect_evidence")
                if not isinstance(evidence_value, Mapping):
                    raise ValueError("capability active proof evidence is missing")
                try:
                    evidence = CapabilityEffectEvidence.from_mapping(evidence_value)
                except (TypeError, ValueError) as exc:
                    raise ValueError("capability active proof evidence is invalid") from exc
                blob = self.cas.load(observation.blob_hash)
                journal = self._repository.load_capability_effect_admission(
                    receipt.receipt_id
                )
                if (
                    blob != evidence.to_json_bytes()
                    or evidence.source_receipt_id != receipt.receipt_id
                    or evidence.assessment_session_id != observation.session_id
                    or evidence.identity_binding != observation.identity.to_dict()
                    or proof.provenance_root != evidence.evidence_root
                    or not evaluate_replay_leak(evidence).eligible
                    or journal is None
                    or journal["admission_id"] != evidence.execution_admission_ref
                    or journal["session_id"] != evidence.assessment_session_id
                    or journal["source_receipt_id"] != evidence.source_receipt_id
                    or journal["source_fingerprint"] != receipt.fingerprint
                    or journal["target_origin"] != evidence.target_origin
                    or journal["identity_data"] != evidence.identity_binding
                    or journal["operation_data"].get("specification_ref")
                    != evidence.specification_ref
                    or journal["operation_data"].get("operation_ref")
                    != evidence.operation_ref
                    or journal["operation_data"].get("execution_policy")
                    != evidence.execution_policy
                    or journal["producer_data"] != evidence.producer_identity
                    or journal.get("evidence_root")
                    not in {None, evidence.evidence_root}
                    or journal.get("cas_blob_hash")
                    not in {None, observation.blob_hash}
                    or journal.get("observation_id")
                    not in {None, observation.id}
                ):
                    raise ValueError("capability active proof evidence does not match")
                continue
            if not self._contains_provenance_root(
                receipt.outcome, proof.provenance_root
            ):
                raise ValueError(
                    "active proof provenance is not committed by the completed receipt"
                )
            if receipt.outcome.get("finding_confirmed") is False:
                raise ValueError("completed receipt does not support an active finding")
            if receipt.outcome.get("oracle_verdict") in {"refuted", "inconclusive"}:
                raise ValueError("completed receipt does not support an active finding")

    def _validate_capability_replay_finding(
        self,
        finding: Finding,
        observations: List[Optional[Observation]],
        *,
        require_committed_journal: bool = True,
    ) -> None:
        """Validate the special R5D10 claim on admission and every restore."""

        capability_observations = [
            item
            for item in observations
            if isinstance(item, ObservationEnvelope)
            and item.tool.name == "capability_effect_evidence"
        ]
        declared = finding.metadata.get("finding_class") == (
            "capability_replay_leak_v1"
        )
        if not declared and not capability_observations:
            return
        if not declared or len(capability_observations) != 1:
            raise ValueError("capability replay finding class is invalid")
        if (
            len(observations) != 1
            or not isinstance(observations[0], ObservationEnvelope)
            or observations[0].tool.name != "capability_effect_evidence"
            or len(finding.active_proof) != 1
        ):
            raise ValueError("capability replay finding evidence shape is invalid")
        observation = observations[0]
        blob = self.cas.load(observation.blob_hash)
        if blob is None:
            raise ValueError("capability replay finding evidence is unavailable")
        from core.behavior.capability_effect_evidence import (
            CapabilityEffectEvidence,
            replay_leak_finding_material,
        )

        try:
            evidence = CapabilityEffectEvidence.from_json_bytes(blob)
            material = replay_leak_finding_material(evidence)
        except (TypeError, ValueError) as exc:
            raise ValueError("capability replay finding evidence is invalid") from exc
        if (
            finding.title != material["title"]
            or finding.severity != material["severity"]
            or finding.description != material["description"]
            or finding.remediation != material["remediation"]
            or finding.confirmation_level != material["confirmation_level"]
            or finding.metadata != material["metadata"]
            or finding.citations != [Citation(observation_id=observation.id)]
            or finding.active_proof[0].observation_id != observation.id
            or finding.active_proof[0].receipt_id != evidence.source_receipt_id
            or finding.active_proof[0].provenance_root != evidence.evidence_root
        ):
            raise ValueError("capability replay finding template mismatch")
        if require_committed_journal:
            journal = self._repository.load_capability_effect_admission(
                evidence.source_receipt_id
            )
            if (
                journal is None
                or journal["state"] != "promoted"
                or journal["evidence_root"] != evidence.evidence_root
                or journal["cas_blob_hash"] != observation.blob_hash
                or journal["observation_id"] != observation.id
                or journal["finding_id"] != finding.id
            ):
                raise ValueError("capability replay promotion journal mismatch")

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

        # Derive confirmation level
        #
        # IMPORTANT (Rev 2 — epistemic rigor):
        # The source check fires BEFORE the citation quality check. This is deliberate.
        # Even if an AI proposal cites a valid tool observation, the CLAIM is still
        # speculative. The tool observation is confirmed evidence, but the AI's
        # interpretation of what that evidence means is a hypothesis.
        # ConfirmationLevel refers to CLAIM certainty, not EVIDENCE existence.
        # Do not reorder these checks.
        if proposal.confirmation_level:
            # Caller explicitly set it — trust it
            derived_confirmation = proposal.confirmation_level
        elif proposal.source in ("ai", "neural_strategy"):
            derived_confirmation = ConfirmationLevel.HYPOTHESIZED.value
        elif proposal.source == "heuristic":
            derived_confirmation = ConfirmationLevel.PROBABLE.value
        else:
            # Source is a tool name or unknown — check if citations reference real tool observations
            has_tool_observation = any(
                self._observations.get(c.observation_id) is not None
                and self._observations[c.observation_id].tool.name
                for c in valid_citations
            )
            derived_confirmation = (
                ConfirmationLevel.CONFIRMED.value if has_tool_observation
                else ConfirmationLevel.PROBABLE.value
            )
            
        # 2. Promote
        metadata = dict(proposal.metadata or {})
        metadata.pop("confirmation_level", None)
        return self.promote_finding(
            title=proposal.title,
            severity=proposal.severity,
            citations=valid_citations,
            description=proposal.description,
            confirmation_level=derived_confirmation,
            remediation=proposal.remediation,
            **metadata
        )

    def promote_finding(self, title: str, severity: str, citations: List[Citation], 
                       description: str, confirmation_level: str = "probable",
                       timestamp_override: Optional[float] = None, **kwargs) -> Finding:
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
            metadata=kwargs,
            confirmation_level=confirmation_level,
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
                "metadata": kwargs,
                "confirmation_level": confirmation_level,
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
            
        entity = self._observations.get(related_id) or self._findings.get(related_id)
        canonical_session_id = getattr(entity, "session_id", None)
        payload = {
            "reason_code": reason_code,
            "notes": notes,
        }
        if canonical_session_id is not None:
            payload["session_id"] = canonical_session_id

        # Canonical suppression must survive restart.  Legacy/global entities
        # retain their historical audit-only behavior.
        self._emit_event(
            event_type=EventType.SUPPRESSED,
            entity_id=related_id,
            payload=payload,
            timestamp_override=timestamp_override,
            canonical_session_id=canonical_session_id,
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
            
        finding = self._findings[finding_id]
        payload = {"reason": reason}
        if finding.session_id is not None:
            payload["session_id"] = finding.session_id
        self._emit_event(
            event_type=EventType.INVALIDATED,
            entity_id=finding_id,
            payload=payload,
            timestamp_override=timestamp_override,
            canonical_session_id=finding.session_id,
        )
        logger.info(f"[EvidenceLedger] Invalidated Finding {finding_id}: {reason}")

    def invalidate_observation(
        self,
        observation_id: str,
        reason: str,
        timestamp_override: Optional[float] = None,
    ) -> StateRecord:
        """Invalidate one canonical atom; dependent finding views cascade closed."""

        observation = self._observations.get(observation_id)
        if not isinstance(observation, ObservationEnvelope):
            raise ValueError("cannot invalidate an unknown canonical observation")
        self._emit_event(
            event_type=EventType.INVALIDATED,
            entity_id=observation_id,
            payload={"reason": reason, "session_id": observation.session_id},
            timestamp_override=timestamp_override,
            canonical_session_id=observation.session_id,
        )
        return self.get_state(observation_id)

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

    def _emit_event(
        self,
        event_type: EventType,
        entity_id: str,
        payload: Dict[str, Any],
        timestamp_override: Optional[float] = None,
        canonical_session_id: Optional[str] = None,
        durable_entity: Optional[Tuple[str, Mapping[str, Any]]] = None,
    ) -> EpistemicEvent:
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

        event_value = {
            "id": event.id,
            "event_type": event.event_type.value,
            "entity_id": event.entity_id,
            "payload": event.payload,
            "timestamp": event.timestamp,
            "run_id": event.run_id,
        }
        if canonical_session_id is not None:
            if payload.get("session_id") != canonical_session_id:
                raise ValueError("canonical event session mismatch")
            if durable_entity is None:
                self._repository.append_event(
                    session_id=canonical_session_id,
                    event=event_value,
                )
            else:
                kind, entity_value = durable_entity
                self._repository.append_entity_event(
                    session_id=canonical_session_id,
                    kind=kind,
                    entity_id=entity_id,
                    commitment=entity_value["commitment"],
                    entity=entity_value,
                    event=event_value,
                )
        elif durable_entity is not None:
            raise ValueError("durable entity requires a canonical session")
        
        self._event_log.append(event)
        
        # Persist to Audit Log
        try:
            self._append_audit_event(event)
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
            self._set_state(
                event.entity_id,
                LifecycleState.OBSERVED,
                reason="Observed",
                timestamp=event.timestamp,
            )
            
        elif event.event_type == EventType.PROMOTED:
            self._set_state(
                event.entity_id,
                LifecycleState.PROMOTED,
                reason="Promoted",
                timestamp=event.timestamp,
            )
            
        elif event.event_type == EventType.SUPPRESSED:
            reason = f"{event.payload.get('reason_code')}: {event.payload.get('notes')}"
            self._set_state(
                event.entity_id,
                LifecycleState.SUPPRESSED,
                reason=reason,
                timestamp=event.timestamp,
            )
            
        elif event.event_type == EventType.INVALIDATED:
            reason = event.payload.get("reason", "Invalidated")
            self._set_state(
                event.entity_id,
                LifecycleState.INVALIDATED,
                reason=reason,
                timestamp=event.timestamp,
            )
            observation = self._observations.get(event.entity_id)
            if isinstance(observation, ObservationEnvelope):
                for finding in self._findings.values():
                    if any(
                        citation.observation_id == observation.id
                        for citation in finding.citations
                    ):
                        self._set_state(
                            finding.id,
                            LifecycleState.INVALIDATED,
                            reason=f"Cited observation invalidated: {reason}",
                            timestamp=event.timestamp,
                        )

    def _set_state(
        self,
        entity_id: str,
        state: LifecycleState,
        reason: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> StateRecord:
        """Internal helper to update state table view."""
        record = StateRecord(
            entity_id=entity_id,
            state=state,
            reason=reason,
            timestamp=timestamp if timestamp is not None else time.time(),
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

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self._findings.get(finding_id)

    def session_read_model(self, session_id: str) -> CanonicalSessionReadModel:
        """Derive the only reader-facing view for one explicit session."""

        if not isinstance(session_id, str) or not session_id or session_id == "global_scan":
            raise ValueError("canonical read model requires an explicit session")
        session_observations = tuple(
            sorted(
                (
                    item
                    for item in self._observations.values()
                    if isinstance(item, ObservationEnvelope)
                    and item.session_id == session_id
                ),
                key=lambda item: item.id,
            )
        )
        active_observations = tuple(
            item
            for item in session_observations
            if self.get_state(item.id) is not None
            and self.get_state(item.id).state is LifecycleState.OBSERVED
        )
        active_observation_ids = {item.id for item in active_observations}
        session_findings = tuple(
            sorted(
                (
                    item
                    for item in self._findings.values()
                    if item.session_id == session_id
                ),
                key=lambda item: item.id,
            )
        )
        active_findings = tuple(
            Finding.from_dict(item.to_dict())
            for item in session_findings
            if self.get_state(item.id) is not None
            and self.get_state(item.id).state is LifecycleState.PROMOTED
            and all(
                citation.observation_id in active_observation_ids
                for citation in item.citations
            )
        )
        state_material = []
        for entity in (*session_observations, *session_findings):
            state = self.get_state(entity.id)
            state_material.append(
                {
                    "id": entity.id,
                    "commitment": entity.commitment,
                    "state": state.state.value if state is not None else "missing",
                    "reason": state.reason if state is not None else None,
                }
            )
        revision = stable_hash(
            "canonical_session_read_model",
            {
                "session_id": session_id,
                "entities": sorted(state_material, key=lambda item: item["id"]),
            },
        )
        return CanonicalSessionReadModel(
            session_id=session_id,
            revision=revision,
            observations=active_observations,
            findings=active_findings,
        )
        
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
            "metadata": finding.metadata,
            "confirmation_level": finding.confirmation_level,
        }
        findings_store.add_finding(finding_dict, persist=False)


def load_canonical_session_read_model(
    session_id: str,
    *,
    config: Optional[SentinelConfig] = None,
    receipt_store: Optional[BehavioralReceiptStore] = None,
) -> CanonicalSessionReadModel:
    """Load a fresh DB/CAS-backed view so readers cannot retain stale truth."""

    return EvidenceLedger(
        config,
        receipt_store=receipt_store,
    ).session_read_model(session_id)
