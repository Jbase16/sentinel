"""
ScanCapsule Models.

Defines the content-addressable block structure for the Merkle-Causal DAG.
These models are the "Atoms" of the Infinite Replay system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class MerkleBlock:
    """
    A single node in the Merkle-Causal DAG.

    Immutability Invariant:
        id == sha256(canonical_json({
            "parents": parents,   # already canonicalized (sorted)
            "kind": kind,
            "payload": payload,
            "meta": meta
        }))

    IMPORTANT:
        - `payload` and `meta` MUST be JSON-serializable.
        - If you include timestamps in meta, identical events at different times
          will not deduplicate. That may be desired. Just be aware.
    """
    id: str
    parents: List[str]      # Causal dependencies (Hash IDs) — canonical order
    kind: str               # e.g. "observed" | "decision" | "fact" | "error"
    payload: Dict[str, Any] # Event data (sanitized later)
    meta: Dict[str, Any]    # Metadata (may include timestamps)

    @property
    def is_redacted(self) -> bool:
        """Check if this block is a redaction tombstone."""
        return self.payload.get("__redacted__") is True


@dataclass
class CapsuleManifest:
    """
    The Container Format for a ScanCapsule.

    Represents a serialized "Flight Recording" of a session:
        - Context (policy/model/tool versions)
        - DAG blocks (topologically sorted list)
        - Integrity seal (hash over canonical manifest content)
    """
    version: str            # Schema version (e.g., "1.0.0")
    capsule_id: str         # UUID of this specific recording
    created_at: float       # Unix timestamp (seconds)

    # Context (World state at start; allowlist-only)
    config: Dict[str, Any]
    tool_versions: Dict[str, str]
    policy_digest: str
    model_identity: str

    # DAG blocks (should be topologically sorted by parents)
    blocks: List[MerkleBlock]

    # Integrity Seal (sha256(canonical_json(manifest_without_hash)))
    hash: str

    # Redaction transparency
    redaction_report: Dict[str, Any] = field(default_factory=dict)
