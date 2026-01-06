"""
ScanCapsule Models.

Defines the content-addressable block structure for the Merkle-Causal DAG.
These models are the "Atoms" of the Infinite Replay system.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass(frozen=True)
class MerkleBlock:
    """
    A single node in the Merkle-Causal DAG.
    
    Immutability Invariant:
        The `id` is ALWAYS sha256(jcs.canonicalize(payload + parents + kind + meta)).
        Changing a single byte of payload changes the ID.
    """
    id: str
    parents: List[str]      # Causal dependencies (Hash IDs)
    kind: str               # "observed" | "decision" | "fact" | "error"
    payload: Dict[str, Any] # The actual event data
    meta: Dict[str, Any]    # Non-functional metadata (timestamp, etc.)

    @property
    def is_redacted(self) -> bool:
        """Check if this block is a redaction tombstone."""
        return self.payload.get("__redacted__") is True

@dataclass
class CapsuleManifest:
    """
    The Container Format for a ScanCapsule.
    
    This represents a serialized "Flight Recording" of a session.
    It contains the DAG blocks and the Context required to replay them.
    """
    version: str            # Schema version (e.g., "1.0.0")
    capsule_id: str         # UUID of this specific recording
    created_at: float       # Unix timestamp
    
    # Context (The "World" state at start)
    config: Dict[str, Any]              # Run configuration
    tool_versions: Dict[str, str]       # "nmap": "7.95"
    policy_digest: str                  # SHA256 of the policy config
    model_identity: str                 # "internal-model-v2"
    
    # The DAG (Topologically sorted list of blocks)
    blocks: List[MerkleBlock]
    
    # Integrity Seal
    hash: str               # SHA256(canonical_json(this_object_excluding_hash))

    # Redaction Report (Transparency)
    redaction_report: Dict[str, Any] = field(default_factory=dict)
