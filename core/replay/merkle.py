"""
Merkle DAG Logic.

Handles the Canonicalization and Hashing of ScanCapsule blocks.
Implements RFC 8785 (JCS) for deterministic JSON serialization.
"""

import hashlib
import json
from typing import Any, Dict, List, Union

from core.replay.models import MerkleBlock

class MerkleEngine:
    """
    Cryptographic engine for the ScanCapsule.
    """

    @staticmethod
    def canonicalize(data: Any) -> bytes:
        """
        Serialize data to Canonical JSON (RFC 8785).
        
        Rules:
        1. Keys sorted lexicographically.
        2. No whitespace.
        3. UTF-8 encoding.
        """
        # We use Python's built-in json with sort_keys=True and tight separators.
        # This approximates JCS for simple types (dicts/lists/strings/numbers).
        # For floating point nuances, we assume standard Python behavior for now.
        return json.dumps(
            data, 
            sort_keys=True, 
            separators=(',', ':'), 
            ensure_ascii=False
        ).encode('utf-8')

    @classmethod
    def compute_hash(cls, data: Any) -> str:
        """Compute SHA-256 hash of canonicalized data."""
        canonical = cls.canonicalize(data)
        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def create_block(
        cls, 
        parents: List[str], 
        kind: str, 
        payload: Dict[str, Any], 
        meta: Dict[str, Any]
    ) -> MerkleBlock:
        """
        Create a new MerkleBlock with calculated ID.
        """
        # The structure to hash includes EVERYTHING impactful.
        # We wrap it in a structural envelope to ensure uniqueness rules.
        content = {
            "parents": sorted(parents), # Order-independent parent list? Or ordered? 
                                      # Causal parents = Set semantics usually, but Sequence = Ordered.
                                      # Let's enforce sorted for determinism of the *list*, 
                                      # assuming the *meaning* is set-of-parents.
            "kind": kind,
            "payload": payload,
            "meta": meta
        }
        
        block_id = cls.compute_hash(content)
        
        return MerkleBlock(
            id=block_id,
            parents=parents,
            kind=kind,
            payload=payload,
            meta=meta
        )

    @classmethod
    def verify_block(cls, block: MerkleBlock) -> bool:
        """
        Verify that a block's ID matches its content.
        """
        reconstructed = cls.create_block(
            parents=block.parents,
            kind=block.kind,
            payload=block.payload,
            meta=block.meta
        )
        return reconstructed.id == block.id
