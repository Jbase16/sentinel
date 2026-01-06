"""
ScanCapsule Codec.

Handles the serialization and deserialization of the full CapsuleManifest (JSON <> Objects).
Bridging the gap between the Merkle DAG logic and the file system.
"""

import json
from typing import Dict, Any, List
from dataclasses import asdict

from core.replay.models import CapsuleManifest, MerkleBlock
from core.replay.merkle import MerkleEngine

class CapsuleCodec:
    """
    Codec for reading/writing ScanCapsules.
    """
    
    @staticmethod
    def encode(manifest: CapsuleManifest) -> str:
        """
        Encode a CapsuleManifest to a JSON string.
        Automated integrity calculation included.
        """
        # 1. Convert blocks to dicts
        blocks_data = [
            {
                "id": b.id,
                "parents": b.parents,
                "kind": b.kind,
                "payload": b.payload,
                "meta": b.meta
            }
            for b in manifest.blocks
        ]
        
        # 2. Build the "Content" dict (everything EXCEPT the outer hash)
        content = {
            "version": manifest.version,
            "capsule_id": manifest.capsule_id,
            "created_at": manifest.created_at,
            "config": manifest.config,
            "tool_versions": manifest.tool_versions,
            "policy_digest": manifest.policy_digest,
            "model_identity": manifest.model_identity,
            "blocks": blocks_data,
            "redaction_report": manifest.redaction_report
        }
        
        # 3. Calculate Integrity Seal
        # The 'hash' field seals the entire content of the capsule.
        integrity_hash = MerkleEngine.compute_hash(content)
        
        # 4. Add hash to final envelope
        envelope = content.copy()
        envelope["hash"] = integrity_hash
        
        # 5. Serialize (Canonical)
        return MerkleEngine.canonicalize(envelope).decode('utf-8')

    @staticmethod
    def decode(json_str: str) -> CapsuleManifest:
        """
        Decode a JSON string to a CapsuleManifest.
        Verifies integrity hash automatically.
        """
        data = json.loads(json_str)
        
        # 1. Verify Integrity
        claimed_hash = data.pop("hash", None)
        if not claimed_hash:
            raise ValueError("Capsule missing integrity hash.")
            
        computed_hash = MerkleEngine.compute_hash(data)
        if computed_hash != claimed_hash:
            raise ValueError(f"Capsule integrity failure. Claimed: {claimed_hash}, Computed: {computed_hash}")
            
        # 2. Rehydrate Blocks
        blocks = [
            MerkleBlock(
                id=b["id"],
                parents=b["parents"],
                kind=b["kind"],
                payload=b["payload"],
                meta=b["meta"]
            )
            for b in data.get("blocks", [])
        ]
        
        # 3. Verify Block Chain (Internal Consistency)
        for block in blocks:
            if not MerkleEngine.verify_block(block):
                raise ValueError(f"Block integrity failure: {block.id}")
        
        return CapsuleManifest(
            version=data["version"],
            capsule_id=data["capsule_id"],
            created_at=data["created_at"],
            config=data["config"],
            tool_versions=data["tool_versions"],
            policy_digest=data["policy_digest"],
            model_identity=data["model_identity"],
            blocks=blocks,
            hash=claimed_hash,
            redaction_report=data.get("redaction_report", {})
        )
