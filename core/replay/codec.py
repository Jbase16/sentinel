"""
ScanCapsule Codec.

Serialization/deserialization for CapsuleManifest (JSON <-> Objects),
including:
- capsule integrity seal (hash over canonical manifest content excluding "hash")
- per-block integrity checks (Merkle ID verification)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from core.replay.models import CapsuleManifest, MerkleBlock
from core.replay.merkle import MerkleEngine


class CapsuleCodec:
    """
    Codec for reading/writing ScanCapsules.
    """

    @staticmethod
    def _manifest_content_dict(manifest: CapsuleManifest) -> Dict[str, Any]:
        """
        Build the dict that is sealed by `manifest.hash` (excludes hash itself).
        """
        blocks_data: List[Dict[str, Any]] = [
            {
                "id": b.id,
                "parents": b.parents,
                "kind": b.kind,
                "payload": b.payload,
                "meta": b.meta,
            }
            for b in manifest.blocks
        ]

        return {
            "version": manifest.version,
            "capsule_id": manifest.capsule_id,
            "created_at": manifest.created_at,
            "config": manifest.config,
            "tool_versions": manifest.tool_versions,
            "policy_digest": manifest.policy_digest,
            "model_identity": manifest.model_identity,
            "blocks": blocks_data,
            "redaction_report": manifest.redaction_report,
        }

    @staticmethod
    def encode(manifest: CapsuleManifest) -> str:
        """
        Encode a CapsuleManifest to a canonical JSON string.
        Computes the integrity seal automatically.
        """
        content = CapsuleCodec._manifest_content_dict(manifest)
        integrity_hash = MerkleEngine.compute_hash(content)

        envelope = dict(content)
        envelope["hash"] = integrity_hash

        # Canonical serialization of the final envelope
        return MerkleEngine.canonicalize(envelope).decode("utf-8")

    @staticmethod
    def decode(json_str: str) -> CapsuleManifest:
        """
        Decode a canonical JSON string to CapsuleManifest.
        Verifies:
        - capsule integrity seal
        - per-block Merkle IDs
        """
        data = json.loads(json_str)

        claimed_hash = data.get("hash")
        if not claimed_hash or not isinstance(claimed_hash, str):
            raise ValueError("Capsule missing integrity hash.")

        # Compute integrity over content *excluding* "hash"
        data_without_hash = dict(data)
        data_without_hash.pop("hash", None)

        computed_hash = MerkleEngine.compute_hash(data_without_hash)
        if computed_hash != claimed_hash:
            raise ValueError(
                f"Capsule integrity failure. Claimed: {claimed_hash}, Computed: {computed_hash}"
            )

        # Rehydrate blocks
        raw_blocks = data_without_hash.get("blocks", [])
        if not isinstance(raw_blocks, list):
            raise ValueError("Capsule 'blocks' must be a list.")

        blocks: List[MerkleBlock] = []
        for b in raw_blocks:
            if not isinstance(b, dict):
                raise ValueError("Each block must be an object/dict.")
            block = MerkleBlock(
                id=b["id"],
                parents=b["parents"],
                kind=b["kind"],
                payload=b["payload"],
                meta=b["meta"],
            )
            # Verify block integrity
            if not MerkleEngine.verify_block(block):
                raise ValueError(f"Block integrity failure: {block.id}")
            blocks.append(block)

        return CapsuleManifest(
            version=data_without_hash["version"],
            capsule_id=data_without_hash["capsule_id"],
            created_at=data_without_hash["created_at"],
            config=data_without_hash["config"],
            tool_versions=data_without_hash["tool_versions"],
            policy_digest=data_without_hash["policy_digest"],
            model_identity=data_without_hash["model_identity"],
            blocks=blocks,
            hash=claimed_hash,
            redaction_report=data_without_hash.get("redaction_report", {}),
        )
