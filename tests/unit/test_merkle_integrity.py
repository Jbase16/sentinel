"""
Unit Tests for Merkle-Causal Replay Core.

Verifies:
1. JCS Canonicalization Determinism
2. Block Hashing (Content Addressing)
3. Chain of Custody (Parent Linking)
4. Capsule Serialization Integrity
"""

import unittest
import json
from core.replay.models import MerkleBlock, CapsuleManifest
from core.replay.merkle import MerkleEngine
from core.replay.codec import CapsuleCodec

class TestMerkleCore(unittest.TestCase):
    
    def test_jcs_determinism(self):
        """Ensure dictionary key ordering doesn't affect hash."""
        data_a = {"b": 1, "a": 2}
        data_b = {"a": 2, "b": 1}
        
        canon_a = MerkleEngine.canonicalize(data_a)
        canon_b = MerkleEngine.canonicalize(data_b)
        
        self.assertEqual(canon_a, canon_b)
        self.assertEqual(MerkleEngine.compute_hash(data_a), MerkleEngine.compute_hash(data_b))

    def test_block_identity(self):
        """Ensure block ID depends on content."""
        payload = {"event": "scan_start"}
        block1 = MerkleEngine.create_block([], "observed", payload, {})
        block2 = MerkleEngine.create_block([], "observed", payload, {})
        
        # Identity
        self.assertEqual(block1.id, block2.id)
        
        # Tamper Payload
        block3 = MerkleEngine.create_block([], "observed", {"event": "scan_stop"}, {})
        self.assertNotEqual(block1.id, block3.id)
        
        # Tamper Parents
        block4 = MerkleEngine.create_block(["parent_x"], "observed", payload, {})
        self.assertNotEqual(block1.id, block4.id)

    def test_capsule_roundtrip(self):
        """Ensure CapsuleCodec handles serialization and integrity checks."""
        # Create a Chain
        b1 = MerkleEngine.create_block([], "root", {"data": "start"}, {})
        b2 = MerkleEngine.create_block([b1.id], "child", {"data": "next"}, {})
        
        manifest = CapsuleManifest(
            version="1.0.0",
            capsule_id="test-uuid",
            created_at=123456789.0,
            config={"safe_mode": True},
            tool_versions={"nmap": "7.95"},
            policy_digest="sha256...",
            model_identity="test-model",
            blocks=[b1, b2],
            hash="", # Computed by codec
            redaction_report={}
        )
        
        # Encode
        json_str = CapsuleCodec.encode(manifest)
        
        # Decode
        decoded = CapsuleCodec.decode(json_str)
        
        self.assertEqual(decoded.capsule_id, "test-uuid")
        self.assertEqual(len(decoded.blocks), 2)
        self.assertEqual(decoded.blocks[0].id, b1.id)
        self.assertEqual(decoded.blocks[1].parents, [b1.id])
        
    def test_tamper_detection(self):
        """Ensure modified JSON fails integrity check."""
        b1 = MerkleEngine.create_block([], "root", {"data": "start"}, {})
        manifest = CapsuleManifest(
            version="1.0.0",
            capsule_id="test-uuid",
            created_at=1234.0,
            config={},
            tool_versions={},
            policy_digest="x",
            model_identity="y",
            blocks=[b1],
            hash="",
            redaction_report={}
        )
        
        json_str = CapsuleCodec.encode(manifest)
        
        # Tamper with the string
        tampered_json = json_str.replace("start", "tamped")
        
        with self.assertRaises(ValueError) as cm:
            CapsuleCodec.decode(tampered_json)
        self.assertIn("Capsule integrity failure", str(cm.exception))

if __name__ == '__main__':
    unittest.main()
