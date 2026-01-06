"""
Unit Tests for Merkle-Causal Replay Core.

Verifies:
1. Canonicalization determinism
2. Block hashing (content addressing)
3. Parent linking behavior
4. Capsule serialization integrity
"""

import unittest

from core.replay.models import CapsuleManifest
from core.replay.merkle import MerkleEngine
from core.replay.codec import CapsuleCodec


class TestMerkleCore(unittest.TestCase):

    def test_canonical_determinism(self):
        """Ensure dict key ordering doesn't affect canonical bytes/hashes."""
        data_a = {"b": 1, "a": 2}
        data_b = {"a": 2, "b": 1}

        canon_a = MerkleEngine.canonicalize(data_a)
        canon_b = MerkleEngine.canonicalize(data_b)

        self.assertEqual(canon_a, canon_b)
        self.assertEqual(MerkleEngine.compute_hash(data_a), MerkleEngine.compute_hash(data_b))

    def test_number_normalization(self):
        """Ensure 1.0 normalizes to 1 for canonicalization stability."""
        a = {"n": 1.0}
        b = {"n": 1}
        self.assertEqual(MerkleEngine.canonicalize(a), MerkleEngine.canonicalize(b))
        self.assertEqual(MerkleEngine.compute_hash(a), MerkleEngine.compute_hash(b))

    def test_block_identity_and_tamper(self):
        payload = {"event": "scan_start"}
        block1 = MerkleEngine.create_block([], "observed", payload, {"t": 1})
        block2 = MerkleEngine.create_block([], "observed", payload, {"t": 1})

        # Identical content => identical id
        self.assertEqual(block1.id, block2.id)

        # Tamper payload => different id
        block3 = MerkleEngine.create_block([], "observed", {"event": "scan_stop"}, {"t": 1})
        self.assertNotEqual(block1.id, block3.id)

        # Tamper parents => different id
        block4 = MerkleEngine.create_block(["parent_x"], "observed", payload, {"t": 1})
        self.assertNotEqual(block1.id, block4.id)

    def test_capsule_roundtrip(self):
        b1 = MerkleEngine.create_block([], "root", {"data": "start"}, {"t": 1})
        b2 = MerkleEngine.create_block([b1.id], "child", {"data": "next"}, {"t": 2})

        manifest = CapsuleManifest(
            version="1.0.0",
            capsule_id="test-uuid",
            created_at=123456789.0,
            config={"safe_mode": True},
            tool_versions={"nmap": "7.95"},
            policy_digest="sha256...",
            model_identity="test-model",
            blocks=[b1, b2],
            hash="",  # computed by codec
            redaction_report={},
        )

        encoded = CapsuleCodec.encode(manifest)
        decoded = CapsuleCodec.decode(encoded)

        self.assertEqual(decoded.capsule_id, "test-uuid")
        self.assertEqual(len(decoded.blocks), 2)
        self.assertEqual(decoded.blocks[0].id, b1.id)
        self.assertEqual(decoded.blocks[1].parents, [b1.id])

    def test_tamper_detection(self):
        b1 = MerkleEngine.create_block([], "root", {"data": "start"}, {"t": 1})
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
            redaction_report={},
        )

        encoded = CapsuleCodec.encode(manifest)

        # Tamper the serialized JSON (breaks integrity seal)
        tampered = encoded.replace("start", "tampered")

        with self.assertRaises(ValueError) as cm:
            CapsuleCodec.decode(tampered)

        self.assertIn("Capsule integrity failure", str(cm.exception))

    def test_advanced_normalization(self):
        """Test auto-conversion of bytes and dataclasses."""
        from dataclasses import dataclass
        @dataclass
        class Config:
            key: str
            data: bytes

        raw = Config(key="test", data=b"hello")
        
        # Should normalize to {"key": "test", "data": "aGVsbG8="}
        normalized = MerkleEngine._normalize_json(raw)
        
        self.assertEqual(normalized["data"], "aGVsbG8=")
        self.assertEqual(normalized["key"], "test")

    def test_error_paths(self):
        """Ensure errors report their location."""
        bad_data = {"a": {"b": [1, float('nan')]}}
        
        with self.assertRaises(ValueError) as cm:
            MerkleEngine.canonicalize(bad_data)
        
        self.assertIn("at '$.a.b[1]'", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
