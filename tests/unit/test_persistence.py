"""
Unit Tests for ScanCapsule Persistence.

Verifies:
1. JSONL Write/Flush correctness.
2. Roundtrip fidelity (Write -> Load -> Compare).
"""

import unittest
import tempfile
import shutil
from pathlib import Path

from core.replay.models import MerkleBlock
from core.replay.merkle import MerkleEngine
from core.replay.persistence import CapsuleRecorder, CapsuleLoader

class TestPersistence(unittest.TestCase):
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.capsule_path = Path(self.test_dir) / "test.capsule"
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_roundtrip(self):
        """Ensure what we write is what we read."""
        
        # 1. Create Data
        b1 = MerkleEngine.create_block([], "root", {"val": 1}, {})
        b2 = MerkleEngine.create_block([b1.id], "child", {"val": 2}, {})
        
        # 2. Record (Using Context Manager)
        with CapsuleRecorder(self.capsule_path) as recorder:
            recorder.start(
                capsule_id="test-cap-001",
                config={"debug": True},
                tool_versions={"nmap": "7.92"},
                policy_digest="sha256:abc",
                model_identity="gpt-4"
            )
            recorder.write_block(b1)
            recorder.write_block(b2)
        
        # 3. Read Back (Normal Load)
        manifest = CapsuleLoader.load(self.capsule_path)
        
        # 4. Verify Header
        self.assertEqual(manifest.capsule_id, "test-cap-001")
        self.assertEqual(manifest.config["debug"], True)
        
        # 5. Verify Streaming Interface
        streamed_blocks = list(CapsuleLoader.stream(self.capsule_path))
        self.assertEqual(len(streamed_blocks), 2)
        self.assertEqual(streamed_blocks[0].id, b1.id)
        self.assertEqual(streamed_blocks[1].id, b2.id)

    def test_partial_read(self):
        """Ensure loader handles files that were cut off (valid JSONL up to that point)."""
        # Manually create a file with 2 valid lines and 1 partial line
        with open(self.capsule_path, "w") as f:
            f.write('{"type": "manifest_header", "capsule_id": "partial"}\n')
            f.write('{"type": "block", "payload": {"id": "b1", "parents":[], "kind": "root", "payload": {}, "meta": {}}}\n')
            f.write('{"type": "block", "payl') # Crash mid-write
            
        # Loader should crash on the bad line? Or ignore it?
        # Our current implementation raises ValueError on JSONDecodeError.
        # Ideally, a crash recovery loader might ignore the last line.
        # But for strictly correct loading, raising error is safest.
        
        with self.assertRaises(ValueError):
            CapsuleLoader.load(self.capsule_path)

if __name__ == '__main__':
    unittest.main()
