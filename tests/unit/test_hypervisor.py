"""
Unit Tests for Counterfactual Hypervisor.

Verifies:
1. Linear Replay (Topological stepping)
2. Fork Isolation (Deepcopy effectiveness)
3. Structural Validation
"""

import unittest
from core.replay.models import MerkleBlock, CapsuleManifest
from core.replay.merkle import MerkleEngine
from core.replay.hypervisor import ReplayEngine, ReplayContext

class TestHypervisor(unittest.TestCase):
    
    def create_manifest(self) -> CapsuleManifest:
        """Create a simple A->B->C chain."""
        b1 = MerkleEngine.create_block([], "root", {"val": 1}, {})
        b2 = MerkleEngine.create_block([b1.id], "step", {"val": 2}, {})
        b3 = MerkleEngine.create_block([b2.id], "step", {"val": 3}, {})
        
        return CapsuleManifest(
            version="1.0.0",
            capsule_id="test-capsule",
            created_at=0.0,
            config={}, tool_versions={}, policy_digest="x", model_identity="y",
            blocks=[b1, b2, b3],
            hash="", # Not checked here
            redaction_report={}
        )

    def test_linear_replay(self):
        """Ensure we can walk the chain A->B->C."""
        manifest = self.create_manifest()
        engine = ReplayEngine(manifest)
        ctx = engine.start_session()
        
        # Step 1 -> A
        block = engine.step(ctx)
        self.assertIsNotNone(block)
        self.assertEqual(block.payload["val"], 1)
        self.assertEqual(ctx.cursor_id, block.id)
        
        # Step 2 -> B
        block = engine.step(ctx)
        self.assertEqual(block.payload["val"], 2)
        
        # Step 3 -> C
        block = engine.step(ctx)
        self.assertEqual(block.payload["val"], 3)
        
        # End
        block = engine.step(ctx)
        self.assertIsNone(block)

    def test_fork_isolation(self):
        """Ensure fork creates a completely isolated universe."""
        manifest = self.create_manifest()
        engine = ReplayEngine(manifest)
        ctx1 = engine.start_session()
        
        # Advance to B
        engine.step(ctx1) # A
        engine.step(ctx1) # B
        
        # Fork Reality
        ctx2 = ctx1.fork()
        
        # Modifying ctx2 should NOT affect ctx1
        ctx2.ledger["evidence"].append("fake_evidence")
        
        self.assertIn("fake_evidence", ctx2.ledger["evidence"])
        self.assertNotIn("fake_evidence", ctx1.ledger["evidence"])
        
        # Advance ctx1 to C
        b_c = engine.step(ctx1)
        self.assertIsNotNone(b_c)
        self.assertEqual(b_c.payload["val"], 3)
        
        # ctx2 should still remain at B (no auto-advance)
        self.assertNotEqual(ctx2.cursor_id, ctx1.cursor_id)

    def test_broken_chain_detection(self):
        """Ensure missing parents raise error."""
        b1 = MerkleEngine.create_block([], "root", {}, {})
        b2 = MerkleEngine.create_block(["missing_id"], "broken", {}, {})
        
        manifest = CapsuleManifest(
            version="1.0", capsule_id="x", created_at=0,
            config={}, tool_versions={}, policy_digest="", model_identity="",
            blocks=[b1, b2], hash="x"
        )
        
        with self.assertRaisesRegex(ValueError, "missing parent"):
            ReplayEngine(manifest)

if __name__ == '__main__':
    unittest.main()
