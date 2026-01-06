"""
Integration Test for Replay Semantics.

Verifies that the Hypervisor correctly drives the EvidenceLedger to reconstruct state.
"The VM runs the code correctly."
"""

import unittest
import time
from core.epistemic.ledger import EvidenceLedger, LifecycleState
from core.replay.models import CapsuleManifest
from core.replay.merkle import MerkleEngine
from core.replay.hypervisor import ReplayEngine, ReplayContext

class TestReplaySemantics(unittest.TestCase):
    
    def test_fidelity(self):
        """
        Prove that replaying a capsule restores the exact state of the ledger.
        """
        # 1. Create Original Reality
        # We manually build the capsule here to mock the "Recorder" which doesn't exist yet.
        # Ideally, we'd have a `LedgerListener` that builds blocks. 
        # For now, we construct blocks representing a history.
        
        ts_start = 1000.0
        b1 = MerkleEngine.create_block(
            parents=[], 
            kind="observed", 
            payload={
                "tool": "nmap", 
                "args": ["-p80"], 
                "target": "localhost", 
                "blob": "gw==" # b"data"
            }, 
            meta={"timestamp": ts_start}
        )
        
        b2 = MerkleEngine.create_block(
            parents=[b1.id], 
            kind="decision", 
            payload={
                "action": "promote",
                "title": "Open Port 80",
                "severity": "info",
                "description": "Port 80 is open",
                "citations": [] # In real life, needs citations.
            }, 
            meta={"timestamp": ts_start + 10}
        )
        
        manifest = CapsuleManifest(
            version="1.0", capsule_id="test", created_at=0,
            config={}, tool_versions={}, policy_digest="x", model_identity="y",
            blocks=[b1, b2], hash="x", redaction_report={}
        )
        
        # 2. Replay into Fresh Ledger
        # We need a real EvidenceLedger instance. 
        # We mock the config to avoid disk I/O / threading issues for this unit test if possible,
        # or use a temp dir.
        
        # Using a specialized subclass or mocking CAS might be needed if EvidenceLedger is heavy.
        # Let's try direct instantiation; it uses CAS -> writes to .sentinelforge usually.
        # We should patch SentinelConfig to use a temp dir.
        from unittest.mock import MagicMock, patch
        
        # Mock GlobalSequenceAuthority
        with patch('core.base.sequence.GlobalSequenceAuthority') as mock_gsa_cls:
            
            mock_gsa = MagicMock()
            mock_gsa.run_id = "test-run-123"
            mock_gsa_cls.instance.return_value = mock_gsa
            
            mock_config = MagicMock()
            mock_config.storage_path = "/tmp/sentinel_test_replay"
            import os
            os.makedirs(mock_config.storage_path, exist_ok=True)
            
            ledger = EvidenceLedger(config=mock_config)
            # Prevent DB writes by mocking the sync method directly
            ledger._update_findings_store = MagicMock()
            
            engine = ReplayEngine(manifest)
            ctx = ReplayContext(ledger) # Bind the Real Ledger
            
            # Step 1: Observed
            engine.step(ctx)
            
            # Assert Observation exists
            # We don't know the OBS ID because it's hash-based.
            # But we know an event should have been emitted.
            self.assertEqual(len(ledger._event_log), 1)
            self.assertEqual(ledger._event_log[0].timestamp, ts_start) # PROOF OF TIME TRAVEL
            
            # Step 2: Decided
            engine.step(ctx)
            
            self.assertEqual(len(ledger._event_log), 2)
            self.assertEqual(ledger._event_log[1].timestamp, ts_start + 10)
            self.assertEqual(ledger._event_log[1].payload["title"], "Open Port 80")
            
            # State Table check
            # We need to find the Finding ID (generated inside promote_finding).
            # We can look at the findings map.
            self.assertEqual(len(ledger._findings), 1)
            finding = list(ledger._findings.values())[0]
            self.assertEqual(finding.title, "Open Port 80")

if __name__ == '__main__':
    unittest.main()
