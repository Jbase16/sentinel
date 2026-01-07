import unittest
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.epistemic.ledger import EvidenceLedger, Citation
from core.base.config import SentinelConfig, StorageConfig

class TestLedgerDeterminism(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.config = SentinelConfig(
            storage=StorageConfig(base_dir=self.test_dir)
        )
        
        # Patch GlobalSequenceAuthority at its source since it is lazily imported
        self.patcher = patch("core.base.sequence.GlobalSequenceAuthority")
        self.mock_gsa_cls = self.patcher.start()
        self.mock_gsa_instance = self.mock_gsa_cls.instance.return_value
        self.mock_gsa_instance.run_id = "run-test-123"
        
        # Patch findings_store instance at its source
        self.fs_patcher = patch("core.data.findings_store.findings_store")
        self.mock_fs = self.fs_patcher.start()
        
        self.ledger = EvidenceLedger(self.config)

    def tearDown(self):
        self.patcher.stop()
        self.fs_patcher.stop()
        shutil.rmtree(self.test_dir)

    def test_finding_idempotency(self):
        """
        Verify that promoting the exact same finding twice results in the same ID.
        """
        citations = [Citation(observation_id="obs-123", snippet="proof")]
        
        args = {
            "title": "SQL Injection",
            "severity": "critical",
            "citations": citations,
            "description": "Found a SQLi",
            "cwe": "89"
        }
        
        f1 = self.ledger.promote_finding(**args)
        
        # Create a FRESH ledger to ensure no state pollution (and no "already exists" checks interfering with ID generation logic verification)
        # Although promote_finding might check existance, the ID generation itself happens first usually.
        # But let's reuse the logic. If I call promote_finding again on same ledger, it might return existing obj or update.
        # Let's check ID generation logic specifically.
        
        ledger2 = EvidenceLedger(self.config)
        f2 = ledger2.promote_finding(**args)
        
        self.assertEqual(f1.id, f2.id, "Finding IDs must be deterministic based on content")
        self.assertTrue(f1.id.startswith("find-"), f"Finding ID should start with find-, got {f1.id}")

    def test_finding_sensitivity(self):
        """
        Verify that changing content changes the ID.
        """
        citations = [Citation(observation_id="obs-123", snippet="proof")]
        base_args = {
            "title": "SQL Injection",
            "severity": "critical",
            "citations": citations,
            "description": "Found a SQLi"
        }
        
        f1 = self.ledger.promote_finding(**base_args)
        
        # Change description
        args2 = base_args.copy()
        args2["description"] = "Found a SQLi variant"
        f2 = self.ledger.promote_finding(**args2)
        
        self.assertNotEqual(f1.id, f2.id, "Different content must produce different IDs")

    def test_event_determinism(self):
        """
        Verify that events generated with same parameters and timestamp have same ID.
        """
        # We need to force a timestamp for this test
        ts = 1234567890.0
        
        # Using record_observation as a trigger for an event
        # Note: record_observation uses uuid5(DNS, ...) which IS deterministic already.
        # But the EVENT it emits uses uuid1() currently.
        
        obs1 = self.ledger.record_observation(
            tool_name="tool", 
            tool_args=["a"], 
            target="t", 
            raw_output=b"data",
            timestamp_override=ts
        )
        
        # Get the event from the log
        evt1 = self.ledger._event_log[-1]
        
        # Clear log and repeat
        self.ledger._event_log = []
        obs2 = self.ledger.record_observation(
            tool_name="tool", 
            tool_args=["a"], 
            target="t", 
            raw_output=b"data",
            timestamp_override=ts
        )
        evt2 = self.ledger._event_log[-1]
        
        self.assertEqual(evt1.id, evt2.id, "Event IDs must be deterministic given same timestamp/payload")
