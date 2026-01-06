
import unittest
import asyncio
from unittest.mock import MagicMock, patch
from core.server.api import start_scan, ScanRequest
from core.errors import SentinelError, ErrorCode, SentinelSecurityError
from core.base.sequence import GlobalSequenceAuthority
from core.cortex.events import GraphEventType

class TestScanFailure(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        GlobalSequenceAuthority.initialize_for_testing(1)

    async def asyncTearDown(self):
        GlobalSequenceAuthority.reset_for_testing()

    async def test_scan_exception_handling(self):
        """Verify that exceptions during scan execution emit a SCAN_FAILED event."""
        print("\n--- Testing Scan Failure Emission ---")
        
        # Mock dependencies
        mock_req = ScanRequest(target="example.com")
        
        with patch('core.server.api.reasoning_engine') as mock_reasoning, \
             patch('core.data.db.Database') as mock_db, \
             patch('core.server.api.get_event_bus') as mock_get_bus, \
             patch('core.server.api.logger') as mock_logger, \
             patch('core.server.api.GraphEvent') as mock_graph_event:
            
            # Setup reasoning engine failure
            mock_reasoning.start_scan.side_effect = Exception("Simulated Reasoner Crash")
            
            # Setup Database async mocks
            mock_database = mock_db.instance.return_value
            
            # Helper to return awaitable
            def make_awaitable(result=None):
                f = asyncio.Future()
                f.set_result(result)
                return f

            # Configuration for Store initialization calls
            mock_database.init.return_value = make_awaitable(None)
            mock_database.get_findings.return_value = make_awaitable([])
            mock_database.get_all_findings.return_value = make_awaitable([])
            mock_database.get_issues.return_value = make_awaitable([])
            mock_database.get_all_issues.return_value = make_awaitable([])
            mock_database.get_evidence.return_value = make_awaitable([])
            
            # Configuration for _begin_scan calls
            mock_database.load_graph_snapshot.return_value = make_awaitable(({}, []))
            mock_database.save_graph_snapshot.return_value = make_awaitable(None)
            
            # Mock Event Bus
            mock_bus = mock_get_bus.return_value
            
            # Execute
            try:
                await start_scan(mock_req, True, "test-session")
            except Exception as e:
                print(f"Unexpected sync failure: {e}")
            
            # Give background task time to run and crash
            await asyncio.sleep(0.5)
            
            # Verify GraphEvent Instantiation
            print("\n--- GraphEvent Instantiations ---")
            found_failure_event = False
            for call in mock_graph_event.call_args_list:
                print(f"GraphEvent call: {call}")
                args, kwargs = call
                event_type = kwargs.get('type')
                
                # Check for SCAN_FAILED
                if event_type == GraphEventType.SCAN_FAILED:
                     print("✅ GraphEvent created with SCAN_FAILED")
                     found_failure_event = True
                     # Verify payload
                     payload = kwargs.get('payload', {})
                     if "Simulated Reasoner Crash" in payload.get('error', ''):
                         print("✅ Error message verified in payload")
                     else:
                         print("❌ Error message mismatch in payload")
            
            if not found_failure_event:
                 self.fail("❌ GraphEvent(type=SCAN_FAILED) NOT created.")

if __name__ == '__main__':
    unittest.main()
