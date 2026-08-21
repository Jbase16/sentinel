
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from core.cortex import events, reasoning
from core.data.db import Database
from core.server.routers.scans import start_scan, ScanRequest
from core.server.state import ApplicationState
from core.base.sequence import GlobalSequenceAuthority
from core.cortex.events import GraphEventType

class TestScanFailure(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        GlobalSequenceAuthority.initialize_for_testing(1)

    async def asyncTearDown(self):
        GlobalSequenceAuthority.reset_for_testing()

    async def test_scan_exception_handling(self):
        """Verify that exceptions during scan execution emit a SCAN_FAILED event."""
        mock_req = ScanRequest(target="http://localhost:9")
        state = ApplicationState()
        mock_database = MagicMock()
        mock_database.init = AsyncMock()
        mock_database.get_findings = AsyncMock(return_value=[])
        mock_database.get_all_findings = AsyncMock(return_value=[])
        mock_database.get_issues = AsyncMock(return_value=[])
        mock_database.get_all_issues = AsyncMock(return_value=[])
        mock_database.get_evidence = AsyncMock(return_value=[])
        mock_database.blackbox.enqueue = AsyncMock()
        mock_database.blackbox.flush = AsyncMock()
        mock_bus = MagicMock()

        with (
            patch.object(Database, "instance", return_value=mock_database),
            patch("core.server.routers.scans.get_state", return_value=state),
            patch.object(
                reasoning.reasoning_engine,
                "start_scan",
                side_effect=Exception("Simulated Reasoner Crash"),
            ),
            patch.object(events, "get_event_bus", return_value=mock_bus),
            patch.object(events, "GraphEvent") as mock_graph_event,
        ):
            response = await start_scan(mock_req)
            await state.active_scan_task

        assert response["status"] == "started"
        failure_calls = [
            call
            for call in mock_graph_event.call_args_list
            if call.kwargs.get("type") == GraphEventType.SCAN_FAILED
        ]
        self.assertEqual(len(failure_calls), 1)
        self.assertIn(
            "Simulated Reasoner Crash",
            failure_calls[0].kwargs["payload"]["error"],
        )

if __name__ == '__main__':
    unittest.main()
