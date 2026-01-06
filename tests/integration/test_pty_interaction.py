
import unittest
import asyncio
import json
from unittest.mock import MagicMock, patch
from core.server.api import terminal_websocket_pty
from fastapi import WebSocket

class TestPTYInteraction(unittest.IsolatedAsyncioTestCase):
    async def test_pty_io_handling(self):
        """Verify WebSocket input routing to PTYSession."""
        print("\n--- Testing PTY Bidirectional I/O ---")
        
        # Mock WebSocket
        mock_ws = MagicMock(spec=WebSocket)
        mock_ws.receive_text = MagicMock()
        mock_ws.receive_json = MagicMock()
        mock_ws.send_text = MagicMock()
        mock_ws.accept = MagicMock() # Mock accept to be async
        
        # Mock Config to bypass security checks for test
        with patch('core.base.config.get_config') as mock_get_config:
            mock_config = MagicMock()
            mock_config.security.terminal_enabled = True
            mock_config.security.terminal_require_auth = False # Bypass auth for this unit test
            mock_get_config.return_value = mock_config
            
            with patch('core.server.api.validate_websocket_connection', return_value=True), \
                 patch('core.engine.pty_manager.PTYManager') as mock_manager_cls:
                
                # Mock PTY Session
                mock_session = MagicMock()
                mock_session.session_id = "test-session"
                mock_session.pid = 1234
                mock_session.read_from_offset.return_value = ("", 0) # No output
                
                mock_manager = mock_manager_cls.instance.return_value
                mock_manager.create_session.return_value = mock_session
                mock_manager.get_or_create_session.return_value = mock_session
                
                # Setup proper async mocks
                f = asyncio.Future()
                f.set_result(None)
                mock_ws.accept.return_value = f
                
                # We need to simulate the loop receiving messages and then closing
                # We can do this by having receive_text return items then raise generic exception to break loop
                
                # BUT, the implementation I'm about to write will likely use receive() or receive_text/json based on detection.
                # Standard FastAPI websockets usually use receive_text or receive_json.
                # Let's assume the implementation uses receive_json or tries to parse text.
                
                # Scenario: 
                # 1. Input "echo hi"
                # 2. Resize 
                # 3. Disconnect
                
                input_msg = json.dumps({"type": "input", "data": "echo hi\n"})
                resize_msg = json.dumps({"type": "resize", "rows": 20, "cols": 40})
                
                # We will mock receive_text to return these, assuming the loop reads text and parses JSON
                
                # Create an AsyncIterator for receive_text to simulate stream
                responses = [
                    input_msg,
                    resize_msg,
                    asyncio.CancelledError("Test End") # To break the loop
                ]
                
                async def side_effect():
                    if responses:
                        r = responses.pop(0)
                        if isinstance(r, BaseException):
                            raise r
                        return r
                    # Default if list empty
                    raise asyncio.CancelledError("List Empty")
                    
                mock_ws.receive_text.side_effect = side_effect
                
                # Run the endpoint (it will block until cancelled)
                try:
                    await terminal_websocket_pty(mock_ws, session_id=None)
                except asyncio.CancelledError:
                    pass
                
                # Verify calls
                mock_session.write.assert_called_with("echo hi\n")
                mock_session.resize.assert_called_with(20, 40)
                print("✅ Input and Resize correctly routed to PTYSession")

if __name__ == '__main__':
    unittest.main()
