
import unittest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from core.server.routers.realtime import terminal_websocket_pty
from fastapi import WebSocket

class TestPTYInteraction(unittest.IsolatedAsyncioTestCase):
    async def test_pty_io_handling(self):
        """Verify WebSocket input routing through the current PTY manager API."""
        mock_ws = MagicMock(spec=WebSocket)
        mock_ws.accept = AsyncMock()
        mock_ws.send_json = AsyncMock()
        mock_ws.send_text = AsyncMock()

        with patch('core.base.config.get_config') as mock_get_config:
            mock_config = MagicMock()
            mock_config.security.terminal_enabled = True
            mock_config.security.terminal_require_auth = False
            mock_get_config.return_value = mock_config

            with patch('core.server.routers.realtime.validate_websocket_connection', return_value=True), \
                 patch('core.server.routers.realtime.PTYManager') as mock_manager_cls:
                mock_manager = mock_manager_cls.instance.return_value
                input_msg = json.dumps({"type": "input", "data": "echo hi\n"})
                arrow_up = "\x1b[A"
                resize_msg = json.dumps({"type": "resize", "rows": 20, "cols": 40})
                responses = [
                    input_msg,
                    arrow_up,
                    resize_msg,
                    asyncio.CancelledError("Test End"),
                ]

                async def side_effect():
                    if responses:
                        r = responses.pop(0)
                        if isinstance(r, BaseException):
                            raise r
                        return r
                    raise asyncio.CancelledError("List Empty")

                mock_ws.receive_text = AsyncMock(side_effect=side_effect)

                try:
                    await terminal_websocket_pty(mock_ws, session_id="test-session")
                except asyncio.CancelledError:
                    pass

                self.assertEqual(
                    mock_manager.write_input.call_args_list,
                    [
                        unittest.mock.call("test-session", "echo hi\n"),
                        unittest.mock.call("test-session", arrow_up),
                    ],
                )
                mock_manager.resize.assert_called_once_with("test-session", 40, 20)
                mock_manager.detach_listener.assert_called_once()

if __name__ == '__main__':
    unittest.main()
