
import unittest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from core.server.api import validate_websocket_connection
from core.base.config import SecurityConfig

class TestCORSSecurity(unittest.IsolatedAsyncioTestCase):
    async def test_websocket_origin_validation_dev_mode(self):
        """Verify WS origin validation behavior when auth is disabled (dev mode)."""
        # Scenario: API running locally, no auth required.
        # Attacker site (malicious.com) connects.
        # Should it be blocked? 
        # API code says: if require_auth is False, origin check is skipped.
        # This implies CSRF is possible in dev mode.
        
        mock_ws = AsyncMock()
        mock_ws.headers = {"origin": "http://malicious.com"}
        
        with patch("core.server.api.get_config") as mock_get_cfg:
            mock_cfg = MagicMock()
            mock_cfg.security.require_auth = False # Dev mode
            mock_cfg.security.allowed_origins = ["http://localhost:3000"]
            mock_get_cfg.return_value = mock_cfg
            
            # Execute
            allowed = await validate_websocket_connection(mock_ws, "/ws/test")
            
            # Now enforced: Origin check active even without auth
            self.assertFalse(allowed, "Should block malicious origin even in dev mode")
            mock_ws.close.assert_called_with(code=4003, reason="Origin not allowed")
            
    async def test_websocket_origin_validation_prod_mode(self):
        """Verify WS origin validation behavior when auth is enabled."""
        mock_ws = AsyncMock()
        mock_ws.headers = {"origin": "http://malicious.com"}
        
        with patch("core.server.api.get_config") as mock_get_cfg:
            mock_cfg = MagicMock()
            mock_cfg.security.require_auth = True # Prod mode
            mock_cfg.security.allowed_origins = ["http://localhost:3000"]
            mock_get_cfg.return_value = mock_cfg
            
            # Execute
            allowed = await validate_websocket_connection(mock_ws, "/ws/test")
            
            self.assertFalse(allowed, "Should block malicious origin in prod mode")
            mock_ws.close.assert_called_with(code=4003, reason="Origin not allowed")

if __name__ == '__main__':
    unittest.main()
