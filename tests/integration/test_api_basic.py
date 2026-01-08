"""
Integration tests for SentinelForge API basic endpoints.

Uses httpx.AsyncClient with ASGITransport for proper async test isolation
instead of spawning a real server thread (which causes cleanup issues).
"""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Ensure we can import core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))


@pytest.fixture
def mock_config():
    """Create a mock config for testing."""
    conf = MagicMock()
    conf.security.require_auth = False  # Disable auth for simpler tests
    conf.security.api_token = "test-token-12345"
    conf.security.allowed_origins = ("http://localhost:*", "http://127.0.0.1:*")
    conf.security.terminal_enabled = True
    conf.security.terminal_require_auth = False
    conf.api_host = "127.0.0.1"
    conf.api_port = 8766
    conf.storage.db_path = "/tmp/sentinel_test.db"
    conf.ai.provider = "ollama"
    conf.ai.ollama_url = "http://localhost:11434"
    return conf


@pytest.fixture
async def async_client(mock_config):
    """Create an async test client using ASGI transport."""
    import httpx
    
    with patch("core.base.config.get_config", return_value=mock_config):
        with patch("core.base.config.SecurityInterlock.verify_safe_boot"):
            # Import after patching to get mocked config
            from core.server.api import app
            
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                yield client


class TestCoreAPI:
    """Core API endpoint tests."""
    
    @pytest.mark.asyncio
    async def test_01_ping(self, async_client):
        """Test ping endpoint returns ok status."""
        response = await async_client.get("/v1/ping")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_02_status_structure(self, async_client):
        """Test status endpoint returns expected structure."""
        response = await async_client.get("/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert "ai" in data
        assert "tools" in data
        assert "installed" in data["tools"]
        assert "missing" in data["tools"]

    @pytest.mark.asyncio
    async def test_03_ai_status(self, async_client):
        """Test AI status is included in status response."""
        response = await async_client.get("/v1/status")
        assert response.status_code == 200
        data = response.json()
        ai = data.get("ai", {})
        assert "connected" in ai
