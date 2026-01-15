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

    @pytest.mark.asyncio
    async def test_04_scan_start_malformed_url_single_slash(self, async_client):
        """Test scan start rejects malformed URL with single slash (http:/localhost:3002)."""
        response = await async_client.post(
            "/v1/scans/start",
            json={"target": "http:/localhost:3002"}
        )
        assert response.status_code == 422  # Pydantic validation error
        data = response.json()
        assert "detail" in data
        assert any("missing scheme" in str(detail).lower() or "invalid target url" in str(detail).lower()
                   for detail in data["detail"])

    @pytest.mark.asyncio
    async def test_05_scan_start_missing_scheme(self, async_client):
        """Test scan start rejects URL without scheme."""
        response = await async_client.post(
            "/v1/scans/start",
            json={"target": "localhost:3002"}
        )
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert any("missing scheme" in str(detail).lower() or "invalid target url" in str(detail).lower()
                   for detail in data["detail"])

    @pytest.mark.asyncio
    async def test_06_scan_start_invalid_scheme(self, async_client):
        """Test scan start rejects URL with invalid scheme."""
        response = await async_client.post(
            "/v1/scans/start",
            json={"target": "ftp://example.com"}
        )
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert any("scheme must be http or https" in str(detail).lower()
                   for detail in data["detail"])

    @pytest.mark.asyncio
    async def test_07_scan_start_missing_netloc(self, async_client):
        """Test scan start rejects URL without network location."""
        response = await async_client.post(
            "/v1/scans/start",
            json={"target": "http://"}
        )
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert any("missing network location" in str(detail).lower() or "invalid target url" in str(detail).lower()
                   for detail in data["detail"])

    @pytest.mark.asyncio
    async def test_08_scan_start_valid_http_url(self, async_client):
        """Test scan start accepts valid HTTP URL."""
        response = await async_client.post(
            "/v1/scans/start",
            json={"target": "http://localhost:3002"}
        )
        # Should return 202 Accepted (scan started) or 422 if auth fails
        # We're just checking it doesn't fail URL validation
        assert response.status_code in (202, 401, 403)

    @pytest.mark.asyncio
    async def test_09_scan_start_valid_https_url(self, async_client):
        """Test scan start accepts valid HTTPS URL."""
        response = await async_client.post(
            "/v1/scans/start",
            json={"target": "https://example.com"}
        )
        # Should return 202 Accepted (scan started) or 422 if auth fails
        # We're just checking it doesn't fail URL validation
        assert response.status_code in (202, 401, 403)
