"""
Unit tests for URL validation in ScanRequest model.
"""
import pytest
from pydantic import ValidationError

from core.server.routers.scans import (
    ScanRequest,
    _extract_attack_paths_from_graph_dto,
    _extract_graph_attack_paths_from_graph_dto,
)


class TestURLValidation:
    """Test URL validation in ScanRequest model."""

    def test_valid_http_url(self):
        """Test valid HTTP URL is accepted."""
        req = ScanRequest(target="http://localhost:3002")
        assert req.target == "http://localhost:3002"

    def test_valid_https_url(self):
        """Test valid HTTPS URL is accepted."""
        req = ScanRequest(target="https://example.com")
        assert req.target == "https://example.com"

    def test_malformed_url_single_slash(self):
        """Test malformed URL with single slash (http:/localhost:3002) is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="http:/localhost:3002")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert any(
            "missing scheme" in str(errors[0]["msg"]).lower() or "invalid target url" in str(errors[0]["msg"]).lower()
            for error in errors
        )

    def test_missing_scheme(self):
        """Test URL without scheme is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="localhost:3002")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert any(
            "missing scheme" in str(errors[0]["msg"]).lower() or "invalid target url" in str(errors[0]["msg"]).lower()
            for error in errors
        )

    def test_invalid_scheme_ftp(self):
        """Test URL with ftp scheme is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="ftp://example.com")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert any(
            "scheme must be http or https" in str(errors[0]["msg"]).lower()
            for error in errors
        )

    def test_invalid_scheme_file(self):
        """Test URL with file scheme is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="file:///etc/passwd")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert any(
            "scheme must be http or https" in str(errors[0]["msg"]).lower()
            for error in errors
        )

    def test_missing_netloc(self):
        """Test URL without network location is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="http://")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert any(
            "missing network location" in str(errors[0]["msg"]).lower() or "invalid target url" in str(errors[0]["msg"]).lower()
            for error in errors
        )

    def test_empty_target(self):
        """Test empty target is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert "cannot be empty" in str(errors[0]["msg"]).lower()

    def test_whitespace_only_target(self):
        """Test whitespace-only target is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="   ")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert "cannot be empty" in str(errors[0]["msg"]).lower()

    def test_dangerous_character_semicolon(self):
        """Test target with semicolon is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="http://localhost:3002; rm -rf /")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert "invalid character" in str(errors[0]["msg"]).lower()

    def test_dangerous_character_pipe(self):
        """Test target with pipe is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="http://localhost:3002| cat /etc/passwd")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "target" in errors[0]["loc"]
        assert "invalid character" in str(errors[0]["msg"]).lower()

    def test_valid_url_with_path(self):
        """Test valid URL with path is accepted."""
        req = ScanRequest(target="http://example.com/path/to/resource")
        assert req.target == "http://example.com/path/to/resource"

    def test_valid_url_with_query(self):
        """Test valid URL with query string is accepted."""
        req = ScanRequest(target="http://example.com?param=value")
        assert req.target == "http://example.com?param=value"

    def test_valid_url_with_port(self):
        """Test valid URL with port is accepted."""
        req = ScanRequest(target="http://example.com:8080")
        assert req.target == "http://example.com:8080"

    def test_valid_url_with_subdomain(self):
        """Test valid URL with subdomain is accepted."""
        req = ScanRequest(target="https://api.example.com")
        assert req.target == "https://api.example.com"


def test_extract_attack_paths_from_graph_dto_handles_empty_and_malformed_chains():
    assert _extract_attack_paths_from_graph_dto({"attack_chains": []}) == []
    assert _extract_attack_paths_from_graph_dto({"attack_chains": None}) == []
    assert _extract_attack_paths_from_graph_dto({}) == []


def test_extract_attack_paths_from_graph_dto_prefers_labels_and_falls_back_to_node_ids():
    dto = {
        "attack_chains": [
            {"labels": ["Exposed Git", "Admin Login"], "node_ids": ["n1", "n2"]},
            {"node_ids": ["n3", "n4"]},
            {"labels": []},
            "invalid",
        ]
    }
    attack_paths = _extract_attack_paths_from_graph_dto(dto)
    assert attack_paths == [
        ["Exposed Git", "Admin Login"],
        ["n3", "n4"],
    ]

    graph_attack_paths = _extract_graph_attack_paths_from_graph_dto(dto)
    assert graph_attack_paths == attack_paths
