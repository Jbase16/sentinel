"""Unit tests for command execution security and validation."""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.toolkit.registry import get_tool_command, TOOLS
# Import kept lazy in tests that need it.
# core.server.api is intentionally not imported at module import time because
# it triggers heavy FastAPI initialization (and can fail collection if API
# surface moves). The command-validation tests focus on toolkit security.
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


# NOTE: CORS validation tests must live next to the implementation.
# This suite does not validate API server wiring.

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


class TestWordlistPath:
    """Test wordlist path resolution."""

    def test_wordlist_dir_points_to_repo_root(self):
        """Verify WORDLIST_DIR points to repository root, not core/."""
        from core.toolkit.registry import WORDLIST_DIR
        import os

        # Should be repo root + assets/wordlists
        path_str = str(WORDLIST_DIR)
        assert "/assets/wordlists" in path_str
        # Should NOT be core/assets/wordlists
        assert "/core/assets/wordlists" not in path_str

    def test_common_wordlist_exists(self):
        """Verify COMMON_WORDLIST is found and is not None."""
        from core.toolkit.registry import COMMON_WORDLIST

        assert COMMON_WORDLIST is not None
        assert isinstance(COMMON_WORDLIST, str)
        # Should be an absolute path
        assert COMMON_WORDLIST.startswith("/")

    def test_wordlist_file_readable(self):
        """Verify the wordlist file can be read."""
        from core.toolkit.registry import COMMON_WORDLIST
        import os

        if COMMON_WORDLIST:
            assert os.path.exists(COMMON_WORDLIST)
            with open(COMMON_WORDLIST) as f:
                # File should have content
                lines = f.readlines()
                assert len(lines) > 0
                # Each line should be a word
                assert "admin" in "".join(lines).lower()  # common wordlist likely has "admin"

    def test_get_wordlist_path_with_missing_file(self):
        """Verify get_wordlist_path falls back to default for missing files."""
        from core.toolkit.registry import get_wordlist_path, DEFAULT_WORDLIST

        # Request a non-existent wordlist - should fall back to default
        result = get_wordlist_path("nonexistent_wordlist.txt")
        # Should return default wordlist path when requested file doesn't exist
        assert result is not None
        assert result == str(DEFAULT_WORDLIST.resolve())


class TestDatabaseInstantiation:
    """Test Database can be instantiated in synchronous context."""

    def test_database_instantiation_without_event_loop(self):
        """Verify Database can be created without a running event loop."""
        from core.data.db import Database
        import threading

        # Database should be instantiable in sync context
        db = Database()

        assert db is not None
        assert db.db_path is not None
        assert db._initialized is False
        # _init_lock should be threading.Lock, not asyncio.Lock
        assert isinstance(db._init_lock, type(threading.Lock()))

    def test_database_singleton_via_instance_method(self):
        """Verify Database singleton pattern works via instance() method."""
        from core.data.db import Database

        db1 = Database.instance()
        db2 = Database.instance()

        # Should return the same instance when using instance()
        assert db1 is db2

    def test_database_multiple_thread_instantiation(self):
        """Verify Database can be instantiated from multiple threads safely."""
        from core.data.db import Database
        import concurrent.futures

        def create_db():
            return Database.instance()

        # Create multiple threads that all call instance()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(create_db) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All should return the same singleton instance
        assert len(set(results)) == 1


class TestSessionCleanup:
    """Test session cleanup prevents memory leaks."""

    def test_cleanup_old_sessions_function_exists(self):
        """Verify cleanup_old_sessions function is defined."""
        from core.server.api import cleanup_old_sessions
        assert callable(cleanup_old_sessions)

    def test_cleanup_removes_old_sessions(self):
        """Verify old sessions are removed by cleanup."""
        import asyncio
        from datetime import datetime, timezone, timedelta
        from core.server.api import cleanup_old_sessions, register_session, _session_manager

        class MockSession:
            def __init__(self, start_time):
                self.start_time = start_time

        async def run_test():
            # Clear any existing sessions
            _session_manager.clear()

            # Create sessions: one old (2 days), one recent (now)
            now = datetime.now(timezone.utc)
            old_session = MockSession((now - timedelta(days=2)).timestamp())
            recent_session = MockSession(now.timestamp())

            await register_session('old', old_session)
            await register_session('recent', recent_session)

            # Should have 2 sessions
            assert len(_session_manager) == 2

            # Run cleanup with 1 day max age
            removed = await cleanup_old_sessions(timedelta(days=1))

            # Should remove 1 old session
            assert removed == 1
            # Should have 1 session remaining
            assert len(_session_manager) == 1
            # Recent session should still exist
            assert 'recent' in _session_manager
            # Old session should be removed
            assert 'old' not in _session_manager

            # Clean up
            _session_manager.clear()

        asyncio.run(run_test())

    def test_cleanup_loop_function_exists(self):
        """Verify _session_cleanup_loop function is defined."""
        from core.server.api import _session_cleanup_loop
        assert callable(_session_cleanup_loop)


class TestCircuitBreaker:
    """Test circuit breaker prevents cascading failures from AI."""

    def test_circuit_breaker_opens_after_threshold(self):
        """Verify circuit breaker opens after N failures."""
        from core.ai.ai_engine import CircuitBreaker, CircuitBreakerOpenError

        cb = CircuitBreaker(failure_threshold=3, timeout=1.0)

        def failing_func():
            raise ValueError("Simulated failure")

        # First 2 failures should not open circuit
        for _ in range(2):
            try:
                cb.call(failing_func)
            except ValueError:
                pass  # Expected

        assert cb.get_state()["failure_count"] == 2
        assert cb.get_state()["is_open"] is False

        # 3rd failure should open circuit
        try:
            cb.call(failing_func)
        except CircuitBreakerOpenError:
            pass  # Expected
        except ValueError:
            pass

        assert cb.get_state()["failure_count"] >= 3
        assert cb.get_state()["is_open"] is True

    def test_circuit_breaker_blocks_when_open(self):
        """Verify circuit breaker blocks calls when open."""
        from core.ai.ai_engine import CircuitBreaker, CircuitBreakerOpenError

        cb = CircuitBreaker(failure_threshold=2, timeout=10.0)

        # Open the circuit
        for _ in range(3):
            try:
                cb.call(lambda: (_ for _ in ()).throw(ValueError()))
            except (ValueError, CircuitBreakerOpenError):
                pass

        # Call should be blocked
        try:
            cb.call(lambda: "success")
            assert False, "Should have raised CircuitBreakerOpenError"
        except CircuitBreakerOpenError:
            pass  # Expected

    def test_circuit_breaker_resets_after_timeout(self):
        """Verify circuit breaker resets after timeout period."""
        import time
        from core.ai.ai_engine import CircuitBreaker, CircuitBreakerOpenError as CBOError

        cb = CircuitBreaker(failure_threshold=2, timeout=0.5)

        # Open the circuit
        def failing_func():
            raise ValueError("Simulated failure")

        for _ in range(3):
            try:
                cb.call(failing_func)
            except (ValueError, CBOError):
                pass

        assert cb.get_state()["is_open"] is True

        # Wait for timeout
        time.sleep(0.6)

        # Circuit should be closed now, call should succeed
        result = cb.call(lambda: "success")
        assert result == "success"
        assert cb.get_state()["failure_count"] == 0

    def test_circuit_breaker_success_resets_count(self):
        """Verify successful call resets failure count."""
        from core.ai.ai_engine import CircuitBreaker

        cb = CircuitBreaker(failure_threshold=5)

        # Add some failures
        for _ in range(3):
            try:
                cb.call(lambda: (_ for _ in ()).throw(ValueError()))
            except ValueError:
                pass

        assert cb.get_state()["failure_count"] == 3

        # Success should reset
        result = cb.call(lambda: "success")
        assert result == "success"
        assert cb.get_state()["failure_count"] == 0

    def test_ai_engine_has_circuit_breaker(self):
        """Verify AIEngine has circuit breaker integrated."""
        from core.ai.ai_engine import AIEngine

        engine = AIEngine()
        assert hasattr(engine, "circuit_breaker")
        assert engine.circuit_breaker is not None

    def test_ai_engine_status_includes_circuit_breaker(self):
        """Verify AIEngine status includes circuit breaker state."""
        from core.ai.ai_engine import AIEngine

        engine = AIEngine()
        status = engine.status()

        assert "circuit_breaker" in status
        assert "failure_count" in status["circuit_breaker"]
        assert "is_open" in status["circuit_breaker"]


class TestResourceGuard:
    """Test resource guard prevents resource exhaustion."""

    def test_resource_guard_has_limits(self):
        """Verify ResourceGuard enforces resource limits."""
        from core.engine.scanner_engine import ResourceGuard, ResourceExhaustedError

        rg = ResourceGuard(max_findings=100, max_disk_mb=10)

        # Check default values
        assert rg.max_findings == 100
        assert rg.max_disk_mb == 10
        assert rg.findings_count == 0
        assert rg.disk_usage == 0

    def test_resource_guard_check_findings_within_limit(self):
        """Verify check_findings allows usage within limit."""
        from core.engine.scanner_engine import ResourceGuard

        rg = ResourceGuard(max_findings=100)
        result = rg.check_findings(50)
        assert result is True
        assert rg.findings_count == 50

    def test_resource_guard_check_findings_exceeds_limit(self):
        """Verify check_findings raises error when limit exceeded."""
        from core.engine.scanner_engine import ResourceGuard, ResourceExhaustedError

        rg = ResourceGuard(max_findings=100)
        rg.check_findings(80)

        try:
            rg.check_findings(50)  # Would total 130 > 100
            assert False, "Should have raised ResourceExhaustedError"
        except ResourceExhaustedError as e:
            assert "130 exceeds limit 100" in str(e)
            assert rg.findings_count == 80  # Count should not increase

    def test_resource_guard_check_disk_within_limit(self):
        """Verify check_disk allows usage within limit."""
        from core.engine.scanner_engine import ResourceGuard

        rg = ResourceGuard(max_disk_mb=10)
        result = rg.check_disk(5 * 1024 * 1024)  # 5MB
        assert result is True
        assert rg.disk_usage == 5 * 1024 * 1024

    def test_resource_guard_check_disk_exceeds_limit(self):
        """Verify check_disk raises error when limit exceeded."""
        from core.engine.scanner_engine import ResourceGuard, ResourceExhaustedError

        rg = ResourceGuard(max_disk_mb=10)
        rg.check_disk(5 * 1024 * 1024)  # 5MB

        try:
            rg.check_disk(10 * 1024 * 1024)  # 10MB more would total 15MB > 10MB
            assert False, "Should have raised ResourceExhaustedError"
        except ResourceExhaustedError as e:
            assert "exceeds limit 10MB" in str(e)
            assert rg.disk_usage == 5 * 1024 * 1024  # Usage should not increase

    def test_resource_guard_get_usage(self):
        """Verify get_usage returns current resource usage."""
        from core.engine.scanner_engine import ResourceGuard

        rg = ResourceGuard(max_findings=1000, max_disk_mb=100)
        rg.check_findings(250)
        rg.check_disk(25 * 1024 * 1024)  # 25MB

        usage = rg.get_usage()
        assert usage["findings_count"] == 250
        assert usage["max_findings"] == 1000
        assert usage["findings_percent"] == 25.0
        assert usage["disk_usage_mb"] == 25.0
        assert usage["max_disk_mb"] == 100
        assert usage["disk_percent"] == 25.0

    def test_scanner_engine_has_resource_guard(self):
        """Verify ScannerEngine has resource_guard integrated."""
        from core.engine.scanner_engine import ScannerEngine

        engine = ScannerEngine()
        assert hasattr(engine, "resource_guard")
        assert engine.resource_guard is not None


class TestEventSequenceCounter:
    """Test global event sequence counter for event-decision correlation."""

    def setup_method(self):
        """Reset event sequence before each test."""
        from core.cortex.events import reset_event_sequence
        reset_event_sequence()

    def test_event_has_sequence_number(self):
        """Verify all events get unique sequence numbers."""
        from core.cortex.events import GraphEvent, GraphEventType

        event1 = GraphEvent(type=GraphEventType.SCAN_STARTED, payload={})
        event2 = GraphEvent(type=GraphEventType.DECISION_MADE, payload={})

        assert event1.event_sequence > 0
        assert event2.event_sequence > event1.event_sequence

    def test_sequence_numbers_are_monotonic(self):
        """Verify sequence numbers strictly increase."""
        from core.cortex.events import GraphEvent, GraphEventType

        sequences = []
        for _ in range(10):
            event = GraphEvent(type=GraphEventType.LOG, payload={"msg": "test"})
            sequences.append(event.event_sequence)

        # Check strictly increasing
        for i in range(1, len(sequences)):
            assert sequences[i] > sequences[i-1]

    def test_event_bus_tracks_last_sequence(self):
        """Verify EventBus tracks last emitted event sequence."""
        from core.cortex.events import EventBus, reset_event_sequence

        bus = EventBus()
        assert bus.last_event_sequence == 0

        # Emit some events
        for i in range(3):
            bus.emit_decision_made(payload={
                "decision_id": f"test_{i}",
                "decision_type": "test",
                "selected_action": "noop",
                "rationale": "testing",
                "confidence": 1.0,
            })

        assert bus.last_event_sequence == 3

    def test_reset_sequence_function(self):
        """Verify reset_event_sequence resets counter to 0."""
        from core.cortex.events import (
            GraphEvent, GraphEventType,
            reset_event_sequence, _next_event_sequence
        )

        # Generate some events
        _next_event_sequence()
        _next_event_sequence()

        # Reset
        reset_event_sequence()

        # Next event should be sequence 1
        event = GraphEvent(type=GraphEventType.LOG, payload={})
        assert event.event_sequence == 1

    def test_decision_with_trigger_event_sequence(self):
        """Verify DecisionPoint can reference triggering event."""
        from core.scheduler.decisions import DecisionPoint, DecisionType

        decision = DecisionPoint.create(
            decision_type=DecisionType.TOOL_SELECTION,
            chosen="nmap",
            reason="Port scan required",
            trigger_event_sequence=42
        )

        assert decision.trigger_event_sequence == 42

        # Verify it's included in event payload
        payload = decision.to_event_payload()
        assert "trigger_event_sequence" in payload
        assert payload["trigger_event_sequence"] == 42

    def test_decision_without_trigger_event_sequence(self):
        """Verify decisions work without trigger_event_sequence."""
        from core.scheduler.decisions import DecisionPoint, DecisionType

        decision = DecisionPoint.create(
            decision_type=DecisionType.TOOL_SELECTION,
            chosen="nmap",
            reason="Port scan required"
        )

        assert decision.trigger_event_sequence is None

        # Verify it's NOT included in event payload
        payload = decision.to_event_payload()
        assert "trigger_event_sequence" not in payload

    def test_decision_context_accepts_trigger_sequence(self):
        """Verify DecisionContext.choose accepts trigger_event_sequence."""
        from core.scheduler.decisions import (
            DecisionContext, DecisionType,
            DecisionLedger
        )

        ledger = DecisionLedger()
        ctx = DecisionContext(ledger=ledger, auto_emit=False)

        decision = ctx.choose(
            decision_type=DecisionType.TOOL_SELECTION,
            chosen="nmap",
            reason="Test",
            trigger_event_sequence=100
        )

        assert decision.trigger_event_sequence == 100

    def test_event_decision_correlation(self):
        """Verify event and decision sequences can be correlated."""
        from core.cortex.events import GraphEvent, GraphEventType
        from core.scheduler.decisions import DecisionPoint, DecisionType

        # Simulate event that triggers a decision
        event = GraphEvent(
            type=GraphEventType.FINDING_CREATED,
            payload={"finding": "open port 80"}
        )
        event_sequence = event.event_sequence

        # Decision references the event
        decision = DecisionPoint.create(
            decision_type=DecisionType.TOOL_SELECTION,
            chosen="nmap",
            reason="Investigate finding",
            trigger_event_sequence=event_sequence
        )

        # Verify correlation
        assert decision.trigger_event_sequence == event_sequence
        # This allows tracing: "decision X was made in response to event Y"


class TestScanTransaction:
    """Test scan transactionality for atomic database operations."""

    def test_scan_transaction_create(self):
        """Verify ScanTransaction can be created."""
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        engine = ScannerEngine()
        txn = ScanTransaction(engine, "test-session-id")

        assert txn._session_id == "test-session-id"
        assert txn._engine is engine
        assert txn.is_active is True
        assert txn._committed is False
        assert txn._rolled_back is False

    def test_scan_transaction_add_finding(self):
        """Verify findings can be staged."""
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        engine = ScannerEngine()
        txn = ScanTransaction(engine, "test-session")

        finding = {"tool": "nmap", "type": "port", "target": "example.com"}
        txn.add_finding(finding)

        assert len(txn._staged_findings) == 1
        assert txn._staged_findings[0] == finding

    def test_scan_transaction_add_issue(self):
        """Verify issues can be staged."""
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        engine = ScannerEngine()
        txn = ScanTransaction(engine, "test-session")

        issue = {"title": "SQL Injection", "severity": "HIGH"}
        txn.add_issue(issue)

        assert len(txn._staged_issues) == 1
        assert txn._staged_issues[0] == issue

    def test_scan_transaction_add_evidence(self):
        """Verify evidence can be staged."""
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        engine = ScannerEngine()
        txn = ScanTransaction(engine, "test-session")

        evidence = {"tool": "nmap", "path": "/tmp/output.txt"}
        txn.add_evidence(evidence)

        assert len(txn._staged_evidence) == 1
        assert txn._staged_evidence[0] == evidence

    def test_scan_transaction_stats(self):
        """Verify stats returns correct counts."""
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        engine = ScannerEngine()
        txn = ScanTransaction(engine, "test-session")

        txn.add_finding({"tool": "nmap"})
        txn.add_finding({"tool": "httprobe"})
        txn.add_issue({"title": "XSS"})
        txn.add_evidence({"path": "/tmp/out"})

        stats = txn.stats()
        assert stats["findings"] == 2
        assert stats["issues"] == 1
        assert stats["evidence"] == 1

    def test_scan_transaction_rollback(self):
        """Verify rollback clears staged data."""
        import asyncio
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        async def test():
            engine = ScannerEngine()
            txn = ScanTransaction(engine, "test-session")

            txn.add_finding({"tool": "nmap"})
            txn.add_issue({"title": "XSS"})

            await txn.rollback()

            assert txn._rolled_back is True
            assert len(txn._staged_findings) == 0
            assert len(txn._staged_issues) == 0
            assert txn.is_active is False

        asyncio.run(test())

    def test_scan_transaction_add_after_close_raises(self):
        """Verify adding data after commit/rollback raises error."""
        import asyncio
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        async def test():
            engine = ScannerEngine()
            txn = ScanTransaction(engine, "test-session")

            await txn.rollback()

            try:
                txn.add_finding({"tool": "nmap"})
                assert False, "Should have raised RuntimeError"
            except RuntimeError as e:
                assert "already closed" in str(e).lower()

        asyncio.run(test())

    def test_scan_transaction_nested_raises(self):
        """Verify nested transactions are prevented."""
        import asyncio
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        async def test():
            engine = ScannerEngine()

            async with ScanTransaction(engine, "session1") as txn1:
                try:
                    # This should raise - nested transactions not allowed
                    async with ScanTransaction(engine, "session2") as txn2:
                        pass
                    assert False, "Should have raised RuntimeError"
                except RuntimeError as e:
                    assert "nested" in str(e).lower()

        asyncio.run(test())

    def test_scanner_engine_has_transaction_state(self):
        """Verify ScannerEngine tracks active transaction."""
        from core.engine.scanner_engine import ScannerEngine

        engine = ScannerEngine()
        assert engine._active_transaction is None

    def test_scan_transaction_context_manager_property(self):
        """Verify is_active property works correctly."""
        from core.engine.scanner_engine import ScannerEngine, ScanTransaction

        engine = ScannerEngine()
        txn = ScanTransaction(engine, "test-session")

        # Initially active
        assert txn.is_active is True

        # After rollback, not active
        import asyncio
        asyncio.run(txn.rollback())
        assert txn.is_active is False


class TestAPIVersioning:
    """Test API versioning with /v1 prefix for breaking changes."""

    def test_v1_router_exists(self):
        """Verify v1_router is created with correct prefix."""
        from core.server.api import v1_router

        assert v1_router is not None
        assert v1_router.prefix == "/v1"

    def test_v1_router_has_routes(self):
        """Verify v1_router has routes registered."""
        from core.server.api import v1_router

        # Check that routes are registered on the router
        routes = [route for route in v1_router.routes if hasattr(route, 'path')]
        # Should have at least some routes
        assert len(routes) > 0, "v1_router should have routes registered"

    def test_v1_router_has_ping_function(self):
        """Verify ping_v1 function exists and is callable."""
        from core.server.api import ping_v1

        assert callable(ping_v1)

    def test_v1_router_has_status_function(self):
        """Verify get_status_v1 function exists and is callable."""
        from core.server.api import get_status_v1

        assert callable(get_status_v1)

    def test_v1_router_has_results_function(self):
        """Verify get_results_v1 function exists and is callable."""
        from core.server.api import get_results_v1

        assert callable(get_results_v1)

    def test_v1_router_has_logs_function(self):
        """Verify get_logs_v1 function exists and is callable."""
        from core.server.api import get_logs_v1

        assert callable(get_logs_v1)

    def test_v1_router_has_tools_status_function(self):
        """Verify tools_status_v1 function exists and is callable."""
        from core.server.api import tools_status_v1

        assert callable(tools_status_v1)

    def test_legacy_ping_delegates_to_v1(self):
        """Verify legacy /ping delegates to /v1/ping."""
        from core.server.api import ping, ping_v1
        import asyncio

        # Both should return the same structure
        v1_result = asyncio.run(ping_v1())
        legacy_result = asyncio.run(ping())

        assert v1_result["status"] == legacy_result["status"]
        assert "timestamp" in v1_result
        assert "timestamp" in legacy_result

    def test_app_includes_v1_router(self):
        """Verify the app includes the v1_router."""
        from core.server.api import app, v1_router

        # Check that v1_router is included in app
        # APIRouter is included as a route in app.routes
        # In FastAPI, when app.include_router is called, the router's routes
        # are added to the app with the prefix applied
        v1_paths = [route.path for route in app.routes if hasattr(route, 'path') and route.path.startswith("/v1/")]

        # Should have at least some v1 paths
        assert len(v1_paths) > 0, f"App should include v1 routes. Found paths: {[r.path for r in app.routes if hasattr(r, 'path')]}"

        # Check that the expected v1 endpoints exist
        assert "/v1/ping" in v1_paths, "Should have /v1/ping endpoint"
        assert "/v1/status" in v1_paths, "Should have /v1/status endpoint"

    def test_v1_router_tag(self):
        """Verify v1_router has proper tag for API documentation."""
        from core.server.api import v1_router

        assert v1_router.tags == ["v1"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
