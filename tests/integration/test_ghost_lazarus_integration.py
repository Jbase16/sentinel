"""
Integration Test: Ghost/Lazarus Pipeline

CRITICAL INVARIANT:
GhostAddon.response() must correctly invoke LazarusEngine.response() for eligible
JavaScript responses without crashing or blocking the HTTP flow.

This test was written to verify the fix for TODO #2:
"GhostAddon.response() calls self.lazarus.process(flow) but LazarusEngine has
no process method - only has response() and _process_async() methods"

The fix uses asyncio.create_task() to invoke LazarusEngine.response() asynchronously,
allowing the HTTP response to continue without blocking.
"""

import asyncio
import pytest
from unittest.mock import Mock, MagicMock, AsyncMock, patch
from mitmproxy import http

# Must set up path before imports
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.ghost.proxy import GhostAddon
from core.ghost.lazarus import LazarusEngine
from core.base.session import ScanSession
from core.data.findings_store import FindingsStore


def _create_mock_js_flow() -> http.HTTPFlow:
    """
    Create a mock HTTP flow with JavaScript content that should be processed.

    Returns:
        A mitmproxy HTTPFlow with JavaScript response
    """
    flow = Mock(spec=http.HTTPFlow)
    flow.request = Mock()
    flow.request.host = "example.com"
    flow.request.pretty_url = "https://example.com/app.js"
    flow.request.method = "GET"

    flow.response = Mock()
    flow.response.headers = {"content-type": "application/javascript", "Server": "nginx"}

    # JavaScript code that's within size bounds (500 < x < 100000 bytes)
    obfuscated_js = "eval(atob('Y29uc29sZS5sb2coJ2hlbGxvJyk='));" * 50  # ~2KB
    flow.response.content = obfuscated_js.encode()
    flow.response.text = obfuscated_js

    return flow


def _create_mock_non_js_flow() -> http.HTTPFlow:
    """Create a mock HTTP flow with HTML content that should NOT be processed."""
    flow = Mock(spec=http.HTTPFlow)
    flow.request = Mock()
    flow.request.host = "example.com"
    flow.request.pretty_url = "https://example.com/index.html"

    flow.response = Mock()
    flow.response.headers = {"content-type": "text/html"}
    flow.response.content = b"<html><body>Hello</body></html>"
    flow.response.text = "<html><body>Hello</body></html>"

    return flow


@pytest.mark.asyncio
async def test_ghost_lazarus_integration_success():
    """
    INVARIANT: GhostAddon.response() must successfully invoke LazarusEngine for JS.

    This test verifies:
    1. GhostAddon.response() doesn't crash when processing JS
    2. LazarusEngine.response() is called via async task
    3. Error handling captures Lazarus failures
    """
    # Setup: Create session with mock findings store
    session = ScanSession(target="example.com")
    session.findings = Mock(spec=FindingsStore)
    session.findings.add_finding = Mock()

    # Create GhostAddon (this internally creates LazarusEngine)
    addon = GhostAddon(session)

    # Mock LazarusEngine.response() to track if it's called
    original_response = addon.lazarus.response
    addon.lazarus.response = AsyncMock(side_effect=original_response)

    # Create JavaScript flow
    js_flow = _create_mock_js_flow()

    # Execute: Call response() (this is synchronous, schedules async work)
    addon.response(js_flow)

    # Give asyncio time to schedule and execute the task
    await asyncio.sleep(0.1)

    # Verify: LazarusEngine.response() was called
    addon.lazarus.response.assert_called_once()

    # Verify: Server header finding was added
    assert session.findings.add_finding.called
    server_findings = [
        call for call in session.findings.add_finding.call_args_list
        if "server_header" in str(call)
    ]
    assert len(server_findings) > 0


@pytest.mark.asyncio
async def test_ghost_lazarus_integration_non_js_skipped():
    """
    INVARIANT: Non-JavaScript responses must NOT be processed by Lazarus.

    This verifies should_process() filtering works correctly.
    """
    session = ScanSession(target="example.com")
    session.findings = Mock(spec=FindingsStore)
    session.findings.add_finding = Mock()

    addon = GhostAddon(session)

    # Mock LazarusEngine.response() to track calls
    addon.lazarus.response = AsyncMock()

    # Create HTML flow (not JavaScript)
    html_flow = _create_mock_non_js_flow()

    # Execute
    addon.response(html_flow)
    await asyncio.sleep(0.1)

    # Verify: LazarusEngine.response() was NOT called
    addon.lazarus.response.assert_not_called()


@pytest.mark.asyncio
async def test_ghost_lazarus_error_handling():
    """
    INVARIANT: Lazarus failures must not crash GhostAddon and must be logged.

    This verifies error handling in _process_lazarus() works correctly.
    """
    session = ScanSession(target="example.com")
    session.findings = Mock(spec=FindingsStore)
    session.findings.add_finding = Mock()

    addon = GhostAddon(session)

    # Mock LazarusEngine.response() to raise an error
    addon.lazarus.response = AsyncMock(side_effect=Exception("AI service unavailable"))

    # Create JavaScript flow
    js_flow = _create_mock_js_flow()

    # Execute: Should not crash despite Lazarus error
    addon.response(js_flow)
    await asyncio.sleep(0.1)

    # Verify: Error was captured as a finding
    error_findings = [
        call for call in session.findings.add_finding.call_args_list
        if "lazarus_error" in str(call)
    ]
    assert len(error_findings) > 0

    # Extract the error finding
    error_finding = error_findings[0][0][0]  # First call, first arg
    assert error_finding["type"] == "lazarus_error"
    assert "AI service unavailable" in error_finding["metadata"]["error"]


@pytest.mark.asyncio
async def test_lazarus_should_process_filtering():
    """
    INVARIANT: LazarusEngine.should_process() must correctly filter responses.

    Filters by:
    1. Content-Type must contain "javascript"
    2. Size must be between 500 and 100,000 bytes
    3. Must not be already processing (via hash deduplication)
    """
    lazarus = LazarusEngine.instance()

    # Test 1: JavaScript within size bounds -> should process
    js_flow = _create_mock_js_flow()
    assert lazarus.should_process(js_flow) is True

    # Test 2: HTML (not JavaScript) -> should NOT process
    html_flow = _create_mock_non_js_flow()
    assert lazarus.should_process(html_flow) is False

    # Test 3: JavaScript too small (< 500 bytes) -> should NOT process
    small_js_flow = Mock(spec=http.HTTPFlow)
    small_js_flow.response = Mock()
    small_js_flow.response.headers = {"content-type": "application/javascript"}
    small_js_flow.response.content = b"console.log('tiny');"  # < 500 bytes
    assert lazarus.should_process(small_js_flow) is False

    # Test 4: JavaScript too large (> 100KB) -> should NOT process
    large_js_flow = Mock(spec=http.HTTPFlow)
    large_js_flow.response = Mock()
    large_js_flow.response.headers = {"content-type": "application/javascript"}
    large_js_flow.response.content = b"x" * 150_000  # > 100KB
    assert lazarus.should_process(large_js_flow) is False


def test_ghost_addon_synchronous_response_hook():
    """
    INVARIANT: GhostAddon.response() must be synchronous (not async).

    This is required by mitmproxy's addon interface - the response() hook is sync.
    We use asyncio.create_task() internally to schedule async work.
    """
    session = ScanSession(target="example.com")
    session.findings = Mock(spec=FindingsStore)
    session.findings.add_finding = Mock()

    addon = GhostAddon(session)

    # Mock to prevent actual processing
    addon.lazarus.should_process = Mock(return_value=False)

    # Create flow
    flow = _create_mock_non_js_flow()

    # Execute: This must complete synchronously (not return a coroutine)
    result = addon.response(flow)

    # Verify: response() returns None (not a coroutine)
    assert result is None  # Sync functions return None, not awaitable
    assert not asyncio.iscoroutine(result)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
