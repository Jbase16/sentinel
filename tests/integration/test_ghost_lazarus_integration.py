"""
Integration Test: Ghost/Lazarus Pipeline

CRITICAL INVARIANTS:
1. GhostAddon.response() (an ASYNC mitmproxy hook) invokes LazarusEngine for
   eligible JavaScript responses and survives Lazarus failures.
2. Lazarus is PASSIVE: it must never modify flow.response — the browser
   receives the server's bytes unchanged (test_lazarus_never_mutates_response_body).

History: these tests were originally written assuming response() was a
*synchronous* hook that scheduled work via asyncio.create_task(). The code is
actually `async def response()`, which mitmproxy awaits — so the old tests
called it unawaited, the body never ran, and the suite silently exercised
nothing. That gap is why a regression (Lazarus overwriting JS response bodies
with a truncated LLM rewrite) shipped undetected. The tests now await the hook
and assert byte-transparency.
"""

import asyncio
import logging
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

    # Real dict so the response() FlowMapper-finalize branch sees no step_ids
    # (a bare Mock would be truthy and crash the iteration).
    flow.metadata = {}

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
    flow.metadata = {}

    return flow


@pytest.mark.asyncio
async def test_ghost_lazarus_integration_success():
    """
    INVARIANT: GhostAddon.response() must successfully invoke LazarusEngine for JS.

    This test verifies passive delegation without finding promotion.
    """
    # Setup: Create session with mock findings store
    session = ScanSession(target="example.com")
    session.findings = Mock(spec=FindingsStore)
    session.findings.add_finding = Mock()

    # Create GhostAddon (this internally creates LazarusEngine)
    addon = GhostAddon(session)

    # SessionBridge expects a real mitmproxy Headers object (.get_all); the
    # mock flow uses a plain dict, so neutralize it — it's not under test here.
    addon.session_bridge = Mock()

    addon.lazarus.response = AsyncMock()

    # Create JavaScript flow
    js_flow = _create_mock_js_flow()

    original_content = js_flow.response.content
    original_text = js_flow.response.text
    await addon.response(js_flow)

    addon.lazarus.response.assert_awaited_once_with(js_flow)
    assert js_flow.response.content == original_content
    assert js_flow.response.text == original_text
    session.findings.add_finding.assert_not_called()


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
    addon.session_bridge = Mock()

    # Mock LazarusEngine.response() to track calls
    addon.lazarus.response = AsyncMock()

    # Create HTML flow (not JavaScript)
    html_flow = _create_mock_non_js_flow()

    # Execute (async hook — await it)
    await addon.response(html_flow)

    # Verify: LazarusEngine.response() was NOT called
    addon.lazarus.response.assert_not_called()


@pytest.mark.asyncio
async def test_ghost_lazarus_error_handling(caplog):
    """
    INVARIANT: Lazarus failures must not crash GhostAddon and must be logged.

    This verifies error handling in _process_lazarus() works correctly.
    """
    session = ScanSession(target="example.com")
    session.findings = Mock(spec=FindingsStore)
    session.findings.add_finding = Mock()

    addon = GhostAddon(session)
    addon.session_bridge = Mock()

    # Mock LazarusEngine.response() to raise an error
    addon.lazarus.response = AsyncMock(side_effect=Exception("AI service unavailable"))

    # Create JavaScript flow
    js_flow = _create_mock_js_flow()

    original_content = js_flow.response.content
    with caplog.at_level(logging.ERROR, logger="core.ghost.proxy"):
        await addon.response(js_flow)

    addon.lazarus.response.assert_awaited_once_with(js_flow)
    assert "Lazarus processing failed: AI service unavailable" in caplog.text
    assert js_flow.response.content == original_content
    session.findings.add_finding.assert_not_called()


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


@pytest.mark.asyncio
async def test_ghost_addon_response_hook_is_awaitable():
    """
    INVARIANT: GhostAddon.response() is an ASYNC mitmproxy hook.

    mitmproxy awaits coroutine addon hooks, so response() is async (unlike
    request(), which is sync). This test previously asserted the hook was
    *synchronous* — which never matched the code, so it failed and emitted
    'coroutine was never awaited' warnings, and the real response path was
    never exercised by the suite (which is how the JS-rewrite bug slipped in).
    """
    session = ScanSession(target="example.com")
    session.findings = Mock(spec=FindingsStore)
    session.findings.add_finding = Mock()

    addon = GhostAddon(session)
    addon.session_bridge = Mock()
    addon.lazarus.should_process = Mock(return_value=False)

    flow = _create_mock_non_js_flow()

    coro = addon.response(flow)
    assert asyncio.iscoroutine(coro)
    result = await coro
    assert result is None


@pytest.mark.asyncio
async def test_lazarus_never_mutates_response_body():
    """
    CRITICAL REGRESSION INVARIANT: Ghost is a PASSIVE proxy — Lazarus must
    never modify the response body the browser receives.

    A prior version overwrote flow.response.text with a truncated, LLM
    "de-obfuscated" rewrite (and, due to an async bug, the string repr of an
    un-awaited coroutine). That corrupted every in-bounds script: pages
    rendered and scrolled, but all click handlers were dead. This locks in
    byte-transparency so that regression can never return silently.
    """
    lazarus = LazarusEngine.instance()

    # Real JS containing an API route the passive miner should still find.
    js = (
        ("function handler(e){e.preventDefault()}\n" * 30)
        + 'fetch("/api/v1/orders");\n'
        + ("var counter = 0;\n" * 30)
    )
    flow = Mock(spec=http.HTTPFlow)
    flow.request = Mock()
    flow.request.pretty_url = "https://example.com/bundle.js"
    flow.response = Mock()
    flow.response.headers = {"content-type": "application/javascript"}
    flow.response.content = js.encode()
    flow.response.text = js

    before = flow.response.text

    # Patch the event bus so route-finding emission doesn't require the global
    # sequence authority; we only care that the BODY is left untouched.
    with patch("core.cortex.events.get_event_bus", return_value=Mock()):
        await lazarus._process_async(flow)

    # The body must be byte-identical after Lazarus runs.
    assert flow.response.text == before
    assert "coroutine object" not in flow.response.text
    assert "[Lazarus] De-obfuscated" not in flow.response.text

    # Passive-analysis VALUE is preserved: the route is still mined statically.
    routes = lazarus._extract_api_routes(js)
    assert any(r["path"] == "/api/v1/orders" for r in routes)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
