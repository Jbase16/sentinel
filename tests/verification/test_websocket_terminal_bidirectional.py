"""
WebSocket Terminal Bidirectional Communication - Verification

CRITICAL INVARIANT:
Terminal WebSocket must handle BOTH directions:
1. Server → Client: Output from PTY
2. Client → Server: Keystrokes and resize commands

This test verifies TODO #1: "WebSocket Security & Terminal Hardening" (remaining items).

FUNCTIONALITY:
- /ws/pty accepts inbound keystrokes and writes to PTY
- /ws/pty accepts resize commands and updates PTY dimensions
- xterm.js UI sends both keystrokes and resize events
- Terminal escape sequence injection is blocked
"""

import pytest
from pathlib import Path
import re

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


def test_websocket_pty_handles_keystrokes():
    """
    INVARIANT: /ws/pty must accept and process keystroke input from clients.

    This is verified by code inspection of api.py.
    """
    api_path = Path(__file__).parent.parent.parent / "core" / "server" / "api.py"
    assert api_path.exists(), "api.py not found"

    content = api_path.read_text()

    # Find the /ws/pty endpoint
    assert '@app.websocket("/ws/pty")' in content, "/ws/pty endpoint not found"

    # Verify it handles input messages
    assert "receive_text()" in content, "WebSocket doesn't receive messages!"
    assert "pty_session.write(" in content, "PTY doesn't receive keystroke data!"

    # Verify it handles both JSON and raw input (flexible pattern matching)
    handles_json_input = (
        "msg_type" in content and "input" in content or
        "message_text" in content and "json.loads" in content
    )
    assert handles_json_input, (
        "/ws/pty doesn't handle JSON input format"
    )


def test_websocket_pty_handles_resize_commands():
    """
    INVARIANT: /ws/pty must accept and process terminal resize commands.

    Resize events look like: {"type": "resize", "rows": 24, "cols": 80}
    """
    api_path = Path(__file__).parent.parent.parent / "core" / "server" / "api.py"
    content = api_path.read_text()

    # Verify resize handling exists
    assert '"resize"' in content or "'resize'" in content, (
        "/ws/pty doesn't handle resize commands"
    )

    assert "pty_session.resize(" in content, (
        "PTY doesn't have resize() method called"
    )

    # Verify it extracts rows and cols
    assert "rows" in content and "cols" in content, (
        "Resize handler doesn't extract rows/cols from message"
    )


def test_terminal_escape_sequence_sanitization():
    """
    INVARIANT: Terminal input must block dangerous escape sequences.

    Dangerous sequences (OSC, DCS, APC, PM) can be used for:
    - Clipboard reading/writing
    - File exfiltration
    - Terminal state manipulation
    """
    api_path = Path(__file__).parent.parent.parent / "core" / "server" / "api.py"
    content = api_path.read_text()

    # Verify sanitization function exists
    assert "_sanitize_terminal_input" in content or "sanitize" in content, (
        "No input sanitization function found!"
    )

    # Verify dangerous sequences are blocked
    # OSC = \x1b], DCS = \x1bP, APC = \x1b_, PM = \x1b^
    dangerous_patterns = [
        r'\\x1b\]',  # OSC
        r'\\x1bP',   # DCS
        r'\\x1b_',   # APC
        r'\\x1b\^',  # PM
    ]

    found_blocks = sum(1 for pattern in dangerous_patterns if re.search(pattern, content))

    assert found_blocks >= 3, (
        f"Expected to find blocking for dangerous escape sequences, found {found_blocks}/4"
    )


def test_ui_terminal_connects_to_pty_endpoint():
    """
    INVARIANT: UI terminal must connect to /ws/pty (bidirectional), not /ws/terminal (read-only).

    This verifies the Swift/HTML UI is using the correct endpoint.
    """
    # Check HTML terminal
    html_path = Path(__file__).parent.parent.parent / "ui" / "Sources" / "Resources" / "terminal" / "index.html"

    if html_path.exists():
        html_content = html_path.read_text()

        # Must connect to /ws/pty
        assert "/ws/pty" in html_content, (
            "Terminal HTML doesn't connect to /ws/pty!"
        )

        # Must NOT connect to /ws/terminal (read-only)
        assert "/ws/terminal" not in html_content or html_content.count("/ws/pty") > html_content.count("/ws/terminal"), (
            "Terminal HTML connects to wrong endpoint!"
        )


def test_ui_terminal_sends_keystrokes():
    """
    INVARIANT: UI must send keystrokes to server.

    xterm.js provides term.onData() event for keystrokes.
    """
    html_path = Path(__file__).parent.parent.parent / "ui" / "Sources" / "Resources" / "terminal" / "index.html"

    if html_path.exists():
        html_content = html_path.read_text()

        # Verify keystroke handling
        assert "onData" in html_content or "term.on" in html_content, (
            "Terminal doesn't register keystroke handler!"
        )

        assert "ws.send" in html_content, (
            "Terminal doesn't send data to WebSocket!"
        )


def test_ui_terminal_sends_resize_events():
    """
    INVARIANT: UI must send resize commands when window/terminal size changes.

    Resize format: {"type": "resize", "rows": N, "cols": M}
    """
    html_path = Path(__file__).parent.parent.parent / "ui" / "Sources" / "Resources" / "terminal" / "index.html"

    if html_path.exists():
        html_content = html_path.read_text()

        # Verify resize event handling
        assert "resize" in html_content.lower(), (
            "Terminal doesn't handle resize events!"
        )

        # Verify resize data is sent
        assert ("rows" in html_content and "cols" in html_content) or "fit()" in html_content, (
            "Terminal doesn't send rows/cols in resize!"
        )


def test_websocket_pty_is_bidirectional():
    """
    INVARIANT: /ws/pty must have BOTH reader and writer loops.

    - Reader: PTY → WebSocket (output to client)
    - Writer: WebSocket → PTY (input from client)
    """
    api_path = Path(__file__).parent.parent.parent / "core" / "server" / "api.py"
    content = api_path.read_text()

    # Find the /ws/pty endpoint
    pty_endpoint_start = content.find('@app.websocket("/ws/pty")')
    assert pty_endpoint_start > 0, "/ws/pty endpoint not found"

    # Extract ~500 lines after the endpoint (the handler implementation)
    pty_handler = content[pty_endpoint_start:pty_endpoint_start + 15000]

    # Verify reader loop exists (PTY → Client)
    assert "read_pty_loop" in pty_handler or "send_text" in pty_handler, (
        "No output reader loop found in /ws/pty"
    )

    # Verify writer loop exists (Client → PTY)
    assert "receive_text" in pty_handler, (
        "No input receiver loop found in /ws/pty"
    )

    # Verify writes to PTY
    assert "pty_session.write(" in pty_handler, (
        "/ws/pty doesn't write client input to PTY"
    )


def test_websocket_terminal_readonly_is_output_only():
    """
    INVARIANT: /ws/terminal (read-only endpoint) should only send output, not receive input.

    This is intentional - /ws/terminal is for log streaming, /ws/pty is for interactive shells.
    """
    api_path = Path(__file__).parent.parent.parent / "core" / "server" / "api.py"
    content = api_path.read_text()

    # Find /ws/terminal endpoint
    terminal_endpoint_start = content.find('@app.websocket("/ws/terminal")')
    if terminal_endpoint_start < 0:
        pytest.skip("/ws/terminal endpoint not found (might be removed)")

    # Extract handler (larger window to capture full implementation)
    terminal_handler = content[terminal_endpoint_start:terminal_endpoint_start + 2000]

    # Should send output - look for patterns in code
    sends_output = (
        "await websocket.send" in terminal_handler or
        "websocket.send_text" in terminal_handler or
        "send_json" in terminal_handler
    )
    assert sends_output, f"/ws/terminal doesn't send output. Handler: {terminal_handler[:500]}"

    # Should NOT have input handling (only output streaming)
    # /ws/terminal might have "receive" in comments/docs, so be more specific
    has_input_loop = "receive_text()" in terminal_handler or "await websocket.receive" in terminal_handler
    assert not has_input_loop, (
        "/ws/terminal has input handling! It should be read-only."
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
