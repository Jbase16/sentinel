"""Module tools: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/tools.py."""
#
# This module has been refactored. The actual logic is now in:
# - normalizer.py: Target normalization functions
# - registry.py: Tool definitions (TOOLS dict)
# - installer.py: Async installation/uninstallation
#
# This file re-exports everything for backward compatibility.
# PATH SETUP - Ensure tools can be found
# RE-EXPORTS from submodules (for backward compatibility)
# PUBLIC API - Used by the scanner and API server
# CALLBACK PLUMBING - Integration with TaskRouter

from typing import Dict, Any
from core.base.task_router import TaskRouter
from core.toolkit.registry import TOOLS, get_tool_command, find_binary
from core.toolkit.installer import install_tools, uninstall_tools

__all__ = [
    "TaskRouter",
    "tool_callback_factory",
    "TOOLS",
    "get_tool_command",
    "get_installed_tools",
    "find_binary",
    "install_tools",
    "uninstall_tools",
]


def tool_callback_factory(tool_name: str):
    """
    Create a callback function for a specific tool.
    """
    def callback(stdout, stderr, rc, metadata):
        """Function callback."""
        TaskRouter.instance().handle_tool_output(
            tool_name=tool_name,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            metadata=metadata
        )
    return callback


def get_installed_tools() -> Dict[str, Dict[str, Any]]:
    """
    Detect which tools from the registry are installed on the system.
    Returns a dictionary of installed tools and their metadata.

    Checks both system PATH and the project's venv bin directory,
    since pip-installed tools may only exist in .venv/bin/.
    """
    installed = {}
    for name, config in TOOLS.items():
        # Internal tools are in-process handlers, not external binaries.
        # Treat them as always available so they can be selected/executed.
        if getattr(config, "tool_type", "subprocess") == "internal":
            installed[name] = config
            continue

        # Check if binary (or cmd[0]) exists in PATH or venv
        binary = config.binary_name or config.cmd_template[0]
        if find_binary(binary):
            installed[name] = config
    return installed
