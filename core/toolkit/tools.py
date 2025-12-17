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

from core.base.task_router import TaskRouter


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
