"""Module tool_callbacks: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/tool_callbacks.py."""
#
# PURPOSE:
# This module is part of the toolkit package in SentinelForge.
# [Specific purpose based on module name: tool_callbacks]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

from core.base.task_router import TaskRouter

def tool_callback_factory(tool_name: str):
    """Function tool_callback_factory."""
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