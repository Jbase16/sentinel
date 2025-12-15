# ============================================================================
# core/toolkit/tool_callbacks.py
# Tool Callbacks Module
# ============================================================================
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
# ============================================================================

from core.base.task_router import TaskRouter

def tool_callback_factory(tool_name: str):
    def callback(stdout, stderr, rc, metadata):
        TaskRouter.instance().handle_tool_output(
            tool_name=tool_name,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            metadata=metadata
        )
    return callback