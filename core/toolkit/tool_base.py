"""Module tool_base: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/tool_base.py."""
#
# PURPOSE:
# This module is part of the toolkit package in SentinelForge.
# [Specific purpose based on module name: tool_base]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

from core.engine.executor import ExecutionEngine
from .tool_callbacks import tool_callback_factory

class ToolBase:
    """
    Base class for all external tools.
    Provides a clean interface for running commands with metadata and callbacks.
    """

    def __init__(self, name: str):
        self.name = name

    def run(self, command: str, timeout: int = 120, metadata=None):
        """Function run."""
        callback = tool_callback_factory(self.name)
        return ExecutionEngine.instance().submit(
            command=command,
            callback=callback,
            timeout=timeout,
            metadata=metadata or {}
        )