from .executor import ExecutionEngine
from .tool_callbacks import tool_callback_factory

class ToolBase:
    """
    Base class for all external tools.
    Provides a clean interface for running commands with metadata and callbacks.
    """

    def __init__(self, name: str):
        self.name = name

    def run(self, command: str, timeout: int = 120, metadata=None):
        callback = tool_callback_factory(self.name)
        return ExecutionEngine.instance().submit(
            command=command,
            callback=callback,
            timeout=timeout,
            metadata=metadata or {}
        )