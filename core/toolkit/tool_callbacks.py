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