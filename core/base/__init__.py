"""Module __init__: inline documentation for /Users/jason/Developer/sentinelforge/core/base/__init__.py."""
#
# PURPOSE:
# Marks the "base" directory as a Python package containing foundational
# components that the rest of the system depends on.
#
# WHAT'S IN THIS MODULE:
# - config.py: Application configuration (AI settings, security rules, paths)
# - session.py: Scan session management (isolates each security test)
# - action_dispatcher.py: Safety layer for dangerous operations (requires approval)
# - task_router.py: Central event bus (connects tools → AI → UI)
#
# WHY IT'S CALLED "BASE":
# These are the building blocks everything else is built on. If you're learning
# the codebase, start here to understand how the system is structured.
#
