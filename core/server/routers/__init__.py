"""
Router initialization module.

Exports all API routers for the SentinelForge backend.
"""
from core.server.routers import auth, scans, ai, system, realtime, cortex, ghost

__all__ = [
    "auth",
    "scans",
    "ai",
    "system",
    "realtime",
    "cortex",
    "ghost",
]