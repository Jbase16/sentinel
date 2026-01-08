"""Pytest configuration for SentinelForge."""
import os
import sys
import warnings


def pytest_configure():
    # Enable development mode for tests so loopback port wildcards are allowed.
    os.environ.setdefault("SENTINEL_DEBUG", "true")
    
    # Suppress known deprecation warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")
