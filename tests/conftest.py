"""Pytest configuration for SentinelForge."""
import os


def pytest_configure():
    # Enable development mode for tests so loopback port wildcards are allowed.
    os.environ.setdefault("SENTINEL_DEBUG", "true")
