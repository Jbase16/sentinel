"""Unit tests for the startup security interlock."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.base.config import SecurityInterlock, SentinelConfig, SecurityConfig, StorageConfig
from core.errors import CriticalSecurityBreach


def _make_config(tmp_path, *, api_host="127.0.0.1", require_auth=False, allowed_origins=None):
    security = SecurityConfig(
        require_auth=require_auth,
        allowed_origins=allowed_origins
        if allowed_origins is not None
        else ("http://127.0.0.1:*", "http://localhost:*", "tauri://localhost"),
    )
    storage = StorageConfig(base_dir=tmp_path)
    return SentinelConfig(security=security, storage=storage, api_host=api_host)


def test_interlock_blocks_exposed_without_auth(tmp_path):
    config = _make_config(tmp_path, api_host="0.0.0.0", require_auth=False)
    with pytest.raises(CriticalSecurityBreach):
        SecurityInterlock.verify_safe_boot(config)


def test_interlock_allows_exposed_with_auth(tmp_path):
    config = _make_config(tmp_path, api_host="0.0.0.0", require_auth=True)
    SecurityInterlock.verify_safe_boot(config)


def test_interlock_blocks_wildcard_origin_without_auth(tmp_path):
    config = _make_config(tmp_path, allowed_origins=("*",), require_auth=False)
    with pytest.raises(CriticalSecurityBreach):
        SecurityInterlock.verify_safe_boot(config)


def test_interlock_allows_wildcard_origin_with_auth(tmp_path):
    config = _make_config(tmp_path, allowed_origins=("http://*",), require_auth=True)
    SecurityInterlock.verify_safe_boot(config)


def test_interlock_allows_port_wildcard_on_localhost_without_auth(tmp_path):
    config = _make_config(tmp_path, allowed_origins=("http://localhost:*",), require_auth=False)
    SecurityInterlock.verify_safe_boot(config)
