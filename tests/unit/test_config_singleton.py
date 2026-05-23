"""
Tests for the SentinelConfig singleton and token persistence.

These tests pin down the two bugs found in Calibration Run #1:
  Bug #2 — token-rotation race when multiple consumers each create their
           own SentinelConfig instead of using the singleton.
  Bug #1 — PATH shadowing where venv-installed binaries (Python httpx)
           outrank system tools (ProjectDiscovery httpx).
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

import core.base.config as config_module
from core.base.config import (
    SentinelConfig,
    get_config,
    normalize_tool_path,
    set_config,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def reset_singleton():
    """Force the config singleton to None before/after each test so the
    tests are hermetic. Other tests may have materialised _config already."""
    config_module._config = None
    yield
    config_module._config = None


@pytest.fixture
def tmp_data_dir(tmp_path, monkeypatch):
    """Redirect ~/.sentinelforge to a tmp dir for tests that need the
    token file."""
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SENTINEL_API_TOKEN", raising=False)
    return tmp_path


# ---------------------------------------------------------------------------
# Singleton stability — the Bug #2 invariants
# ---------------------------------------------------------------------------

class TestSingletonStability:
    def test_get_config_returns_same_instance(self, reset_singleton, tmp_data_dir):
        a = get_config()
        b = get_config()
        assert a is b, "get_config() must return the same instance"
        assert a.security.api_token == b.security.api_token

    def test_token_persists_across_materialisation(self, reset_singleton, tmp_data_dir):
        """If the singleton is wiped (as happens during tests, or in pathological
        production paths), a fresh from_env() must read the token from the
        file rather than generating a new one."""
        # First materialisation
        c1 = get_config()
        original_token = c1.security.api_token
        token_path = tmp_data_dir / "api_token"
        assert token_path.exists()
        assert token_path.read_text() == original_token

        # Wipe the singleton and re-materialise
        config_module._config = None
        c2 = get_config()

        # Token must be identical because it was read from the file.
        assert c2.security.api_token == original_token, (
            "Second SentinelConfig must read existing token from file, "
            "not regenerate. See Bug #2."
        )
        # File contents must match.
        assert token_path.read_text() == original_token

    def test_direct_from_env_also_uses_file(self, reset_singleton, tmp_data_dir):
        """Even callers that bypass get_config() and instantiate
        SentinelConfig.from_env() directly must get the same token."""
        c1 = get_config()
        token = c1.security.api_token

        # Simulating a buggy caller (e.g. the old cas.py / ledger.py pattern).
        c2 = SentinelConfig.from_env()
        assert c2.security.api_token == token, (
            "Any from_env() caller must converge on the persisted token."
        )

    def test_token_env_var_overrides_file(self, reset_singleton, tmp_data_dir, monkeypatch):
        """Explicit env var precedence: SENTINEL_API_TOKEN beats the file."""
        # Seed the file with token A
        (tmp_data_dir / "api_token").write_text("a" * 40)
        # Set env to token B
        monkeypatch.setenv("SENTINEL_API_TOKEN", "b" * 40)
        c = get_config()
        assert c.security.api_token == "b" * 40

    def test_concurrent_get_config_returns_same_instance(self, reset_singleton, tmp_data_dir):
        """Multiple threads racing on get_config() must not produce
        multiple SentinelConfig instances."""
        results: list = []
        errors: list = []
        barrier = threading.Barrier(8)

        def worker():
            try:
                barrier.wait(timeout=5)
                results.append(get_config())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"thread errors: {errors}"
        assert len(results) == 8
        first = results[0]
        for r in results[1:]:
            assert r is first, "all threads must observe the same singleton"

    def test_token_file_write_is_idempotent(self, reset_singleton, tmp_data_dir, caplog):
        """When the token file already contains the same token, _write_token_file
        must NOT rewrite or emit a log line. This prevents log spam and (more
        importantly) signals that the bug isn't re-occurring."""
        import logging

        # First creation — should write
        with caplog.at_level(logging.INFO, logger="core.base.config"):
            c = get_config()
            assert any("API token written" in r.message for r in caplog.records)

        # Wipe singleton, re-create with same persisted token
        caplog.clear()
        config_module._config = None
        with caplog.at_level(logging.INFO, logger="core.base.config"):
            c2 = get_config()
            assert c2.security.api_token == c.security.api_token
            assert not any("API token written" in r.message for r in caplog.records), (
                "_write_token_file must be a no-op when the file already has the same token"
            )


# ---------------------------------------------------------------------------
# PATH normalisation — the Bug #1 invariants
# ---------------------------------------------------------------------------

class TestPathNormalization:
    def test_homebrew_appears_before_venv(self, monkeypatch, tmp_path):
        """The whole point of the fix: a venv bin path must not shadow
        /opt/homebrew/bin for tool lookups."""
        # Build a PATH that puts a fake venv first (the bug shape)
        fake_venv = tmp_path / "fake_venv" / "bin"
        fake_venv.mkdir(parents=True)
        monkeypatch.setenv(
            "PATH",
            f"{fake_venv}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        )

        normalize_tool_path()

        parts = os.environ["PATH"].split(os.pathsep)
        # /opt/homebrew/bin must appear before the fake_venv path
        if Path("/opt/homebrew/bin").exists():
            homebrew_idx = parts.index("/opt/homebrew/bin")
            venv_idx = parts.index(str(fake_venv))
            assert homebrew_idx < venv_idx, (
                f"Homebrew must outrank venv: PATH={parts}"
            )

    def test_idempotent(self, monkeypatch):
        """Running normalize_tool_path twice produces the same PATH."""
        monkeypatch.setenv("PATH", "/opt/homebrew/bin:/usr/bin:/bin")
        normalize_tool_path()
        first = os.environ["PATH"]
        normalize_tool_path()
        assert os.environ["PATH"] == first

    def test_preserves_unique_entries(self, monkeypatch, tmp_path):
        """User-specified paths not in the preferred set must be retained
        (just demoted below the system paths)."""
        custom = tmp_path / "custom_tools"
        custom.mkdir()
        monkeypatch.setenv(
            "PATH",
            f"{custom}:/opt/homebrew/bin:/usr/bin:/bin",
        )
        normalize_tool_path()
        parts = os.environ["PATH"].split(os.pathsep)
        assert str(custom) in parts, "custom user paths must be preserved"

    def test_only_existing_paths_in_result(self, monkeypatch):
        """Whatever ends up in PATH must point to existing directories.
        normalize_tool_path() must not add /opt/homebrew/bin on a machine
        that doesn't have Homebrew installed, etc."""
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        normalize_tool_path()
        for path in os.environ["PATH"].split(os.pathsep):
            # Any path we PREPENDED (from the preferred list) must exist.
            # Paths the user had originally may or may not — we preserve those.
            # So just assert the well-known preferred paths exist if present.
            if path in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"):
                assert Path(path).exists(), (
                    f"{path} is in PATH but doesn't exist on this system"
                )
