"""
Tests for scripts/sentinel_token.py (Phase 2G-C).

token_store is patched so tests never touch the real Keychain. The
security-critical contracts:
  - token never read from argv (add uses getpass)
  - show never prints the token, only the handle
  - list returns platform names only
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO / "scripts"))

sentinel_token = importlib.import_module("sentinel_token")
from core.intel.token_store import StoredCredential, TokenStoreError


# ─────────────────────────── add ───────────────────────────────────

class TestAdd:
    def test_add_reads_token_via_getpass_not_argv(self, capsys):
        # The token must come from getpass, never from a CLI argument.
        with patch.object(sentinel_token, "getpass") as mock_getpass, \
             patch.object(sentinel_token.token_store, "put") as mock_put, \
             patch.object(sentinel_token.token_store, "backend_name", return_value="keychain"):
            mock_getpass.getpass.return_value = "SECRET_TOKEN"
            code = sentinel_token.main(["add", "hackerone", "--handle", "myhandle"])
        assert code == 0
        mock_getpass.getpass.assert_called_once()
        mock_put.assert_called_once_with("hackerone", "myhandle", "SECRET_TOKEN")
        # The token must not appear in stdout.
        out = capsys.readouterr().out
        assert "SECRET_TOKEN" not in out

    def test_add_empty_token_rejected(self):
        with patch.object(sentinel_token, "getpass") as mock_getpass:
            mock_getpass.getpass.return_value = "   "  # whitespace only
            code = sentinel_token.main(["add", "hackerone", "--handle", "h"])
        assert code == sentinel_token.EXIT_USAGE

    def test_add_storage_failure_returns_error(self):
        with patch.object(sentinel_token, "getpass") as mock_getpass, \
             patch.object(sentinel_token.token_store, "put",
                          side_effect=TokenStoreError("boom")):
            mock_getpass.getpass.return_value = "tok"
            code = sentinel_token.main(["add", "hackerone", "--handle", "h"])
        assert code == sentinel_token.EXIT_ERROR

    def test_add_invalid_platform_rejected_by_argparse(self):
        with pytest.raises(SystemExit):
            sentinel_token.main(["add", "notreal", "--handle", "h"])


# ─────────────────────────── list ──────────────────────────────────

class TestList:
    def test_list_shows_platforms(self, capsys):
        with patch.object(sentinel_token.token_store, "list_stored",
                          return_value=["hackerone", "bugcrowd"]), \
             patch.object(sentinel_token.token_store, "backend_name", return_value="file"):
            code = sentinel_token.main(["list"])
        assert code == 0
        out = capsys.readouterr().out
        assert "hackerone" in out and "bugcrowd" in out

    def test_list_empty_gives_hint(self, capsys):
        with patch.object(sentinel_token.token_store, "list_stored", return_value=[]):
            code = sentinel_token.main(["list"])
        assert code == 0
        assert "No stored credentials" in capsys.readouterr().out


# ─────────────────────────── show ──────────────────────────────────

class TestShow:
    def test_show_prints_handle_never_token(self, capsys):
        cred = StoredCredential(platform="hackerone", handle="myhandle", token="SECRET")
        with patch.object(sentinel_token.token_store, "get", return_value=cred):
            code = sentinel_token.main(["show", "hackerone"])
        assert code == 0
        out = capsys.readouterr().out
        assert "myhandle" in out
        # The token must NEVER be printed.
        assert "SECRET" not in out

    def test_show_missing_returns_error(self):
        with patch.object(sentinel_token.token_store, "get", return_value=None):
            code = sentinel_token.main(["show", "hackerone"])
        assert code == sentinel_token.EXIT_ERROR


# ─────────────────────────── remove ────────────────────────────────

class TestRemove:
    def test_remove_existing(self, capsys):
        with patch.object(sentinel_token.token_store, "remove", return_value=True):
            code = sentinel_token.main(["remove", "hackerone"])
        assert code == 0
        assert "Removed" in capsys.readouterr().out

    def test_remove_absent(self, capsys):
        with patch.object(sentinel_token.token_store, "remove", return_value=False):
            code = sentinel_token.main(["remove", "hackerone"])
        assert code == 0
        assert "nothing to remove" in capsys.readouterr().out


# ─────────────────────────── usage ─────────────────────────────────

class TestUsage:
    def test_no_command_errors(self):
        with pytest.raises(SystemExit):
            sentinel_token.main([])
