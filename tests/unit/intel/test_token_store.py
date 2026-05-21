"""
Tests for token_store (Phase 2G-A).

The unit tests exercise the file backend with a temp path (no Keychain
side effects). One smoke test verifies the Keychain backend is at
least selectable on Darwin.

Contracts under test:

  1. File backend stores + retrieves + removes credentials correctly.
  2. File is mode 0600 after write.
  3. ``StoredCredential.__repr__`` redacts the token.
  4. Unsupported platforms raise ``TokenStoreError``.
  5. Empty handle/token raise ``TokenStoreError``.
  6. Get returns None (not exception) for absent platforms.
  7. Remove returns False (not exception) when nothing to remove.
  8. list_stored returns only platform names — never tokens.
  9. Tokens are not present in any string representation.
  10. Atomic write doesn't leave .tmp files behind on success.
"""
from __future__ import annotations

import json
import os
import platform as platform_module
import stat
from pathlib import Path
from typing import Optional

import pytest

import core.intel.token_store as token_store
from core.intel.token_store import (
    StoredCredential,
    TokenStoreError,
    _FileBackend,
    _KeychainBackend,
    _keychain_available,
)


# ─────────────────────────── Helpers ───────────────────────────────

@pytest.fixture
def temp_backend(tmp_path):
    """A _FileBackend pointed at a tmp_path file. No global state."""
    return _FileBackend(path=tmp_path / "creds.json")


# ─────────────────────────── StoredCredential ──────────────────────

class TestStoredCredential:
    def test_repr_redacts_token(self):
        c = StoredCredential(platform="hackerone", handle="h", token="SECRET")
        s = repr(c)
        assert "SECRET" not in s
        assert "<redacted>" in s
        # But the platform and handle should be visible for debugging.
        assert "hackerone" in s
        assert "'h'" in s

    def test_token_still_accessible_via_attribute(self):
        # Redacted in repr — but the value itself must still be reachable.
        c = StoredCredential(platform="hackerone", handle="h", token="SECRET")
        assert c.token == "SECRET"


# ─────────────────────────── File backend basics ───────────────────

class TestFileBackend:
    def test_get_returns_none_for_absent(self, temp_backend):
        assert temp_backend.get("hackerone") is None

    def test_put_and_get_round_trip(self, temp_backend):
        temp_backend.put("hackerone", "test-handle", "TOKEN_VALUE")
        result = temp_backend.get("hackerone")
        assert result is not None
        assert result.platform == "hackerone"
        assert result.handle == "test-handle"
        assert result.token == "TOKEN_VALUE"

    def test_put_overwrites_existing(self, temp_backend):
        temp_backend.put("hackerone", "h1", "T1")
        temp_backend.put("hackerone", "h2", "T2")
        result = temp_backend.get("hackerone")
        assert result.handle == "h2"
        assert result.token == "T2"

    def test_multiple_platforms_coexist(self, temp_backend):
        temp_backend.put("hackerone", "h1", "T1")
        temp_backend.put("bugcrowd", "b1", "T2")
        assert temp_backend.get("hackerone").handle == "h1"
        assert temp_backend.get("bugcrowd").handle == "b1"

    def test_remove_existing_returns_true(self, temp_backend):
        temp_backend.put("hackerone", "h", "T")
        assert temp_backend.remove("hackerone") is True
        assert temp_backend.get("hackerone") is None

    def test_remove_absent_returns_false(self, temp_backend):
        assert temp_backend.remove("hackerone") is False

    def test_remove_last_entry_deletes_file(self, temp_backend, tmp_path):
        temp_backend.put("hackerone", "h", "T")
        assert (tmp_path / "creds.json").exists()
        temp_backend.remove("hackerone")
        # File removed when last entry deleted (cleaner than leaving a {} file).
        assert not (tmp_path / "creds.json").exists()

    def test_list_stored_returns_platform_names(self, temp_backend):
        temp_backend.put("hackerone", "h", "T")
        temp_backend.put("bugcrowd", "b", "T2")
        assert sorted(temp_backend.list_stored()) == ["bugcrowd", "hackerone"]

    def test_list_stored_does_not_include_tokens(self, temp_backend):
        temp_backend.put("hackerone", "h", "SECRET_TOKEN_VALUE")
        names = temp_backend.list_stored()
        # The returned list should contain only short platform names.
        assert "SECRET_TOKEN_VALUE" not in str(names)
        assert "hackerone" in names


# ─────────────────────────── File permissions ──────────────────────

class TestFilePermissions:
    def test_file_is_mode_0600_after_write(self, temp_backend, tmp_path):
        temp_backend.put("hackerone", "h", "T")
        st = os.stat(tmp_path / "creds.json")
        # 0o600 = owner read/write only, no group, no other.
        mode = stat.S_IMODE(st.st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_no_tmp_file_left_behind_after_successful_write(self, temp_backend, tmp_path):
        temp_backend.put("hackerone", "h", "T")
        # The atomic-write path uses a .tmp suffix, then rename.
        # After a clean write, no .tmp should remain.
        assert not (tmp_path / "creds.json.tmp").exists()


# ─────────────────────────── Public API (with patched backend) ─────

class TestPublicApi:
    """Patch _select_backend so we exercise the module-level get/put/remove
    without touching real Keychain or ~/.sentinelforge."""

    def test_public_get_returns_credential(self, temp_backend, monkeypatch):
        monkeypatch.setattr(token_store, "_select_backend", lambda: temp_backend)
        temp_backend.put("hackerone", "h", "T")
        c = token_store.get("hackerone")
        assert c is not None
        assert c.token == "T"

    def test_public_put_validates_platform(self, monkeypatch, temp_backend):
        monkeypatch.setattr(token_store, "_select_backend", lambda: temp_backend)
        with pytest.raises(TokenStoreError, match="unsupported platform"):
            token_store.put("not-a-platform", "h", "T")

    def test_public_put_validates_empty_handle(self, monkeypatch, temp_backend):
        monkeypatch.setattr(token_store, "_select_backend", lambda: temp_backend)
        with pytest.raises(TokenStoreError, match="handle"):
            token_store.put("hackerone", "", "T")

    def test_public_put_validates_empty_token(self, monkeypatch, temp_backend):
        monkeypatch.setattr(token_store, "_select_backend", lambda: temp_backend)
        with pytest.raises(TokenStoreError, match="token"):
            token_store.put("hackerone", "h", "")

    def test_public_remove_returns_bool(self, monkeypatch, temp_backend):
        monkeypatch.setattr(token_store, "_select_backend", lambda: temp_backend)
        temp_backend.put("hackerone", "h", "T")
        assert token_store.remove("hackerone") is True
        assert token_store.remove("hackerone") is False

    def test_public_list_returns_platform_names(self, monkeypatch, temp_backend):
        monkeypatch.setattr(token_store, "_select_backend", lambda: temp_backend)
        temp_backend.put("hackerone", "h", "T")
        assert token_store.list_stored() == ["hackerone"]

    def test_unsupported_platform_rejected_at_get(self, monkeypatch, temp_backend):
        monkeypatch.setattr(token_store, "_select_backend", lambda: temp_backend)
        with pytest.raises(TokenStoreError):
            token_store.get("not-a-platform")


# ─────────────────────────── Atomicity ─────────────────────────────

class TestAtomicWrite:
    def test_concurrent_writes_dont_corrupt_file(self, tmp_path):
        # Two backends pointed at the same path, sequential writes.
        # We're not testing thread safety (the lock would be too
        # heavyweight for a credential store) — we're testing that
        # each individual write is atomic enough that the file is
        # never half-written.
        backend = _FileBackend(path=tmp_path / "creds.json")
        backend.put("hackerone", "h1", "T1")
        backend.put("hackerone", "h2", "T2")
        backend.put("bugcrowd", "b1", "T3")
        # File should always be parseable JSON.
        data = json.loads((tmp_path / "creds.json").read_text())
        assert data["hackerone"]["handle"] == "h2"
        assert data["bugcrowd"]["handle"] == "b1"


# ─────────────────────────── Keychain backend (smoke) ──────────────

@pytest.mark.skipif(
    platform_module.system() != "Darwin",
    reason="Keychain backend is macOS-only",
)
class TestKeychainSmoke:
    """Smoke-test the Keychain backend — verify it instantiates and
    its accessor methods don't crash. We don't write/read real
    credentials in tests (would pollute the real Keychain)."""

    def test_keychain_available_on_macos(self):
        # ``security`` should be in $PATH on any standard macOS install.
        assert _keychain_available() is True

    def test_keychain_backend_instantiates(self):
        kb = _KeychainBackend()
        assert kb.name == "keychain"

    def test_keychain_get_returns_none_for_unset_platform(self):
        # We never wrote "bugcrowd" to Keychain in tests, so get should
        # return None — and crucially, must NOT raise.
        kb = _KeychainBackend()
        # The actual user might have a real entry here; if so, this test
        # would falsely "pass" by getting back a real credential. So we
        # only assert that the call completes without raising. This is a
        # smoke test, not a contract test.
        result = kb.get("bugcrowd")
        assert result is None or isinstance(result, StoredCredential)


# ─────────────────────────── Backend selection ─────────────────────

class TestBackendSelection:
    def test_backend_name_returns_string(self):
        # Whichever backend is selected, its name is a non-empty string.
        name = token_store.backend_name()
        assert name in ("keychain", "file")
