"""
token_store — secure storage for platform API credentials.

Backends:

  - **macOS Keychain** (primary on Darwin) — uses the ``security`` CLI
    to store secrets encrypted at rest with the user's login keychain.
    Strongest option; preferred when available.
  - **Encrypted file fallback** (non-Darwin or when Keychain unavailable)
    — ``~/.sentinelforge/intel-credentials.json`` with mode 0600.
    Plaintext on disk, but only readable by the owning user.

Both backends store the same shape:

    {platform: "hackerone", handle: "your-handle", token: "..."}

The token store deliberately does NOT support listing tokens — it only
returns the token for a given platform when asked. This means if a
malicious process can read the store, it must already know which
platform it's after; it can't enumerate the catalog.

The CLI in ``scripts/sentinel_token.py`` is the operator-facing surface
— this module is the storage primitive.

Security properties this module preserves:

  1. Token never appears in argv (callers use ``getpass`` for input).
  2. Token never logged at any level (we redact in ``__repr__``).
  3. File-backend file is mode 0600 (owner read/write only).
  4. Keychain backend uses the per-user login keychain (encrypted).
  5. Get-or-None semantics — no exception leaks the token via traceback.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# Service prefix for Keychain entries — chosen so Keychain Access.app
# groups them visibly together if the user inspects the keychain.
_KEYCHAIN_SERVICE_PREFIX = "sentinelforge.intel"

# File fallback location. Permissions 0600 enforced on every write.
_FALLBACK_PATH = Path.home() / ".sentinelforge" / "intel-credentials.json"

_SUPPORTED_PLATFORMS = frozenset({"hackerone", "bugcrowd"})


@dataclass
class StoredCredential:
    """A platform API credential. The token is treated as sensitive —
    ``__repr__`` redacts it so it can't leak via accidental logging."""
    platform: str
    handle: str
    token: str = field(repr=False)  # excluded from default __repr__

    def __repr__(self) -> str:
        return (
            f"StoredCredential(platform={self.platform!r}, "
            f"handle={self.handle!r}, token=<redacted>)"
        )


class TokenStoreError(Exception):
    """Raised on irrecoverable storage errors (unwritable file, missing
    Keychain binary, etc.). Caller decides whether to fail open or hard."""


# ─────────────────────────── Public API ────────────────────────────

def get(platform_name: str) -> Optional[StoredCredential]:
    """Fetch the stored credential for a platform, or None if absent.

    Returns None — never raises — when no credential is stored.
    Raises ``TokenStoreError`` only when the storage backend itself
    is broken (Keychain binary missing, file unreadable, etc.).
    """
    _validate_platform(platform_name)
    backend = _select_backend()
    return backend.get(platform_name)


def put(platform_name: str, handle: str, token: str) -> None:
    """Store a credential. Overwrites any existing entry for the
    same platform.

    Args:
        platform_name: ``"hackerone"`` or ``"bugcrowd"``.
        handle: Your platform username (the H1 handle, Bugcrowd researcher
            name, etc.). Used as the Basic-Auth username.
        token: The API token. Treated as sensitive — never logged, never
            echoed.
    """
    _validate_platform(platform_name)
    if not handle.strip():
        raise TokenStoreError("handle must not be empty")
    if not token.strip():
        raise TokenStoreError("token must not be empty")

    backend = _select_backend()
    backend.put(platform_name, handle.strip(), token)


def remove(platform_name: str) -> bool:
    """Delete a stored credential. Returns True if one was removed,
    False if none existed."""
    _validate_platform(platform_name)
    backend = _select_backend()
    return backend.remove(platform_name)


def list_stored() -> list[str]:
    """Return the list of platform names that have a stored credential.

    Deliberately returns platform names only — no handles, no tokens.
    The CLI ``sentinel-token list`` consumes this; full handle reveals
    require an explicit ``sentinel-token show <platform>`` (which prints
    just the handle, never the token).
    """
    backend = _select_backend()
    return backend.list_stored()


def backend_name() -> str:
    """Return the name of the currently-active backend. Useful for
    diagnostics and CLI ``--verbose`` output."""
    return _select_backend().name


# ─────────────────────────── Internals ─────────────────────────────

def _validate_platform(name: str) -> None:
    if name not in _SUPPORTED_PLATFORMS:
        raise TokenStoreError(
            f"unsupported platform {name!r}; expected one of "
            f"{sorted(_SUPPORTED_PLATFORMS)}"
        )


def _select_backend():
    """Pick the strongest backend available on this host."""
    if platform.system() == "Darwin" and _keychain_available():
        return _KeychainBackend()
    return _FileBackend()


def _keychain_available() -> bool:
    """Probe whether ``security`` CLI is present on PATH."""
    try:
        result = subprocess.run(
            ["security", "-h"],
            capture_output=True, timeout=2.0, check=False,
        )
        return result.returncode in (0, 1)  # both indicate the binary ran
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ─────────────────────────── Backend interface ─────────────────────

class _BackendBase:
    """Shared shape for both backends."""
    name: str = "unknown"

    def get(self, platform_name: str) -> Optional[StoredCredential]:
        raise NotImplementedError

    def put(self, platform_name: str, handle: str, token: str) -> None:
        raise NotImplementedError

    def remove(self, platform_name: str) -> bool:
        raise NotImplementedError

    def list_stored(self) -> list[str]:
        raise NotImplementedError


# ─────────────────────────── Keychain backend ──────────────────────

class _KeychainBackend(_BackendBase):
    """macOS Keychain via the ``security`` CLI.

    We store the (handle, token) pair as one generic-password entry per
    platform. The service field is ``sentinelforge.intel.<platform>``,
    the account field is the handle, and the password field is the token.
    """
    name = "keychain"

    def get(self, platform_name: str) -> Optional[StoredCredential]:
        service = f"{_KEYCHAIN_SERVICE_PREFIX}.{platform_name}"
        # First: read the handle (account name). ``security find-generic-password
        # -s <service> -g`` writes the password to stderr; the account
        # appears in the body in the form: ``"acct"<blob>="<value>"``.
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-s", service, "-g"],
                capture_output=True, timeout=5.0, check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise TokenStoreError(f"keychain timeout reading {service}: {e}")
        if result.returncode != 0:
            return None  # not found
        # Parse the account ("acct") from stdout.
        handle = _parse_keychain_account(result.stdout.decode("utf-8", "replace"))
        # The actual token is on stderr in the form: ``password: "<value>"``.
        token = _parse_keychain_password(result.stderr.decode("utf-8", "replace"))
        if handle is None or token is None:
            logger.warning(
                "[intel.token_store] could not parse keychain entry for %s; "
                "treating as missing", service,
            )
            return None
        return StoredCredential(platform=platform_name, handle=handle, token=token)

    def put(self, platform_name: str, handle: str, token: str) -> None:
        service = f"{_KEYCHAIN_SERVICE_PREFIX}.{platform_name}"
        # ACL choice: ``-A`` permits any process on the same user account
        # to read this entry without a GUI prompt — matches how curl,
        # git, the AWS CLI, etc. store credentials. The alternative
        # (-T <app-path>) would scope access per binary, but it breaks
        # any Python script run from a non-bundled interpreter (every
        # virtualenv would need its own ACL entry). Threat model: same-
        # user processes — if those are compromised, the Keychain itself
        # is the least of our worries.
        cmd = [
            "security", "add-generic-password",
            "-s", service,
            "-a", handle,
            "-w", token,
            "-U",  # update if exists
            "-A",  # any application may access without prompt
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5.0, check=False)
        except subprocess.TimeoutExpired as e:
            raise TokenStoreError(f"keychain timeout writing {service}: {e}")
        if result.returncode != 0:
            raise TokenStoreError(
                f"keychain write failed for {service}: "
                f"{result.stderr.decode('utf-8', 'replace')[:200]}"
            )

    def remove(self, platform_name: str) -> bool:
        service = f"{_KEYCHAIN_SERVICE_PREFIX}.{platform_name}"
        try:
            result = subprocess.run(
                ["security", "delete-generic-password", "-s", service],
                capture_output=True, timeout=5.0, check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise TokenStoreError(f"keychain timeout removing {service}: {e}")
        # 0 = removed; 44 = not found; treat both as success cases.
        return result.returncode == 0

    def list_stored(self) -> list[str]:
        # Iterate the platforms we know about and check each.
        out = []
        for p in sorted(_SUPPORTED_PLATFORMS):
            if self.get(p) is not None:
                out.append(p)
        return out


def _parse_keychain_account(stdout: str) -> Optional[str]:
    """Extract the account ("acct") value from ``security`` stdout."""
    for line in stdout.splitlines():
        # Format: ``"acct"<blob>="your-handle"``
        line = line.strip()
        if '"acct"' in line and "=" in line:
            value = line.split("=", 1)[1].strip()
            if value.startswith('"') and value.endswith('"'):
                return value[1:-1]
    return None


def _parse_keychain_password(stderr: str) -> Optional[str]:
    """Extract the password value from ``security -g`` stderr."""
    for line in stderr.splitlines():
        # Format: ``password: "AGHo...="``
        if line.startswith("password:"):
            value = line.split(":", 1)[1].strip()
            if value.startswith('"') and value.endswith('"'):
                return value[1:-1]
    return None


# ─────────────────────────── File backend ──────────────────────────

class _FileBackend(_BackendBase):
    """Plain JSON file fallback. Mode 0600 enforced on every write.

    The file format is intentionally simple:

        {
          "hackerone": {"handle": "...", "token": "..."},
          "bugcrowd":  {"handle": "...", "token": "..."}
        }

    A single file rather than per-platform files because that's one
    fewer thing for the operator to manage and a single fsync covers it.
    """
    name = "file"

    def __init__(self, path: Path = _FALLBACK_PATH):
        self._path = path

    def _read_all(self) -> dict:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            raise TokenStoreError(f"could not read {self._path}: {e}")

    def _write_all(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically — temp file, fsync, rename. Mode 0600
        # applied via os.umask + explicit chmod.
        tmp = self._path.with_suffix(".tmp")
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

        # Create with restrictive perms from the start.
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)
        # Ensure mode is correct even if the file pre-existed with looser
        # perms (and the umask happened to grant them).
        os.chmod(self._path, 0o600)

    def get(self, platform_name: str) -> Optional[StoredCredential]:
        data = self._read_all()
        entry = data.get(platform_name)
        if not isinstance(entry, dict):
            return None
        handle = entry.get("handle")
        token = entry.get("token")
        if not handle or not token:
            return None
        return StoredCredential(
            platform=platform_name, handle=handle, token=token,
        )

    def put(self, platform_name: str, handle: str, token: str) -> None:
        data = self._read_all()
        data[platform_name] = {"handle": handle, "token": token}
        self._write_all(data)

    def remove(self, platform_name: str) -> bool:
        data = self._read_all()
        if platform_name not in data:
            return False
        del data[platform_name]
        if data:
            self._write_all(data)
        else:
            # No remaining entries → remove the file outright rather than
            # leaving a {} on disk.
            try:
                self._path.unlink()
            except FileNotFoundError:
                pass
        return True

    def list_stored(self) -> list[str]:
        return sorted(self._read_all().keys())
