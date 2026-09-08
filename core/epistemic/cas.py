"""
Content-Addressable Storage (CAS) for SentinelForge.

This module implements the "Blob Store" for raw evidence reliability.
Instead of storing logs in a database or mutable files, we store them
as immutable blobs addressed by their SHA256 hash.

Design:
- Blob Path: {storage_root}/evidence/blobs/{sha256}
- Deduplication: Identical outputs map to the same hash
- Integrity: Verification is trivial (hash the file, compare to filename)
"""

import hashlib
import logging
import os
from pathlib import Path
import secrets
import stat
from typing import Optional

from core.base.config import SentinelConfig
from core.epistemic.storage_boundary import EvidenceStorageAnchor

logger = logging.getLogger(__name__)


class ContentAddressableStorage:
    """
    Immutable blob storage for raw evidence.
    """

    def __init__(
        self,
        config: Optional[SentinelConfig] = None,
        *,
        storage_anchor: Optional[EvidenceStorageAnchor] = None,
    ):
        # Use the global singleton when no config is injected.
        # Historical bug: this used SentinelConfig.from_env() directly,
        # which created a new SentinelConfig with a fresh random api_token
        # every time CAS was instantiated mid-scan — desynchronising the
        # token file from the auth handler's in-memory token. See
        # docs/CALIBRATION_RUN_001.md Bug #2.
        from core.base.config import get_config

        self.config = config or get_config()
        self._storage_anchor = storage_anchor
        # Storage root: ~/.sentinelforge/evidence/blobs
        self.blob_dir = self.config.storage.evidence_path / "blobs"
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        """Create and pin the blob directory without accepting a final symlink."""

        self._assert_storage_anchor()
        if self.blob_dir.is_symlink():
            raise ValueError("CAS blob directory is unsafe")
        created = False
        try:
            self.blob_dir.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
        if created:
            self._fsync_directory(self.blob_dir.parent)
        self._assert_storage_anchor()
        descriptor = self._open_directory_unpinned()
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o022
            ):
                raise ValueError("CAS blob directory ownership or mode is unsafe")
            self._blob_dir_identity = (metadata.st_dev, metadata.st_ino)
        finally:
            os.close(descriptor)
        if self._storage_anchor is not None:
            self._storage_anchor.seal()

    def _assert_storage_anchor(self) -> None:
        if self._storage_anchor is not None:
            self._storage_anchor.assert_unchanged()

    @staticmethod
    def _valid_address(blob_hash: str) -> bool:
        return (
            isinstance(blob_hash, str)
            and len(blob_hash) == 64
            and all(character in "0123456789abcdef" for character in blob_hash)
        )

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _open_directory_unpinned(self) -> int:
        return os.open(
            self.blob_dir,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )

    def _open_directory(self) -> int:
        self._assert_storage_anchor()
        descriptor = self._open_directory_unpinned()
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != self._blob_dir_identity:
            os.close(descriptor)
            raise ValueError("CAS blob directory changed after admission")
        return descriptor

    @staticmethod
    def _read_existing(directory_fd: int, name: str, expected: str) -> bytes:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o022
            ):
                raise ValueError("CAS blob path ownership or mode is unsafe")
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                chunks.append(chunk)
            if digest.hexdigest() != expected:
                raise ValueError("CAS blob content does not match its address")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def preflight(self) -> None:
        """Prove the pinned CAS directory can durably create and remove a file."""

        directory_fd = self._open_directory()
        temporary_name = f".preflight.{os.getpid()}.{secrets.token_hex(8)}"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.unlink(temporary_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)

    def store(self, data: bytes) -> str:
        """
        Store raw bytes and return their SHA256 hash.

        Args:
            data: Raw bytes to store (e.g. tool stdout)

        Returns:
            str: SHA256 hash of the data (the address)
        """
        if not isinstance(data, bytes):
            raise TypeError("CAS payload must be bytes")

        # 1. Calculate Hash
        sha256 = hashlib.sha256(data).hexdigest()

        # 2. Publish only fully synchronized bytes.  A hard-link gives us
        # create-if-absent semantics across processes without ever exposing a
        # partial final blob.
        directory_fd = self._open_directory()
        temporary_name = f".{sha256}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        descriptor = -1
        try:
            try:
                self._read_existing(directory_fd, sha256, sha256)
                logger.debug(f"[CAS] Blob {sha256[:8]} already exists (deduplicated)")
                return sha256
            except FileNotFoundError:
                pass

            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise OSError("CAS write made no progress")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            try:
                os.link(
                    temporary_name,
                    sha256,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                self._read_existing(directory_fd, sha256, sha256)
            os.fsync(directory_fd)
            logger.debug(f"[CAS] Stored blob {sha256[:8]} ({len(data)} bytes)")
        except Exception as exc:
            logger.error(f"[CAS] Failed to write blob {sha256}: {exc}")
            raise
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)

        return sha256

    def load(self, blob_hash: str) -> Optional[bytes]:
        """
        Retrieve data by its hash.

        Args:
            blob_hash: SHA256 hash of the blob

        Returns:
            bytes: The raw data, or None if not found
        """
        # Security: accept only the canonical content address.
        if not self._valid_address(blob_hash):
            logger.warning(f"[CAS] Invalid blob hash requested: {blob_hash}")
            return None

        directory_fd = -1
        try:
            directory_fd = self._open_directory()
            return self._read_existing(directory_fd, blob_hash, blob_hash)
        except FileNotFoundError:
            logger.warning(f"[CAS] Blob check failed: {blob_hash} not found")
            return None
        except (OSError, ValueError):
            logger.warning(f"[CAS] Blob integrity failed: {blob_hash}")
            return None
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

    def exists(self, blob_hash: str) -> bool:
        """Check if a blob exists."""
        return self.load(blob_hash) is not None
