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
from pathlib import Path
from typing import Optional

from core.base.config import SentinelConfig

logger = logging.getLogger(__name__)


class ContentAddressableStorage:
    """
    Immutable blob storage for raw evidence.
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig.from_env()
        # Storage root: ~/.sentinelforge/evidence/blobs
        self.blob_dir = self.config.storage.evidence_path / "blobs"
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        """Ensure the blob storage directory exists."""
        self.blob_dir.mkdir(parents=True, exist_ok=True)

    def store(self, data: bytes) -> str:
        """
        Store raw bytes and return their SHA256 hash.
        
        Args:
            data: Raw bytes to store (e.g. tool stdout)
            
        Returns:
            str: SHA256 hash of the data (the address)
        """
        # 1. Calculate Hash
        sha256 = hashlib.sha256(data).hexdigest()
        
        # 2. Determine Path
        blob_path = self.blob_dir / sha256
        
        # 3. Write (Idempotent: if exists, it's the same data)
        if not blob_path.exists():
            try:
                # atomic write pattern? slightly overkill for now, direct write is fine
                # for single-process. For multi-process, we trust OS file locking or
                # simply that overwriting identical bytes is harmless.
                blob_path.write_bytes(data)
                logger.debug(f"[CAS] Stored blob {sha256[:8]} ({len(data)} bytes)")
            except Exception as e:
                logger.error(f"[CAS] Failed to write blob {sha256}: {e}")
                raise
        else:
            logger.debug(f"[CAS] Blob {sha256[:8]} already exists (deduplicated)")
            
        return sha256

    def load(self, blob_hash: str) -> Optional[bytes]:
        """
        Retrieve data by its hash.
        
        Args:
            blob_hash: SHA256 hash of the blob
            
        Returns:
            bytes: The raw data, or None if not found
        """
        # Security: Prevent directory traversal
        if ".." in blob_hash or "/" in blob_hash or "\\" in blob_hash:
            logger.warning(f"[CAS] Invalid blob hash requested: {blob_hash}")
            return None
            
        blob_path = self.blob_dir / blob_hash
        
        if not blob_path.exists():
            logger.warning(f"[CAS] Blob check failed: {blob_hash} not found")
            return None
            
        return blob_path.read_bytes()

    def exists(self, blob_hash: str) -> bool:
        """Check if a blob exists."""
        return (self.blob_dir / blob_hash).exists()
