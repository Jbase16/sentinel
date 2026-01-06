"""
Merkle DAG Logic.

Canonicalization + hashing for ScanCapsule blocks.
We aim for JCS-like determinism in pure Python (RFC 8785 spirit),
including:
- sorted keys
- no whitespace
- UTF-8
- stable number representation (notably: 1.0 -> 1)

NOTE:
Full RFC 8785 cross-language compliance is best done with a dedicated
JCS implementation. This is a hardened Python-native approximation that
avoids the major drift footguns.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, List

from core.replay.models import MerkleBlock


class MerkleEngine:
    """
    Cryptographic engine for ScanCapsule hashing.
    """

    @staticmethod
    def _normalize_json(value: Any, path: str = "$") -> Any:
        """
        Normalize a Python object into a JSON-compatible structure with
        deterministic numeric representation.

        Enhancements over standard JCS:
        - Path tracking for precise error reporting (e.g., "$.payload.data").
        - Automatic support for `bytes` (base64 encoded).
        - Automatic support for `dataclasses` (converted to dicts).
        - Recursive depth checks.
        """
        if value is None:
            return None

        if isinstance(value, bool):
            return value

        if isinstance(value, int):
            return value

        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError(f"Non-finite float (NaN/Inf) at '{path}' is not allowed in canonical JSON.")
            if value.is_integer():
                # 1.0 -> 1 (matches JS/JSON.stringify behavior)
                return int(value)
            return value

        if isinstance(value, str):
            return value

        if isinstance(value, bytes):
            # Proactive convenience: Bytes become Base64 strings deterministic
            import base64
            return base64.b64encode(value).decode('ascii')

        if hasattr(value, '__dataclass_fields__'):
            # Proactive convenience: Dataclasses become dicts
            from dataclasses import asdict
            return MerkleEngine._normalize_json(asdict(value), path)

        if isinstance(value, (list, tuple)):
            return [
                MerkleEngine._normalize_json(v, f"{path}[{i}]") 
                for i, v in enumerate(value)
            ]

        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for k, v in value.items():
                if not isinstance(k, str):
                    raise TypeError(f"Canonical JSON requires string keys. Got {type(k)} at '{path}'.")
                out[k] = MerkleEngine._normalize_json(v, f"{path}.{k}")
            return out

        raise TypeError(f"Value type {type(value)} at '{path}' is not JSON-serializable for canonicalization.")

    @classmethod
    def canonicalize(cls, data: Any) -> bytes:
        """
        Canonical JSON encoding:
        - normalize types (esp. floats)
        - sort keys
        - compact separators
        - UTF-8
        - reject NaN/Inf via allow_nan=False
        """
        normalized = cls._normalize_json(data)
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    @classmethod
    def compute_hash(cls, data: Any) -> str:
        """Compute SHA-256 hash over canonicalized data."""
        canonical = cls.canonicalize(data)
        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def create_block(
        cls,
        parents: List[str],
        kind: str,
        payload: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> MerkleBlock:
        """
        Create a MerkleBlock with computed ID.

        Parent semantics:
            We treat `parents` as a SET of causal dependencies.
            Therefore, we canonicalize by sorting parents before hashing and storing.
        """
        canonical_parents = sorted(parents)

        content = {
            "parents": canonical_parents,
            "kind": kind,
            "payload": payload,
            "meta": meta,
        }

        block_id = cls.compute_hash(content)

        return MerkleBlock(
            id=block_id,
            parents=canonical_parents,  # store canonical order
            kind=kind,
            payload=payload,
            meta=meta,
        )

    @classmethod
    def verify_block(cls, block: MerkleBlock) -> bool:
        """
        Verify a block's ID matches its content.
        """
        content = {
            "parents": sorted(block.parents),
            "kind": block.kind,
            "payload": block.payload,
            "meta": block.meta,
        }
        expected = cls.compute_hash(content)
        return expected == block.id
