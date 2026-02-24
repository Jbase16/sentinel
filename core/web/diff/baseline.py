from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional

from ..contracts.models import BaselineSignature


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_body(body: bytes) -> bytes:
    # Deterministic normalization hook: Agent can add removal of volatile tokens, timestamps, etc.
    # Keep it stable, bounded, and testable.
    return body.strip()


def _json_shape_hash(body: bytes) -> Optional[str]:
    try:
        obj = json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        return None
    # Deterministic "shape": keys-only traversal.
    def shape(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: shape(x[k]) for k in sorted(x.keys())}
        if isinstance(x, list):
            return [shape(x[0])] if x else []
        return type(x).__name__
    shaped = shape(obj)
    return _sha256_hex(json.dumps(shaped, sort_keys=True).encode("utf-8"))


@dataclass
class BaselineBuilder:
    def build(self, status: int, headers: dict[str, str], body: bytes, ttfb_ms: int, total_ms: int) -> BaselineSignature:
        raw_hash = _sha256_hex(body)
        norm = _normalize_body(body)
        norm_hash = _sha256_hex(norm)
        shape_hash = _json_shape_hash(norm)

        return BaselineSignature(
            status_code=status,
            body_hash=raw_hash,
            normalized_hash=norm_hash,
            dom_hash=None,
            json_shape_hash=shape_hash,
            ttfb_ms=ttfb_ms,
            total_ms=total_ms,
        )
