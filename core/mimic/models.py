from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, List


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Asset:
    asset_id: str
    url: str
    content_type: Optional[str]
    size_bytes: int
    sha256: str
    content: bytes
    discovered_from: Optional[str] = None


@dataclass(frozen=True)
class Route:
    route: str
    method: Optional[str] = None
    confidence: int = 50
    hidden: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Secret:
    secret_type: str
    confidence: int
    redacted_preview: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MimicSummary:
    assets_analyzed: int = 0
    routes_found: int = 0
    hidden_routes_found: int = 0
    secrets_found: int = 0
    notes: List[str] = field(default_factory=list)
