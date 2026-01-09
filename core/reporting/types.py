from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ReportArtifact:
    report_id: str
    created_at: str  # ISO8601
    target: str
    scope: Optional[str]
    format: str  # "json" or "markdown"
    content: str  # JSON string or Markdown text


@dataclass(frozen=True)
class PoCArtifact:
    finding_id: str
    title: str
    risk: str
    safe: bool
    commands: List[str]
    notes: List[str]
    created_at: str  # ISO8601


from datetime import datetime, timezone

# ...

def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
