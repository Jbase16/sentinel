"""
core/base/execution_policy.py
Data models governing execution limits before execution.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional

@dataclass
class ExecutionPolicy:
    """Transport limits. Defaults are passive and fail closed."""

    allow_methods: List[str] = field(default_factory=lambda: ["GET", "HEAD", "OPTIONS"])
    allow_payload_size: int = 256 * 1024
    disallow_destructive_patterns: bool = True
    require_headers: Dict[str, str] = field(default_factory=dict)
    max_rps_per_host: int = 5
    allowed_tools: Optional[Set[str]] = None
    banned_tools: Optional[Set[str]] = None
    allow_authentication: bool = False

    @classmethod
    def for_scan_mode(cls, mode: str) -> "ExecutionPolicy":
        """Build explicit transport bounds from the sealed scan mode."""

        normalized = str(mode or "").strip().lower()
        if normalized == "owned_lab":
            return cls(
                allow_methods=[
                    "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH",
                ],
                allow_payload_size=10 * 1024 * 1024,
                max_rps_per_host=50,
                allow_authentication=True,
            )
        if normalized in {"bug_bounty", "bounty"}:
            return cls(
                allow_methods=["GET", "HEAD", "POST", "PUT", "OPTIONS", "PATCH"],
                allow_payload_size=1024 * 1024,
                max_rps_per_host=5,
                allow_authentication=True,
            )
        return cls()
