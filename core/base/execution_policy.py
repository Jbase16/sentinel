"""
core/base/execution_policy.py
Data models governing execution limits before execution.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional

@dataclass
class ExecutionPolicy:
    """Authoritative execution policy rules."""
    allow_methods: List[str] = field(default_factory=lambda: ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"])
    allow_payload_size: int = 10 * 1024 * 1024  # 10MB
    disallow_destructive_patterns: bool = True
    require_headers: Dict[str, str] = field(default_factory=dict)
    max_rps_per_host: int = 50
    allowed_tools: Optional[Set[str]] = None
    banned_tools: Optional[Set[str]] = None
    allow_authentication: bool = True
