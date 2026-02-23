"""
core/base/context.py
Engine-wide operational contexts.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional

from core.base.scope import ScopeRegistry
from core.base.execution_policy import ExecutionPolicy

@dataclass
class ScopeContext:
    """Created at scan start. Holds ScopeRegistry, ExecutionPolicy, execution mode, and identity headers."""
    registry: ScopeRegistry = field(default_factory=ScopeRegistry)
    policy: ExecutionPolicy = field(default_factory=ExecutionPolicy)
    mode: str = "NORMAL"
    identity_headers: Dict[str, str] = field(default_factory=dict)
    scan_id: Optional[str] = None
