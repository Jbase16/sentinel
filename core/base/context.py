"""
core/base/context.py
Engine-wide operational contexts.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional

from core.base.scope import ScopeRegistry
from core.base.execution_policy import ExecutionPolicy as TransportExecutionPolicy

@dataclass
class ScopeContext:
    """Created at scan start. Holds ScopeRegistry, ExecutionPolicy, execution mode, and identity headers."""
    registry: ScopeRegistry = field(default_factory=ScopeRegistry)
    policy: TransportExecutionPolicy = field(default_factory=TransportExecutionPolicy)
    mode: str = "NORMAL"
    strict_scope: bool = False
    identity_headers: Dict[str, str] = field(default_factory=dict)
    scan_id: Optional[str] = None
    authorization_envelope_id: Optional[str] = None
    authorization_envelope_ref: Optional[str] = None
