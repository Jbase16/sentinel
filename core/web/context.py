from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .contracts.ids import PrincipalId
import httpx

from core.net.http_factory import create_sync_client


@dataclass
class WebContext:
    """
    Stateful per-principal session container.
    No network I/O here; it is passed into transport-executing components.
    """
    principal_id: PrincipalId
    cookie_jar: Dict[str, str] = field(default_factory=dict)
    default_headers: Dict[str, str] = field(default_factory=dict)
    csrf_tokens: Dict[str, str] = field(default_factory=dict)
    auth_tokens: Dict[str, str] = field(default_factory=dict)
    request_counter: int = 0
    client: httpx.Client = field(default_factory=create_sync_client)
    # Optional ScopeEnforcer — when set, auth flows validate URLs before requests.
    # Typed as Any to avoid circular imports; expected type is core.scope.enforcer.ScopeEnforcer.
    scope_enforcer: Any = None

    def bump_request_counter(self) -> int:
        self.request_counter += 1
        return self.request_counter
