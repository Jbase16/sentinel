from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from .contracts.ids import PrincipalId
import httpx


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
    client: httpx.Client = field(default_factory=lambda: httpx.Client(verify=False, follow_redirects=True))

    def bump_request_counter(self) -> int:
        self.request_counter += 1
        return self.request_counter
