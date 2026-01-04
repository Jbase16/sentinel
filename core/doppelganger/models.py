from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional
from enum import Enum
import time


class Role(str, Enum):
    ADMIN = "ADMIN"
    USER = "USER"
    GUEST = "GUEST"
    SERVICE = "SERVICE"


@dataclass(frozen=True)
class Credential:
    """
    Static authentication secrets.
    """
    username: str
    password: str
    role: Role = Role.USER

    def __repr__(self) -> str:
        return f"Credential(username='{self.username}', role='{self.role}', password='***')"


@dataclass
class Persona:
    """
    A live Identity session.
    Maintains the state of being "logged in".
    """
    id: str
    credential: Credential
    session_token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    # JWT metadata (optional but useful for refresh decisions)
    token_issued_at: Optional[int] = None
    token_expires_at: Optional[int] = None

    @property
    def is_authenticated(self) -> bool:
        return bool(self.session_token or self.cookies)

    @property
    def is_token_expired(self) -> bool:
        if not self.session_token:
            return True
        if self.token_expires_at is None:
            return False
        return int(time.time()) >= int(self.token_expires_at)

    def should_refresh(self, skew_seconds: int = 30) -> bool:
        """
        Refresh if token expires soon (or missing).
        """
        if not self.session_token:
            return True
        if self.token_expires_at is None:
            return False
        return int(time.time()) >= (int(self.token_expires_at) - int(skew_seconds))

    def get_auth_headers(self) -> Dict[str, str]:
        """
        Construct headers for outbound requests.
        """
        h = dict(self.headers) if self.headers else {}
        if self.session_token:
            h["Authorization"] = f"Bearer {self.session_token}"
        return h

    def get_cookies(self) -> Dict[str, str]:
        """
        Return cookies as a plain dict for httpx per-request injection.
        """
        return dict(self.cookies) if self.cookies else {}
