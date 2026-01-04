"""
core/doppelganger/models.py

Purpose:
    Defines the atoms of Identity: Credentials and Personas.

Magnum Opus Standards:
    - Security: Credentials should ideally be treated with care (redacted in logs).
    - Immutability: Personas are state containers, but Credentials are static.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional
from enum import Enum

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
    
    def __repr__(self):
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
    
    @property
    def is_authenticated(self) -> bool:
        """True if we hold a session token or cookies."""
        return bool(self.session_token or self.cookies)
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Construct headers for outbound requests.
        Merges static headers with dynamic auth tokens.
        """
        h = self.headers.copy()
        if self.session_token:
            h["Authorization"] = f"Bearer {self.session_token}"
        
        # Cookie string construction if needed
        # (Usually handled by httpx cookie jar, but exposed here if manual injection needed)
        
        return h
