from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Optional

from ..context import WebContext
from ..contracts.models import PrincipalProfile, WebMission


class AuthProvider(ABC):
    """Base class for authentication flow providers.

    Each provider implements a specific auth strategy (form login, OAuth, etc.)
    and is responsible for establishing a valid session on the given WebContext.
    """

    @abstractmethod
    def authenticate(
        self,
        mission: WebMission,
        ctx: WebContext,
        profile: PrincipalProfile,
    ) -> AuthResult:
        """Execute the authentication flow.

        Must populate ctx with appropriate cookies, tokens, and/or headers.
        Returns an AuthResult describing what was established.

        Raises:
            AuthenticationError: If the login flow fails definitively.
        """
        ...


class AuthResult:
    """Outcome of an authentication attempt."""

    __slots__ = ("success", "signal", "fingerprint", "error")

    def __init__(
        self,
        success: bool,
        signal: str = "",
        fingerprint: str = "",
        error: Optional[str] = None,
    ):
        self.success = success
        self.signal = signal
        self.fingerprint = fingerprint
        self.error = error


class AuthenticationError(Exception):
    """Raised when an auth provider cannot establish a session."""
