"""
core/net/http_factory.py
Centralised HTTP client factory for SentinelForge.

Every outbound httpx client in the codebase MUST be created through this
module so that TLS verification, timeouts, and redirect behaviour are
governed by a single configuration knob (``NetworkConfig``).

Usage
-----
    from core.net.http_factory import create_async_client, create_sync_client

    async with create_async_client() as client:
        resp = await client.get("https://example.com")

    with create_sync_client() as client:
        resp = client.get("https://example.com")

Redirect following is never delegated to the transport. Callers that need it
must use ``core.net.egress.EgressBroker`` so every hop is re-admitted.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


def _get_network_config():
    """Lazy import to avoid circular dependency at module load time."""
    from core.base.config import get_config
    return get_config().network


# ── Async client ────────────────────────────────────────────────────────────

def create_async_client(
    *,
    verify: Optional[bool] = None,
    timeout: Optional[httpx.Timeout] = None,
    follow_redirects: Optional[bool] = None,
    high_evasion: bool = False,
    **kwargs,
) -> httpx.AsyncClient:
    """Create an ``httpx.AsyncClient`` with platform-wide TLS defaults.

    Parameters
    ----------
    verify : bool | None
        Override TLS verification.  ``None`` = use ``NetworkConfig.verify``.
    timeout : httpx.Timeout | None
        Override timeout.  ``None`` = use ``NetworkConfig.timeout``.
    follow_redirects : bool | None
        Must be false/None. Redirects are handled by ``EgressBroker``.
    high_evasion : bool
        If True, injects the GhostGatewayTransport to inherit native macOS/WebKit TLS fingerprint
        and Cloudflare evasion capabilities.
    **kwargs
        Forwarded to ``httpx.AsyncClient()``.
    """
    cfg = _get_network_config()
    if follow_redirects:
        raise ValueError("transport redirect following is disabled; use EgressBroker")
    
    if high_evasion:
        from core.net.ghost_gateway import GhostGatewayTransport
        # The transport overrides redirects to ensure we can see 3xx codes in the scanner
        transport = GhostGatewayTransport()
        kwargs["transport"] = transport
        
    return httpx.AsyncClient(
        verify=cfg.verify if verify is None else verify,
        timeout=timeout if timeout is not None else cfg.timeout,
        follow_redirects=False,
        **kwargs,
    )


# ── Sync client ─────────────────────────────────────────────────────────────

def create_sync_client(
    *,
    verify: Optional[bool] = None,
    timeout: Optional[httpx.Timeout] = None,
    follow_redirects: Optional[bool] = None,
    **kwargs,
) -> httpx.Client:
    """Create an ``httpx.Client`` (synchronous) with platform-wide TLS defaults.

    Same parameter semantics as :func:`create_async_client`.
    """
    cfg = _get_network_config()
    if follow_redirects:
        raise ValueError("transport redirect following is disabled; use SyncEgressBroker")
    return httpx.Client(
        verify=cfg.verify if verify is None else verify,
        timeout=timeout if timeout is not None else cfg.timeout,
        follow_redirects=False,
        **kwargs,
    )
