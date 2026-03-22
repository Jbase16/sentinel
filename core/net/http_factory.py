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

Override any default per call-site when the scanner truly needs it
(e.g. ``follow_redirects=False`` for redirect-detection tests).
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
        Override redirect following.  ``None`` = use ``NetworkConfig.follow_redirects``.
    **kwargs
        Forwarded to ``httpx.AsyncClient()``.
    """
    cfg = _get_network_config()
    return httpx.AsyncClient(
        verify=cfg.verify if verify is None else verify,
        timeout=timeout if timeout is not None else cfg.timeout,
        follow_redirects=cfg.follow_redirects if follow_redirects is None else follow_redirects,
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
    return httpx.Client(
        verify=cfg.verify if verify is None else verify,
        timeout=timeout if timeout is not None else cfg.timeout,
        follow_redirects=cfg.follow_redirects if follow_redirects is None else follow_redirects,
        **kwargs,
    )
