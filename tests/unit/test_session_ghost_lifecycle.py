"""Regression proof for ScanSession-owned Ghost shutdown."""

from unittest.mock import AsyncMock, Mock

import pytest

from core.base.session import ScanSession


@pytest.mark.asyncio
async def test_stop_ghost_awaits_interceptor_once_and_clears_handle():
    session = ScanSession.__new__(ScanSession)
    interceptor = Mock()
    interceptor.stop = AsyncMock()
    session.ghost = interceptor

    await session.stop_ghost()
    await session.stop_ghost()

    interceptor.stop.assert_awaited_once_with()
    assert session.ghost is None
