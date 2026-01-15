# core/cortex/subscriptions.py

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable, Optional

from core.cortex.events import EventBus, GraphEvent


@dataclass
class SubscriptionHandle:
    """
    Normalized subscription handle with a guaranteed unsubscribe() method.
    """
    _raw: Any

    def unsubscribe(self) -> None:
        if not self._raw:
            return
        fn = getattr(self._raw, "unsubscribe", None)
        if callable(fn):
            fn()


def subscribe_safe(
    bus: EventBus,
    handler: Callable[[GraphEvent], Awaitable[None]],
    *,
    event_types: Optional[Iterable[Any]] = None,
    name: str = "subscriber",
    critical: bool = False,
) -> SubscriptionHandle:
    """
    Canonical subscription adapter for SentinelForge.

    This is the ONLY function that should ever touch EventBus.subscribe*
    directly. Everything else goes through this.

    Preference order:
      1. subscribe_async(handler, event_types=..., name=..., critical=...)
      2. subscribe_async(handler, event_types)
      3. subscribe_async(handler)
      4. Legacy subscribe(...) with multiple safe fallbacks
    """

    # ------------------------------------------------------------------
    # Modern API: subscribe_async
    # ------------------------------------------------------------------
    sub_async = getattr(bus, "subscribe_async", None)
    if callable(sub_async):
        # Best-case: keyword-supporting async API
        try:
            raw = sub_async(
                handler,
                event_types=event_types,
                name=name,
                critical=critical,
            )
            return SubscriptionHandle(raw)
        except TypeError:
            pass

        # Positional fallbacks
        try:
            raw = sub_async(handler, event_types)
            return SubscriptionHandle(raw)
        except TypeError:
            pass

        raw = sub_async(handler)
        return SubscriptionHandle(raw)

    # ------------------------------------------------------------------
    # Legacy API: subscribe
    # ------------------------------------------------------------------
    sub = getattr(bus, "subscribe", None)
    if not callable(sub):
        raise RuntimeError(
            "EventBus has neither subscribe_async() nor subscribe()"
        )

    etypes = None if event_types is None else list(event_types)

    # Try to understand the signature (best-effort)
    try:
        sig = inspect.signature(sub)
        params = list(sig.parameters.values())
        if params and params[0].name == "self":
            params = params[1:]
        param_names = [p.name for p in params]
    except Exception:
        param_names = []

    attempts = []

    # Common legacy shapes
    attempts.append(lambda: sub(handler, etypes))
    attempts.append(lambda: sub(handler, etypes or None))
    attempts.append(lambda: sub(handler))
    attempts.append(lambda: sub(etypes, handler))
    attempts.append(lambda: sub(handler, event_types=etypes))

    if etypes:
        for et in etypes:
            attempts.append(lambda et=et: sub(et, handler))

    last_error: Optional[BaseException] = None
    for attempt in attempts:
        try:
            raw = attempt()
            return SubscriptionHandle(raw)
        except TypeError as e:
            last_error = e
            continue

    raise RuntimeError(
        f"Unable to subscribe using EventBus.subscribe(); "
        f"signature={param_names}, last_error={last_error}"
    )
