"""Fail-isolated shadow-mode integration for finalized HTTP exchanges."""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Mapping, Optional

from .graph import BehaviorGraph, GraphLimits, ObservationResult
from .normalize import normalize_exchange

logger = logging.getLogger(__name__)

SHADOW_ENV = "SENTINELFORGE_BEHAVIOR_SHADOW"
_TRUE = frozenset({"1", "true", "yes", "on"})


def shadow_enabled() -> bool:
    return os.environ.get(SHADOW_ENV, "").strip().lower() in _TRUE


class ShadowBehaviorRegistry:
    """Thread-safe collection of bounded passive graphs keyed by capture context."""

    def __init__(self, *, limits: Optional[GraphLimits] = None, max_contexts: int = 64):
        if not isinstance(max_contexts, int) or max_contexts <= 0:
            raise ValueError("max_contexts must be a positive integer")
        self.limits = limits or GraphLimits()
        self.max_contexts = max_contexts
        self._graphs: Dict[str, BehaviorGraph] = {}
        self._lock = threading.RLock()
        self.dropped_contexts = 0
        self.errors = 0

    def observe(
        self,
        context_id: str,
        record: Mapping[str, Any],
        *,
        world_id: str = "anonymous",
        source_id: Optional[str] = None,
    ) -> ObservationResult:
        context = str(context_id or "default")
        with self._lock:
            graph = self._graphs.get(context)
            if graph is None:
                if len(self._graphs) >= self.max_contexts:
                    self.dropped_contexts += 1
                    return ObservationResult(False, reason="context_limit")
                graph = BehaviorGraph(self.limits)
                self._graphs[context] = graph
            try:
                exchange = normalize_exchange(
                    record,
                    source_id=source_id,
                    world_id=world_id,
                )
                return graph.observe(exchange)
            except Exception as exc:
                self.errors += 1
                logger.debug(
                    "[behavior-shadow] observation rejected: %s",
                    type(exc).__name__,
                )
                return ObservationResult(False, reason="normalization_error")

    def snapshot(self, context_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            graph = self._graphs.get(str(context_id or "default"))
            if graph is None:
                return None
            snapshot = graph.snapshot()
            snapshot["registry_errors"] = self.errors
            snapshot["dropped_contexts"] = self.dropped_contexts
            return snapshot

    def context_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._graphs)


_registry: Optional[ShadowBehaviorRegistry] = None
_registry_lock = threading.Lock()


def get_shadow_registry() -> ShadowBehaviorRegistry:
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = ShadowBehaviorRegistry()
    return _registry


def observe_flow_step_if_enabled(flow_id: str, step: Any) -> Optional[ObservationResult]:
    """Observe a finalized Ghost FlowStep when shadow mode is explicitly enabled.

    This function is best-effort by design.  A shadow failure can never alter the
    capture result or raise into the existing Ghost flow path.
    """
    if not shadow_enabled():
        return None
    try:
        record = step.to_dict() if hasattr(step, "to_dict") else dict(step)
        persona = record.get("persona_at_capture")
        world_id = f"persona:{persona}" if persona else f"flow:{flow_id}"
        return get_shadow_registry().observe(
            context_id=f"ghost:{flow_id}",
            record=record,
            world_id=world_id,
            source_id=record.get("id"),
        )
    except Exception as exc:
        logger.debug(
            "[behavior-shadow] flow observation failed: %s",
            type(exc).__name__,
        )
        return None


def reset_shadow_registry_for_tests() -> None:
    global _registry
    with _registry_lock:
        _registry = None
