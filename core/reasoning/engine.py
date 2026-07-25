"""
core/reasoning/engine.py

ReasoningEngine
---------------
High-level reasoning coordinator that consumes Cortex + Mimic signals
and produces hypotheses, insights, and escalations.

This engine is NON-CAUSAL:
- It must never block the EventBus
- All handlers are async
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Optional, Dict, Any, List

from core.contracts.events import EventType
from core.cortex.events import (
    EventBus,
    GraphEvent,
    get_event_bus,
    SubscriptionHandle,
)
from core.reasoning.models import Hypothesis, Confidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hypothesis generation rules
# ---------------------------------------------------------------------------

_HIDDEN_ROUTE_RULE = "RULE_HIDDEN_ENDPOINT_EXPOSURE"
_SECRET_LEAK_RULE = "RULE_CLIENT_SIDE_SECRET_LEAK"
_ADMIN_SURFACE_RULE = "RULE_ADMIN_SURFACE"
_API_PATTERN_RULE = "RULE_UNDOCUMENTED_API_PATTERN"

# Keywords that escalate confidence for hidden routes
_HIGH_VALUE_ROUTE_KEYWORDS = {
    "admin", "internal", "debug", "graphql", "private",
    "config", "settings", "management", "console", "dashboard",
}

# Secret types that warrant immediate escalation
_CRITICAL_SECRET_TYPES = {
    "private_key_pem", "aws_access_key_id", "stripe_live_key",
}


def _hypothesis_id(rule_id: str, scan_id: str, discriminator: str) -> str:
    """Stable, deterministic hypothesis ID."""
    raw = f"{rule_id}:{scan_id}:{discriminator}"
    return f"hyp-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


class ReasoningEngine:
    """
    Singleton reasoning engine.

    Consumes Mimic route/secret events and produces hypotheses about
    the target's attack surface, stored in-memory per scan_id.
    """

    _instance: Optional["ReasoningEngine"] = None

    def __init__(self, bus: EventBus):
        self._bus = bus
        self._subscriptions: List[SubscriptionHandle] = []
        self._started: bool = False
        # In-memory hypothesis store, keyed by scan_id -> hypothesis_id
        self._hypotheses: Dict[str, Dict[str, Hypothesis]] = {}

    # ------------------------------------------------------------------
    # Singleton access
    # ------------------------------------------------------------------

    @classmethod
    def get(cls, bus: Optional[EventBus] = None) -> "ReasoningEngine":
        if cls._instance is None:
            cls._instance = cls(bus=bus or get_event_bus())
        return cls._instance

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._started:
            return

        self._subscriptions.append(
            self._bus.subscribe_sync(
                self._on_mimic_route,
                [EventType.MIMIC_ROUTE_FOUND, EventType.MIMIC_HIDDEN_ROUTE_FOUND],
                name="reasoning.mimic_routes",
                critical=False,
            )
        )

        self._subscriptions.append(
            self._bus.subscribe_sync(
                self._on_mimic_secret,
                [EventType.MIMIC_SECRET_FOUND],
                name="reasoning.mimic_secrets",
                critical=False,
            )
        )

        self._started = True
        logger.info("[ReasoningEngine] Started and subscribed to EventBus")

    def shutdown(self) -> None:
        for sub in self._subscriptions:
            sub.unsubscribe()
        self._subscriptions.clear()
        self._hypotheses.clear()
        self._started = False
        logger.info("[ReasoningEngine] Shutdown complete")

    def stop(self) -> None:
        """Alias for shutdown()."""
        self.shutdown()

    @classmethod
    def reset_for_testing(cls) -> None:
        """Reset the singleton for testing. Only use in tests."""
        if cls._instance is not None:
            cls._instance.shutdown()
        cls._instance = None

    def get_hypotheses(self, scan_id: str) -> List[Hypothesis]:
        """Return all active hypotheses for a scan."""
        store = self._hypotheses.get(scan_id, {})
        return [h for h in store.values() if h.state == "active"]

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_mimic_route(self, event: GraphEvent) -> None:
        """Handle discovered routes (visible or hidden)."""
        scan_id = event.scan_id
        payload = event.payload or {}

        if not scan_id:
            return

        route = payload.get("route")
        confidence = payload.get("confidence", 50)
        is_hidden = event.type == EventType.MIMIC_HIDDEN_ROUTE_FOUND
        method = payload.get("method")

        if not isinstance(route, str):
            return

        store = self._hypotheses.setdefault(scan_id, {})
        route_lower = route.lower()

        if is_hidden:
            # Hidden route -> generate hypothesis about exposed admin surface
            rule_id = _HIDDEN_ROUTE_RULE
            hyp_id = _hypothesis_id(rule_id, scan_id, route)

            if hyp_id not in store:
                # Base confidence from discovery confidence
                base_conf = min(confidence / 100.0, 0.8)

                # Boost for high-value keywords
                for keyword in _HIGH_VALUE_ROUTE_KEYWORDS:
                    if keyword in route_lower:
                        base_conf = min(base_conf + 0.15, 0.95)
                        break

                hyp = Hypothesis(
                    hypothesis_id=hyp_id,
                    scan_id=scan_id,
                    rule_id=rule_id,
                    summary=f"Hidden endpoint '{route}' may expose admin/debug functionality",
                    confidence=Confidence(value=base_conf),
                )
                hyp.add_evidence(
                    source_id=f"mimic:route:{route}",
                    confidence_delta=0.0,  # Already set above
                    reason=f"Discovered hidden route via JS analysis (confidence={confidence})",
                )
                store[hyp_id] = hyp

                self._emit_hypothesis(scan_id, hyp, "formed")
            else:
                # Additional evidence strengthens existing hypothesis
                hyp = store[hyp_id]
                hyp.add_evidence(
                    source_id=f"mimic:route:{route}:{method or 'ANY'}",
                    confidence_delta=0.05,
                    reason=f"Additional method/evidence for hidden route",
                )
                self._emit_hypothesis(scan_id, hyp, "updated")

        else:
            # Visible route — check for admin/internal surface keywords
            if any(kw in route_lower for kw in _HIGH_VALUE_ROUTE_KEYWORDS):
                rule_id = _ADMIN_SURFACE_RULE
                hyp_id = _hypothesis_id(rule_id, scan_id, route)

                if hyp_id not in store:
                    base_conf = min(confidence / 100.0, 0.7)
                    hyp = Hypothesis(
                        hypothesis_id=hyp_id,
                        scan_id=scan_id,
                        rule_id=rule_id,
                        summary=f"Possible administrative surface '{route}' found in client JS",
                        confidence=Confidence(value=base_conf),
                    )
                    hyp.add_evidence(
                        source_id=f"mimic:route:{route}",
                        confidence_delta=0.0,
                        reason=f"Admin/internal route extracted from JS bundle (confidence={confidence})",
                    )
                    store[hyp_id] = hyp
                    self._emit_hypothesis(scan_id, hyp, "formed")

            # Also check for undocumented API patterns
            elif any(seg in route_lower for seg in ("/api/", "/v1/", "/v2/", "/graphql")):
                rule_id = _API_PATTERN_RULE
                hyp_id = _hypothesis_id(rule_id, scan_id, route)

                if hyp_id not in store:
                    hyp = Hypothesis(
                        hypothesis_id=hyp_id,
                        scan_id=scan_id,
                        rule_id=rule_id,
                        summary=f"Undocumented API endpoint '{route}' found in client JS",
                        confidence=Confidence(value=min(confidence / 100.0, 0.6)),
                    )
                    hyp.add_evidence(
                        source_id=f"mimic:route:{route}",
                        confidence_delta=0.0,
                        reason=f"API route extracted from JS bundle (confidence={confidence})",
                    )
                    store[hyp_id] = hyp
                    self._emit_hypothesis(scan_id, hyp, "formed")

        logger.info(
            "[ReasoningEngine] Route processed",
            extra={
                "scan_id": scan_id,
                "route": route,
                "is_hidden": is_hidden,
                "hypotheses_count": len(store),
            },
        )

    def _on_mimic_secret(self, event: GraphEvent) -> None:
        """Handle discovered secrets — always generate a hypothesis."""
        scan_id = event.scan_id
        payload = event.payload or {}

        if not scan_id:
            return

        secret_type = payload.get("secret_type", "unknown")
        confidence = payload.get("confidence", 50)
        redacted = payload.get("redacted_preview", "***")

        store = self._hypotheses.setdefault(scan_id, {})

        rule_id = _SECRET_LEAK_RULE
        hyp_id = _hypothesis_id(rule_id, scan_id, f"{secret_type}:{redacted}")

        if hyp_id not in store:
            # Critical secrets get higher base confidence
            base_conf = min(confidence / 100.0, 0.85)
            if secret_type in _CRITICAL_SECRET_TYPES:
                base_conf = min(base_conf + 0.1, 0.95)

            hyp = Hypothesis(
                hypothesis_id=hyp_id,
                scan_id=scan_id,
                rule_id=rule_id,
                summary=f"Client-side secret leak: {secret_type} ({redacted})",
                confidence=Confidence(value=base_conf),
            )
            hyp.add_evidence(
                source_id=f"mimic:secret:{secret_type}:{redacted}",
                confidence_delta=0.0,
                reason=f"Secret of type '{secret_type}' found in JS bundle",
            )
            store[hyp_id] = hyp
            self._emit_hypothesis(scan_id, hyp, "formed")
        else:
            hyp = store[hyp_id]
            hyp.add_evidence(
                source_id=f"mimic:secret:{secret_type}:{redacted}:dup",
                confidence_delta=0.05,
                reason="Same secret found in additional asset",
            )
            self._emit_hypothesis(scan_id, hyp, "updated")

        logger.warning(
            "[ReasoningEngine] Secret hypothesis generated",
            extra={
                "scan_id": scan_id,
                "secret_type": secret_type,
                "confidence": float(hyp.confidence),
            },
        )

    # ------------------------------------------------------------------
    # Emission helpers
    # ------------------------------------------------------------------

    def _emit_hypothesis(
        self, scan_id: str, hyp: Hypothesis, action: str
    ) -> None:
        """Emit a hypothesis event to the EventBus."""
        event_type_map = {
            "formed": EventType.NEXUS_HYPOTHESIS_FORMED,
            "updated": EventType.NEXUS_HYPOTHESIS_UPDATED,
            "confirmed": EventType.NEXUS_HYPOTHESIS_CONFIRMED,
            "refuted": EventType.NEXUS_HYPOTHESIS_REFUTED,
        }
        event_type = event_type_map.get(action, EventType.NEXUS_HYPOTHESIS_FORMED)

        self._bus.emit(
            GraphEvent(
                type=event_type,
                scan_id=scan_id,
                payload={
                    "scan_id": scan_id,
                    "hypothesis_id": hyp.hypothesis_id,
                    "confidence": float(hyp.confidence),
                    "summary": hyp.summary,
                    "explanation": "; ".join(hyp.explanation[-3:]),  # Last 3 entries
                    "sources": list(hyp.sources),
                    "rule_id": hyp.rule_id,
                },
            )
        )
