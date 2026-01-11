from __future__ import annotations

import logging
import uuid
from typing import Dict, List, Optional, Callable, Set

from core.cortex.events import EventBus, GraphEvent
from core.contracts.events import EventType
from core.contracts.budget import Budget
from core.reasoning.models import Hypothesis, Confidence

logger = logging.getLogger(__name__)

class ReasoningEngine:
    _instance: Optional["ReasoningEngine"] = None

    @classmethod
    def get(cls, bus: EventBus) -> "ReasoningEngine":
        if cls._instance is None:
            cls._instance = cls(bus=bus)
        return cls._instance

    @classmethod
    def reset_for_testing(cls):
        """Reset singleton state for deterministic tests."""
        cls._instance = None


    def __init__(self, bus: EventBus):
        self._bus = bus
        self._hypotheses: Dict[str, Dict[str, Hypothesis]] = {} # scan_id -> {hypothesis_id -> Hypothesis}
        
        # Subscriptions
        # We listen to Mimic events to form hypotheses
        self._bus.subscribe(self._on_mimic_route, event_types=[EventType.MIMIC_ROUTE_FOUND, EventType.MIMIC_HIDDEN_ROUTE_FOUND])
        self._bus.subscribe(self._on_mimic_secret, event_types=[EventType.MIMIC_SECRET_FOUND])
        # We also listen to Hypothesis Updates to check for threshold confirmation (internal loop)
        
    def start(self):
        logger.info("ReasoningEngine initialized (Probabilistic Logic active)")
        
    def stop(self):
        self._hypotheses.clear()

    def _get_store(self, scan_id: str) -> Dict[str, Hypothesis]:
        if scan_id not in self._hypotheses:
            self._hypotheses[scan_id] = {}
        return self._hypotheses[scan_id]

    # ------------------------------------------------------------------
    # EVENT HANDLERS (The "Thinking" Loop)
    # ------------------------------------------------------------------
    
    def _on_mimic_route(self, event: GraphEvent):
        # Strict isolation check
        scan_id = getattr(event, "scan_id", None) or (event.payload or {}).get("scan_id")
        if not scan_id:
            return

        payload = event.payload or {}
        route = payload.get("route")
        
        # RULE: Admin API Surface
        # If we see /admin or /internal, hypothesize an administrative surface exists
        if route and ("/admin" in route or "/internal" in route):
            self._propose_hypothesis(
                scan_id=scan_id,
                rule_id="RULE_ADMIN_SURFACE",
                summary=f"Possible administrative interface detected at {route}",
                confidence_delta=0.35, # Starting confidence
                source_id=payload.get("asset_id", "unknown"),
                reason=f"Mimic found explicit route '{route}'"
            )

    def _on_mimic_secret(self, event: GraphEvent):
        # Strict isolation check
        scan_id = getattr(event, "scan_id", None) or (event.payload or {}).get("scan_id")
        if not scan_id:
            return

        payload = event.payload or {}
        stype = payload.get("secret_type")
        
        # RULE: Leaked Credential
        if stype:
            self._propose_hypothesis(
                scan_id=scan_id,
                rule_id="RULE_LEAKED_CREDENTIAL",
                summary=f"High-confidence credential leak: {stype}",
                confidence_delta=0.70, # Strong starting confidence for secrets
                source_id=payload.get("asset_id", "unknown"),
                reason=f"Mimic Miner identified {stype} pattern"
            )

    # ------------------------------------------------------------------
    # CORE LOGIC
    # ------------------------------------------------------------------

    def _propose_hypothesis(self, scan_id: str, rule_id: str, summary: str, confidence_delta: float, source_id: str, reason: str):
        store = self._get_store(scan_id)
        
        # De-duplication key: (scan_id, rule_id, summary)
        # In a real system, we might have a robust clustering key.
        # For now, simplistic dedup to avoid hypothesis explosion.
        hyp_key = f"{rule_id}:{summary}" 
        
        existing_id = None
        for hid, h in store.items():
            if f"{h.rule_id}:{h.summary}" == hyp_key:
                existing_id = hid
                break
        
        if existing_id:
            # Update existing
            hyp = store[existing_id]
            if hyp.state != "active":
                return # Don't update terminal hypotheses
            
            # TODO: Check budget logic here if needed, but updates are cheap.
            hyp.add_evidence(source_id, 0.1, "Corroborating instance") # Smaller delta for subsequent
            self._emit_lifecycle_event(EventType.NEXUS_HYPOTHESIS_UPDATED, hyp)
        else:
            # Create new
            # Deterministic ID generation (Point 10)
            import hashlib
            hasher = hashlib.sha256()
            hasher.update(scan_id.encode('utf-8'))
            hasher.update(rule_id.encode('utf-8'))
            hasher.update(summary.encode('utf-8'))
            # In real world, would include sorted sources, but here source triggers creation
            hid = hasher.hexdigest()

            # Budget Check (Point 9)
            # In a real impl, we'd consume from a Budget object.
            # For now, we stub the check.
            # if not budget.can_afford(COST_HYPOTHESIS_CREATION): return

            hyp = Hypothesis(
                hypothesis_id=hid,
                scan_id=scan_id,
                rule_id=rule_id,
                summary=summary
            )
            hyp.add_evidence(source_id, confidence_delta, reason)
            store[hid] = hyp
            self._emit_lifecycle_event(EventType.NEXUS_HYPOTHESIS_FORMED, hyp)

    def _emit_lifecycle_event(self, event_type: EventType, hyp: Hypothesis):
        # Pure output - no side effects on graph
        # Strict typing for event_type (Point 3)
        self._bus.emit(
            GraphEvent(
                type=event_type,
                scan_id=hyp.scan_id,
                payload={
                    "scan_id": hyp.scan_id,
                    "hypothesis_id": hyp.hypothesis_id,
                    "confidence": float(hyp.confidence),
                    "summary": hyp.summary,
                    "explanation": " | ".join(hyp.explanation[-3:]), # Last 3 logs
                    "sources": list(hyp.sources),
                    "rule_id": hyp.rule_id,
                    "is_terminal": hyp.state in ("confirmed", "refuted")
                }
            )
        )
