"""Module engine: inline documentation for /Users/jason/Developer/sentinelforge/core/cal/engine.py."""
#
# PURPOSE:
# The runtime kernel of the Argumentation Engine.
#
# LOGIC:
# - ReasoningSession: A container for a debate (e.g., "Scan of Impact on Host X").
# - Claim Graph: Assets are nodes, Claims are edges.
# - Debate Loop:
#   1. New Evidence arrives.
#   2. Rules trigger (Policy).
#   3. Claims are Updated (Confidence adjustment).
#   4. Decisions are emitted (if threshold reached).
#

import logging
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field

from core.cal.types import Claim, Evidence, ValidationStatus, Provenance
from core.cortex.events import get_event_bus, GraphEventType, GraphEvent

logger = logging.getLogger(__name__)

class ReasoningSession:
    """
    State container for an ongoing argumentation session.
    Equivalent to a "Court Case" - holds all locally relevant Claims and Evidence.
    """
    def __init__(self, session_id: str, topic: str):
        self.session_id = session_id
        self.topic = topic
        self.claims: Dict[str, Claim] = {}
        self.evidence: Dict[str, Evidence] = {}
        self.event_bus = get_event_bus()
    
    def assert_claim(self, statement: str, evidence: Evidence, metadata: Dict = None) -> Claim:
        """
        An agent makes a NEW assertion about the world.
        """
        # Deduplication check (simplistic for now)
        for c in self.claims.values():
            if c.statement == statement:
                logger.info(f"[CAL] Supporting existing claim: {statement}")
                c.add_support(evidence)
                self._check_convergence(c)
                return c

        new_claim = Claim(statement=statement, metadata=metadata or {})
        new_claim.add_support(evidence)
        self.claims[new_claim.id] = new_claim
        
        logger.info(f"[CAL] New Claim Asserted: {statement}")
        self._emit_event(GraphEventType.DECISION_MADE, {
            "intent": "assert_claim",
            "claim_id": new_claim.id,
            "statement": statement,
            "status": new_claim.status
        })
        return new_claim

    def dispute_claim(self, claim_id: str, evidence: Evidence, reason: str):
        """
        An agent challenges an existing assertion.
        """
        claim = self.claims.get(claim_id)
        if not claim:
            logger.warning(f"[CAL] Attempted to dispute unknown claim {claim_id}")
            return

        logger.info(f"[CAL] Disputing Claim {claim_id}: {reason}")
        claim.add_dispute(evidence)
        self._check_convergence(claim)

    def _check_convergence(self, claim: Claim):
        """
        The "Judge" logic. Decides if a Claim has settled into a final state.
        """
        prev_status = claim.status
        
        # Simple threshold logic (Placeholders for complex policy later)
        if claim.confidence >= 0.9:
            claim.status = ValidationStatus.VALIDATED
        elif claim.confidence <= 0.1:
            claim.status = ValidationStatus.REJECTED
        elif len(claim.disputed_by) > 0:
            claim.status = ValidationStatus.DISPUTED
            
        if claim.status != prev_status:
            logger.info(f"[CAL] Claim {claim.id} moved to {claim.status}")
            self._emit_event(GraphEventType.DECISION_MADE, {
                "intent": "update_claim_status",
                "claim_id": claim.id,
                "old_status": prev_status,
                "new_status": claim.status
            })

    def _emit_event(self, event_type: str, payload: Dict):
        """Helper to link CAL logic to the global Event Bus."""
        payload["session_id"] = self.session_id
        self.event_bus.emit(GraphEvent(type=event_type, payload=payload))

    def stats(self) -> Dict:
        return {
            "total_claims": len(self.claims),
            "validated": sum(1 for c in self.claims.values() if c.status == ValidationStatus.VALIDATED),
            "disputed": sum(1 for c in self.claims.values() if c.status == ValidationStatus.DISPUTED),
        }
