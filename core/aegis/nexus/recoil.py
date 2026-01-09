from __future__ import annotations

import logging
from typing import Dict, Any

from core.cortex.events import get_event_bus, GraphEventType, GraphEvent
from core.contracts.events import EventType
from core.cortex.reasoning import get_reasoning_engine
from core.cal.types import Evidence, Provenance

logger = logging.getLogger(__name__)

class EpistemicRecoil:
    """
    Automated Falsification Engine.
    
    Rule: "If a Hypothesis is Refuted, the Truth (Findings) must be disputed."
    
    Listens for: NEXUS_HYPOTHESIS_REFUTED
    Action: Files CAL Disputes against constituent findings.
    """
    
    def __init__(self):
        self.bus = get_event_bus()
        self._subscription_id = None
        
    def start(self):
        """Start listening for refutations."""
        self._subscription_id = self.bus.subscribe(self._handle_event)
        logger.info("[EpistemicRecoil] Armed and listening for hypothesis refutations.")

    def stop(self):
        """Stop listening."""
        if self._subscription_id:
            self.bus.unsubscribe(self._subscription_id)

    async def _handle_event(self, event: GraphEvent):
        """
        Process bus events.
        """
        if event.type != EventType.NEXUS_HYPOTHESIS_REFUTED:
            return

        payload = event.payload
        hypothesis_id = payload.get("hypothesis_id")
        reason = payload.get("reason", "Hypothesis validation failed")
        
        # We need to know WHICH findings to dispute.
        # Ideally the event payload has them, or we look them up in Nexus state.
        # For this implementation, we expect 'constituent_finding_ids' in the refutation payload
        # or we would need to query Nexus.
        # Let's assume the emitter includes them for statelessness.
        finding_ids = payload.get("constituent_finding_ids", [])
        
        if not finding_ids:
            logger.warning(f"[Recoil] Refutation for {hypothesis_id} received but no finding IDs attached.")
            return

        logger.info(f"[Recoil] TRIGGERED: Disputing {len(finding_ids)} findings due to hypothesis failure.")

        for finding_id in finding_ids:
            self._file_dispute(finding_id, hypothesis_id, reason)

    def _file_dispute(self, finding_id: str, hypothesis_id: str, reason: str):
        """
        File a formal dispute in the CAL Reasoning Engine.
        """
        # Construct falsifying evidence
        evidence = Evidence(
            content={
                "hypothesis_id": hypothesis_id,
                "refutation_reason": reason,
                "type": "epistemic_recoil"
            },
            description=f"Automated Recoil: Hypothesis {hypothesis_id[:8]}... was refuted during validation.",
            provenance=Provenance(
                source="Nexus.EpistemicRecoil",
                method="falsification_loop",
                run_id="continuous"
            ),
            confidence=0.95 # High confidence in the failure
        )
        
        # Submit dispute to CAL
        # supporting=False means we are ATTACKING the claim
        reasoning = get_reasoning_engine()
        reasoning.add_evidence(
            claim_id=finding_id,
            evidence=evidence,
            supporting=False
        )
        logger.info(f"[Recoil] Filed dispute against Finding {finding_id}")
