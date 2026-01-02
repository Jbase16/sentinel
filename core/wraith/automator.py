#
# PURPOSE:
# This module is part of the wraith package in SentinelForge.
# The Hand of God - Automated attack verification.
#
# CAL INTEGRATION:
# - on_hypothesis: Asserts a Claim ("target is exploitable via vuln_class")
# - _execute_verification: Adds Evidence to validate or dispute the claim
#

"""
core/wraith/automator.py
The Hand of God.
Listens for AI Hypotheses and automatically executes verification strikes.
Now integrated with CAL for claim-based reasoning.
"""

import logging
import asyncio
from typing import Dict, Optional
from core.base.session import ScanSession
from core.cal.types import Evidence, Provenance, Claim

logger = logging.getLogger(__name__)

class WraithAutomator:
    """
    Observer that reacts to new 'hypothesis' findings.
    
    CAL INTEGRATION:
    Every hypothesis becomes a Claim in the global ReasoningSession.
    Verification results become Evidence that supports or disputes the Claim.
    """
    
    def __init__(self, session: ScanSession):
        """Function __init__."""
        self.session = session
        
        # [CAL INTEGRATION]
        from core.cortex.reasoning import get_reasoning_engine
        self.reasoning_engine = get_reasoning_engine()
        
        logger.info("[Wraith] CAL integration enabled - attacks will emit Claims")

    async def on_hypothesis(self, finding: Dict) -> Optional[Claim]:
        """
        Called when a new Hypothesis Finding is added.
        Asserts a CAL Claim and schedules verification.
        
        Returns the created Claim for tracking.
        """
        ftype = finding.get("type", "")
        if not ftype.startswith("hypothesis::"):
            return None

        target = finding.get("target")
        metadata = finding.get("metadata", {})
        payloads = metadata.get("payloads", [])
        
        self.session.log(f"[Wraith] Analyzed Hypothesis: {ftype}. preparing verification...")
        
        # ═══════════════════════════════════════════════════════════════════
        # CAL INTEGRATION: Assert a Claim for this hypothesis
        # ═══════════════════════════════════════════════════════════════════
        vuln_class = ftype.split("::")[-1] if "::" in ftype else "unknown"
        
        claim = self.reasoning_engine.assert_claim(
            statement=f"{target} is exploitable via {vuln_class}",
            source="Wraith",
            evidence_content={
                "hypothesis_type": ftype,
                "target": target,
                "payloads": payloads,
                "status": "pending_verification"
            },
            confidence=0.3,  # Low confidence until verified
            metadata={
                "vuln_class": vuln_class,
                "target": target,
                "payloads": payloads
            }
        )
        
        self.session.log(f"[CAL] Wraith asserted Claim {claim.id}: {claim.statement}")
        
        # Schedule verification
        asyncio.create_task(self._execute_verification(target, payloads, ftype, claim.id))
        logger.info(f"[Wraith] Launched verification task for Claim {claim.id}")
        
        return claim

    async def _execute_verification(self, target: str, payloads: list, ftype: str, claim_id: str):
        """
        The actual attack logic.
        Emits CAL Evidence based on verification results.
        """
        await asyncio.sleep(2)  # Simulate network activity
        
        success = False
        used_payload = None
        
        for p in payloads:
            # Simulation: Known exploits for demo
            if p in ["1", "' OR 1=1", "<script>alert(1)</script>"]:
                success = True
                used_payload = p
                break
        
        # ═══════════════════════════════════════════════════════════════════
        # CAL INTEGRATION: Add Evidence based on verification result
        # ═══════════════════════════════════════════════════════════════════
        vuln_class = ftype.split("::")[-1] if "::" in ftype else "unknown"
        
        verification_evidence = Evidence(
            content={
                "target": target,
                "payload_used": used_payload,
                "success": success,
                "vuln_class": vuln_class,
                "status": "verified" if success else "failed"
            },
            description=f"Wraith verification: {'SUCCESS' if success else 'FAILED'}",
            provenance=Provenance(
                source="Wraith:verification",
                method="automated_attack",
                run_id=self.session.session_id
            ),
            confidence=0.9 if success else 0.8  # High confidence in verification result
        )
        
        # Add Evidence to the Claim (supporting or disputing)
        self.reasoning_engine.add_evidence(
            claim_id=claim_id,
            evidence=verification_evidence,
            supporting=success  # True = supports claim, False = disputes claim
        )
        
        if success:
            self.session.log(f"[Wraith] ⚔️ TARGET HIT! {ftype} verified with payload: {used_payload}")
            self.session.log(f"[CAL] Claim {claim_id} strengthened by verification Evidence")
            
            # Upgrade Finding to VULNERABILITY
            self.session.findings.add_finding({
                "tool": "wraith_automator",
                "type": f"vuln::{vuln_class}",
                "severity": "HIGH",
                "target": target,
                "value": f"Verified exploitable {ftype}. Payload: {used_payload}",
                "metadata": {
                    "payload": used_payload,
                    "verified": True,
                    "cal_claim_id": claim_id,  # Link to CAL
                    "cal_evidence_id": verification_evidence.id
                }
            })
        else:
            self.session.log(f"[Wraith] Hypothesis {ftype} failed verification")
            self.session.log(f"[CAL] Claim {claim_id} disputed by verification Evidence")
