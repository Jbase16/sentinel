"""Module reasoning: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/reasoning.py."""
# core/cortex/reasoning.py
#
# PURPOSE:
# Central Reasoning Hub for SentinelForge.
# Provides system-wide access to the CAL ReasoningSession.
# All subsystems (Ghost, Wraith, Mimic) access claims through this hub.
#

from typing import Dict, List, Any, Optional
from core.cortex.arbitration import ArbitrationEngine
from core.cortex.narrator import NarratorEngine
from core.cortex.events import get_event_bus
from core.scheduler.decisions import DecisionLedger
from core.scheduler.strategos import Strategos
from core.cal.engine import ReasoningSession
from core.cal.types import Claim, Evidence, Provenance, ValidationStatus

import logging

logger = logging.getLogger(__name__)

class ReasoningEngine:
    """
    Composition root for the reasoning stack.
    This wires Strategos + Cortex + Narrator + CAL together.
    
    THE COGNITIVE HUB:
    All subsystems access the central ReasoningSession through this engine.
    Claims from any component (Ghost, Wraith, Mimic, Strategy) flow here.
    """

    _instance = None

    def __init__(self):
        """Function __init__."""
        self.event_bus = get_event_bus()  # SINGLETON - never instantiate directly
        self.ledger = DecisionLedger()
        self.narrator = NarratorEngine(event_bus=self.event_bus)
        self.cortex = ArbitrationEngine()

        self.strategos = Strategos(
            event_bus=self.event_bus,
            narrator=self.narrator
        )
        
        # ═══════════════════════════════════════════════════════════════════
        # CAL INTEGRATION: Central Reasoning Session
        # ═══════════════════════════════════════════════════════════════════
        # This is the GLOBAL reasoning session for the entire Sentinel system.
        # All subsystems (Ghost, Wraith, Mimic) can:
        #   - Assert claims: reasoning_engine.assert_claim(...)
        #   - Add evidence: reasoning_engine.add_evidence(claim_id, evidence)
        #   - Query claims: reasoning_engine.get_validated_claims()
        #
        self.reasoning_session = ReasoningSession(
            session_id="global",
            topic="SentinelForge Cognitive State"
        )
        
        # Initialize Epistemic Recoil (Automated Falsification)
        from core.aegis.nexus.recoil import EpistemicRecoil
        self.recoil = EpistemicRecoil()
        self.recoil.start()
        
        logger.info("[CAL] ReasoningEngine initialized with global ReasoningSession")
        
    @classmethod
    def instance(cls) -> "ReasoningEngine":
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    # ═══════════════════════════════════════════════════════════════════════
    # CAL PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════
    
    def assert_claim(
        self,
        statement: str,
        source: str,
        evidence_content: Dict[str, Any],
        confidence: float = 0.5,
        metadata: Optional[Dict] = None
    ) -> Claim:
        """
        Assert a new claim from any subsystem.
        
        Args:
            statement: The claim text (e.g., "user_id is vulnerable to IDOR")
            source: The component making the claim (e.g., "Wraith", "Mimic")
            evidence_content: Supporting data for the claim
            confidence: Initial confidence (0.0-1.0)
            metadata: Optional additional context
            
        Returns:
            The created Claim object
        """
        evidence = Evidence(
            content=evidence_content,
            description=f"Evidence from {source}",
            provenance=Provenance(
                source=source,
                method="automated",
                run_id="global"
            ),
            confidence=confidence
        )
        
        claim = self.reasoning_session.assert_claim(
            statement=statement,
            evidence=evidence,
            metadata=metadata or {}
        )
        
        logger.debug(f"[CAL] Claim asserted by {source}: {statement} (conf: {confidence})")
        return claim
    
    def add_evidence(self, claim_id: str, evidence: Evidence, supporting: bool = True):
        """
        Add evidence to an existing claim.
        
        Args:
            claim_id: The ID of the claim to update
            evidence: The Evidence object
            supporting: True = supports claim, False = disputes claim
        """
        claim = self.reasoning_session.claims.get(claim_id)
        if not claim:
            logger.warning(f"[CAL] Cannot add evidence: Claim {claim_id} not found")
            return
            
        if supporting:
            claim.add_support(evidence)
        else:
            claim.add_dispute(evidence)
            
        # Trigger convergence check
        self.reasoning_session._check_convergence(claim)
        
    def get_validated_claims(self) -> List[Claim]:
        """Get all claims that have reached VALIDATED status."""
        return [
            c for c in self.reasoning_session.claims.values()
            if c.status == ValidationStatus.VALIDATED
        ]
    
    def get_claims_by_source(self, source: str) -> List[Claim]:
        """Get all claims from a specific source (e.g., 'Wraith', 'Mimic')."""
        result = []
        for claim in self.reasoning_session.claims.values():
            for evidence in claim.supported_by:
                if evidence.provenance.source == source:
                    result.append(claim)
                    break
        return result
    
    def cal_stats(self) -> Dict:
        """Get CAL statistics for monitoring."""
        claims = self.reasoning_session.claims.values()
        return {
            "total_claims": len(claims),
            "validated": sum(1 for c in claims if c.status == ValidationStatus.VALIDATED),
            "disputed": sum(1 for c in claims if c.status == ValidationStatus.DISPUTED),
            "pending": sum(1 for c in claims if c.status == ValidationStatus.PENDING),
            "rejected": sum(1 for c in claims if c.status == ValidationStatus.REJECTED),
        }
        
    def analyze(self) -> dict:
        """
        Return a summary of the reasoning state (Decision Ledger + CAL + Nexus).
        Used by /cortex/reasoning API endpoint and Report Engine.
        """
        from core.aegis.nexus.context import NexusContext
        
        ledger_stats = {}
        if self.strategos._decision_ledger:
            ledger_stats = self.strategos._decision_ledger.stats()
            
        # Get synthesized context from Nexus
        nexus_context = NexusContext.instance().analyze_context()
            
        return {
            "status": "ok",
            "scope": "global",
            "decision_ledger": ledger_stats,
            "cal": self.cal_stats(),
            "attack_paths": nexus_context.get("attack_paths", []),
            "recommended_phases": nexus_context.get("recommended_phases", [])
        }
        
    async def start_scan(self, 
        target: str, 
        available_tools: list[str], 
        mode: str, 
        dispatch_tool: callable, 
        log_fn: callable = None
    ):
        """
        Entry point used by API.
        """
        from core.scheduler.modes import ScanMode
        try:
            scan_mode = ScanMode(mode)
        except ValueError:
            scan_mode = ScanMode.STANDARD
            
        return await self.strategos.run_mission(
            target=target,
            available_tools=available_tools,
            mode=scan_mode,
            dispatch_tool=dispatch_tool,
            log_fn=log_fn
        )


def get_reasoning_engine() -> ReasoningEngine:
    """Get the global ReasoningEngine singleton."""
    return ReasoningEngine.instance()


# Optional singleton (matches API import)
reasoning_engine = ReasoningEngine()

