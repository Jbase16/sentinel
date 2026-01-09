from __future__ import annotations

import logging
import hashlib
import json
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

from core.data.findings_store import findings_store
from core.epistemic.ledger import EvidenceLedger, Finding
from core.cortex.events import get_event_bus, GraphEventType, GraphEvent
from core.contracts.events import EventType

logger = logging.getLogger(__name__)

@dataclass
class NexusInsight:
    """A synthesized insight derived from raw data."""
    title: str
    description: str
    severity: str
    related_findings: List[str]  # IDs of related findings

class NexusContext:
    """
    The Sense-Making Core of Sentinel.
    
    Responsibilities:
    1. Ingest findings from the Epistemic Ledger.
    2. Contextualize them against the Goal (Target).
    3. Synthesize 'Insights' (Attack Chains, Strategic Risks).
    4. Emit 'Hypothesis' events for auditable reasoning.
    5. Provide the narrative backbone for Reporting.
    """
    
    _instance = None
    
    @classmethod
    def instance(cls) -> NexusContext:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.ledger = EvidenceLedger()
        self.bus = get_event_bus()
        self._emitted_hypotheses = set()
        self._active_hypotheses = {} # Map id -> {finding_ids}
        self.bus.subscribe(self._handle_event)
        
    async def _handle_event(self, event: GraphEvent):
        """
        Listen for tool completions to drive falsification.
        Also listen for Finding invalidation to prevent epistemic drift.
        """
        if event.type == EventType.TOOL_COMPLETED:
            # Check if this tool run was validating a hypothesis
            # We assume metadata/payload carries this context
            pass
        
        elif event.type in (EventType.FINDING_INVALIDATED, EventType.FINDING_SUPPRESSED):
            finding_id = event.payload.get("finding_id")
            if not finding_id:
                return

            # Epistemic Hygiene: Remove hypotheses that depend on this dead finding
            to_remove = []
            for hyp_id, fids in self._active_hypotheses.items():
                if finding_id in fids:
                    to_remove.append(hyp_id)
            
            if to_remove:
                logger.info(f"[Nexus] Epistemic Hygiene: Removing {len(to_remove)} hypotheses due to invalidation of finding {finding_id}")
                for hyp_id in to_remove:
                    del self._active_hypotheses[hyp_id]
                    # Optionally emit NEXUS_HYPOTHESIS_REFUTED (implicit refutation by dependency death)


    def refute_hypothesis(self, hypothesis_id: str, reason: str):
        """
        Public API to report a hypothesis failure.
        This triggers the Epistemic Recoil loop.
        """
        # Retrieve finding IDs from memory or re-calculate
        # For statelessness, we might need them passed in, or we store them in _active_hypotheses
        finding_ids = self._active_hypotheses.get(hypothesis_id, [])
        
        if not finding_ids:
            logger.warning(f"[Nexus] Cannot refute unknown/expired hypothesis {hypothesis_id}")
            return
            
        logger.info(f"[Nexus] Refuting Hypothesis {hypothesis_id}: {reason}")
        
        self.bus.emit(GraphEvent(
            type=EventType.NEXUS_HYPOTHESIS_REFUTED,
            payload={
                "hypothesis_id": hypothesis_id,
                "reason": reason,
                "constituent_finding_ids": finding_ids
            }
        ))
        
    def _generate_hypothesis_id(self, finding_ids: List[str], rule_id: str, rule_version: str) -> str:
        """
        Generate deterministic hash for a hypothesis.
        Hash(canonical_json({finding_ids_sorted, rule_id, rule_version}))
        """
        payload = {
            "finding_ids": sorted(finding_ids),
            "rule_id": rule_id,
            "rule_version": rule_version
        }
        canonical = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def synthesize_attack_paths(self) -> List[List[str]]:
        """
        Analyze current findings to construct probable attack paths.
        Emits NEXUS_HYPOTHESIS_FORMED events for new discoveries.
        Returns a list of paths for immediate consumption.
        """
        findings = findings_store.get_all()
        paths = []
        
        open_ports = [f for f in findings if "port" in f.get("type", "").lower()]
        web_vulns = [f for f in findings if "xss" in f.get("type", "").lower() or "sql" in f.get("type", "").lower()]
        criticals = [f for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]]
        
        # Rule 1: Web Exposure -> Web Vuln
        RULE_ID = "rule_web_exposure_chain"
        RULE_VERSION = "1.0"
        
        for port in open_ports:
            if "80" in str(port.get("value", "")) or "443" in str(port.get("value", "")):
                for vuln in web_vulns:
                    path_desc = [
                        f"External Exposure ({port.get('value')})",
                        f"Web Application Attack Surface",
                        f"Vulnerability Exploitation ({vuln.get('type')})"
                    ]
                    paths.append(path_desc)
                    
                    # Emit Hypothesis
                    finding_ids = [port.get("id", "unknown"), vuln.get("id", "unknown")]
                    # Filter out unknowns if IDs aren't present (e.g. from heuristic store)
                    finding_ids = [fid for fid in finding_ids if fid != "unknown"]
                    
                    if finding_ids:
                        hyp_id = self._generate_hypothesis_id(finding_ids, RULE_ID, RULE_VERSION)
                        
                        if hyp_id not in self._emitted_hypotheses:
                            self.bus.emit(GraphEvent(
                                type=EventType.NEXUS_HYPOTHESIS_FORMED,
                                payload={
                                    "hypothesis_id": hyp_id,
                                    "constituent_finding_ids": finding_ids,
                                    "rule_id": RULE_ID,
                                    "rule_version": RULE_VERSION,
                                    "confidence": 0.8,
                                    "explanation": f"Open web port combined with {vuln.get('type')} suggests exploitable surface."
                                }
                            ))
                            self._emitted_hypotheses.add(hyp_id)
                            self._active_hypotheses[hyp_id] = finding_ids
        
        # Rule 2: High Severity Isolated
        RULE_ID_CRIT = "rule_critical_isolated"
        for crit in criticals:
            paths.append([
                "Critical Exposure",
                f"{crit.get('type')} ({crit.get('value')})",
                "Potential System Compromise"
            ])
            
            finding_ids = [crit.get("id")]
            if all(finding_ids):
                hyp_id = self._generate_hypothesis_id(finding_ids, RULE_ID_CRIT, RULE_VERSION)
                if hyp_id not in self._emitted_hypotheses:
                     self.bus.emit(GraphEvent(
                        type=EventType.NEXUS_HYPOTHESIS_FORMED,
                        payload={
                            "hypothesis_id": hyp_id,
                            "constituent_finding_ids": finding_ids,
                            "rule_id": RULE_ID_CRIT,
                            "rule_version": RULE_VERSION,
                            "confidence": 0.9,
                            "explanation": f"Critical severity finding {crit.get('type')} represents immediate compromise risk."
                        }
                    ))
                     self._emitted_hypotheses.add(hyp_id)
                     self._active_hypotheses[hyp_id] = finding_ids
            
        return paths

    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate strategic recommendations based on the aggregate state.
        """
        findings = findings_store.get_all()
        recs = []
        
        if not findings:
            return [{"phase": "Discovery", "action": "Increase scan depth or scope."}]
            
        has_critical = any(f.get("severity") == "CRITICAL" for f in findings)
        if has_critical:
            recs.append({
                "phase": "Immediate Action", 
                "action": "Isolate affected assets and patch critical vulnerabilities immediately."
            })
            
        return recs

    def analyze_context(self) -> Dict[str, Any]:
        """
        Return the full synthesized context for consumers (Reporting, UI).
        """
        return {
            "attack_paths": self.synthesize_attack_paths(),
            "recommended_phases": self.generate_recommendations(),
            "insight_count": len(self._emitted_hypotheses)
        }