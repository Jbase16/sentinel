from __future__ import annotations

import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

from core.data.findings_store import findings_store
from core.epistemic.ledger import EvidenceLedger, Finding
from core.cortex.events import get_event_bus

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
    4. Provide the narrative backbone for Reporting.
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
    
    def synthesize_attack_paths(self) -> List[List[str]]:
        """
        Analyze current findings to construct probable attack paths.
        Returns a list of paths, where each path is a list of descriptions.
        
        Example: ["Recon: Open Port 80", "Vuln: Outdated Apache", "Exploit: RCE"]
        """
        findings = findings_store.get_all()
        paths = []
        
        # Simple heuristic chaining (Phase 1 Logic)
        # Real logic would use a graph traversal, but we start with pattern matching
        
        open_ports = [f for f in findings if "port" in f.get("type", "").lower()]
        web_vulns = [f for f in findings if "xss" in f.get("type", "").lower() or "sql" in f.get("type", "").lower()]
        criticals = [f for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]]
        
        # Chain 1: Web Exposure -> Web Vuln
        for port in open_ports:
            if "80" in str(port.get("value", "")) or "443" in str(port.get("value", "")):
                for vuln in web_vulns:
                    paths.append([
                        f"External Exposure ({port.get('value')})",
                        f"Web Application Attack Surface",
                        f"Vulnerability Exploitation ({vuln.get('type')})"
                    ])
        
        # Chain 2: High Severity Isolated
        for crit in criticals:
            paths.append([
                "Critical Exposure",
                f"{crit.get('type')} ({crit.get('value')})",
                "Potential System Compromise"
            ])
            
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
            "insight_count": 0 # Placeholder for Phase 11
        }
