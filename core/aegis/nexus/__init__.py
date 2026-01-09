"""
Project NEXUS - The Chain Reactor

Logic chaining to turn low-severity findings (Primitives) into high-impact chains.
This transforms "noise" into "signal" by connecting individual vulnerabilities into
exploit paths.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Understand the cumulative risk of minor issues
- Identify exploit chains that attackers could use
- Prioritize remediation based on actual impact potential
- Test defense-in-depth during red team exercises

SAFETY CONSTRAINTS:
- All chains are theoretical models (not executed)
- No exploitation or payload injection
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits NEXUS_CHAIN_DISCOVERED, NEXUS_PRIMITIVE_COLLECTED events
- DecisionLedger: Logs chain construction decisions
- KnowledgeGraph: Stores primitive relationships and chains
"""

from core.aegis.nexus.recoil import EpistemicRecoil

__all__ = [
    "EpistemicRecoil",
]
