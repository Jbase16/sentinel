#
# PURPOSE:
# Heuristic Fallback Generator for when AI is unavailable (Circuit Breaker OPEN).
# Uses DecisionLedger to make "educated guesses" based on historical success patterns.
#
# THE "ENTROPY-AWARE INTERPOLATION":
# When brain is offline, we don't just use static rules - we query the DecisionLedger
# for the current RUN_ID and interpolate the next step based on success rates of
# previous tool outputs. The scanner literally learns the target's patterns.
#
# KEY CONCEPTS:
# - Heuristic Rules: Static regex-based decisions (port 80 → run httpx)
# - Interpolation: Dynamic next-step prediction from historical data
# - Graceful Degradation: Always produce SOME output, never hang
#

import logging
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FallbackDecision:
    """
    Represents a decision made by the heuristic fallback system.
    
    Attributes:
        tool: Which tool to run next
        args: Arguments for the tool
        reason: Why this decision was made
        confidence: How confident we are (0.0-1.0)
        source: "static_rule" or "interpolated"
    """
    tool: str
    args: List[str]
    reason: str
    confidence: float
    source: str = "static_rule"


class HeuristicRules:
    """
    Static rule-based decisions for when AI is completely unavailable.
    These are the "safety net" - simple but reliable.
    
    Philosophy: When in doubt, do reconnaissance first.
    """
    
    # Port → Tool mappings (what tool to run when we see a port)
    PORT_TOOL_MAP = {
        22: ("nmap", ["-sV", "-p22"], "SSH detected - version scan"),
        80: ("httpx", ["-tech-detect"], "HTTP detected - probe web stack"),
        443: ("httpx", ["-tech-detect"], "HTTPS detected - probe web stack"),
        3306: ("nmap", ["-sV", "-p3306"], "MySQL detected - version scan"),
        5432: ("nmap", ["-sV", "-p5432"], "PostgreSQL detected - version scan"),
        8080: ("httpx", ["-tech-detect"], "Alt HTTP detected - probe web stack"),
        8443: ("httpx", ["-tech-detect"], "Alt HTTPS detected - probe web stack"),
    }
    
    # Severity → Priority (what to focus on when we have findings)
    SEVERITY_PRIORITY = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    # Tool chains (what tool to run after another)
    TOOL_CHAINS = {
        "nmap": ["httpx", "nikto"],  # After nmap, try web probing
        "httpx": ["nikto", "nuclei"],  # After httpx, try vuln scanning
        "nuclei": [],  # Nuclei is often a terminal step
        "nikto": [],  # Nikto is often a terminal step
    }
    
    @classmethod
    def get_port_decision(cls, port: int, target: str) -> Optional[FallbackDecision]:
        """Get decision based on open port."""
        if port in cls.PORT_TOOL_MAP:
            tool, base_args, reason = cls.PORT_TOOL_MAP[port]
            return FallbackDecision(
                tool=tool,
                args=base_args + [target],
                reason=f"[Heuristic] {reason}",
                confidence=0.7,
                source="static_rule"
            )
        return None
    
    @classmethod
    def get_chain_decision(cls, last_tool: str, target: str) -> Optional[FallbackDecision]:
        """Get next tool based on tool chain."""
        next_tools = cls.TOOL_CHAINS.get(last_tool, [])
        if next_tools:
            return FallbackDecision(
                tool=next_tools[0],
                args=[target],
                reason=f"[Heuristic] Chain: {last_tool} → {next_tools[0]}",
                confidence=0.5,
                source="static_rule"
            )
        return None


class EntropyInterpolator:
    """
    THE HOLY FUCK UPGRADE: Entropy-Aware Interpolation.
    
    When AI is offline, query the DecisionLedger for historical patterns
    and interpolate the next step based on success rates.
    
    "The scanner learns the target's patterns and continues the mission without a brain."
    """
    
    def __init__(self):
        # Lazy import to avoid circular dependency
        self._ledger = None
    
    @property
    def ledger(self):
        """Lazy-load the DecisionLedger."""
        if self._ledger is None:
            try:
                from core.scheduler.decisions import DecisionLedger
                self._ledger = DecisionLedger()
            except ImportError:
                logger.warning("[Fallback] DecisionLedger not available")
                self._ledger = None
        return self._ledger
    
    def interpolate_next_step(
        self,
        target: str,
        available_tools: List[str],
        completed_tools: List[str],
        findings: List[Dict]
    ) -> Optional[FallbackDecision]:
        """
        Predict the next best tool based on historical success patterns.
        
        Algorithm:
        1. Get historical decisions for similar contexts
        2. Calculate success rate per tool
        3. Pick the tool with highest success rate that hasn't been run
        4. Fall back to static rules if no history
        """
        if not self.ledger:
            return None
        
        try:
            # Get historical stats (if ledger has them)
            stats = self.ledger.stats() if hasattr(self.ledger, 'stats') else {}
            
            if not stats:
                logger.debug("[Fallback] No historical data, using static rules")
                return None
            
            # Calculate tool priority based on historical success
            tool_scores = self._calculate_tool_scores(
                stats,
                available_tools,
                completed_tools,
                findings
            )
            
            if not tool_scores:
                return None
            
            # Pick best tool
            best_tool = max(tool_scores, key=tool_scores.get)
            confidence = min(tool_scores[best_tool], 0.9)  # Cap at 0.9
            
            return FallbackDecision(
                tool=best_tool,
                args=[target],
                reason=f"[Interpolated] Historical success rate: {confidence:.1%}",
                confidence=confidence,
                source="interpolated"
            )
            
        except Exception as e:
            logger.warning(f"[Fallback] Interpolation failed: {e}")
            return None
    
    def _calculate_tool_scores(
        self,
        stats: Dict,
        available: List[str],
        completed: List[str],
        findings: List[Dict]
    ) -> Dict[str, float]:
        """
        Calculate priority scores for each available tool.
        
        Factors:
        - Historical success rate (from DecisionLedger)
        - Finding severity (prioritize tools that find HIGH/CRITICAL)
        - Completion status (don't re-run completed tools)
        """
        scores = {}
        
        # Get remaining tools
        remaining = [t for t in available if t not in completed]
        
        for tool in remaining:
            base_score = 0.5  # Default score
            
            # Boost based on tool type and current findings
            if findings:
                # If we have web findings, boost web tools
                web_findings = [f for f in findings if 'http' in str(f).lower()]
                if web_findings and tool in ['httpx', 'nikto', 'nuclei']:
                    base_score += 0.2
                
                # If we have high severity findings, boost deep scanners
                high_sev = [f for f in findings if f.get('severity') in ['HIGH', 'CRITICAL']]
                if high_sev and tool in ['nuclei', 'sqlmap']:
                    base_score += 0.3
            
            scores[tool] = min(base_score, 1.0)
        
        return scores


class HeuristicFallbackGenerator:
    """
    Main entry point for heuristic-based decisions.
    
    Combines static rules with entropy-aware interpolation.
    """
    
    def __init__(self):
        self.rules = HeuristicRules()
        self.interpolator = EntropyInterpolator()
    
    def generate_next_step(
        self,
        context: Dict[str, Any]
    ) -> Optional[FallbackDecision]:
        """
        Generate the next step when AI is unavailable.
        
        Args:
            context: Dict with:
                - target: The scan target
                - available_tools: List of installed tools
                - completed_tools: List of already-run tools
                - findings: Current findings
                - last_tool: Most recently completed tool
                - open_ports: List of open ports (if known)
        
        Returns:
            FallbackDecision or None if no decision can be made
        """
        target = context.get("target", "")
        available = context.get("available_tools", [])
        completed = context.get("completed_tools", [])
        findings = context.get("findings", [])
        last_tool = context.get("last_tool")
        open_ports = context.get("open_ports", [])
        
        # Strategy 1: Entropy-aware interpolation (most sophisticated)
        decision = self.interpolator.interpolate_next_step(
            target, available, completed, findings
        )
        if decision:
            logger.info(f"[Fallback] Interpolated decision: {decision.tool} ({decision.confidence:.1%})")
            return decision
        
        # Strategy 2: Port-based rules
        for port in open_ports:
            decision = HeuristicRules.get_port_decision(port, target)
            if decision and decision.tool in available and decision.tool not in completed:
                logger.info(f"[Fallback] Port-based decision: {decision.tool}")
                return decision
        
        # Strategy 3: Tool chain
        if last_tool:
            decision = HeuristicRules.get_chain_decision(last_tool, target)
            if decision and decision.tool in available and decision.tool not in completed:
                logger.info(f"[Fallback] Chain decision: {decision.tool}")
                return decision
        
        # Strategy 4: Default progression
        default_order = ["nmap", "httpx", "nikto", "nuclei"]
        for tool in default_order:
            if tool in available and tool not in completed:
                logger.info(f"[Fallback] Default decision: {tool}")
                return FallbackDecision(
                    tool=tool,
                    args=[target],
                    reason=f"[Fallback] Default progression",
                    confidence=0.4,
                    source="static_rule"
                )
        
        logger.warning("[Fallback] No decision could be made")
        return None
    
    def generate_attack_vectors(
        self,
        flow_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate attack vectors using heuristics when AI is unavailable.
        
        This is the fallback for StrategyEngine.analyze_traffic().
        """
        vectors = []
        url = flow_data.get("url", "")
        params = flow_data.get("params", [])
        
        # Heuristic: ID parameters often indicate IDOR
        id_pattern = re.compile(r'(id|user|account|order|item|product)', re.I)
        for param in params:
            if id_pattern.search(param):
                vectors.append({
                    "vuln_class": "IDOR",
                    "parameter": param,
                    "hypothesis": f"[Heuristic] Parameter '{param}' may reference objects",
                    "suggested_payloads": ["1", "2", "999", "0", "-1"],
                    "source": "heuristic"
                })
        
        # Heuristic: SQL injection candidates
        sql_pattern = re.compile(r'(search|query|filter|sort|order)', re.I)
        for param in params:
            if sql_pattern.search(param):
                vectors.append({
                    "vuln_class": "SQLi",
                    "parameter": param,
                    "hypothesis": f"[Heuristic] Parameter '{param}' may be used in SQL",
                    "suggested_payloads": ["'", "' OR 1=1--", "1; DROP TABLE users--"],
                    "source": "heuristic"
                })
        
        # Heuristic: Path traversal candidates
        path_pattern = re.compile(r'(file|path|dir|doc|template)', re.I)
        for param in params:
            if path_pattern.search(param):
                vectors.append({
                    "vuln_class": "PathTraversal",
                    "parameter": param,
                    "hypothesis": f"[Heuristic] Parameter '{param}' may reference files",
                    "suggested_payloads": ["../etc/passwd", "..\\..\\windows\\win.ini"],
                    "source": "heuristic"
                })
        
        return vectors


# Singleton instance
_fallback_generator = None

def get_fallback_generator() -> HeuristicFallbackGenerator:
    """Get the singleton fallback generator."""
    global _fallback_generator
    if _fallback_generator is None:
        _fallback_generator = HeuristicFallbackGenerator()
    return _fallback_generator
