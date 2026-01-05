#
# PURPOSE:
# Multi-Agent Adversarial Debate for AI-generated exploit validation.
# "Before any exploit is forged, spawn two agents: Red (writes) and Blue (critiques)."
#
# THE HOLY FUCK UPGRADE:
# - Red Agent: Writes/defends the exploit
# - Blue Agent: Critiques for safety and effectiveness
# - Arbiter: High-confidence model that signs off on "Safety Attestation"
#
# Only when the Arbiter approves does code hit disk.
#

import logging
import json
from typing import Dict, Optional, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DebateVerdict(Enum):
    """Outcome of the adversarial debate."""
    APPROVED = "approved"       # Arbiter signed off
    REJECTED = "rejected"       # Blue Agent won the debate
    INCONCLUSIVE = "inconclusive"  # No clear winner
    ERROR = "error"             # Debate process failed


@dataclass
class AgentArgument:
    """An argument made by an agent in the debate."""
    agent: str  # "red", "blue", or "arbiter"
    position: str  # The argument content
    confidence: float  # 0.0 - 1.0
    evidence: List[str]  # Supporting evidence


@dataclass
class DebateResult:
    """Result of the adversarial debate."""
    verdict: DebateVerdict
    red_arguments: List[AgentArgument]
    blue_arguments: List[AgentArgument]
    arbiter_ruling: Optional[str]
    safety_attestation: Optional[str]  # Signed attestation if approved
    
    def to_dict(self) -> Dict:
        return {
            "verdict": self.verdict.value,
            "red_arguments": [{"position": a.position, "confidence": a.confidence} for a in self.red_arguments],
            "blue_arguments": [{"position": a.position, "confidence": a.confidence} for a in self.blue_arguments],
            "arbiter_ruling": self.arbiter_ruling,
            "safety_attestation": self.safety_attestation
        }


class AdversarialDebate:
    """
    Orchestrates the Red/Blue debate before exploit code is written to disk.
    
    Flow:
    1. Red Agent receives the exploit context and defends it
    2. Blue Agent critiques the exploit for safety and effectiveness
    3. Red Agent responds to critiques
    4. Arbiter evaluates both sides and issues verdict
    5. If approved, Safety Attestation is generated
    """
    
    def __init__(self, ai_engine=None):
        """
        Initialize debate orchestrator.
        
        Args:
            ai_engine: AIEngine instance. If None, uses singleton.
        """
        self._ai = ai_engine
    
    @property
    def ai(self):
        """Lazy-load AI engine."""
        if self._ai is None:
            from core.ai.ai_engine import AIEngine
            self._ai = AIEngine.instance()
        return self._ai
    
    def debate(
        self,
        exploit_code: str,
        target_context: str,
        anomaly_context: str
    ) -> DebateResult:
        """
        Run the adversarial debate on proposed exploit code.
        
        Args:
            exploit_code: The AI-generated exploit code
            target_context: Target being exploited
            anomaly_context: Vulnerability being targeted
        
        Returns:
            DebateResult with verdict and attestation
        """
        red_arguments = []
        blue_arguments = []
        
        # Check if AI is available
        self.ai.ensure_client()
        if not self.ai.client:
            logger.warning("[Debate] AI unavailable - using static analysis only")
            return self._static_debate(exploit_code, target_context)
        
        try:
            # Round 1: Red Agent defends the exploit
            red_arg = self._red_agent_turn(exploit_code, target_context, anomaly_context)
            red_arguments.append(red_arg)
            
            # Round 2: Blue Agent critiques
            blue_arg = self._blue_agent_turn(exploit_code, red_arg)
            blue_arguments.append(blue_arg)
            
            # Round 3: Red Agent responds
            red_response = self._red_agent_respond(exploit_code, blue_arg)
            red_arguments.append(red_response)
            
            # Arbiter ruling
            arbiter_ruling, verdict = self._arbiter_rule(
                exploit_code,
                red_arguments,
                blue_arguments
            )
            
            # Generate attestation if approved
            safety_attestation = None
            if verdict == DebateVerdict.APPROVED:
                safety_attestation = self._generate_attestation(
                    exploit_code, target_context, arbiter_ruling
                )
            
            return DebateResult(
                verdict=verdict,
                red_arguments=red_arguments,
                blue_arguments=blue_arguments,
                arbiter_ruling=arbiter_ruling,
                safety_attestation=safety_attestation
            )
            
        except Exception as e:
            logger.error(f"[Debate] Error during debate: {e}")
            return DebateResult(
                verdict=DebateVerdict.ERROR,
                red_arguments=red_arguments,
                blue_arguments=blue_arguments,
                arbiter_ruling=f"Debate failed: {e}",
                safety_attestation=None
            )
    
    def _red_agent_turn(
        self,
        code: str,
        target: str,
        anomaly: str
    ) -> AgentArgument:
        """Red Agent: Defend the exploit."""
        system_prompt = (
            "You are the RED AGENT in an adversarial security review. "
            "Your job is to DEFEND the provided exploit code. "
            "Explain why it is safe to execute, effective against the target, "
            "and follows security best practices. "
            "Be specific about safety measures in the code. "
            "Return JSON: {\"position\": \"...\", \"confidence\": 0.0-1.0, \"evidence\": [...]}"
        )
        
        user_prompt = (
            f"Target: {target}\n"
            f"Vulnerability: {anomaly}\n"
            f"Exploit Code:\n{code[:2000]}\n\n"
            "Defend this exploit:"
        )
        
        response = self.ai.client.generate(user_prompt, system_prompt)
        return self._parse_agent_response(response, "red")
    
    def _blue_agent_turn(
        self,
        code: str,
        red_argument: AgentArgument
    ) -> AgentArgument:
        """Blue Agent: Critique the exploit."""
        system_prompt = (
            "You are the BLUE AGENT in an adversarial security review. "
            "Your job is to CRITIQUE the provided exploit code. "
            "Look for: "
            "1. Safety issues (could harm the operator's system) "
            "2. Effectiveness issues (may not work as intended) "
            "3. Ethical issues (could cause unintended harm) "
            "4. Detection risk (too loud, will trigger alerts) "
            "Return JSON: {\"position\": \"...\", \"confidence\": 0.0-1.0, \"evidence\": [...]}"
        )
        
        user_prompt = (
            f"Red Agent's Defense:\n{red_argument.position}\n\n"
            f"Exploit Code:\n{code[:2000]}\n\n"
            "Critique this exploit:"
        )
        
        response = self.ai.client.generate(user_prompt, system_prompt)
        return self._parse_agent_response(response, "blue")
    
    def _red_agent_respond(
        self,
        code: str,
        blue_argument: AgentArgument
    ) -> AgentArgument:
        """Red Agent: Respond to Blue's critique."""
        system_prompt = (
            "You are the RED AGENT responding to the Blue Agent's critique. "
            "Address each concern raised. If the critique is valid, acknowledge it. "
            "If you can refute it, do so with evidence. "
            "Return JSON: {\"position\": \"...\", \"confidence\": 0.0-1.0, \"evidence\": [...]}"
        )
        
        user_prompt = (
            f"Blue Agent's Critique:\n{blue_argument.position}\n\n"
            f"Exploit Code:\n{code[:2000]}\n\n"
            "Respond to the critique:"
        )
        
        response = self.ai.client.generate(user_prompt, system_prompt)
        return self._parse_agent_response(response, "red")
    
    def _arbiter_rule(
        self,
        code: str,
        red_args: List[AgentArgument],
        blue_args: List[AgentArgument]
    ) -> tuple:
        """Arbiter: Issue final ruling."""
        system_prompt = (
            "You are the ARBITER in an adversarial security review. "
            "You have reviewed arguments from both Red (attacker) and Blue (defender). "
            "Issue a FINAL RULING on whether this exploit should be approved. "
            "Consider: safety, effectiveness, ethics, and operational security. "
            "Return JSON: {\"verdict\": \"approved|rejected|inconclusive\", \"ruling\": \"...\"}"
        )
        
        red_summary = "\n".join([f"- {a.position}" for a in red_args])
        blue_summary = "\n".join([f"- {a.position}" for a in blue_args])
        
        user_prompt = (
            f"RED AGENT ARGUMENTS:\n{red_summary}\n\n"
            f"BLUE AGENT ARGUMENTS:\n{blue_summary}\n\n"
            f"CODE PREVIEW:\n{code[:1000]}\n\n"
            "Issue your verdict:"
        )
        
        response = self.ai.client.generate(user_prompt, system_prompt)
        
        try:
            data = json.loads(response)
            verdict_str = data.get("verdict", "inconclusive").lower()
            ruling = data.get("ruling", "No ruling provided")
            
            if verdict_str == "approved":
                return ruling, DebateVerdict.APPROVED
            elif verdict_str == "rejected":
                return ruling, DebateVerdict.REJECTED
            else:
                return ruling, DebateVerdict.INCONCLUSIVE
        except:
            return "Failed to parse arbiter response", DebateVerdict.INCONCLUSIVE
    
    def _generate_attestation(
        self,
        code: str,
        target: str,
        arbiter_ruling: str
    ) -> str:
        """Generate safety attestation for approved exploit."""
        import hashlib
        from datetime import datetime, timezone
        
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        timestamp = datetime.now(timezone.utc).isoformat()
        
        attestation = (
            f"=== SAFETY ATTESTATION ===\n"
            f"Timestamp: {timestamp}\n"
            f"Target: {target}\n"
            f"Code Hash: {code_hash}\n"
            f"Arbiter Ruling: {arbiter_ruling[:200]}\n"
            f"Status: APPROVED FOR SANDBOXED EXECUTION\n"
            f"=========================="
        )
        
        return attestation
    
    def _parse_agent_response(
        self,
        response: Optional[str],
        agent: str
    ) -> AgentArgument:
        """Parse agent response into structured argument."""
        if not response:
            return AgentArgument(
                agent=agent,
                position="[No response from AI]",
                confidence=0.0,
                evidence=[]
            )
        
        try:
            data = json.loads(response)
            return AgentArgument(
                agent=agent,
                position=data.get("position", response),
                confidence=float(data.get("confidence", 0.5)),
                evidence=data.get("evidence", [])
            )
        except:
            # If not valid JSON, use raw response
            return AgentArgument(
                agent=agent,
                position=response[:500],
                confidence=0.5,
                evidence=[]
            )
    
    def _static_debate(
        self,
        code: str,
        target: str
    ) -> DebateResult:
        """Fallback static analysis when AI is unavailable."""
        from core.forge.validator import validate_code
        
        result = validate_code(code)
        
        if result.safe:
            return DebateResult(
                verdict=DebateVerdict.APPROVED,
                red_arguments=[AgentArgument(
                    agent="red",
                    position="[Static] Code passed validation",
                    confidence=0.7,
                    evidence=[]
                )],
                blue_arguments=[],
                arbiter_ruling="[Static] No critical violations detected",
                safety_attestation=self._generate_attestation(code, target, "Static validation passed")
            )
        else:
            return DebateResult(
                verdict=DebateVerdict.REJECTED,
                red_arguments=[],
                blue_arguments=[AgentArgument(
                    agent="blue",
                    position=f"[Static] Violations: {result.violations}",
                    confidence=0.9,
                    evidence=[v.get("reason", "") for v in result.violations]
                )],
                arbiter_ruling=f"[Static] Rejected: {result.risk_level.value} risk",
                safety_attestation=None
            )


# Convenience function
def run_debate(
    exploit_code: str,
    target: str,
    anomaly: str
) -> DebateResult:
    """Run adversarial debate on exploit code."""
    return AdversarialDebate().debate(exploit_code, target, anomaly)
