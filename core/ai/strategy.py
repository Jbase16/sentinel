"""Module strategy: inline documentation for /Users/jason/Developer/sentinelforge/core/ai/strategy.py."""
#
# PURPOSE:
# Analyzes intercepted network traffic (from Ghost proxy) and uses AI to hypothesize
# specific attack vectors. Goes beyond pattern matching to "think like a hacker."
#
# WHAT IT DOES:
# - Examines HTTP requests captured by the proxy
# - Identifies parameters that might be vulnerable (IDs, flags, paths)
# - Uses AI to generate attack hypotheses (IDOR, SQLi, mass assignment, etc.)
# - Suggests specific payloads to test each hypothesis
#
# WHY AI FOR STRATEGY:
# - Recognizes subtle patterns humans might miss
# - Understands context (e.g., "user_id=5" in profile API → potential IDOR)
# - Generates creative test cases beyond wordlists
# - Learns from fine-tuned security knowledge
#
# KEY CONCEPTS:
# - IDOR (Insecure Direct Object Reference): Access other users' data by changing IDs
# - BOLA (Broken Object Level Authorization): Similar to IDOR but broader
# - Mass Assignment: Modify hidden object properties via API
# - Logic Vulnerabilities: Business logic flaws vs. technical bugs
#
# WORKFLOW:
# Ghost captures traffic → Strategy analyzes → Wraith executes test payloads
#

import json
import logging
import asyncio
from typing import List, Dict
from dataclasses import dataclass

from core.ai.ai_engine import AIEngine
from core.base.session import ScanSession

logger = logging.getLogger(__name__)

@dataclass
class AttackVector:
    """Class AttackVector."""
    vuln_class: str  # e.g., "IDOR", "SQLi", "XSS"
    parameter: str   # e.g., "user_id"
    hypothesis: str  # e.g., "The id looks sequential, user 5 might access user 4."
    suggested_payloads: List[str]

class StrategyEngine:
    """
    Bridges the gap between Raw Traffic (Ghost) and Actionable Attacks (Wraith).
    """

    def __init__(self, session: ScanSession):
        """Function __init__."""
        self.session = session
        self.ai = AIEngine.instance()

    async def analyze_traffic(self, flow_data: Dict) -> List[AttackVector]:
        """
        Asks Gemma to analyze a traffic snapshot associated with a session.
        """
        # Conditional branch.
        if not self.ai.client:
            return []

        url = flow_data.get("url")
        params = flow_data.get("params", [])
        method = flow_data.get("method")
        
        # Conditional branch.
        if not params:
            return [] # Logic fuzzing needs inputs

        # The "God Tier" Prompt
        # Designed for fine-tuned Gemma 9B (Bug Bounty Specialization)
        system_prompt = (
            "You are a world-class Bug Bounty Hunter utilizing the Gemma 9B model. "
            "Your goal is to inspect HTTP requests and deduce hidden vulnerability logic. "
            "Think like a hacker: Look for IDOR, BOLA, Mass Assignment, SQLi, and Command Injection opportunities. "
            "Return a JSON object with a key 'vectors' containing a list of objects with fields: "
            "'vuln_class', 'parameter', 'hypothesis', 'suggested_payloads'."
        )

        user_prompt = (
            f"Target Request:\n"
            f"Method: {method}\n"
            f"URL: {url}\n"
            f"Parameters: {params}\n\n"
            "Analyze this request structure. "
            "If these parameters look suceptible to logic attacks (e.g. IDs, debug flags, file paths), "
            "generate specific attack hypotheses."
        )

        # Call AI (Wrapper around synch method for now, or use asyncio runner if AIEngine updated)
        # Assuming AIEngine.client.generate is blocking HTTP, we should Ideally thread this.
        # But for this prototype, we call directly.
        try:
            print(f"[DEBUG] Asking AI: {user_prompt[:50]}...")
            response_json = self.ai.client.generate(user_prompt, system_prompt)
            print(f"[DEBUG] AI Response: {response_json}")
            
            if not response_json:
                print("[DEBUG] Empty response")
                return []
            
            data = json.loads(response_json)
            vectors_raw = data.get("vectors", [])
            print(f"[DEBUG] Vectors found: {len(vectors_raw)}")
            
            results = []
            for v in vectors_raw:
                vec = AttackVector(
                    vuln_class=v.get("vuln_class", "Unknown"),
                    parameter=v.get("parameter", "unknown"),
                    hypothesis=v.get("hypothesis", "AI generated suspicion."),
                    suggested_payloads=v.get("suggested_payloads", [])
                )
                results.append(vec)
                
                # Log this purely as an AI insight for now
                self.session.log(f"[Neural Strategy] Proposed {vec.vuln_class} on {vec.parameter}")
                
            return results

        except Exception as e:
            logger.error(f"[Strategy] Analysis failed: {e}")
            return []

    async def propose_attacks(self, flow_data: Dict):
        """
        High-level entry: Analyze -> Create 'Pending Tasks' in Session.
        """
        vectors = await self.analyze_traffic(flow_data)
        print(f"[DEBUG] propose_attacks got {len(vectors)} vectors")
        
        # Loop over items.
        for vec in vectors:
            # Create a "Neural Finding" - a finding that is a HYPOTHESIS, not a fact.
            self.session.findings.add_finding({
                "tool": "neural_strategy",
                "type": f"hypothesis::{vec.vuln_class.lower()}",
                "severity": "MEDIUM", # Hypotheses are medium until proven
                "target": flow_data.get("host", "unknown"),
                "value": vec.hypothesis,
                "metadata": {
                    "parameter": vec.parameter,
                    "payloads": vec.suggested_payloads,
                    "url": flow_data.get("url")
                }
            })
            
            # TRIGGER WRAITH (The Hand)
            # Auto-verification of the hypothesis
            asyncio.create_task(self.session.wraith.on_hypothesis({
                 "type": f"hypothesis::{vec.vuln_class.lower()}",
                 "target": flow_data.get("host", "unknown"),
                 "metadata": {"payloads": vec.suggested_payloads}
            }))
