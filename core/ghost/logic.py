"""
core/ghost/logic.py
The Business Logic Fuzzer.
"Ghost breaks the rules, not just the inputs."
"""

import logging
from typing import List, Dict, Any
from core.ghost.flow import UserFlow, FlowStep

logger = logging.getLogger(__name__)

class LogicFuzzer:
    """
    Apply semantic mutations to UserFlows.
    """
    
    @staticmethod
    def fuzz_invariants(flow: UserFlow) -> List[Dict]:
        """
        Tests numerical invariants (e.g. Price < 0, Quantity > Max).
        """
        tests = []
        
        for step in flow.steps:
            # Look for numerical params
            for key, val in step.params.items():
                if str(val).isdigit():
                    # 1. Negative Value Test
                    tests.append({
                        "name": f"Negative {key}",
                        "step_id": step.id,
                        "param": key,
                        "mutation": "-1",
                        "expected": "400/Block"
                    })
                    
                    # 2. Integer Overflow Test
                    tests.append({
                        "name": f"Overflow {key}",
                        "step_id": step.id,
                        "param": key,
                        "mutation": "99999999999999999",
                        "expected": "400/Block"
                    })
                    
        return tests

    @staticmethod
    def fuzz_idor(flow: UserFlow, alt_tokens: Dict[str, str]) -> List[Dict]:
        """
        Tests for IDOR by replaying the flow with a different user's session.
        """
        tests = []
        
        # We need a flow recorded by User A, and tokens for User B
        if not alt_tokens:
            return []
            
        for step in flow.steps:
            # If request has IDs in URL/Params, keep them, but SWAP the Auth Headers
            tests.append({
                "name": f"IDOR Check on {step.url}",
                "step_id": step.id,
                "strategy": "swap_auth",
                "new_headers": alt_tokens 
            })
            
        return tests

    @staticmethod
    def fuzz_race_conditions(flow: UserFlow) -> List[Dict]:
        """
        Identifies steps that modify state (POST/PUT) and suggests parellel execution.
        """
        tests = []
        for step in flow.steps:
            if step.method in ["POST", "PUT", "DELETE"]:
                tests.append({
                    "name": f"Race Condition on {step.url}",
                    "step_id": step.id,
                    "strategy": "parallel_reqs",
                    "count": 10
                })
        return tests
