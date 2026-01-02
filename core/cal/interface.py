"""Module interface: inline documentation for /Users/jason/Developer/sentinelforge/core/cal/interface.py."""
#
# PURPOSE:
# The Developer Experience (DX) layer for CAL.
# Allows writing Argumentation Rules without dealing with the raw Engine loop.
#
# USAGE:
# @cal_rule(on="SQLi_Claim")
# def verify_waf(claim, context):
#     if context.has_evidence("WAF_Detected"):
#         claim.dispute("Blocked by WAF")
#

import functools
from typing import Callable, List, Type
from core.cal.engine import ReasoningSession
from core.cal.types import Claim, Evidence

# Registry of rules
_CAL_RULES = {}

def cal_rule(on_claim_type: str = "*"):
    """
    Decorator to register a function as a CAL Reasoning Rule.
    
    Args:
        on_claim_type: Filter rules to run only for specific claim types (regex-like).
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(claim: Claim, session: ReasoningSession, **kwargs):
            return func(claim, session, **kwargs)
        
        # Register
        if on_claim_type not in _CAL_RULES:
            _CAL_RULES[on_claim_type] = []
        _CAL_RULES[on_claim_type].append(wrapper)
        return wrapper
    return decorator

class CALInterface:
    """
    Facade for interacting with the CAL system.
    """
    
    @staticmethod
    def apply_rules(session: ReasoningSession):
        """
        Run all registered rules against the current session state.
        This is the 'Reactive Loop'.
        """
        for claim in session.claims.values():
            # 1. Run global rules
            for rule in _CAL_RULES.get("*", []):
                rule(claim, session)
            
            # 2. Run specific rules (simple exact match for now)
            # Metadata 'type' is the key we use for filtering
            c_type = claim.metadata.get("type", "unknown")
            for rule in _CAL_RULES.get(c_type, []):
                rule(claim, session)
