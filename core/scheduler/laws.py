#
# PURPOSE:
# This module is part of the scheduler package in SentinelForge.
# [Specific purpose based on module name: laws]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
core/scheduler/laws.py
The Constitution of Strategos.
Enforces the Laws of a God-Level Scan via CAL (Collaborative Agent Logic).
"""

import logging
import os
from typing import Dict, Any, List
from dataclasses import dataclass
from pathlib import Path

from core.cal.parser import CALParser, Law, Action, Condition

logger = logging.getLogger(__name__)

@dataclass
class Decision:
    """Class Decision."""
    allowed: bool
    reason: str
    blocking_law: str = None

class Constitution:
    """
    Enforces laws defined in assets/laws/constitution.cal.
    Replaces legacy hardcoded Law classes.
    """
    _instance = None
    
    def __init__(self, constitution_path: str = "assets/laws/constitution.cal"):
        self.laws: List[Law] = []
        self._load_laws(constitution_path)
        
    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_laws(self, path_str: str):
        """Parse the CAL file."""
        try:
            # Resolve relative paths from project root
            # heuristic: finding sentinel root by looking for 'core'
            base_dir = Path(os.getcwd())
            full_path = base_dir / path_str
            
            if not full_path.exists():
                logger.warning(f"[CAL] Constitution file not found at {full_path}. Laws will be empty.")
                return

            parser = CALParser()
            self.laws = parser.parse_file(str(full_path))
            logger.info(f"[CAL] Loaded {len(self.laws)} laws from {path_str}")
        except Exception as e:
            logger.error(f"[CAL] Failed to load constitution: {e}")
            self.laws = []

    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        """
        Evaluate all loaded CAL laws against the context.
        """
        if not self.laws:
            # Fail open or closed? 
            # For V1, if no laws, allow (legacy behavior default)
            return Decision(True, "No laws loaded (Anarchy Mode)")

        for law in self.laws:
            # Check conditions (AND logic)
            all_conditions_met = True
            for condition in law.conditions:
                if not condition.evaluate(context, tool_def):
                    all_conditions_met = False
                    break
            
            # If all triggers match, EXECUTE the Action
            if all_conditions_met:
                if law.action and law.action.verb == "DENY":
                    # Format the reason string
                    reason = law.action.reason_template
                    try:
                        # Simple format map
                        safe_scope = {
                            "context": context, 
                            "tool": tool_def
                        }
                        # We might need a better formatter for objects
                        # This is a basic f-string simulation
                        reason = reason.replace("{tool.phase}", str(tool_def.get("phase", "?")))
                        reason = reason.replace("{context.phase_index}", str(getattr(context, "phase_index", "?")))
                        reason = reason.replace("{tool.gates}", str(tool_def.get("gates", "?")))
                    except Exception:
                        pass
                        
                    return Decision(False, reason, law.name)

        return Decision(True, "All laws passed")

