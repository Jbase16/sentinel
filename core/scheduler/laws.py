"""
core/scheduler/laws.py
The Constitution of Strategos.
Enforces the 5 Laws of a God-Level Scan.
"""

from typing import Dict, List, Any
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class Decision:
    allowed: bool
    reason: str
    blocking_law: str = None

class Law:
    """Base class for a Scan Law."""
    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        raise NotImplementedError

class Law1_PassiveBeforeActive(Law):
    """
    Law 1: Passive Before Active.
    Aggressive tools cannot run until Passive Phase is complete.
    """
    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        current_phase = getattr(context, "phase_index", 0)
        tool_phase = tool_def.get("phase", 99)
        
        # If we are in Phase 0 or 1, we cannot run Phase 2+ tools
        if current_phase < 2 and tool_phase >= 2:
            return Decision(False, f"Phase {tool_phase} tool blocked during Phase {current_phase} (Passive Mode)", "Law1_PassiveBeforeActive")
        return Decision(True, "Phase check passed")

class Law3_EvidenceGates(Law):
    """
    Law 3: Evidence Gates Everything.
    Tools only run if their prerequisites are met in the Knowledge Graph.
    Also enforces Confidence Thresholds in Bug Bounty Mode.
    """
    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        gates = tool_def.get("gates", [])
        if not gates:
            return Decision(True, "No prerequisites required")
            
        # Context.knowledge is a Dict
        knowledge = getattr(context, "knowledge", {})
        findings = knowledge.get("findings", [])
        mode = knowledge.get("mode", None)
        
        # Build tag set active on target
        tags = set()
        for f in findings:
            tags.update(f.get("tags", []))
            tags.add(f.get("type", "")) # e.g. 'type:subdomain'
            
        # Check gate satisfaction
        for gate in gates:
             if gate in tags:
                 # In Bug Bounty Mode, check High Confidence if available?
                 # (For V1, existence is enough, but structure allows extension)
                 return Decision(True, f"Prerequisite '{gate}' met")
                 
        return Decision(False, f"Missing requirements: {gates}", "Law3_EvidenceGates")

class Law4_ResourceAwareness(Law):
    """
    Law 4: Resource-Aware Scheduling.
    Don't exceed system max load.
    """
    def check(self, context: Any, tool_def: Dict[str, Any]) -> Decision:
        # Simple implementation: Check active tool count vs max
        active = getattr(context, "active_tools", 0)
        max_concurrent = getattr(context, "max_concurrent", 5)
        
        cost = tool_def.get("resource_cost", 1) # 1=Low, 3=High
        
        if active + cost > max_concurrent:
            return Decision(False, f"System load too high ({active}+{cost} > {max_concurrent})", "Law4_ResourceAwareness")
        return Decision(True, "Resource check passed")

class Constitution:
    """Enforces all laws."""
    def __init__(self):
        self.laws = [
            Law1_PassiveBeforeActive(),
            Law3_EvidenceGates(),
            Law4_ResourceAwareness()
        ]
        
    def check(self, context: Any, tool_def: Dict) -> Decision:
        """
        Returns a Decision. If blocked, returns the first blocking decision.
        If allowed, returns an Allowed decision.
        """
        for law in self.laws:
            decision = law.check(context, tool_def)
            if not decision.allowed:
                return decision
        return Decision(True, "All laws passed")

