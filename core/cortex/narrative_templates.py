"""Module narrative_templates: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/narrative_templates.py."""
#
# PURPOSE:
# Defines HOW decisions are explained.
# Converts raw DecisionPoints into rich, human-readable narratives.
#
# DESIGN:
# - Each Template handles a specific DecisionType.
# - Templates extract "Why" from the decision context.
# - Templates are stateless and deterministic.
#

from __future__ import annotations

from abc import ABC, abstractmethod

from core.scheduler.decisions import DecisionPoint, DecisionType


class NarrativeTemplate(ABC):
    """
    Base class for decision explanation templates.
    """
    
    @abstractmethod
    def matches(self, decision_type: DecisionType) -> bool:
        """Does this template handle this decision type?"""
        pass
    
    @abstractmethod
    def render(self, decision: DecisionPoint) -> str:
        """Convert decision to narrative string."""
        pass


class PhaseTemplate(NarrativeTemplate):
    """
    Explains major lifecycle changes (e.g. "Entering Attack Phase").
    """
    def matches(self, decision_type: DecisionType) -> bool:
        """Function matches."""
        return decision_type == DecisionType.PHASE_TRANSITION

    def render(self, d: DecisionPoint) -> str:
        """Function render."""
        phase_name = str(d.chosen).replace("_", " ").title()
        return f"PHASE CHANGE: Entering {phase_name}. {d.reason}."


class IntentTemplate(NarrativeTemplate):
    """
    Explains strategic shifts (e.g. "Focusing on SQL Injection").
    """
    def matches(self, decision_type: DecisionType) -> bool:
        """Function matches."""
        return decision_type == DecisionType.INTENT_TRANSITION
    
    def render(self, d: DecisionPoint) -> str:
        # "intent_vuln_scanning" -> "Vuln Scanning"
        """Function render."""
        intent_name = str(d.chosen).replace("intent_", "").replace("_", " ").title()
        return f"STRATEGY: Transitioning to {intent_name}. ({d.reason})"


class ToolSelectionTemplate(NarrativeTemplate):
    """
    Explains tactical tool choices.
    """
    def matches(self, decision_type: DecisionType) -> bool:
        """Function matches."""
        return decision_type == DecisionType.TOOL_SELECTION
    
    def render(self, d: DecisionPoint) -> str:
        """Function render."""
        # Conditional branch.
        if d.chosen == "SKIP":
            return f"TACTIC: Skipping tool execution. {d.reason}"
        
        tools = d.chosen if isinstance(d.chosen, list) else [d.chosen]
        tool_list = ", ".join(str(t) for t in tools)
        
        # Add context if available (e.g. target)
        target = d.context.get("target", "")
        target_str = f" against {target}" if target else ""
        
        return f"TACTIC: Deploying {len(tools)} tools: [{tool_list}]{target_str}."


class ToolRejectionTemplate(NarrativeTemplate):
    """
    Explains why a tool was BLOCKED (Crucial for trust).
    """
    def matches(self, decision_type: DecisionType) -> bool:
        """Function matches."""
        return decision_type == DecisionType.TOOL_REJECTION
    
    def render(self, d: DecisionPoint) -> str:
        # Grouped Rejection (Phase 4)
        """Function render."""
        # Conditional branch.
        if "tools" in d.context:
            tools = d.context["tools"]
            count = len(tools)
            tool_list = ", ".join(str(t) for t in tools)
            # "DEFENSE: Blocked 3 tools [masscan, zmap, rustscan] by Mode Overlay."
            return f"DEFENSE: Blocked {count} tools [{tool_list}] by {d.reason}."
            
        # Legacy/Singular Rejection
        tool_name = d.context.get("tool", "tool")
        blocker = d.context.get("blocker", "Policy")
        return f"DEFENSE: Blocked {tool_name} by {blocker}. {d.reason}"


class EarlyTerminationTemplate(NarrativeTemplate):
    """
    Explains why the mission was aborted.
    """
    def matches(self, decision_type: DecisionType) -> bool:
        """Function matches."""
        return decision_type == DecisionType.EARLY_TERMINATION
    
    def render(self, d: DecisionPoint) -> str:
        """Function render."""
        return f"MISSION: Terminating scan. {d.reason}"


class ModeAdaptationTemplate(NarrativeTemplate):
    """
    Explains mode-specific adjustments (e.g. Bug Bounty vs Stealth).
    """
    def matches(self, decision_type: DecisionType) -> bool:
        """Function matches."""
        return decision_type == DecisionType.MODE_ADAPTATION
    
    def render(self, d: DecisionPoint) -> str:
        """Function render."""
        return f"ADAPTATION: {d.reason}"


class DefaultTemplate(NarrativeTemplate):
    """Fallback for unhandled types."""
    
    def matches(self, decision_type: DecisionType) -> bool:
        """Function matches."""
        return True
    
    def render(self, d: DecisionPoint) -> str:
        """Function render."""
        return f"DECISION: {d.type.value} -> {d.chosen}. {d.reason}"
