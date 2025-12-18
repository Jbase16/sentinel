"""Module narrator: inline documentation for /Users/jason/Developer/sentinelforge/core/cortex/narrator.py."""
#
# PURPOSE:
# The Narrator Engine gives the system a voice.
# It sits structurally downstream of the Decision Engine (Layer 2).
# It does NOT make decisions. It does NOT execute tools.
# It simply explains what just happened in plain English.
#
# ARCHITECTURE:
# - Input: DecisionPoint (Immutable data)
# - Logic: Deterministic string formatting (Templates)
# - Output: NARRATIVE_EMITTED event (via EventBus)
#
# DESIGN RULES:
# 1. No Side Effects: Cannot modify the decision or execution state.
# 2. Deterministic: Same decision + same context = same narrative.
# 3. Async-Safe: Must be non-blocking.
#

from __future__ import annotations

import logging
from typing import Dict, Any, Optional, List

from core.scheduler.decisions import DecisionPoint, DecisionType
from core.cortex.events import EventBus

from core.cortex.narrative_templates import (
    NarrativeTemplate,
    PhaseTemplate,
    IntentTemplate,
    ToolSelectionTemplate,
    ToolRejectionTemplate,
    EarlyTerminationTemplate,
    ModeAdaptationTemplate,
    DefaultTemplate
)

logger = logging.getLogger(__name__)

class NarratorEngine:
    """
    The Storyteller.
    Converts structural decisions into human-readable narratives.
    """
    
    def __init__(self, event_bus: Optional[EventBus] = None):
        """Function __init__."""
        self._event_bus = event_bus
        self._templates: List[NarrativeTemplate] = [
            PhaseTemplate(),
            IntentTemplate(),
            ToolSelectionTemplate(),
            ToolRejectionTemplate(),
            EarlyTerminationTemplate(),
            ModeAdaptationTemplate(),
            DefaultTemplate() # Must be last
        ]

    def narrate(self, decision: DecisionPoint) -> None:
        """
        Produce a narrative for the given decision and emit it.
        """
        narrative = self._generate_narrative(decision)
        # Conditional branch.
        if not narrative:
            return

        # Log internally (Layer 0/1 visibility)
        logger.info(f"[Narrator] {narrative}")

        # Emit event (Layer 3 visibility)
        if self._event_bus:
            self._event_bus.emit_narrative_emitted(
                narrative=narrative,
                decision_id=decision.id,
                decision_type=decision.type.value,
                context=decision.context
            )

    def _generate_narrative(self, d: DecisionPoint) -> str:
        """
        The Core Logic: Data -> Text.
        Delegates to registered templates.
        """
        # Loop over items.
        for template in self._templates:
            if template.matches(d.type):
                try:
                    return template.render(d)
                except Exception as e:
                    logger.error(f"[Narrator] Template {type(template).__name__} failed: {e}")
                    continue
                    
        return f"DECISION: {d.type.value} -> {d.chosen}. {d.reason}"
