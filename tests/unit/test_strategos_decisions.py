"""
tests/unit/test_strategos_decisions.py
Unit tests for Strategos decision logic.
"""

import pytest
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set

from core.scheduler.strategos import Strategos, ScanContext
from core.scheduler.modes import ScanMode
from core.scheduler.intents import (
    INTENT_PASSIVE_RECON,
    INTENT_ACTIVE_LIVE_CHECK,
    INTENT_SURFACE_ENUMERATION,
    INTENT_VULN_SCANNING,
    INTENT_HEAVY_ARTILLERY
)


class TestStrategosIntentProgression:
    """Test that Strategos correctly progresses through intents."""
    
    def test_initial_intent_is_passive_recon(self):
        """First intent should always be passive recon."""
        brain = Strategos()
        # Access the initial intent logic
        next_intent = brain._decide_next_step(None)
        assert next_intent == INTENT_PASSIVE_RECON
    
    def test_passive_recon_leads_to_active_check(self):
        """After passive recon, should move to active check."""
        brain = Strategos()
        brain.context = ScanContext(target="example.com")
        brain.context.phase_index = 1
        
        next_intent = brain._decide_next_step(INTENT_PASSIVE_RECON)
        assert next_intent == INTENT_ACTIVE_LIVE_CHECK
    
    def test_intent_progression_standard_mode(self):
        """Standard mode should progress through all intents."""
        brain = Strategos()
        brain.context = ScanContext(target="example.com")
        
        intents = []
        current = None
        # Loop over items.
        for _ in range(5):
            current = brain._decide_next_step(current)
            if current is None:
                break
            intents.append(current)
            brain.context.phase_index += 1
        
        # Should have at least passive and active
        assert INTENT_PASSIVE_RECON in intents
        assert INTENT_ACTIVE_LIVE_CHECK in intents


class TestStrategosToolSelection:
    """Test that Strategos correctly selects tools for intents."""
    
    def test_passive_tools_selected_for_passive_intent(self):
        """Passive intent should select passive tools."""
        brain = Strategos()
        brain.context = ScanContext(target="example.com")
        
        available = ["subfinder", "httpx", "nmap", "nuclei"]
        selected = brain._select_tools(INTENT_PASSIVE_RECON, available, ScanMode.STANDARD)
        
        # Should prioritize passive tools
        assert len(selected) > 0
        # Should not include aggressive tools in first pass
        assert "nuclei" not in selected or selected.index("nuclei") > 0
    
    def test_bug_bounty_mode_disables_noisy_tools(self):
        """Bug bounty mode should disable noisy tools."""
        brain = Strategos()
        brain.context = ScanContext(target="example.com")
        
        available = ["subfinder", "httpx", "nmap", "masscan", "nuclei"]
        selected = brain._select_tools(INTENT_PASSIVE_RECON, available, ScanMode.BUG_BOUNTY)
        
        # Masscan should be disabled or deprioritized in bug bounty
        if "masscan" in selected:
            # Should be at lower priority
            assert selected.index("masscan") > len(selected) // 2


class TestStrategosScoringMechanism:
    """Test the tool scoring/prioritization logic."""
    
    def test_higher_score_tools_selected_first(self):
        """Higher scoring tools should be selected first."""
        brain = Strategos()
        
        tool_def_high = {"cost": 1, "phase": 1}
        tool_def_low = {"cost": 10, "phase": 5}
        
        score_high = brain._calculate_score(tool_def_high, ScanMode.STANDARD)
        score_low = brain._calculate_score(tool_def_low, ScanMode.STANDARD)
        
        # Lower cost should mean higher score
        assert score_high > score_low
    
    def test_stealth_mode_penalizes_aggressive_tools(self):
        """Stealth mode should penalize high-cost tools."""
        brain = Strategos()
        
        aggressive_tool = {"cost": 10, "phase": 5}
        
        score_standard = brain._calculate_score(aggressive_tool, ScanMode.STANDARD)
        score_stealth = brain._calculate_score(aggressive_tool, ScanMode.STEALTH)
        
        # Stealth should penalize aggressive tools more
        assert score_stealth <= score_standard


class TestStrategosFindingsIngestion:
    """Test that findings are correctly ingested and tracked."""
    
    def test_findings_added_to_context(self):
        """Findings should be added to context."""
        brain = Strategos()
        brain.context = ScanContext(target="example.com")
        
        findings = [
            {"type": "subdomain", "data": "sub.example.com"},
            {"type": "port", "data": "80/tcp"}
        ]
        
        brain.ingest_findings(findings)
        
        assert len(brain.context.findings) == 2
    
    def test_duplicate_findings_tracked(self):
        """Duplicate findings should not inflate count excessively."""
        brain = Strategos()
        brain.context = ScanContext(target="example.com")
        
        finding = {"type": "subdomain", "data": "sub.example.com", "source": "subfinder"}
        
        brain.ingest_findings([finding])
        brain.ingest_findings([finding])
        
        # Should have 2 entries (we don't dedupe, just track)
        assert len(brain.context.findings) == 2


class TestStrategosWalkAway:
    """Test the 'walk away' logic for bug bounty mode."""
    
    def test_walk_away_on_no_surface_delta(self):
        """Should walk away if no new surface discovered."""
        brain = Strategos()
        brain.context = ScanContext(target="example.com")
        brain.context.phase_index = 3  # After surface enumeration
        brain.context.surface_delta_this_intent = 0
        brain.context.knowledge["mode"] = ScanMode.BUG_BOUNTY
        
        next_intent = brain._decide_next_step(INTENT_SURFACE_ENUMERATION)
        
        # In bug bounty mode with no surface, should terminate (walk away)
        assert next_intent is None, f"Expected None (walk away) but got {next_intent}"
