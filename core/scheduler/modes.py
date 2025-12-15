# ============================================================================
# core/scheduler/modes.py
# Modes Module
# ============================================================================
#
# PURPOSE:
# This module is part of the scheduler package in SentinelForge.
# [Specific purpose based on module name: modes]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#
# ============================================================================

"""
core/scheduler/modes.py
Defines Scan Modes and Registry Overlays.
Allows "Bug Bounty Mode" to re-weight tools without rewriting them.
"""

from typing import Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass, field

class ScanMode(Enum):
    STANDARD = "standard"
    BUG_BOUNTY = "bug_bounty"
    STEALTH = "stealth"

@dataclass
class ToolOverlay:
    """Modifies a tool's base definition."""
    disabled: bool = False
    cost_modifier: int = 0
    gate_modifier: Optional[list] = None
    phase_modifier: Optional[int] = None
    intent_modifier: Optional[str] = None
    
    # Priority boost (higher = chosen first)
    priority_boost: int = 0

class ModeRegistry:
    """
    Defines the Overlays for each Mode.
    """
    
    # Bug Bounty Mode: 
    # - Disable heavy/loud tools
    # - Prioritize logic/smart tools
    BUG_BOUNTY_OVERLAY: Dict[str, ToolOverlay] = {
        # Disable Heavy Artillery
        "masscan": ToolOverlay(disabled=True),
        "amass": ToolOverlay(disabled=True), # Too slow/heavy usually
        "dirsearch": ToolOverlay(cost_modifier=1), # Make it expensive
        
        # Boost Smart Tools
        "httpx": ToolOverlay(priority_boost=10),
        "whatweb": ToolOverlay(priority_boost=5),
        "subjack": ToolOverlay(priority_boost=5), # High impact, low noise
        
        # Restrict Noisy Tools
        "nuclei": ToolOverlay(cost_modifier=1), # Nuanced: Nuclei is loud
        "gobuster": ToolOverlay(disabled=True), # Brute force is boring
        "feroxbuster": ToolOverlay(disabled=True)
    }
    
    STEALTH_OVERLAY: Dict[str, ToolOverlay] = {
        "nmap": ToolOverlay(disabled=True), # Too loud
        "masscan": ToolOverlay(disabled=True),
        "nuclei": ToolOverlay(disabled=True),
        "dirsearch": ToolOverlay(disabled=True),
        # Only passive allowed essentially or very light active
    }

    @staticmethod
    def get_overlay(mode: ScanMode) -> Dict[str, ToolOverlay]:
        if mode == ScanMode.BUG_BOUNTY:
            return ModeRegistry.BUG_BOUNTY_OVERLAY
        if mode == ScanMode.STEALTH:
            return ModeRegistry.STEALTH_OVERLAY
        return {}
