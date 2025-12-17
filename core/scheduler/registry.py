#
# PURPOSE:
# This module is part of the scheduler package in SentinelForge.
# [Specific purpose based on module name: registry]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
core/scheduler/registry.py
The Enhanced Tool Registry for Strategos.
Maps tools to Phases, Costs, Prerequisites, and INTENTS.
"""

from typing import Dict, List, Any
from core.scheduler.intents import (
    INTENT_PASSIVE_RECON,
    INTENT_ACTIVE_LIVE_CHECK,
    INTENT_SURFACE_ENUMERATION,
    INTENT_PARAMETER_FUZZING,
    INTENT_VULN_SCANNING,
    INTENT_HEAVY_ARTILLERY
)

# Phase Definitions
PHASE_1_PASSIVE = 1
PHASE_2_LIGHT = 2
PHASE_3_SURFACE = 3
PHASE_4_DEEP = 4
PHASE_5_HEAVY = 5

class ToolRegistry:
    """
    Metadata Overlay for the standard TOOLS definitions.
    """
    
    METADATA: Dict[str, Dict[str, Any]] = {
        # --- Phase 1: Passive (Zero Touch / Public Data) ---
        "subfinder": {
            "intent": INTENT_PASSIVE_RECON,
            "phase": PHASE_1_PASSIVE,
            "cost": 1,
            "intrusiveness": 0,
            "gates": [] # Always allowed
        },
        "assetfinder": {
            "intent": INTENT_PASSIVE_RECON,
            "phase": PHASE_1_PASSIVE,
            "cost": 1, 
            "intrusiveness": 0,
        },
        "dnsx": {
            "intent": INTENT_PASSIVE_RECON,
            "phase": PHASE_1_PASSIVE,
            "cost": 1,
            "intrusiveness": 0, # Mostly DNS
        },
        "hakrevdns": {
            "intent": INTENT_PASSIVE_RECON,
            "phase": PHASE_1_PASSIVE,
            "cost": 1,
            "intrusiveness": 0,
        },
        
        # --- Phase 2: Light Active (Touch but gentle) ---
        "httpx": {
            "intent": INTENT_ACTIVE_LIVE_CHECK,
            "phase": PHASE_2_LIGHT,
            "cost": 2,
            "intrusiveness": 1, 
        },
        "httprobe": {
            "intent": INTENT_ACTIVE_LIVE_CHECK,
            "phase": PHASE_2_LIGHT,
            "cost": 2,
            "intrusiveness": 1,
        },
        "whatweb": {
            "intent": INTENT_ACTIVE_LIVE_CHECK,
            "phase": PHASE_2_LIGHT,
            "cost": 1,
            "intrusiveness": 1,
            "gates": ["protocol:http", "protocol:https"]
        },
        "wafw00f": {
            "intent": INTENT_ACTIVE_LIVE_CHECK,
            "phase": PHASE_2_LIGHT,
            "cost": 1,
            "intrusiveness": 1,
             "gates": ["protocol:http", "protocol:https"]
        },
        "sslyze": {
            "intent": INTENT_ACTIVE_LIVE_CHECK,
            "phase": PHASE_2_LIGHT,
            "cost": 2,
            "intrusiveness": 1,
            "gates": ["protocol:https"]
        },
        "pshtt": {
            "intent": INTENT_ACTIVE_LIVE_CHECK,
            "phase": PHASE_2_LIGHT,
            "cost": 2,
            "intrusiveness": 1,
            "gates": ["protocol:https"]
        },
        "testssl": {
            "intent": INTENT_ACTIVE_LIVE_CHECK,
            "phase": PHASE_2_LIGHT,
            "cost": 3, 
            "intrusiveness": 1,
            "gates": ["protocol:https"]
        },
        
        # --- Phase 3: Surface Mapping (Crawling/Enumeration) ---
        "nmap": {
             "intent": INTENT_SURFACE_ENUMERATION,
            "phase": PHASE_3_SURFACE,
            "cost": 2,
            "intrusiveness": 2,
            "gates": [] 
        },
        "naabu": {
            "intent": INTENT_SURFACE_ENUMERATION,
            "phase": PHASE_3_SURFACE,
            "cost": 2,
            "intrusiveness": 2,
        },
        "hakrawler": {
            "intent": INTENT_SURFACE_ENUMERATION,
            "phase": PHASE_3_SURFACE,
            "cost": 2,
            "intrusiveness": 2,
            "gates": ["protocol:http", "protocol:https"]
        },
         "feroxbuster": {
            "intent": INTENT_SURFACE_ENUMERATION,
            "phase": PHASE_3_SURFACE,
            "cost": 3,
            "intrusiveness": 3, 
            "gates": ["protocol:http", "protocol:https"]
        },
         "eyewitness": {
            "intent": INTENT_SURFACE_ENUMERATION,
            "phase": PHASE_3_SURFACE,
            "cost": 3,
            "intrusiveness": 2,
            "gates": ["protocol:http", "protocol:https"]
        },
         "gobuster": {
             "intent": INTENT_SURFACE_ENUMERATION,
             "phase": PHASE_3_SURFACE,
             "cost": 3,
             "intrusiveness": 3,
             "gates": ["protocol:http", "protocol:https"]
        },
        "dirsearch": {
            "intent": INTENT_SURFACE_ENUMERATION,
            "phase": PHASE_3_SURFACE,
            "cost": 3,
            "intrusiveness": 3, 
            "gates": ["protocol:http", "protocol:https"]
        },
        
        # --- Phase 4: Conditional Deep (Specifics) ---
        "nuclei": {
            "intent": INTENT_VULN_SCANNING,
            "phase": PHASE_4_DEEP,
            "cost": 2,
            "intrusiveness": 3,
            "gates": ["protocol:http", "protocol:https"]
        },
        "nikto": {
            "intent": INTENT_VULN_SCANNING,
            "phase": PHASE_4_DEEP,
            "cost": 2,
            "intrusiveness": 3, 
            "gates": ["protocol:http", "protocol:https"]
        },
        "jaeles": {
            "intent": INTENT_VULN_SCANNING,
            "phase": PHASE_4_DEEP,
            "cost": 2,
            "intrusiveness": 3,
            "gates": ["protocol:http", "protocol:https"]
        },
        "wfuzz": {
            "intent": INTENT_VULN_SCANNING,
            "phase": PHASE_4_DEEP,
            "cost": 3,
            "intrusiveness": 4,
            "gates": ["protocol:http", "protocol:https"]
        },
        "subjack": {
             "intent": INTENT_VULN_SCANNING,
             "phase": PHASE_4_DEEP,
             "cost": 1,
             "intrusiveness": 1,
             "gates": ["type:subdomain"] # Only run on subs
        },
        
        # --- Phase 5: Heavy Artillery (Opt-in) ---
        "masscan": {
             "intent": INTENT_HEAVY_ARTILLERY,
             "phase": PHASE_5_HEAVY,
             "cost": 3, 
             "intrusiveness": 5, # Nuclear
             "aggressive": True
        },
        "amass": {
             "intent": INTENT_HEAVY_ARTILLERY,
             "phase": PHASE_5_HEAVY,
             "cost": 3,
             "intrusiveness": 2
        }
    }
    
    @classmethod
    def get(cls, tool_name: str, mode: Any = None) -> Dict[str, Any]:
        """
        Get tool definition, applying Mode Overlay if present.
        """
        from core.scheduler.modes import ModeRegistry, ToolOverlay
        
        base = cls.METADATA.get(tool_name, {
            "phase": 99, 
            "cost": 1, 
            "gates": []
        }).copy()
        
        if mode:
            overlay_map = ModeRegistry.get_overlay(mode)
            overlay = overlay_map.get(tool_name)
            if overlay:
                if overlay.disabled:
                    base["disabled"] = True # Mark as disabled
                if overlay.cost_modifier:
                    base["cost"] = base.get("cost", 1) + overlay.cost_modifier
                # Can extend for gating logic
                
        return base

    @classmethod
    def get_tools_for_phase(cls, phase: int, mode: Any = None) -> List[str]:
        # Legacy support mostly
        """Function get_tools_for_phase."""
        candidates = [t for t, meta in cls.METADATA.items() if meta["phase"] == phase]
        if mode:
            return cls._filter_by_mode(candidates, mode)
        return candidates
    
    @classmethod
    def get_tools_for_intent(cls, intent: str, mode: Any = None) -> List[str]:
        """
        Returns all tools capable of fulfilling this intent.
        Filters disabled tools based on Mode.
        """
        candidates = [t for t, meta in cls.METADATA.items() if meta.get("intent") == intent]
        if mode:
            return cls._filter_by_mode(candidates, mode)
        return candidates

    @classmethod
    def _filter_by_mode(cls, tools: List[str], mode: Any) -> List[str]:
        """Function _filter_by_mode."""
        from core.scheduler.modes import ModeRegistry
        overlay_map = ModeRegistry.get_overlay(mode)
        
        filtered = []
        for t in tools:
            overlay = overlay_map.get(t)
            if overlay and overlay.disabled:
                continue
            filtered.append(t)
            
        # Optional: Sort by priority boost?
        # For now just filter.
        return filtered
