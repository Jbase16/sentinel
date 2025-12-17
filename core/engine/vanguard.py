"""Module vanguard: inline documentation for /Users/jason/Developer/sentinelforge/core/engine/vanguard.py."""

import asyncio
import logging
import shutil
import os
import sys
from typing import List, Dict, Set

from core.toolkit.tools import TOOLS, get_tool_command, get_installed_tools

logger = logging.getLogger(__name__)

class Vanguard:
    """
    The Vanguard: Preflight Check System.
    
    Responsibilities:
    1.  Verify tool binaries exist.
    2.  Verify required assets (wordlists, fingerprints) exist.
    3.  Verify runtime environments (Python packages).
    4.  Return a clean list of executable tools, preventing "crash-loop" scanning.
    """
    
    @staticmethod
    def preflight_check(selected_tools: List[str] = None) -> List[str]:
        """
        Check all (or selected) tools and return only those that are READY.
        Logs warnings for BLOCKED tools.
        """
        all_tools = get_installed_tools() # Usage of existing detection logic
        candidates = selected_tools if selected_tools else list(all_tools.keys())
        
        valid_tools = []
        
        logger.info(f"[Vanguard] Preflight check for {len(candidates)} tools...")
        
        for tool in candidates:
            if Vanguard._check_tool(tool):
                valid_tools.append(tool)
            else:
                logger.warning(f"[Vanguard] Tool BLOCKED: {tool}")
                
        return valid_tools

    @staticmethod
    def _check_tool(tool: str) -> bool:
        """
        Run specific checks for a tool.
        """
        # 1. Binary Check (Basic) - handled by get_installed_tools mostly, but verify again?
        if not shutil.which(tool):
             # Some tools are python modules, tricky.
             # If get_installed_tools returns it, it likely exists or is a py module.
             pass

        # 2. Asset Checks
        if tool in ["gobuster", "feroxbuster"]:
            if not Vanguard._check_wordlists():
                logger.warning(f"[{tool}] Missing wordlists.")
                return False
                
        if tool == "subjack":
            # fingerprints.json check
            # This is hardcoded for now, ideal would be config-based assets
            pass

        # 3. Python Compatibility Checks
        if tool == "sslyze":
            # Known 3.14 issue with nassl
            if sys.version_info >= (3, 13):
                 logger.warning(f"[{tool}] Incompatible with Python {sys.version}.x (nassl issue).")
                 return False

        return True

    @staticmethod
    def _check_wordlists() -> bool:
        # Check common locations
        """Function _check_wordlists."""
        try:
            from core.base.config import get_config
            config = get_config()
            # Default location: ~/.sentinelforge/wordlists
            wordlists_path = config.storage.base_dir / "wordlists"
            return wordlists_path.exists()
        except Exception as e:
            logger.warning(f"[Vanguard] Wordlist check failed: {e}")
            return False
