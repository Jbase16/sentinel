# core/action_dispatcher.py
# Validates and dispatches autonomous actions suggested by the AI.

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class ActionDispatcher:
    """
    Safety layer for autonomous actions.
    Prevents infinite loops and validates tool requests.
    """
    
    ALLOWED_TOOLS = ["nmap", "nikto", "httpx", "dnsx", "sslscan", "whois"]
    MAX_DEPTH = 3  # Max recursion depth for autonomous tasks
    
    def __init__(self):
        self.history = set() # Track (tool, target_signature) to prevent dupes

    def validate_action(self, action: Dict, target: str) -> Optional[Dict]:
        """
        Checks if an action is safe and valid.
        Returns the validated action dict or None.
        """
        tool = action.get("tool", "").lower()
        args = action.get("args", [])
        reason = action.get("reason", "")
        
        if tool not in self.ALLOWED_TOOLS:
            logger.warning(f"AI suggested blocked tool: {tool}")
            return None
            
        # Create a signature to detect duplicates
        # Simple signature: tool + args string
        signature = f"{tool}:{sorted(args)}"
        
        if signature in self.history:
            logger.info(f"Skipping duplicate action: {signature}")
            return None
            
        self.history.add(signature)
        
        return {
            "tool": tool,
            "args": args,
            "target": target, # In a real app, we might parse target from args if it changed
            "reason": reason
        }
