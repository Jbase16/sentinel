# core/action_dispatcher.py
# Validates and dispatches autonomous actions suggested by the AI.

import logging
import uuid
from typing import List, Dict, Optional
from core.utils.observer import Observable, Signal
from core.base.config import get_config

logger = logging.getLogger(__name__)

class ActionDispatcher(Observable):
    """
    Safety layer for autonomous actions.
    Manages the queue of actions requiring human approval.
    """
    
    action_needed = Signal() # Emits (action_id, action_details)
    action_approved = Signal() # Emits (action_details)
    
    _instance = None

    @staticmethod
    def instance():
        if ActionDispatcher._instance is None:
            ActionDispatcher._instance = ActionDispatcher()
        return ActionDispatcher._instance

    def __init__(self):
        super().__init__()
        self.history = set() # Track (tool, target_signature) to prevent dupes
        self._pending_actions: Dict[str, Dict] = {}

    def request_action(self, action: Dict, target: str) -> Optional[str]:
        """
        Processes a requested action.
        - If safe: returns "AUTO_APPROVED" and emits action_approved.
        - If restricted: returns "PENDING", stores it, and emits action_needed.
        - If invalid/dupe: returns "DROPPED".
        """
        config = get_config()
        
        tool = action.get("tool", "").lower()
        args = action.get("args", [])
        reason = action.get("reason", "")
        
        # Deduplication
        signature = f"{tool}:{sorted(args)}"
        if signature in self.history:
            return "DROPPED"
        self.history.add(signature)

        full_action = {
            "id": str(uuid.uuid4()),
            "tool": tool,
            "args": args,
            "target": target,
            "reason": reason,
            "timestamp": logging.Formatter.formatTime(logging.Formatter(), logging.LogRecord("",0,"","",0,0,0))
        }

        if tool in config.scan.safe_tools:
            self.action_approved.emit(full_action)
            return "AUTO_APPROVED"
        
        if tool in config.scan.restricted_tools:
            self._pending_actions[full_action["id"]] = full_action
            self.action_needed.emit(full_action["id"], full_action)
            return "PENDING"
            
        logger.warning(f"AI suggested unknown tool: {tool}")
        return "DROPPED"

    def approve_action(self, action_id: str):
        if action_id in self._pending_actions:
            action = self._pending_actions.pop(action_id)
            self.action_approved.emit(action)
            return True
        return False

    def deny_action(self, action_id: str):
        if action_id in self._pending_actions:
            self._pending_actions.pop(action_id)
            return True
        return False

    def get_pending(self) -> List[Dict]:
        return list(self._pending_actions.values())
