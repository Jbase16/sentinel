"""Module action_dispatcher: inline documentation for /Users/jason/Developer/sentinelforge/core/base/action_dispatcher.py."""
#
# PURPOSE:
# The AI can suggest running security tools autonomously (like "run nmap on this target").
# This module ensures dangerous operations require human approval before execution.
#
# SECURITY MODEL:
# - Safe tools (passive reconnaissance): Auto-approve
# - Restricted tools (active scanning, system modification): Require human approval
# - Unknown tools: Block completely
#
# WHY THIS MATTERS:
# Prevents the AI from:
# - Running destructive scans that could crash services
# - Triggering security alerts unnecessarily
# - Modifying the system without permission (brew install, pip install, etc.)
#
# KEY CONCEPTS:
# - Singleton: One global queue of pending actions
# - Observer Pattern: UI subscribes to action requests/approvals
# - Deduplication: Don't run the same scan twice
#

import logging
import uuid
from typing import List, Dict, Optional
from core.utils.observer import Observable, Signal
from core.base.config import get_config

logger = logging.getLogger(__name__)

class ActionDispatcher(Observable):
    """
    Safety layer for autonomous AI actions.
    
    Acts as a gatekeeper between the AI's suggestions and actual tool execution.
    Maintains a queue of actions awaiting human approval.
    
    Design Pattern: Singleton (one global approval queue)
    Observable: Emits signals when actions need approval or get approved
    """
    
    # Signal emitted when AI suggests an action needing approval
    # UI can subscribe to this to show approval dialog
    # Emits: (action_id: str, action_details: dict)
    action_needed = Signal()
    
    # Signal emitted when an action is approved (either auto or manual)
    # Scan orchestrator subscribes to actually execute the tool
    # Emits: (action_details: dict)
    action_approved = Signal()
    
    # Singleton instance (one global dispatcher)
    _instance = None

    @staticmethod
    def instance():
        """
        Get the global ActionDispatcher singleton.
        
        Returns:
            The shared ActionDispatcher instance
        """
        if ActionDispatcher._instance is None:
            ActionDispatcher._instance = ActionDispatcher()
        return ActionDispatcher._instance

    def __init__(self):
        """
        Initialize the action dispatcher.
        
        Sets up the pending action queue and deduplication history.
        Should only be called once by instance() method.
        """
        # Initialize Observable base class (handles signal management)
        super().__init__()
        
        # Set of (tool, args) combinations we've already processed
        # Prevents running "nmap example.com" twice if AI suggests it multiple times
        self.history = set()
        
        # Dictionary of actions awaiting approval: {action_id: action_details}
        # When human approves, we pop from here and emit action_approved signal
        self._pending_actions: Dict[str, Dict] = {}

    def request_action(self, action: Dict, target: str) -> Optional[str]:
        """
        Process an AI-suggested action and decide what to do with it.
        
        Decision logic:
        1. Check if we've already done this action (deduplication)
        2. Check if tool is "safe" → auto-approve
        3. Check if tool is "restricted" → queue for human approval
        4. Otherwise → reject (unknown/dangerous tool)
        
        Args:
            action: Dictionary with {tool: str, args: list, reason: str}
            target: What we're scanning (for logging/context)
            
        Returns:
            "AUTO_APPROVED" - Safe tool, already executed
            "PENDING" - Restricted tool, waiting for approval
            "DROPPED" - Duplicate or unknown tool, rejected
        """
        # Load config to check safe/restricted tool lists
        config = get_config()
        
        # Extract action details
        tool = action.get("tool", "").lower()  # Tool name (e.g., "nmap")
        args = action.get("args", [])  # Arguments (e.g., ["-p80,443", "example.com"])
        reason = action.get("reason", "")  # Why AI suggests this (e.g., "Check for open ports")
        
        # Deduplication: have we already processed this exact action?
        # Signature = "tool:sorted_args" (e.g., "nmap:['-p80,443', 'example.com']")
        signature = f"{tool}:{sorted(args)}"
        if signature in self.history:
            # Already ran this, don't run again
            return "DROPPED"
        # Mark as seen so we don't process it again
        self.history.add(signature)

        # Build complete action record with metadata
        full_action = {
            "id": str(uuid.uuid4()),  # Unique ID for this action request
            "tool": tool,
            "args": args,
            "target": target,
            "reason": reason,  # AI's explanation for why this tool should run
            "timestamp": logging.Formatter.formatTime(logging.Formatter(), logging.LogRecord("",0,"","",0,0,0))
        }

        # Decision 1: Is this a safe tool? (passive reconnaissance)
        if tool in config.scan.safe_tools:
            # Auto-approve and immediately emit for execution
            self.action_approved.emit(full_action)
            return "AUTO_APPROVED"
        
        # Decision 2: Is this a restricted tool? (active scanning, needs approval)
        if tool in config.scan.restricted_tools:
            # Add to pending queue and ask human for approval
            self._pending_actions[full_action["id"]] = full_action
            self.action_needed.emit(full_action["id"], full_action)
            return "PENDING"
            
        # Decision 3: Unknown tool → reject for safety
        logger.warning(f"AI suggested unknown tool: {tool}")
        return "DROPPED"

    def approve_action(self, action_id: str):
        """
        Human approved a pending action - execute it.
        
        Removes action from pending queue and emits approval signal.
        Scan orchestrator will receive the signal and actually run the tool.
        
        Args:
            action_id: UUID of the action to approve
            
        Returns:
            True if action was found and approved, False if not found
        """
        if action_id in self._pending_actions:
            # Remove from pending queue
            action = self._pending_actions.pop(action_id)
            # Emit approval signal (scan orchestrator will execute)
            self.action_approved.emit(action)
            return True
        return False  # Action ID not found (maybe already processed?)

    def deny_action(self, action_id: str):
        """
        Human denied a pending action - discard it.
        
        Simply removes from pending queue without executing.
        
        Args:
            action_id: UUID of the action to deny
            
        Returns:
            True if action was found and denied, False if not found
        """
        if action_id in self._pending_actions:
            # Remove from pending queue without executing
            self._pending_actions.pop(action_id)
            return True
        return False  # Action ID not found

    def get_pending(self) -> List[Dict]:
        """
        Get all actions awaiting human approval.
        
        Used by UI to show the approval queue.
        
        Returns:
            List of action dictionaries with {id, tool, args, target, reason, timestamp}
        """
        return list(self._pending_actions.values())
