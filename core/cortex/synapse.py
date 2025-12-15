# ============================================================================
# core/cortex/synapse.py
# Synapse Module
# ============================================================================
#
# PURPOSE:
# This module is part of the cortex package in SentinelForge.
# [Specific purpose based on module name: synapse]
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
core/cortex/synapse.py
The Neural Interface: Connects the symbolic Knowledge Graph to the LLM for semantic verification.
"""

from __future__ import annotations

import logging
import json
from typing import Dict, Optional
from core.ai.ai_engine import AIEngine

logger = logging.getLogger(__name__)

class Synapse:
    """
    Acts as a specialized worker that uses the LLM to 'think' about specific security artifacts.
    Unlike the generic Chat interface, Synapse tasks are highly structured.
    """
    
    _instance = None
    
    @staticmethod
    def instance():
        if Synapse._instance is None:
            Synapse._instance = Synapse()
        return Synapse._instance
        
    def __init__(self):
        self.ai = AIEngine.instance()

    def verify_vulnerability(self, vulnerability_type: str, context: str) -> float:
        """
        Asks the LLM: "Given this context (code/output), how likely is this vulnerability?"
        Returns a probability score (0.0 - 1.0).
        """
        if not self.ai.client:
            return 0.5 # Unknown/Fallback

        system_prompt = (
             "You are a Senior Vulnerability Researcher. "
             "Your task is to VERIFY if a specific vulnerability exists in the provided technical context. "
             "Return ONLY a JSON object: {\"probability\": <0.0-1.0>, \"reason\": \"<brief explanation>\"}"
        )
        
        user_prompt = (
            f"Vulnerability Type: {vulnerability_type}\n"
            f"Context Material:\n{context[:4000]}\n\n"
            "Analyze the likelihood of this being a True Positive."
        )
        
        try:
            response = self.ai.client.generate(user_prompt, system_prompt)
            if not response:
                return 0.0
            
            data = json.loads(response)
            prob = float(data.get("probability", 0.0))
            logger.info(f"Synapse Verification: {vulnerability_type} -> {prob} ({data.get('reason')})")
            return prob
        except Exception as e:
            logger.error(f"Synapse verification failed: {e}")
            return 0.0

    def extract_tech_stack(self, raw_headers: str, html_snippet: str) -> Dict[str, str]:
        """
        Extracts technology versions from raw HTTP data using LLM reasoning.
        """
        if not self.ai.client:
            return {}

        system_prompt = (
            "You are a Fingerprinting Engine. "
            "Extract technologies and versions from the provided HTTP headers and HTML snippet. "
            "Return JSON: {\"technologies\": {\"<name>\": \"<version_or_unknown>\"}}"
        )

        user_prompt = (
            f"Headers:\n{raw_headers}\n\n"
            f"HTML Snippet:\n{html_snippet[:2000]}\n\n"
            "Identify the stack."
        )
        
        try:
            response = self.ai.client.generate(user_prompt, system_prompt)
            if not response:
                return {}
            data = json.loads(response)
            return data.get("technologies", {})
        except Exception:
            return {}
