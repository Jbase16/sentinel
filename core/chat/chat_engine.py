#
# PURPOSE:
# This module is part of the chat package in SentinelForge.
# [Specific purpose based on module name: chat_engine]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
core/chat/chat_engine.py
The Context-Aware AI Chat.
It knows the state of the Knowledge Graph.
"""

import json
from typing import Dict, List, Any
from core.ai.ai_engine import AIEngine
from core.cortex.memory import KnowledgeGraph, NodeType
from core.data.findings_store import findings_store

class GraphAwareChat:
    """Class GraphAwareChat."""
    _instance = None
    
    @staticmethod
    def instance():
        """Function instance."""
        if GraphAwareChat._instance is None:
            GraphAwareChat._instance = GraphAwareChat()
        return GraphAwareChat._instance

    def __init__(self):
        self.ai = AIEngine.instance()
        self.graph = KnowledgeGraph.instance()

    def query(self, user_question: str) -> str:
        """
        Answers user questions with full context of the current mission.
        """
        # 1. Gather Context
        context_data = self._gather_context()
        
        # 2. Prompt Engineering
        system_prompt = (
            "You are Sentinel, an Autonomous AI Offensive Security Agent. "
            "You have access to a live Knowledge Graph of the target. "
            "Answer the user's questions based strictly on the provided context. "
            "If the user asks about vulnerabilities, cite the specific findings. "
            "Be concise, technical, and 'God-Tier'. "
            "Do not hallucinate findings not in the context."
        )
        
        user_prompt = (
            f"User Question: {user_question}\n\n"
            f"Current Mission Context:\n"
            f"{json.dumps(context_data, indent=2)}\n"
        )
        
        # 3. Generate Answer
        if self.ai.client:
            return self.ai.client.generate(user_prompt, system_prompt) or "My neural link is currently offline."
        
        return "AI Engine not connected."

    def _gather_context(self) -> Dict[str, Any]:
        """
        Retrieves relevant high-level state.
        """
        # Get Graph Summary
        nodes = self.graph.export_json().get("nodes", [])
        assets = [n for n in nodes if n["type"] == NodeType.ASSET.value]
        vulns = [n for n in nodes if n.get("risk_score", 0) > 7.0] # High risk only
        
        # Get Findings
        findings = findings_store.get_all()
        critical_findings = [f for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]]
        
        return {
            "assets_count": len(assets),
            "high_risk_nodes": len(vulns),
            "critical_findings": critical_findings[:5], # Top 5
            "latest_logs": "Log gathering not implemented yet." 
        }
