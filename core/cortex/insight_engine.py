from typing import List, Dict, Any, Optional
import json
import time
import logging
from core.ai.ai_engine import AIEngine
from core.cortex.models import InsightRequest, InsightResponse, InsightClaim

logger = logging.getLogger(__name__)

class InsightEngine:
    """
    Generates semantic insights using LLM.
    Strictly validates output schema to prevent hallucination.
    """
    def __init__(self):
        self.ai = AIEngine()
        
    async def generate_insights(self, request: InsightRequest, graph_context: Dict[str, Any]) -> InsightResponse:
        """
        Generates insights for specific nodes based on graph context.
        """
        # 1. Prepare Prompt
        # We need to serialize the relevant slice of the graph for the LLM.
        # Including whole graph is too big. Just include target nodes + neighbors.
        # For phase 11, let's assume we pass enough context.
        
        prompt = self._construct_prompt(request, graph_context)
        
        # 2. Call LLM (Safe Generation)
        # We expect JSON output.
        system_prompt = (
            "You are a cyber-security analyst. Analyze the provided graph topology data. "
            "Output MUST be strict JSON matching this schema: "
            "{ 'insights': [ { 'claim': 'string', 'evidence': ['node_id_1'], 'confidence': 0.95 } ] }"
        )
        
        try:
            raw_response = await self.ai.safe_generate(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True
            )
            
            if not raw_response:
                logger.warning("Insight generation failed (empty response).")
                return InsightResponse(
                    graph_hash=request.graph_hash,
                    insights=[]
                )
            
            # 3. Parse & Validate
            data = json.loads(raw_response)
            valid_insights = []
            
            for item in data.get("insights", []):
                # Validate evidence anchors
                evidence_refs = item.get("evidence", [])
                valid_refs = [ref for ref in evidence_refs if self._validate_ref(ref, graph_context)]
                
                # Downgrade or Skip if evidence is missing/invalid
                if not valid_refs:
                    # Weak claim, maybe downgrade confidence or skip
                    continue
                    
                valid_insights.append(InsightClaim(
                    claim=item.get("claim", "Unknown Insight"),
                    evidence=valid_refs,
                    confidence=float(item.get("confidence", 0.5))
                ))
                
            return InsightResponse(
                graph_hash=request.graph_hash,
                insights=valid_insights
            )
            
        except Exception as e:
            logger.error(f"Insight generation error: {e}")
            # Fail safe
            return InsightResponse(graph_hash=request.graph_hash, insights=[])

    def _construct_prompt(self, request: InsightRequest, graph_context: Dict[str, Any]) -> str:
        # Construct a minimized text representation of the nodes of interest
        nodes_of_interest = request.target_nodes
        details = []
        
        # Simple lookup - in real impl, use a graph index
        # Assuming graph_context has "nodes" list
        all_nodes = {n["id"]: n for n in graph_context.get("nodes", [])}
        
        for nid in nodes_of_interest:
            if nid in all_nodes:
                node = all_nodes[nid]
                details.append(f"Node: {nid}, Type: {node.get('type')}, Attrs: {node.get('attributes')}")
        
        return f"Analyze these nodes for '{request.insight_type}':\n" + "\n".join(details)

    def _validate_ref(self, ref: str, graph_context: Dict[str, Any]) -> bool:
        # Check if ref exists in graph_context nodes/edges
        # Optimizable with set lookup
        # For now, linear scan is fine for small context
        # TODO: Build an index once per request
        for n in graph_context.get("nodes", []):
            if n["id"] == ref: return True
        return False
