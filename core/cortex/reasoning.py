"""
core/cortex/reasoning.py
The Logic Core: Neural Reasoning via Sentinel-9B (over AIEngine).
"""

import logging
import json
from typing import List, Dict, Set
from core.cortex.memory import KnowledgeGraph, NodeType, EdgeType
from core.ai_engine import AIEngine

logger = logging.getLogger(__name__)

# 🛡️ MINDSET PRIMING
SYSTEM_PROMPT = """You are Sentinel, an autonomous AI Bug Bounty Hunter. 
Your goal is to identify high-impact security vulnerabilities by reasoning like a human researcher.
Analyze the provided Attack Surface Context and think step-by-step:
1. Identify the most critical assets and technologies.
2. Correlate open ports with potential service misconfigurations.
3. Recall specific CVEs or exploit classes relevant to the stack (e.g., Apache, PHP, IoT).
4. Propose a precise, actionable plan using the available tools:
   - 'nmap': Port scanning
   - 'nikto': Web server scanning
   - 'nuclei': Vulnerability scanning (Give specific args like -t cves/)
   - 'gobuster': Directory enumeration
   - 'wraith_evasion': Stealthy probing
   - 'ghost_logic': Flow analysis

FORMAT OUTPUT AS JSON ONLY:
[
  {"tool": "tool_name", "target": "target_ip_or_url", "args": ["arg1", "arg2"], "reason": "Detailed technical justification"}
]
Do not output markdown code blocks. Just the raw JSON string.
"""

class ReasoningEngine:
    """
    Analyzes the Knowledge Graph using Sentinel-9B (via AIEngine) to derive 'Next Best Actions'.
    """
    
    def __init__(self):
        self.graph = KnowledgeGraph.instance()
        self.ai = AIEngine.instance()
        self._proposed_actions: Set[str] = set()

    def analyze(self) -> Dict[str, object]:
        """
        Main analysis loop.
        Constructs context -> Neural Inference -> Opportunities.
        """
        context_str = self._get_graph_context_str()
        
        opportunities = []
        
        # Call Neural Brain if available
        if self.ai.client:
            opportunities = self._neural_reasoning(context_str)
        
        # Fallback / Augment with heuristics
        if not opportunities:
            logger.info("[ReasoningEngine] Neural output empty or failed, falling back to heuristics.")
            opportunities = self._heuristic_reasoning()
        
        risks = self._assess_risks()
        
        return {
            "opportunities": opportunities,
            "risks": risks,
            "graph_summary": {
                "nodes": self.graph._graph.number_of_nodes(),
                "edges": self.graph._graph.number_of_edges()
            }
        }

    def _get_graph_context_str(self) -> str:
        """Summarize graph state for the LLM."""
        assets = self.graph.find_all(NodeType.ASSET)
        ports = self.graph.find_all(NodeType.PORT)
        techs = self.graph.find_all(NodeType.TECH)
        
        summary = "ATTACK SURFACE CONTEXT:\n"
        
        if not assets:
            return summary + "No assets found yet."
            
        for asset in assets:
            a_id = asset.get('id', 'unknown')
            summary += f"- Asset: {a_id}\n"
            
            # Find related ports
            asset_ports = []
            for p in ports:
                if p['id'].startswith(a_id): 
                    asset_ports.append(f"{p.get('port')}/{p.get('protocol', 'tcp')}")
            if asset_ports:
                summary += f"  Open Ports: {', '.join(asset_ports)}\n"
                
            # Find related tech
            asset_techs = []
            neighbors = self.graph.get_neighbors(a_id, EdgeType.USES_TECH)
            for n in neighbors:
                asset_techs.append(f"{n.get('name')} {n.get('version', '')}")
            if asset_techs:
                summary += f"  Technologies: {', '.join(asset_techs)}\n"

        return summary

    def _neural_reasoning(self, context_str: str) -> List[Dict]:
        """Query Sentinel-9B for the next move."""
        if not self.ai.client:
            return []
            
        logger.info("[ReasoningEngine] Engaging Neural Synapse...")
        try:
            # We use the raw generate method which returns a string (possibly JSON)
            # System prompt primes the JSON format.
            response = self.ai.client.generate(prompt=context_str, system=SYSTEM_PROMPT, force_json=True)
            
            if not response:
                return []

            logger.info(f"[ReasoningEngine] Neural Thought: {response[:100]}...") 
            
            # Sanitize response
            clean_response = response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            
            ops = json.loads(clean_response)
            
            # Validate format
            valid_ops = []
            for op in ops:
                if "tool" in op and "target" in op:
                    action_key = f"{op['tool']}:{op['target']}:{op.get('args', [])}"
                    if action_key not in self._proposed_actions:
                        self._proposed_actions.add(action_key)
                        valid_ops.append(op)
            
            return valid_ops
            
        except Exception as e:
            logger.error(f"[ReasoningEngine] Neural Inference failed: {e}")
            return []

    def _heuristic_reasoning(self) -> List[Dict]:
        """Legacy rule-based logic (Scan Logic v1)"""
        ops = []
        ports = self.graph.find_all(NodeType.PORT)
        for p in ports:
            port = p.get('port')
            if port in [80, 443, 8080]:
                target = p.get('id', '').split(':')[0]
                action_key = f"nikto:{target}:{port}"
                if action_key not in self._proposed_actions:
                    self._proposed_actions.add(action_key)
                    ops.append({
                        "tool": "nikto", 
                        "target": target, 
                        "args": ["-h", target], 
                        "reason": "Heuristic fallback: HTTP port detected"
                    })
        return ops

    def _assess_risks(self) -> List[Dict]:
        risks = []
        findings = self.graph.find_all(NodeType.FINDING)
        for finding in findings:
            severity = finding.get('severity', 'INFO').upper()
            if severity in ['HIGH', 'CRITICAL']:
                risks.append({
                    "id": finding.get('id', ''),
                    "type": finding.get('type', 'unknown'),
                    "severity": severity,
                    "message": finding.get('message', '')[:200],
                    "tool": finding.get('tool', 'unknown')
                })
        return risks
    
    def clear_proposed_actions(self):
        self._proposed_actions.clear()

reasoning_engine = ReasoningEngine()
