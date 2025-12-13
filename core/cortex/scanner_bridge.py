"""
core/cortex/scanner_bridge.py
The Bridge: Routes tool output from ScannerEngine -> Cortex Parsers.
Uses the comprehensive raw_classifier.py for parsing, with Cortex parsers
for graph updates.
"""

import logging
from typing import List, Dict

from core.raw_classifier import classify as raw_classify
from core.cortex.parsers.nmap import NmapParser
from core.cortex.parsers.httpx import HttpxParser
from core.cortex.memory import KnowledgeGraph, NodeType, EdgeType

logger = logging.getLogger(__name__)

class ScannerBridge:
    """
    Static entry point for the Cortex engine.
    Uses raw_classifier for comprehensive parsing, then updates the Knowledge Graph.
    """
    
    _graph_parsers = {
        "nmap": NmapParser(),
        "httpx": HttpxParser(),
    }

    @classmethod
    def classify(cls, tool: str, target: str, output: str) -> List[Dict]:
        """
        Routes the output through raw_classifier for comprehensive parsing,
        then optionally updates the Knowledge Graph via specialized parsers.
        """
        # 1. Use the comprehensive raw_classifier for all tools
        findings = []
        try:
            findings = raw_classify(tool, target, output)
        except Exception as e:
            logger.error(f"raw_classifier failed for {tool}: {e}", exc_info=True)
            findings = []
        
        # 2. Also update Knowledge Graph if we have a specialized parser
        graph_parser = cls._graph_parsers.get(tool)
        if graph_parser:
            try:
                graph_parser.parse(tool, target, output)
            except Exception as e:
                logger.warning(f"Graph parser failed for {tool}: {e}")
        else:
            # Add basic asset node for tools without specialized parsers
            cls._add_basic_graph_nodes(tool, target, findings)
        
        # 3. Return findings from raw_classifier (or minimal fallback)
        if not findings:
            return cls._fallback(tool, target, output)
        
        return findings

    @classmethod
    def _add_basic_graph_nodes(cls, tool: str, target: str, findings: List[Dict]):
        """Add basic nodes to Knowledge Graph from findings."""
        graph = KnowledgeGraph.instance()
        
        # Always add the target as an asset
        graph.add_node(target, NodeType.ASSET, {"tool": tool})
        
        # Add findings as linked nodes
        for finding in findings:
            finding_type = finding.get("type", "unknown")
            severity = finding.get("severity", "INFO")
            
            # Create a finding node
            finding_id = f"{target}:{tool}:{finding_type}"
            graph.add_node(finding_id, NodeType.FINDING, {
                "finding_type": finding_type,  # Use finding_type to avoid conflict with NodeType parameter
                "severity": severity,
                "tool": tool,
                "message": finding.get("message", "")[:200]
            })
            
            # Link asset to finding
            graph.add_edge(target, finding_id, EdgeType.EXPOSES)

    @classmethod
    def _fallback(cls, tool: str, target: str, output: str) -> List[Dict]:
        """
        Minimal fallback if parsing produces no results.
        """
        return [{
            "tool": tool,
            "type": "raw_output",
            "target": target,
            "severity": "INFO",
            "message": f"{tool} completed",
            "proof": output[:1000] if output else "No output",
            "tags": ["raw"],
            "families": [],
            "metadata": {"output_length": len(output) if output else 0}
        }]
