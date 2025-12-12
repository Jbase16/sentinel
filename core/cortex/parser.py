"""
core/cortex/parser.py
Abstract Base Class for Neuro-Symbolic Parsers.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from .memory import KnowledgeGraph, NodeType, EdgeType

class SignalParser(ABC):
    """
    Base class for parsers that digest tool output and update the Knowledge Graph.
    """
    
    def __init__(self, graph: KnowledgeGraph = None):
        self.graph = graph or KnowledgeGraph.instance()

    @abstractmethod
    def parse(self, tool_name: str, target: str, output: str) -> List[Dict]:
        """
        Parse raw output into structured findings, AND update the graph.
        Returns the findings list for backward compatibility with the old engine.
        """
        pass

    def ingest(self, tool_name: str, target: str, output: str):
        """
        Public entry point. Wraps parse with error handling.
        """
        try:
            self.parse(tool_name, target, output)
        except Exception as e:
            # Fallback to saving raw finding?
            pass
