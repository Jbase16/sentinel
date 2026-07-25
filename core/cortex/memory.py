
from enum import Enum
from typing import Dict, List, Any

class NodeType(Enum):
    ASSET = "asset"
    FINDING = "finding"
    VULNERABILITY = "vulnerability"

class KnowledgeGraph:
    """
    In-memory representation of the knowledge graph (nodes and edges).
    Singleton.
    """
    _instance = None
    
    def __init__(self):
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []

    @staticmethod
    def instance():
        if KnowledgeGraph._instance is None:
            KnowledgeGraph._instance = KnowledgeGraph()
        return KnowledgeGraph._instance

    def add_node(self, node: Dict[str, Any]):
        self.nodes.append(node)

    def export_json(self) -> Dict[str, Any]:
        """
        Exports the current graph state as a dictionary.
        Required by GraphAwareChat.
        """
        return {
            "nodes": self.nodes,
            "edges": self.edges
        }
