"""
core/cortex/memory.py
The Hippocampus of Sentinel: A graph database for tracking security context.
"""

from __future__ import annotations

import logging
import json
import threading
from typing import List, Dict, Optional, Any, Set
from datetime import datetime, timezone
from enum import Enum

import networkx as nx

logger = logging.getLogger(__name__)

class NodeType(str, Enum):
    ASSET = "asset"        # IP, Domain
    PORT = "port"          # 80/tcp
    SERVICE = "service"    # nginx, ssh
    TECH = "tech"          # react, flask
    FINDING = "finding"    # generic vuln/issue
    EXPLOIT = "exploit"    # known exploit path

class EdgeType(str, Enum):
    HAS_PORT = "HAS_PORT"
    RUNS = "RUNS"
    USES_TECH = "USES_TECH"
    EXPOSES = "EXPOSES"      # Asset/Service exposes Finding
    LINKS_TO = "LINKS_TO"    # Hyperlink/Reference
    VULNERABLE_TO = "VULNERABLE_TO"

class KnowledgeGraph:
    """
    A thread-safe, NetworkX-backed graph store for security context.
    Enables multi-hop reasoning (e.g., "Find all Assets running Nginx that have High severity findings").
    """
    
    _instance = None
    _lock = threading.RLock()

    @staticmethod
    def instance():
        if KnowledgeGraph._instance is None:
            with KnowledgeGraph._lock:
                if KnowledgeGraph._instance is None:
                    KnowledgeGraph._instance = KnowledgeGraph()
        return KnowledgeGraph._instance

    def __init__(self):
        self._graph = nx.DiGraph()
        self._dirty = False

    def add_node(self, node_id: str, type: NodeType, attributes: Dict[str, Any] = None):
        """
        idempotent add_node.
        """
        with self._lock:
            if not self._graph.has_node(node_id):
                self._graph.add_node(
                    node_id, 
                    type=type, 
                    created_at=datetime.now(timezone.utc).isoformat(),
                    **(attributes or {})
                )
            else:
                # Update attributes merge
                current = self._graph.nodes[node_id]
                if attributes:
                    current.update(attributes)
                    current["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._dirty = True

    def add_edge(self, source_id: str, target_id: str, type: EdgeType, weight: float = 1.0, meta: Dict = None):
        with self._lock:
            if not self._graph.has_node(source_id) or not self._graph.has_node(target_id):
                logger.warning(f"Attempted to link missing nodes: {source_id} -> {target_id}")
                return
            
            self._graph.add_edge(
                source_id, 
                target_id, 
                type=type, 
                weight=weight,
                created_at=datetime.now(timezone.utc).isoformat(),
                **(meta or {})
            )
            self._dirty = True

    def get_neighbors(self, node_id: str, relation: EdgeType = None) -> List[Dict]:
        with self._lock:
            if not self._graph.has_node(node_id):
                return []
            
            results = []
            for neighbor in self._graph.successors(node_id):
                edge_data = self._graph.get_edge_data(node_id, neighbor)
                if relation and edge_data.get("type") != relation:
                    continue
                node_data = self._graph.nodes[neighbor]
                results.append({"id": neighbor, **node_data, "link": edge_data})
            return results

    def find_all(self, type: NodeType) -> List[Dict]:
        with self._lock:
            return [
                {"id": n, **self._graph.nodes[n]} 
                for n in self._graph.nodes 
                if self._graph.nodes[n].get("type") == type
            ]

    def params_for_query(self, query_template: str) -> List[str]:
        """
        Placeholder for future Cypher-like or vector queries.
        """
        pass

    def export_json(self) -> Dict:
        with self._lock:
            return nx.node_link_data(self._graph)

    def import_json(self, data: Dict):
        with self._lock:
            self._graph = nx.node_link_graph(data)

    def clear(self):
        with self._lock:
            self._graph.clear()
