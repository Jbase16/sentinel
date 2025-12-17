"""Module test_pathfinder: inline documentation for /Users/jason/Developer/sentinelforge/tests/unit/test_pathfinder.py."""

import pytest
from core.cortex.pathfinder import GraphAnalyzer

def test_attack_path():
    # Linear: A -> B -> C
    """Function test_attack_path."""
    nodes = [{"id": "A"}, {"id": "B"}, {"id": "C"}]
    edges = [
        {"source": "A", "target": "B"},
        {"source": "B", "target": "C"}
    ]
    analyzer = GraphAnalyzer(nodes, edges)
    
    path = analyzer.find_attack_path("A", "C")
    assert path == ["A", "B", "C"]
    
    # Reverse should fail (directed)
    assert analyzer.find_attack_path("C", "A") is None

def test_bridges():
    # Bowtie: (1-2-3) - 4 - (5-6-7)
    # Node 4 is the bridge.
    """Function test_bridges."""
    nodes = [{"id": str(i)} for i in range(1, 8)]
    edges = [
        {"source": "1", "target": "2"}, {"source": "2", "target": "3"}, # Cluster L
        {"source": "3", "target": "4"}, # Bridge
        {"source": "4", "target": "5"}, # Bridge
        {"source": "5", "target": "6"}, {"source": "6", "target": "7"}  # Cluster R
    ]
    analyzer = GraphAnalyzer(nodes, edges)
    
    bridges = analyzer.find_critical_bridges(to_k=1)
    # Node 4 should have highest betweenness (it's on all paths from L to R)
    assert bridges[0][0] == "4"

def test_blast_radius():
    # Star: Center -> Leaves (L1, L2)
    """Function test_blast_radius."""
    nodes = [{"id": "C"}, {"id": "L1"}, {"id": "L2"}]
    edges = [
        {"source": "C", "target": "L1"},
        {"source": "C", "target": "L2"}
    ]
    analyzer = GraphAnalyzer(nodes, edges)
    
    # Depth 1 from C should reach L1, L2
    radius = analyzer.calculate_blast_radius("C", depth=1)
    assert "L1" in radius
    assert "L2" in radius
    # Length should be 2 (L1, L2), self excluded by implementation
    assert len(radius) == 2

