
import pytest
from core.cortex.correlator import GraphCorrelator

def test_correlator_favicon_match():
    # Setup 3 nodes: A and B share favicon, C does not
    nodes = [
        {"id": "A", "attributes": {"favicon_hash": "123456"}},
        {"id": "B", "attributes": {"favicon_hash": "123456"}},
        {"id": "C", "attributes": {"favicon_hash": "999999"}},
    ]
    
    correlator = GraphCorrelator()
    edges = correlator.process(nodes)
    
    # Expect 1 edge relating B to A (Star topology from A)
    # A is first, B is second. Pivot=A. Edge A->B.
    assert len(edges) == 1
    edge = edges[0]
    assert edge["source"] == "A"
    assert edge["target"] == "B"
    assert edge["type"] == "IMPLIED_LINK"
    assert "Shared Favicon" in edge["label"]

def test_correlator_multiple_matches():
    # A and B share favicon, B and C share SimHash
    nodes = [
        {"id": "A", "attributes": {"favicon_hash": "123456", "simhash": "abc"}},
        {"id": "B", "attributes": {"favicon_hash": "123456", "simhash": "xyz"}},
        {"id": "C", "attributes": {"favicon_hash": "999999", "simhash": "xyz"}},
    ]
    
    correlator = GraphCorrelator()
    edges = correlator.process(nodes)
    
    # 1 edge for Favicon (A->B)
    # 1 edge for SimHash (B->C)
    assert len(edges) == 2
    
    labels = [e["label"] for e in edges]
    assert any("Shared Favicon" in l for l in labels)
    assert any("Content Similarity" in l for l in labels)
