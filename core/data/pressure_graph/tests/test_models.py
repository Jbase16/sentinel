"""
Tests for pressure graph models.
"""

import pytest

from core.data.pressure_graph.models import (
    PressureNode,
    PressureEdge,
    Remediation,
    EdgeType
)


def test_pressure_node_deterministic():
    """Test that pressure node computes deterministic values."""
    node = PressureNode(
        id="node1",
        type="vulnerability",
        severity=8.0,
        exposure=0.7,
        exploitability=0.9,
        privilege_gain=0.6,
        asset_value=5.0,
        tool_reliability=0.9,
        evidence_quality=0.8,
        corroboration_count=2
    )
    
    # Base pressure should be deterministic
    expected_base = 8.0 * 0.7 * 0.9 * 0.6 * 5.0
    assert node.base_pressure == pytest.approx(expected_base)
    
    # Confidence should be deterministic
    # Formula: tool_reliability * (0.5 + 0.5 * evidence_quality) * (1.0 - 0.1^(corroboration_count + 1))
    expected_confidence = 0.9 * (0.5 + 0.5 * 0.8) * (1.0 - 0.1 ** 3)
    assert node.confidence == pytest.approx(expected_confidence)


def test_pressure_node_evidence_quality():
    """Test that confidence scales with evidence quality."""
    node_low = PressureNode(
        id="low",
        type="vulnerability",
        severity=5.0,
        exposure=0.5,
        exploitability=0.5,
        privilege_gain=0.5,
        asset_value=5.0,
        evidence_quality=0.3
    )
    
    node_high = PressureNode(
        id="high",
        type="vulnerability",
        severity=5.0,
        exposure=0.5,
        exploitability=0.5,
        privilege_gain=0.5,
        asset_value=5.0,
        evidence_quality=0.9
    )
    
    # Higher evidence quality should mean higher confidence
    assert node_high.confidence > node_low.confidence


def test_pressure_node_corroboration():
    """Test that confidence increases with corroboration."""
    node_single = PressureNode(
        id="single",
        type="vulnerability",
        severity=5.0,
        exposure=0.5,
        exploitability=0.5,
        privilege_gain=0.5,
        asset_value=5.0,
        corroboration_count=0
    )
    
    node_multi = PressureNode(
        id="multi",
        type="vulnerability",
        severity=5.0,
        exposure=0.5,
        exploitability=0.5,
        privilege_gain=0.5,
        asset_value=5.0,
        corroboration_count=3
    )
    
    # More corroboration should mean higher confidence
    assert node_multi.confidence > node_single.confidence


def test_pressure_edge_creation():
    """Test pressure edge creation."""
    edge = PressureEdge(
        id="edge1",
        source_id="node1",
        target_id="node2",
        type=EdgeType.ENABLES,
        transfer_factor=0.8,
        confidence=0.9,
        evidence_sources=["tool1", "tool2"]
    )
    
    assert edge.id == "edge1"
    assert edge.source_id == "node1"
    assert edge.target_id == "node2"
    assert edge.type == EdgeType.ENABLES
    assert edge.transfer_factor == 0.8
    assert edge.confidence == 0.9
    assert len(edge.evidence_sources) == 2


def test_edge_types():
    """Test all edge types."""
    assert EdgeType.ENABLES.value == "enables"
    assert EdgeType.REACHES.value == "reaches"
    assert EdgeType.REQUIRES.value == "requires"
    assert EdgeType.AMPLIFIES.value == "amplifies"


def test_remediation_node_removal():
    """Test remediation that removes a node."""
    remediation = Remediation(
        id="rem1",
        name="Patch vulnerability",
        nodes_to_remove={"vuln1"}
    )
    
    node = PressureNode(
        id="vuln1",
        type="vulnerability",
        severity=8.0,
        exposure=0.7,
        exploitability=0.9,
        privilege_gain=0.6,
        asset_value=5.0
    )
    
    # Applying remediation to node should return None (removed)
    result = remediation.apply_to_node(node)
    assert result is None


def test_remediation_pressure_reduction():
    """Test remediation that reduces node pressure."""
    remediation = Remediation(
        id="rem1",
        name="Add WAF",
        node_pressure_reductions={"node1": 10.0}
    )
    
    node = PressureNode(
        id="node1",
        type="exposure",
        severity=8.0,
        exposure=0.7,
        exploitability=0.9,
        privilege_gain=0.6,
        asset_value=5.0
    )
    
    original_pressure = node.base_pressure
    
    # Applying remediation should reduce pressure
    result = remediation.apply_to_node(node)
    assert result is not None
    assert result.base_pressure == max(0.0, original_pressure - 10.0)
    assert result.id == "node1"  # Other fields preserved


def test_remediation_edge_removal():
    """Test remediation that removes an edge."""
    remediation = Remediation(
        id="rem1",
        name="Block network path",
        edges_to_remove={"edge1"}
    )
    
    edge = PressureEdge(
        id="edge1",
        source_id="node1",
        target_id="node2",
        type=EdgeType.REACHES,
        transfer_factor=0.8,
        confidence=0.9
    )
    
    # Applying remediation to edge should return None (removed)
    result = remediation.apply_to_edge(edge)
    assert result is None


def test_remediation_transfer_reduction():
    """Test remediation that reduces edge transfer factor."""
    remediation = Remediation(
        id="rem1",
        name="Add MFA",
        edge_transfer_reductions={"edge1": 0.3}
    )
    
    edge = PressureEdge(
        id="edge1",
        source_id="node1",
        target_id="node2",
        type=EdgeType.REACHES,
        transfer_factor=0.8,
        confidence=0.9
    )
    
    # Applying remediation should reduce transfer factor
    result = remediation.apply_to_edge(edge)
    assert result is not None
    assert result.transfer_factor == max(0.0, 0.8 - 0.3)
    assert result.id == "edge1"  # Other fields preserved


def test_remediation_no_change():
    """Test that remediation doesn't affect nodes/edges not specified."""
    remediation = Remediation(
        id="rem1",
        name="Patch something else",
        nodes_to_remove={"other_node"}
    )
    
    node = PressureNode(
        id="node1",
        type="vulnerability",
        severity=5.0,
        exposure=0.5,
        exploitability=0.5,
        privilege_gain=0.5,
        asset_value=5.0
    )
    
    # Applying remediation should return unchanged node
    result = remediation.apply_to_node(node)
    assert result is not None
    assert result.base_pressure == node.base_pressure