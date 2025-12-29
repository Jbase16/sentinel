"""
Tests for pressure propagator.
"""

import pytest

from core.data.pressure_graph.models import (
    PressureNode,
    PressureEdge,
    EdgeType
)
from core.data.pressure_graph.propagator import PressurePropagator


def test_simple_chain_propagation():
    """Test propagation through simple chain."""
    nodes = {
        "entry": PressureNode(
            id="entry",
            type="exposure",
            severity=8.0,
            exposure=0.9,
            exploitability=0.9,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "middle": PressureNode(
            id="middle",
            type="vulnerability",
            severity=7.0,
            exposure=0.7,
            exploitability=0.8,
            privilege_gain=0.6,
            asset_value=5.0
        ),
        "crown_jewel": PressureNode(
            id="crown_jewel",
            type="asset",
            severity=10.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.0,
            asset_value=10.0
        )
    }
    
    edges = {
        "e1": PressureEdge(
            id="e1",
            source_id="entry",
            target_id="middle",
            type=EdgeType.ENABLES,
            transfer_factor=0.8,
            confidence=0.9
        ),
        "e2": PressureEdge(
            id="e2",
            source_id="middle",
            target_id="crown_jewel",
            type=EdgeType.ENABLES,
            transfer_factor=0.7,
            confidence=0.9
        )
    }
    
    propagator = PressurePropagator(nodes, edges)
    pressures = propagator.propagate(crown_jewel_ids={"crown_jewel"})
    
    # Crown jewel should have pressure from both base and inbound
    assert pressures["crown_jewel"] > nodes["crown_jewel"].base_pressure
    assert pressures["crown_jewel"] > 0.0
    
    # Entry should have base pressure
    assert pressures["entry"] == pytest.approx(nodes["entry"].base_pressure)


def test_diamond_graph_propagation():
    """Test propagation through diamond graph (multiple paths)."""
    nodes = {
        "entry": PressureNode(
            id="entry",
            type="exposure",
            severity=8.0,
            exposure=0.9,
            exploitability=0.9,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "path1": PressureNode(
            id="path1",
            type="vulnerability",
            severity=6.0,
            exposure=0.6,
            exploitability=0.7,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "path2": PressureNode(
            id="path2",
            type="vulnerability",
            severity=7.0,
            exposure=0.7,
            exploitability=0.8,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "crown_jewel": PressureNode(
            id="crown_jewel",
            type="asset",
            severity=10.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.0,
            asset_value=10.0
        )
    }
    
    edges = {
        "e1": PressureEdge(
            id="e1",
            source_id="entry",
            target_id="path1",
            type=EdgeType.ENABLES,
            transfer_factor=0.6,
            confidence=0.9
        ),
        "e2": PressureEdge(
            id="e2",
            source_id="entry",
            target_id="path2",
            type=EdgeType.ENABLES,
            transfer_factor=0.7,
            confidence=0.9
        ),
        "e3": PressureEdge(
            id="e3",
            source_id="path1",
            target_id="crown_jewel",
            type=EdgeType.ENABLES,
            transfer_factor=0.8,
            confidence=0.9
        ),
        "e4": PressureEdge(
            id="e4",
            source_id="path2",
            target_id="crown_jewel",
            type=EdgeType.ENABLES,
            transfer_factor=0.9,
            confidence=0.9
        )
    }
    
    propagator = PressurePropagator(nodes, edges)
    pressures = propagator.propagate(crown_jewel_ids={"crown_jewel"})
    
    # Crown jewel should receive pressure from both paths
    assert pressures["crown_jewel"] > nodes["crown_jewel"].base_pressure
    
    # Both intermediate nodes should receive pressure from entry
    assert pressures["path1"] > nodes["path1"].base_pressure
    assert pressures["path2"] > nodes["path2"].base_pressure


def test_cycle_handling():
    """Test that propagator handles cycles correctly."""
    nodes = {
        "node1": PressureNode(
            id="node1",
            type="vulnerability",
            severity=5.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "node2": PressureNode(
            id="node2",
            type="vulnerability",
            severity=5.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "node3": PressureNode(
            id="node3",
            type="asset",
            severity=10.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.0,
            asset_value=10.0
        )
    }
    
    # Create cycle: node1 -> node2 -> node1, node2 -> node3
    edges = {
        "e1": PressureEdge(
            id="e1",
            source_id="node1",
            target_id="node2",
            type=EdgeType.ENABLES,
            transfer_factor=0.5,
            confidence=0.9
        ),
        "e2": PressureEdge(
            id="e2",
            source_id="node2",
            target_id="node1",
            type=EdgeType.ENABLES,
            transfer_factor=0.5,
            confidence=0.9
        ),
        "e3": PressureEdge(
            id="e3",
            source_id="node2",
            target_id="node3",
            type=EdgeType.ENABLES,
            transfer_factor=0.5,
            confidence=0.9
        )
    }
    
    propagator = PressurePropagator(nodes, edges)
    
    # Should converge without infinite loop
    pressures = propagator.propagate(crown_jewel_ids={"node3"})
    
    # Pressures should be finite
    assert all(isinstance(p, float) and not p != p for p in pressures.values())  # Check for NaN
    assert all(p >= 0 for p in pressures.values())


def test_convergence():
    """Test that propagation converges within iteration limit."""
    nodes = {
        "entry": PressureNode(
            id="entry",
            type="exposure",
            severity=5.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "sink": PressureNode(
            id="sink",
            type="asset",
            severity=10.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.0,
            asset_value=10.0
        )
    }
    
    edges = {
        "e1": PressureEdge(
            id="e1",
            source_id="entry",
            target_id="sink",
            type=EdgeType.ENABLES,
            transfer_factor=0.5,
            confidence=0.9
        )
    }
    
    propagator = PressurePropagator(
        nodes, 
        edges,
        damping_factor=0.85,
        epsilon=1e-6,
        max_iterations=100
    )
    
    pressures = propagator.propagate(crown_jewel_ids={"sink"})
    
    # Should converge
    assert "entry" in pressures
    assert "sink" in pressures
    assert pressures["entry"] > 0
    assert pressures["sink"] > 0


def test_invariant_validation():
    """Test that invariant holds: increasing severity shouldn't decrease crown-jewel pressure."""
    nodes = {
        "entry": PressureNode(
            id="entry",
            type="vulnerability",
            severity=5.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "middle": PressureNode(
            id="middle",
            type="vulnerability",
            severity=5.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "crown_jewel": PressureNode(
            id="crown_jewel",
            type="asset",
            severity=10.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.0,
            asset_value=10.0
        )
    }
    
    edges = {
        "e1": PressureEdge(
            id="e1",
            source_id="entry",
            target_id="middle",
            type=EdgeType.ENABLES,
            transfer_factor=0.5,
            confidence=0.9
        ),
        "e2": PressureEdge(
            id="e2",
            source_id="middle",
            target_id="crown_jewel",
            type=EdgeType.ENABLES,
            transfer_factor=0.5,
            confidence=0.9
        )
    }
    
    propagator = PressurePropagator(nodes, edges)
    baseline_pressures = propagator.propagate(crown_jewel_ids={"crown_jewel"})
    
    # Validate invariant
    invariant_holds = propagator.validate_invariant(
        {"crown_jewel"},
        baseline_pressures
    )
    
    assert invariant_holds, "Invariant violated: increasing severity decreased crown-jewel pressure"


def test_compute_pressure_contribution():
    """Test computing pressure contribution from a specific source."""
    nodes = {
        "source1": PressureNode(
            id="source1",
            type="vulnerability",
            severity=8.0,
            exposure=0.9,
            exploitability=0.9,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "source2": PressureNode(
            id="source2",
            type="vulnerability",
            severity=5.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.5,
            asset_value=5.0
        ),
        "sink": PressureNode(
            id="sink",
            type="asset",
            severity=10.0,
            exposure=0.5,
            exploitability=0.5,
            privilege_gain=0.0,
            asset_value=10.0
        )
    }
    
    edges = {
        "e1": PressureEdge(
            id="e1",
            source_id="source1",
            target_id="sink",
            type=EdgeType.ENABLES,
            transfer_factor=0.8,
            confidence=0.9
        ),
        "e2": PressureEdge(
            id="e2",
            source_id="source2",
            target_id="sink",
            type=EdgeType.ENABLES,
            transfer_factor=0.5,
            confidence=0.9
        )
    }
    
    propagator = PressurePropagator(nodes, edges)
    
    # Compute contribution from source1
    contribution = propagator.compute_pressure_contribution(
        "source1",
        {"sink"}
    )
    
    # Source1 should not be in contribution (it's the source itself)
    assert "source1" not in contribution
    
    # Sink should be in contribution
    assert "sink" in contribution
    
    # Contribution should be positive
    assert contribution["sink"] > 0