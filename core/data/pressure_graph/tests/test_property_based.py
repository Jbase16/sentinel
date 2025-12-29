"""
Property-based tests for pressure graph invariants.

Uses Hypothesis to generate random inputs and verify invariants.
"""

import pytest
from hypothesis import given, strategies as st
from typing import Dict, Set

from ..models import PressureNode, PressureEdge, EdgeType
from ..propagator import PressurePropagator


# Strategies for generating test data
severity_strategy = st.floats(min_value=0.0, max_value=10.0)
exposure_strategy = st.floats(min_value=0.0, max_value=1.0)
exploitability_strategy = st.floats(min_value=0.0, max_value=1.0)
privilege_gain_strategy = st.floats(min_value=0.0, max_value=1.0)
asset_value_strategy = st.floats(min_value=0.0, max_value=10.0)
confidence_strategy = st.floats(min_value=0.0, max_value=1.0)
transfer_factor_strategy = st.floats(min_value=0.0, max_value=1.0)


def create_simple_pressure_graph():
    """
    Create a simple test graph with known structure.
    
    Structure:
        vuln_1 -> service -> db_prod (crown jewel)
        vuln_2 -> service
    """
    nodes = {
        "vuln_1": PressureNode(
            id="vuln_1",
            type="vulnerability",
            severity=8.0,
            exposure=0.8,
            exploitability=0.9,
            privilege_gain=0.7,
            asset_value=2.0
        ),
        "vuln_2": PressureNode(
            id="vuln_2",
            type="vulnerability",
            severity=7.0,
            exposure=0.6,
            exploitability=0.7,
            privilege_gain=0.5,
            asset_value=1.5
        ),
        "service": PressureNode(
            id="service",
            type="asset",
            severity=5.0,
            exposure=0.9,
            exploitability=0.8,
            privilege_gain=0.9,
            asset_value=8.0
        ),
        "db_prod": PressureNode(
            id="db_prod",
            type="asset",
            severity=4.0,
            exposure=0.5,
            exploitability=0.3,
            privilege_gain=1.0,
            asset_value=10.0
        ),
    }
    
    edges = {
        "edge_1": PressureEdge(
            id="edge_1",
            source_id="vuln_1",
            target_id="service",
            type=EdgeType.REACHES,
            transfer_factor=0.8,
            confidence=0.9
        ),
        "edge_2": PressureEdge(
            id="edge_2",
            source_id="vuln_2",
            target_id="service",
            type=EdgeType.REACHES,
            transfer_factor=0.6,
            confidence=0.8
        ),
        "edge_3": PressureEdge(
            id="edge_3",
            source_id="service",
            target_id="db_prod",
            type=EdgeType.REACHES,
            transfer_factor=0.9,
            confidence=0.95
        ),
    }
    
    return nodes, edges, {"db_prod"}


@given(severity_increase=st.floats(min_value=0.1, max_value=2.0))
def test_monotonicity_crown_jewel_pressure(severity_increase):
    """
    Property: If node severity increases, Crown Jewel pressure must not decrease.
    
    This is a critical invariant - increasing upstream severity cannot
    reduce downstream pressure.
    """
    nodes, edges, crown_jewel_ids = create_simple_pressure_graph()
    
    # Create propagator
    propagator = PressurePropagator(
        nodes,
        edges,
        damping_factor=0.85,
        epsilon=1e-6,
        max_iterations=1000
    )
    
    # Get baseline pressures
    baseline_pressures = propagator.propagate(crown_jewel_ids)
    baseline_cj_pressure = baseline_pressures["db_prod"]
    
    # Increase severity of vuln_1 (upstream node)
    from copy import deepcopy
    modified_nodes = {
        node_id: deepcopy(node)
        for node_id, node in nodes.items()
    }
    modified_nodes["vuln_1"].severity = min(10.0, modified_nodes["vuln_1"].severity + severity_increase)
    modified_nodes["vuln_1"].base_pressure = (
        modified_nodes["vuln_1"].severity *
        modified_nodes["vuln_1"].exposure *
        modified_nodes["vuln_1"].exploitability *
        modified_nodes["vuln_1"].privilege_gain *
        modified_nodes["vuln_1"].asset_value
    )
    
    # Create new propagator with modified nodes
    new_propagator = PressurePropagator(
        modified_nodes,
        edges,
        damping_factor=0.85,
        epsilon=1e-6,
        max_iterations=1000
    )
    
    # Get new pressures
    new_pressures = new_propagator.propagate(crown_jewel_ids)
    new_cj_pressure = new_pressures["db_prod"]
    
    # Assert monotonicity: crown jewel pressure should not decrease
    assert new_cj_pressure >= baseline_cj_pressure - 1e-6, \
        f"Monotonicity violation: Crown jewel pressure decreased from {baseline_cj_pressure} to {new_cj_pressure}"


@given(transfer_factor=st.floats(min_value=0.0, max_value=1.0),
       confidence=st.floats(min_value=0.1, max_value=1.0))
def test_edge_transfer_non_negative(transfer_factor, confidence):
    """
    Property: Edge pressure transfer should always be non-negative.
    """
    nodes, edges, crown_jewel_ids = create_simple_pressure_graph()
    
    # Modify edge with random parameters
    from copy import deepcopy
    modified_edges = deepcopy(edges)
    modified_edges["edge_3"].transfer_factor = transfer_factor
    modified_edges["edge_3"].confidence = confidence
    
    # Create propagator
    propagator = PressurePropagator(
        nodes,
        modified_edges,
        damping_factor=0.85,
        epsilon=1e-6,
        max_iterations=1000
    )
    
    # Propagate
    pressures = propagator.propagate(crown_jewel_ids)
    
    # All pressures should be non-negative
    for node_id, pressure in pressures.items():
        assert pressure >= 0.0, \
            f"Negative pressure at node {node_id}: {pressure}"


@given(damping_factor=st.floats(min_value=0.5, max_value=0.95))
def test_damping_factor_bounds(damping_factor):
    """
    Property: Damping factor should produce pressures in expected range.
    """
    nodes, edges, crown_jewel_ids = create_simple_pressure_graph()
    
    # Create propagator with random damping factor
    propagator = PressurePropagator(
        nodes,
        edges,
        damping_factor=damping_factor,
        epsilon=1e-6,
        max_iterations=1000
    )
    
    # Propagate
    pressures = propagator.propagate(crown_jewel_ids)
    
    # Pressures should be bounded by max possible pressure
    max_base_pressure = max(
        node.severity * node.exposure * node.exploitability * 
        node.privilege_gain * node.asset_value
        for node in nodes.values()
    )
    
    for node_id, pressure in pressures.items():
        assert 0.0 <= pressure <= max_base_pressure * 2.0, \
            f"Pressure out of bounds at node {node_id}: {pressure}"


@given(perturbations=st.lists(
    st.tuples(
        st.sampled_from(["vuln_1", "vuln_2", "service"]),
        severity_strategy
    ),
    min_size=1,
    max_size=5
))
def test_monotonicity_multiple_severity_changes(perturbations):
    """
    Property: Multiple severity increases should not reduce crown jewel pressure.
    
    Tests monotonicity under cumulative changes.
    """
    nodes, edges, crown_jewel_ids = create_simple_pressure_graph()
    
    # Create propagator
    propagator = PressurePropagator(
        nodes,
        edges,
        damping_factor=0.85,
        epsilon=1e-6,
        max_iterations=1000
    )
    
    # Get baseline pressures
    baseline_pressures = propagator.propagate(crown_jewel_ids)
    baseline_cj_pressure = baseline_pressures["db_prod"]
    
    # Apply perturbations
    from copy import deepcopy
    modified_nodes = {
        node_id: deepcopy(node)
        for node_id, node in nodes.items()
    }
    
    for node_id, severity_increase in perturbations:
        modified_nodes[node_id].severity = min(10.0, modified_nodes[node_id].severity + severity_increase)
        modified_nodes[node_id].base_pressure = (
            modified_nodes[node_id].severity *
            modified_nodes[node_id].exposure *
            modified_nodes[node_id].exploitability *
            modified_nodes[node_id].privilege_gain *
            modified_nodes[node_id].asset_value
        )
    
    # Create new propagator with modified nodes
    new_propagator = PressurePropagator(
        modified_nodes,
        edges,
        damping_factor=0.85,
        epsilon=1e-6,
        max_iterations=1000
    )
    
    # Get new pressures
    new_pressures = new_propagator.propagate(crown_jewel_ids)
    new_cj_pressure = new_pressures["db_prod"]
    
    # Assert monotonicity
    assert new_cj_pressure >= baseline_cj_pressure - 1e-6, \
        f"Monotonicity violation with multiple perturbations: {baseline_cj_pressure} -> {new_cj_pressure}"


def test_propagator_immutability():
    """
    Test that PressurePropagator enforces immutability.
    """
    nodes, edges, crown_jewel_ids = create_simple_pressure_graph()
    
    # Create propagator
    propagator = PressurePropagator(
        nodes,
        edges,
        damping_factor=0.85,
        epsilon=1e-6,
        max_iterations=1000
    )
    
    # After initialization, propagator should be frozen
    assert propagator._frozen is True
    
    # Attempting to modify nodes/edges should raise error
    # (This is enforced by _check_mutable if called)
    # For now, verify the flag is set correctly
    
    # Verify propagator can still be used
    pressures = propagator.propagate(crown_jewel_ids)
    assert "db_prod" in pressures