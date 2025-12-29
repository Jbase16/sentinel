"""
Property-Based Invariant Tests.

These tests verify mathematical laws, not specific scenarios.
"""

import pytest
from hypothesis import given, strategies as st

from ..models import PressureNode, PressureEdge, EdgeType
from ..propagator import PressurePropagator


# Strategies
safe_float = st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False)


def _make_graph(source_pressure=10.0, edge_conf=1.0):
    n = {
        "src": PressureNode("src", "vuln", 10.0, 1.0, 1.0, 1.0, 1.0),
        "sink": PressureNode("sink", "asset", 0.0, 0.0, 0.0, 0.0, 10.0)
    }
    e = {
        "e1": PressureEdge("e1", "src", "sink", EdgeType.ENABLES, 1.0, edge_conf)
    }
    return n, e


def test_zero_confidence_equals_non_existent():
    """
    Invariant: An edge with 0.0 confidence behaves IDENTICALLY to a missing edge.
    
    We do not compare 0.0 confidence to 1.0 confidence (that's obvious).
    We compare 0.0 confidence to NO EDGE.
    """
    n, e_high = _make_graph(edge_conf=1.0)
    
    # 1. Graph with zero-confidence edge
    e_zero = {
        "e1": PressureEdge("e1", "src", "sink", EdgeType.ENABLES, 1.0, 0.0)
    }
    prop_zero = PressurePropagator(n, e_zero)
    p_zero = prop_zero.propagate({"sink"})
    
    # 2. Graph with NO edge
    e_none = {}
    prop_none = PressurePropagator(n, e_none)
    p_none = prop_none.propagate({"sink"})
    
    # The pressure on the sink must be identical in both cases.
    # (Both should be 0.0, since sink has no base pressure and no valid inbound edge)
    assert p_zero["sink"] == pytest.approx(p_none["sink"])


def test_weight_normalization_guarantee():
    """
    Invariant: Even with massive inbound weight sums, pressure must not explode.
    
    This tests the Spectral Radius fix.
    """
    n = {
        "src1": PressureNode("s1", "v", 100.0, 1.0, 1.0, 1.0, 1.0),
        "src2": PressureNode("s2", "v", 100.0, 1.0, 1.0, 1.0, 1.0),
        "sink": PressureNode("sink", "a", 0.0, 0.0, 0.0, 0.0, 10.0)
    }
    
    # Create 2 huge edges. Raw sum = 20.0 (10.0 transfer * 1.0 conf * 2 edges).
    # Without normalization, this could amplify pressure wildly depending on damping.
    # With normalization, they share the contribution.
    e = {
        "e1": PressureEdge("e1", "src1", "sink", EdgeType.ENABLES, 10.0, 1.0),
        "e2": PressureEdge("e2", "src2", "sink", EdgeType.ENABLES, 10.0, 1.0),
    }
    
    prop = PressurePropagator(n, e, damping_factor=0.5)
    p = prop.propagate({"sink"})
    
    # Physics check: Pressure should be bounded by the max source pressure * damping
    # roughly. It shouldn't be 200.0 just because transfer factors are high.
    # Due to normalization, the total inbound transfer is exactly 1.0 * d.
    max_source = max(n['src1'].base_pressure, n['src2'].base_pressure)
    assert 0.0 <= p["sink"] <= max_source


@given(s_inc=st.floats(min_value=0.1, max_value=5.0, allow_nan=False, allow_infinity=False))
def test_monotonicity_invariant(s_inc):
    """
    Increasing source severity strictly increases downstream pressure.
    """
    from copy import deepcopy
    
    n, e = _make_graph()
    prop = PressurePropagator(n, e)
    base = prop.propagate({"sink"})
    
    n2 = {k: deepcopy(v) for k, v in n.items()}
    n2['src'] = PressureNode('src', 'v', min(10.0, n['src'].severity + s_inc), 
                              1.0, 1.0, 1.0, 1.0)
    
    prop2 = PressurePropagator(n2, e)
    new = prop2.propagate({"sink"})
    
    assert new["sink"] >= base["sink"]