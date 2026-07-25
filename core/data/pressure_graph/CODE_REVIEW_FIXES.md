# Code Review Fixes - Pressure Graph Implementation

## Overview
This document summarizes the fixes applied to address code review feedback for the pressure graph implementation.

## Fixes Applied

### 1. CounterfactualEngine Shadow Graph Usage (CRITICAL)
**Issue:** The shadow graph was created but not used. The original propagator was called instead, meaning remediations were never actually applied to the graph during simulation.

**Fix:** Modified `simulate_remediation()` to create a shadow propagator with the modified shadow nodes/edges. This ensures remediations are properly applied during simulation.

**File:** `core/data/pressure_graph/counterfactual.py`

**Impact:** Counterfactual simulations now correctly reflect the effect of remediations.

---

### 2. Add Edge Confidence to Propagation (CRITICAL)
**Issue:** Edge confidence was not factored into pressure propagation, violating the evidence-traceability principle. Low-confidence edges propagated pressure as strongly as high-confidence edges.

**Fix:** Modified the propagation formula to multiply by `edge.confidence`:
```python
inbound_pressure += (
    source_pressure *
    edge.transfer_factor *
    edge.confidence  # Added
)
```

**File:** `core/data/pressure_graph/propagator.py`

**Impact:** Pressure propagation now respects edge confidence. Low-confidence causal relationships contribute less to downstream pressure.

---

### 3. Fix Invariant Validation Mutation (SAFETY)
**Issue:** The `validate_invariant()` method mutated live node objects by temporarily increasing severity. This could affect concurrent operations and violate immutability expectations.

**Fix:** Modified to clone nodes and create a temporary propagator for validation, ensuring no mutation of live graph state.

**File:** `core/data/pressure_graph/propagator.py`

**Impact:** Invariant validation is now safe and doesn't affect the live graph.

---

### 4. Remove total_pressure Field (CLEANUP)
**Issue:** The `PressureNode` class had both `inbound_pressure` and `total_pressure` fields, creating confusion about which should be used. The propagator returns a dict of pressures, not stored in nodes.

**Fix:** Removed the redundant `total_pressure` field from `PressureNode`. The propagation result is returned as a separate dict from `propagate()`.

**File:** `core/data/pressure_graph/models.py`

**Impact:** Clearer API - pressure is computed and returned, not stored on nodes.

---

### 5. Document Min-Cut Limitation (API CLARITY)
**Issue:** The `MinimalFixSetEngine.compute_minimal_fix_sets()` method takes a `max_sets` parameter but only returns a single min-cut. This is misleading API design.

**Fix:** Added clear documentation in the class docstring explaining the limitation:
```python
LIMITATIONS:
- Currently returns only the single minimum-cost min-cut
- Does not enumerate alternative min-cuts with same cost
- Future enhancement: Use Gomory-Hu tree or min-cut enumeration
  to generate multiple disjoint fix sets
```

**File:** `core/data/pressure_graph/min_fix_set.py`

**Impact:** API users are now aware of the current limitation and potential future enhancements.

---

## Summary

All critical and safety issues have been resolved. The codebase now:
- ✅ Correctly applies remediations in counterfactual simulations
- ✅ Propagates pressure respecting edge confidence
- ✅ Validates invariants without mutating live state
- ✅ Has a cleaner, less confusing API
- ✅ Documents its limitations clearly

## Testing Recommendations

After these fixes, verify:
1. Counterfactual simulations show different pressures when remediations are applied
2. Low-confidence edges contribute less to downstream pressure
3. Invariant validation passes without affecting graph state
4. Pressure propagation works without `total_pressure` field
5. API users understand the min-cut limitation

## Future Enhancements

As documented in the min-cut limitation, future work could include:
- Gomory-Hu tree for enumerating all min-cuts
- Alternative min-cut enumeration algorithms
- Support for multiple disjoint fix sets with equivalent cost