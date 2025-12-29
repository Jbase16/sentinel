# Pressure Graph - Deterministic Attack Path Analysis

## Overview

The Pressure Graph is a deterministic, evidence-traceable system for analyzing attack paths and prioritizing remediations. It models security vulnerabilities and their causal relationships as a directed graph where "pressure" propagates from entry points to crown jewels (critical assets).

## Key Properties

### Deterministic
- All pressure calculations are mathematically defined
- No AI/ML black boxes
- Results are reproducible and explainable

### Evidence-Traceable
- Every node and edge is traceable to scanner output
- Confidence scores based on tool reliability, evidence quality, and corroboration
- Auditable decision chains

### Cycle-Safe
- Uses iterative relaxation (power iteration) to handle cycles naturally
- Guaranteed convergence for damping factor < 1.0
- No topological sorting required

## Core Concepts

### Pressure Nodes
Represent security entities with intrinsic pressure:

```
base_pressure = severity × exposure × exploitability × privilege_gain × asset_value
```

- **severity**: CVSS or tool output (0-10)
- **exposure**: How accessible is this? (0-1)
- **exploitability**: How easily can it be exploited? (0-1)
- **privilege_gain**: What access does this provide? (0-1)
- **asset_value**: Business criticality (0-10)

### Pressure Edges
Represent causal relationships between nodes:

- **type**: ENABLES, REACHES, REQUIRES, AMPLIFIES
- **transfer_factor**: How much pressure propagates (0-1)
- **confidence**: How certain we are this edge exists (0-1)

### Pressure Propagation
Uses damped power iteration:

```
P_new = (1 - d) × Base_Pressure + d × Σ(Inbound_Pressure × Transfer_Factor)
```

- **d**: Damping factor (default 0.85)
- Crown jewels are sinks (accumulate pressure, don't forward)

## Components

### 1. Models (`models.py`)
- `PressureNode`: Security entity with intrinsic pressure
- `PressureEdge`: Causal relationship
- `Remediation`: Security fix or mitigation
- `EdgeType`: Enum of relationship types

### 2. Propagator (`propagator.py`)
- Cycle-safe pressure propagation
- Iterative relaxation algorithm
- Convergence validation
- Pressure contribution analysis

### 3. Counterfactual Engine (`counterfactual.py`)
- Fast remediation impact simulation
- Dirty subgraph optimization for performance
- Top remediation discovery
- Chokepoint analysis

### 4. Minimal Fix Set Engine (`min_fix_set.py`)
- Node-splitting min-cut algorithm
- Dinic's max-flow implementation
- Computes optimal remediation sets that break all attack paths

### 5. Manager (`manager.py`)
- Integration with Sentinel stores
- Bridges `issues_store` and `killchain_store` to pressure graph
- High-level APIs for reports and analysis
- Signal-based reactive updates

## Usage

### Basic Setup

```python
from core.data.pressure_graph.manager import PressureGraphManager

# Create manager for session
manager = PressureGraphManager(session_id="scan_123")

# Mark crown jewels (critical assets)
manager.set_crown_jewels({
    "database_primary",
    "customer_data_store"
})

# Generate comprehensive report
report = manager.generate_report()
```

### Report Structure

```python
{
    "pressure_metrics": {
        "total_system_pressure": 150.5,
        "total_crown_jewel_pressure": 45.2,
        "node_count": 23,
        "edge_count": 31
    },
    "top_remediations": [
        {
            "remediation": Remediation(...),
            "delta_system_pressure": -15.3,
            "delta_crown_jewel_pressure": -8.7,
            "attack_paths_eliminated": 3,
            "residual_attack_path": [...]
        },
        # ... more remediations
    ],
    "minimal_fix_sets": [
        [Remediation(...), Remediation(...)],
        # ... more fix sets
    ],
    "critical_paths": [
        {
            "path": ["entry_vuln", "priv_esc", "crown_jewel"],
            "pressure": 25.4,
            "confidence": 0.92,
            "length": 3
        },
        # ... more paths
    ],
    "chokepoints": [
        {
            "node_id": "priv_esc_vuln",
            "node_type": "vulnerability",
            "delta_crown_jewel_pressure": -8.7,
            "delta_system_pressure": -15.3
        },
        # ... more chokepoints
    ]
}
```

## Integration with Sentinel

### Data Flow

```
Scanner Output → issues_store → PressureNode
Killchain Data → killchain_store → PressureEdge
                         ↓
                PressureGraphManager
                         ↓
        Propagator → Counterfactual → MinimalFixSet
                         ↓
                    generate_report()
```

### Store Mapping

**Issues → Nodes:**
- `severity` → `severity` (mapped to 0-10)
- `type` → `node_type`
- `cvss.exploitability` → `exploitability`
- `proof` → `privilege_gain` (heuristic)

**Killchain Edges → Pressure Edges:**
- `edge_type` → `EdgeType`
- `severity` → `confidence`
- `transfer_factor` → `transfer_factor`

### Signals

The manager observes store changes via signals:

- `issues_store.issues_changed` → Rebuild nodes
- `killchain_store.edges_changed` → Rebuild edges

## Performance

### Benchmarks

- **Propagation**: <10ms for 100-node graph
- **Counterfactual query**: <100ms per remediation
- **Min-cut computation**: <1s for 100-node graph

### Optimizations

1. **Dirty Subgraph**: Only recompute affected components
2. **Edge Caching**: Lazy initialization for O(1) lookups
3. **Damping Factor**: Guarantees fast convergence
4. **Depth Limiting**: Prunes impossible paths in chokepoint analysis

## Testing

### Running Tests

```bash
# Run all pressure graph tests
pytest core/data/pressure_graph/tests/

# Run specific test file
pytest core/data/pressure_graph/tests/test_propagator.py
```

### Test Coverage

- `test_models.py`: Data model validation
- `test_propagator.py`: Propagation correctness
- `test_counterfactual.py`: Remediation simulation
- `test_min_fix_set.py`: Min-cut computation
- `test_manager.py`: Integration with stores

### Invariants

All tests validate:
1. **Monotonicity**: Increasing severity never decreases crown-jewel pressure
2. **Convergence**: Propagation always converges
3. **Non-negativity**: Pressures are never negative
4. **Cycle Safety**: Cycles don't cause infinite loops

## Design Decisions

### Why Damping Factor?

Prevents infinite pressure amplification in cycles and models real-world decay of exploit utility. Default 0.85 matches PageRank proven values.

### Why Node-Splitting?

Allows min-cut algorithms to work on node removal problems by converting nodes to edges with capacity = remediation cost.

### Why Iterative Relaxation?

Handles arbitrary graph structures including cycles without topological sorting. Guaranteed convergence and numerically stable.

### Why Deterministic?

Security decisions require explainability. Black-box AI models are unacceptable for audit trails. All pressure values are mathematically traceable to evidence.

## Future Enhancements

### Phase 2 (P2)
- Risk-calibrated remediation prioritization
- Time-based decay factors
- Multi-objective optimization (cost vs. risk)

### Phase 3 (P3)
- Interactive pressure landscape visualization
- Real-time graph updates during scanning
- Integration with remediation automation

### Phase 4 (P4)
- Machine learning for parameter tuning (auxiliary only)
- Threat intelligence integration
- Attack prediction based on observed campaigns

## References

### Algorithms
- **Power Iteration**: Eigenvalue computation for pressure propagation
- **Dinic's Algorithm**: Max-flow min-cut for minimal fix sets
- **Node Splitting**: Technique for node-capacity flow networks

### Research
- "PageRank" (Brin & Page, 1998) - Damping factor inspiration
- "Attack Graph Analysis" (Jha et al., 2002) - Foundational work
- "Causal Attack Graphs" (Ou et al., 2005) - Causal modeling

## License

Part of SentinelForge project. See LICENSE for details.