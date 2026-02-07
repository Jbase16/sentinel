# Phase 3 Implementation Plan: Cross-Target Correlation, Graph-Informed Confidence, Combined Leverage Metrics

**Status**: PLAN ONLY — No Code
**Scope**: Deferred items from Design Proposal (Sections 4, 6, and extended confidence modeling)
**Prerequisite**: Phase 1 and Phase 2 must be complete

---

## Executive Summary

Phase 3 extends SentinelForge's capability model beyond single-target analysis into cross-asset correlation, graph-informed confidence adjustment, and combined leverage scoring. While Phases 1 and 2 built the foundational layers (confirmation weighting, information synthesis, enablement edges), Phase 3 teaches the system to:

1. **Model cross-target enablement relationships** (credentials from A unlock resources on B)
2. **Adjust hypothesis confidence based on graph topology** (a finding that enables many others is more valuable)
3. **Rank findings on three-axis leverage** (time-to-impact + uncertainty reduction + effort eliminated)
4. **Introduce effort-eliminated as configurable YAML** (instead of hardcoded values)
5. **Implement gradual rollout** (feature flags for risky changes)

### Key Changes

- **CausalGraph**: Cross-target enablement edges with explicit controls and deduplication
- **NexusContext**: Graph-informed confidence adjustment (one-shot, named, independent, capped)
- **RiskEngine / OMEGA**: Combined leverage metrics and three-axis priority scoring
- **Config infrastructure**: Expose EFFORT_ELIMINATED in YAML for tuning
- **Feature flags**: Gradual rollout of cross-target and graph-informed features

### Impact on Users

- Credentials found on monitoring systems now visibly unlock resources on production systems
- Confirmed information findings with high graph leverage get confidence boost (+0.10 max) — but only once
- Priority ranking now reflects attacker decision-making: fastest path + most uncertainty reduction + most effort eliminated
- Advanced teams can tune effort-elimination values per engagement without code changes
- New features can be toggled on/off safely during rollout

---

## Prerequisites (Phase 1+2 Completion Checklist)

### Phase 1: ConfirmationLevel + Capability Types (Required)

**Verify in code**:
```bash
grep -n "confirmation_level" core/epistemic/ledger.py | wc -l  # Should be 8+
grep -n "capability_types" core/toolkit/vuln_rules.py | wc -l  # Should be 30+
grep -n "CONFIRMATION_MULTIPLIERS" core/data/risk.py           # Should exist
```

**Verification checklist**:
- [ ] Finding.confirmation_level exists (default "probable")
- [ ] VulnRule.capability_types exists (default ["execution"])
- [ ] CREDENTIAL_INDICATORS (21 items) defined in vuln_rules.py
- [ ] Content-aware escalation in _match_backup_rule()
- [ ] Confirmation multiplier applied in VulnRule.apply() and RiskEngine.recalculate()

### Phase 2: NexusContext + CausalGraph + Strategos (Required)

**Verify in code**:
```bash
grep -n "EnablementStrength" core/cortex/causal_graph.py        # Should exist (enum)
grep -n "INFORMATION_HYPOTHESIS_CONFIDENCE" core/cortex/nexus_context.py  # Should exist
grep -n "CONFIRMED_EXPOSURE" core/contracts/schemas.py          # Should exist
```

**Verification checklist**:
- [ ] CausalGraph has EnablementStrength enum (DIRECT=2.0, INDIRECT=1.0, WEAK=0.5)
- [ ] CausalGraph has EFFORT_ELIMINATED_BY_CAPABILITY constant
- [ ] _infer_information_enablement_edges() implemented
- [ ] NexusContext Rule 3 (information enablement synthesis) fires for confirmed info
- [ ] Strategos routes CONFIRMED + access → CONFIRMED_EXPOSURE action
- [ ] Strategos deprioritizes HYPOTHESIZED findings by +2 priority

---

## 1. New Data Structures and Enums

### 1.1 Cross-Target Correlation Controls Enum

**File**: `core/cortex/causal_graph.py` (new, at module top)

```python
class CrossTargetControl(str, Enum):
    """Controls for cross-target enablement edge creation."""
    DISABLED = "disabled"           # No cross-target edges (Phase 2 behavior, safe)
    CREDENTIALS_ONLY = "credentials_only"  # Only credential findings enable cross-target
    EXPLICIT_CORRELATION = "explicit_correlation"  # Only via correlation rules
    FULL_HEURISTIC = "full_heuristic"  # All info findings can enable cross-target (Phase 3 experimental)
```

### 1.2 Graph-Informed Confidence Adjustment Config

**File**: `core/cortex/nexus_context.py` (new, at module top)

```python
class GraphConfidenceConfig:
    """Configuration for graph-informed confidence adjustment."""
    ENABLED = False  # Feature flag: activate in Phase 3+
    CAP_BOOST = 0.10  # Maximum boost to confidence (prevents runaway inflation)
    ENABLEMENT_EDGE_WEIGHT_THRESHOLD = 1.0  # Only count edges with strength >= this
    MAX_ENABLED_FINDINGS = 10  # Only boost if enables <= this many (prevents noise)
    MIN_FINDING_CONFIRMATION = "probable"  # Only boost if source is CONFIRMED+ (not HYPOTHESIZED)
```

### 1.3 Three-Axis Ranking Weights

**File**: `core/data/risk.py` (new constants)

```python
# Three-axis ranking dimensions (Phase 3)
TIME_TO_IMPACT_WEIGHT = 0.40
UNCERTAINTY_REDUCTION_WEIGHT = 0.30
EFFORT_ELIMINATED_WEIGHT = 0.30

# Sanity check
assert abs(TIME_TO_IMPACT_WEIGHT + UNCERTAINTY_REDUCTION_WEIGHT + EFFORT_ELIMINATED_WEIGHT - 1.0) < 0.001
```

### 1.4 Extended PressurePoint Dataclass

**File**: `core/cortex/causal_graph.py` (extend existing PressurePoint)

```python
# Update existing @dataclass PressurePoint:
@dataclass
class PressurePoint:
    finding_id: str
    finding_title: str
    severity: str
    out_degree: int
    attack_paths_blocked: int
    downstream_findings: List[str]
    centrality_score: float
    enablement_score: float = 0.0

    # NEW Phase 3 fields:
    cross_target_edges: int = 0  # Count of cross-target enablement edges
    combined_leverage: float = 0.0  # Derived: centrality + enablement + cross-target

    # NEW Phase 3: Three-axis ranking breakdown
    time_to_impact_score: float = 0.0
    uncertainty_reduction_score: float = 0.0
    effort_eliminated_score: float = 0.0
    priority_composite_score: float = 0.0  # Weighted combination of above
```

### 1.5 Finding Confidence Boost Metadata

**File**: `core/cortex/nexus_context.py` (extend NexusContext)

```python
@dataclass
class ConfidenceBoostMetadata:
    """Track confidence boosts from graph-informed adjustment."""
    finding_id: str
    original_confidence: float
    boost_reason: str  # e.g., "enablement_edge_count", "cross_target_unlock"
    boost_amount: float  # 0.0 to 0.10
    boosted_confidence: float
    enabled_findings_count: int
    applied_at: float  # timestamp
    rule_version: int = 1
```

---

## 2. Step-by-Step Implementation (Dependency Order)

### Step 1: Add Config Infrastructure for EFFORT_ELIMINATED

**Files**: `core/base/config.py`, `rules.yaml`

#### Step 1.1: Extend ScanConfig with capability model settings

**File**: `core/base/config.py`

Add to existing ScanConfig dataclass:

```python
@dataclass(frozen=True)
class CapabilityModelConfig:
    """Configuration for attacker capability model (Phase 3+)."""

    # Cross-target correlation controls
    cross_target_control: str = "credentials_only"  # or "disabled" for Phase 2 behavior

    # Graph-informed confidence adjustment
    graph_confidence_enabled: bool = False  # Feature flag
    confidence_boost_cap: float = 0.10  # Max boost per finding

    # Three-axis ranking weights
    time_to_impact_weight: float = 0.40
    uncertainty_reduction_weight: float = 0.30
    effort_eliminated_weight: float = 0.30

    # Effort elimination table (dict, loaded from YAML)
    effort_eliminated_by_capability: Dict[str, float] = field(
        default_factory=lambda: {
            "credential_exposure": 9.0,
            "source_code": 8.0,
            "topology": 7.0,
            "confirmed_injection": 6.0,
            "stack_disclosure": 4.0,
            "port_disclosure": 3.0,
            "partial_info": 2.0,
        }
    )

    @classmethod
    def from_env_and_file(cls, config_path: Optional[Path] = None) -> "CapabilityModelConfig":
        """
        Load config from environment variables and optional YAML file.

        Environment variables take precedence:
        - SENTINEL_CROSS_TARGET_CONTROL
        - SENTINEL_GRAPH_CONFIDENCE_ENABLED
        - SENTINEL_CONFIDENCE_BOOST_CAP
        - SENTINEL_TIME_TO_IMPACT_WEIGHT
        - etc.

        If config_path points to a YAML file, load effort_eliminated table from it.
        """
        import os
        import yaml

        kwargs = {}

        # Load from environment
        cross_target = os.getenv("SENTINEL_CROSS_TARGET_CONTROL", "credentials_only")
        if cross_target in ("disabled", "credentials_only", "explicit_correlation", "full_heuristic"):
            kwargs["cross_target_control"] = cross_target

        graph_conf_enabled = os.getenv("SENTINEL_GRAPH_CONFIDENCE_ENABLED", "").lower()
        if graph_conf_enabled in ("true", "1", "yes"):
            kwargs["graph_confidence_enabled"] = True

        conf_boost_cap = os.getenv("SENTINEL_CONFIDENCE_BOOST_CAP")
        if conf_boost_cap:
            try:
                kwargs["confidence_boost_cap"] = float(conf_boost_cap)
            except ValueError:
                pass  # Use default

        # Load effort table from YAML if provided
        if config_path and config_path.exists():
            try:
                with open(config_path) as f:
                    data = yaml.safe_load(f)
                    if data and "effort_eliminated" in data:
                        kwargs["effort_eliminated_by_capability"] = data["effort_eliminated"]
            except Exception as e:
                logger.warning(f"Failed to load capability config from {config_path}: {e}")

        return cls(**kwargs)
```

#### Step 1.2: Create sample YAML config file

**File**: `core/cortex/capability_model_config.yaml`

```yaml
# SentinelForge Phase 3: Capability Model Configuration
# This file defines effort elimination values and feature flags.
# All values can be overridden by environment variables.

# Cross-target correlation controls
# Options: disabled, credentials_only, explicit_correlation, full_heuristic
cross_target_control: credentials_only

# Graph-informed confidence adjustment (Phase 3+ feature)
graph_confidence_enabled: false
confidence_boost_cap: 0.10

# Three-axis ranking weights (must sum to 1.0)
time_to_impact_weight: 0.40
uncertainty_reduction_weight: 0.30
effort_eliminated_weight: 0.30

# Effort elimination values: how much attacker work is replaced by each finding type
# Values are on a 0-10 scale (like severity scores)
effort_eliminated:
  credential_exposure: 9.0      # Replaces brute-force authentication
  source_code: 8.0              # Replaces black-box code discovery
  topology: 7.0                 # Replaces network enumeration
  confirmed_injection: 6.0      # Replaces fuzzing for injection points
  stack_disclosure: 4.0         # Replaces fingerprinting
  port_disclosure: 3.0          # Replaces port scanning
  partial_info: 2.0             # Generic reconnaissance value
```

#### Step 1.3: Integrate config loading into application startup

**File**: `core/base/app.py` or initialization code

```python
from core.base.config import CapabilityModelConfig
from pathlib import Path

# During app initialization:
capability_config = CapabilityModelConfig.from_env_and_file(
    config_path=Path("core/cortex/capability_model_config.yaml")
)

# Make it globally accessible
CAPABILITY_MODEL_CONFIG = capability_config
```

---

### Step 2: Add Cross-Target Enablement Edge Inference

**File**: `core/cortex/causal_graph.py`

#### Step 2.1: Add CrossTargetControl enum and guards

**Location**: After EnablementStrength enum

```python
class CrossTargetControl(str, Enum):
    DISABLED = "disabled"
    CREDENTIALS_ONLY = "credentials_only"
    EXPLICIT_CORRELATION = "explicit_correlation"
    FULL_HEURISTIC = "full_heuristic"
```

#### Step 2.2: Create cross-target enablement inference method

**Location**: Inside CausalGraph class, after `_infer_information_enablement_edges()`

```python
def _infer_cross_target_enablement_edges(
    self,
    findings: List[dict],
    cross_target_control: str = "credentials_only"
) -> List[dict]:
    """
    Create enablement edges ACROSS targets.

    Example:
      Finding A: API credentials on monitoring.example.com
      Finding B: AWS authentication on prod.example.com
      Edge: A enables B (credentials from monitoring unlock prod auth)

    Args:
        findings: All findings from all targets
        cross_target_control: Enum value controlling scope

    Returns:
        List of cross-target enablement edges

    Safety guarantees:
    1. Only CONFIRMED findings create cross-target edges (hypothesized cannot)
    2. Deduplication: only one edge per (source, target) pair
    3. Heuristic guards: only credential findings in "credentials_only" mode
    4. Rate limiting: max N edges per source finding (prevents explosion)
    """
    if cross_target_control == CrossTargetControl.DISABLED.value:
        return []

    edges = []
    max_edges_per_source = 5  # Rate limit

    # Index findings by target for faster lookup
    by_target = {}
    for finding in findings:
        target = finding.get("target", "unknown")
        by_target.setdefault(target, []).append(finding)

    # Find credential/access findings (sources of cross-target edges)
    credential_findings = [
        f for f in findings
        if f.get("confirmation_level") == "confirmed"
        and any(cap in f.get("capability_types", [])
               for cap in ["access", "information"])
    ]

    # For each credential finding, find targets it could enable on other targets
    seen_edges = set()  # Deduplication

    for source_finding in credential_findings:
        source_id = source_finding.get("id", "unknown")
        source_target = source_finding.get("target", "unknown")
        enablement_class = self._classify_enablement(source_finding)

        # Determine if this source can cross targets
        if cross_target_control == CrossTargetControl.CREDENTIALS_ONLY.value:
            # Only credential/access findings cross targets
            if enablement_class not in ("credential_exposure", "source_code"):
                continue
        elif cross_target_control == CrossTargetControl.EXPLICIT_CORRELATION.value:
            # Only explicit correlation rules create cross-target edges
            # (handled separately, not here)
            continue
        elif cross_target_control == CrossTargetControl.FULL_HEURISTIC.value:
            # Any confirmed info/access finding can cross targets
            pass
        else:
            continue

        # Find target findings on OTHER targets
        edges_created = 0
        for other_target, other_findings in by_target.items():
            if other_target == source_target:
                continue  # Skip same-target (already handled by Phase 2)

            if edges_created >= max_edges_per_source:
                break

            # Find findings on other_target that could benefit
            target_findings = [
                f for f in other_findings
                if f.get("confirmation_level") in ("confirmed", "probable")
                and any(cap in f.get("capability_types", [])
                       for cap in ["execution", "access"])
            ]

            for target_finding in target_findings:
                target_id = target_finding.get("id", "unknown")
                edge_key = (source_id, target_id)

                # Deduplication check
                if edge_key in seen_edges:
                    continue

                # Would this enabling actually help?
                if not self._cross_target_would_benefit(
                    target_finding, enablement_class, source_target, other_target
                ):
                    continue

                # Create edge
                strength = self._enablement_strength(
                    source_finding.get("capability_types", []),
                    enablement_class
                )
                effort = EFFORT_ELIMINATED_BY_CAPABILITY.get(enablement_class, 2.0)

                edges.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "enablement",
                    "strength": float(strength),
                    "enablement_class": enablement_class,
                    "effort_replaced": float(effort),
                    "cross_target": True,  # NEW: flag to distinguish
                    "source_target": source_target,
                    "target_target": other_target,
                    "enabled_at": time.time(),
                })

                seen_edges.add(edge_key)
                edges_created += 1

    return edges
```

#### Step 2.3: Add helper for cross-target benefit evaluation

**Location**: Inside CausalGraph class

```python
def _cross_target_would_benefit(
    self,
    target_finding: dict,
    enablement_class: str,
    source_target: str,
    other_target: str
) -> bool:
    """
    Heuristic: does a finding on other_target benefit from credentials on source_target?

    Example: Credentials on monitoring.example.com would benefit an auth bypass on
    prod.example.com if the credentials are for a shared service/account.
    """
    target_tags = set(target_finding.get("tags", []))
    target_type = target_finding.get("type", "").lower()

    # Credentials can unlock auth on any target (same service, shared accounts)
    if enablement_class == "credential_exposure":
        # Always true — credentials from one target often unlock others
        return True

    # Source code can help exploit other targets if same tech stack
    if enablement_class == "source_code":
        # Check if both targets have similar characteristics
        # (simplified: both are web, both are APIs, etc.)
        if any(tag in target_tags for tag in ["api", "web", "auth"]):
            return True

    # Topology helps with lateral movement
    if enablement_class == "topology":
        # IP disclosure helps if other target is internal/reachable
        if any(tag in target_tags for tag in ["internal", "private", "database"]):
            return True

    return False
```

#### Step 2.4: Integrate cross-target edges into _infer_dependencies()

**Location**: End of existing `_infer_dependencies()` method

```python
def _infer_dependencies(self, findings: List[dict]) -> List[dict]:
    """
    Infer dependencies between findings.

    Rules 1-4: Existing chain rules
    Rule 5: Single-target enablement edges (Phase 2)
    Rule 6: NEW - Cross-target enablement edges (Phase 3)
    """
    # ... existing Rules 1-5 code ...

    # Rule 6: Cross-target enablement edges (Phase 3, gated by feature flag)
    from core.base.app import CAPABILITY_MODEL_CONFIG  # Import at use time
    cross_target_control = CAPABILITY_MODEL_CONFIG.cross_target_control
    cross_target_edges = self._infer_cross_target_enablement_edges(
        findings,
        cross_target_control
    )
    edges.extend(cross_target_edges)

    return edges
```

#### Step 2.5: Update graph metrics to track cross-target edges

**Location**: Inside `get_attack_chains()` method, in the node summary section

```python
# In the node_summary dict building:
cross_target_edge_count = sum(
    1 for edge in node_edges
    if edge.get("cross_target") is True
)

node_summary["cross_target_edge_count"] = cross_target_edge_count

# Update combined_leverage to include cross-target contribution
combined_leverage = (
    node["centrality_score"] +
    node["enablement_score"] +
    (cross_target_edge_count * 0.5)  # Weight cross-target lower than same-target
)

node_summary["combined_leverage"] = combined_leverage
```

---

### Step 3: Graph-Informed Confidence Adjustment in NexusContext

**File**: `core/cortex/nexus_context.py`

#### Step 3.1: Add GraphConfidenceConfig class

**Location**: After existing INFORMATION_HYPOTHESIS_CONFIDENCE

```python
@dataclass
class GraphConfidenceConfig:
    """Configuration for graph-informed confidence adjustment."""
    enabled: bool = False
    cap_boost: float = 0.10
    enablement_weight_threshold: float = 1.0
    max_enabled_findings: int = 10

    @classmethod
    def from_app_config(cls) -> "GraphConfidenceConfig":
        """Load from global app config."""
        from core.base.app import CAPABILITY_MODEL_CONFIG
        return cls(
            enabled=CAPABILITY_MODEL_CONFIG.graph_confidence_enabled,
            cap_boost=CAPABILITY_MODEL_CONFIG.confidence_boost_cap,
        )
```

#### Step 3.2: Add graph-informed confidence boost method

**Location**: Inside NexusContext class, after Rule 3 synthesis

```python
def _apply_graph_informed_confidence_boost(
    self,
    finding: dict,
    base_confidence: float,
    causal_graph: Optional["CausalGraph"] = None
) -> Tuple[float, Optional[ConfidenceBoostMetadata]]:
    """
    One-shot graph reading: boost hypothesis confidence if finding has
    high enablement leverage.

    Design constraints (from Phase 3 spec):
    1. ONE-SHOT: Read graph once, snapshot it. Don't re-read after hypothesis.
    2. NAMED CONCEPT: Not a buried multiplier. Return metadata explaining boost.
    3. INDEPENDENT: Test separately from Rule 3 confidence mapping.
    4. CAPPED: Maximum +0.10 boost per finding.

    Args:
        finding: The finding being scored
        base_confidence: Confidence from _confidence_for_information_finding()
        causal_graph: Optional graph (for testing; defaults to global)

    Returns:
        Tuple[boosted_confidence, metadata]
    """
    config = GraphConfidenceConfig.from_app_config()

    if not config.enabled or causal_graph is None:
        return base_confidence, None

    # ONE-SHOT: Read graph state once
    chains = causal_graph.get_attack_chains()

    finding_id = finding.get("id", "unknown")
    node = None
    for chain in chains:
        for n in chain.get("nodes", []):
            if n.get("id") == finding_id:
                node = n
                break
        if node:
            break

    if not node:
        # Finding not in graph, no boost
        return base_confidence, None

    # Calculate boost based on enablement leverage
    enablement_score = node.get("enablement_score", 0.0)
    enabled_count = node.get("downstream_findings", [])

    # Safety guard: only boost if enablement is meaningful
    if enablement_score < config.enablement_weight_threshold:
        return base_confidence, None

    if len(enabled_count) > config.max_enabled_findings:
        # Too many; treat as noise, don't boost
        return base_confidence, None

    # Compute boost: proportional to leverage, capped at cap_boost
    # Formula: boost = min(cap, enablement_score / 10.0)
    raw_boost = min(config.cap_boost, enablement_score / 10.0)

    boosted_confidence = min(1.0, base_confidence + raw_boost)

    metadata = ConfidenceBoostMetadata(
        finding_id=finding_id,
        original_confidence=base_confidence,
        boost_reason="graph_enablement_leverage",
        boost_amount=raw_boost,
        boosted_confidence=boosted_confidence,
        enabled_findings_count=len(enabled_count),
        applied_at=time.time(),
    )

    return boosted_confidence, metadata
```

#### Step 3.3: Update Rule 3 to optionally use graph boost

**Location**: Inside synthesize_attack_paths(), in Rule 3 section

Modify the existing Rule 3 code:

```python
# Rule 3: Information Enablement Synthesis
for finding in rule_3_findings:
    finding_id = finding.get("id", "unknown")
    finding_type = finding.get("type", "").lower()
    base_score = finding.get("base_score", 5.0)

    # Determine base confidence from finding content
    base_confidence = self._confidence_for_information_finding(finding)

    # NEW Phase 3: Apply graph-informed boost (one-shot, capped)
    causal_graph = self._get_causal_graph_snapshot()  # See Step 3.4
    final_confidence, boost_metadata = self._apply_graph_informed_confidence_boost(
        finding,
        base_confidence,
        causal_graph
    )

    # Emit hypothesis with boosted confidence
    hypothesis_id = self._generate_hypothesis_id(
        finding_ids=[finding_id],
        rule_id="rule_information_enablement",
        rule_version=2  # Bump version for Phase 3 changes
    )

    if hypothesis_id not in self._seen_hypothesis_ids:
        explanation = self._enablement_explanation(finding)
        if boost_metadata:
            explanation += (
                f"\n[Confidence boost: {base_confidence:.2f} → {final_confidence:.2f} "
                f"due to {boost_metadata.enabled_findings_count} downstream enabled findings]"
            )

        self._emit_hypothesis_event(
            event_type=NexusEventType.NEXUS_HYPOTHESIS_FORMED,
            hypothesis_id=hypothesis_id,
            finding_ids=[finding_id],
            confidence=final_confidence,  # Use boosted value
            explanation=explanation,
            rule="information_enablement",
            finding_type=finding_type,
            base_score=base_score,
            metadata={
                "base_confidence": base_confidence,
                "confidence_boost": boost_metadata,
            } if boost_metadata else {},
        )
        self._seen_hypothesis_ids.add(hypothesis_id)
```

#### Step 3.4: Add causal graph snapshot getter

**Location**: Inside NexusContext class

```python
def _get_causal_graph_snapshot(self) -> Optional["CausalGraph"]:
    """
    Get a one-time snapshot of the causal graph.

    This is called once per NexusContext synthesis to avoid
    bidirectional dependencies (graph ↔ hypotheses).
    """
    try:
        from core.cortex.causal_graph import CausalGraph
        return CausalGraph.instance()  # Or however the graph is accessed
    except Exception as e:
        logger.warning(f"Could not access causal graph for confidence boost: {e}")
        return None
```

---

### Step 4: Three-Axis Ranking and Combined Leverage Metrics

**Files**: `core/data/risk.py`, `core/cortex/causal_graph.py`

#### Step 4.1: Add three-axis scoring helper in RiskEngine

**File**: `core/data/risk.py`

```python
from core.base.app import CAPABILITY_MODEL_CONFIG

class RiskEngine(Observable):
    # ... existing code ...

    def compute_three_axis_priority(
        self,
        issue: dict,
        causal_graph: Optional[dict] = None
    ) -> Dict[str, float]:
        """
        Compute priority using three axes:
        1. Time-to-Impact (how quickly can attacker use this)
        2. Uncertainty Reduction (how many unknowns does this eliminate)
        3. Effort Eliminated (how much work does this replace)

        Returns dict with breakdown:
        {
            "time_to_impact": float (0-10),
            "uncertainty_reduction": float (0-10),
            "effort_eliminated": float (0-10),
            "priority_composite": float (0-10),
        }
        """
        confirmation = issue.get("confirmation_level", "probable")
        capability_types = issue.get("capability_types", ["execution"])
        base_score = issue.get("base_score", 5.0)

        # Time-to-Impact scoring
        time_to_impact = self._compute_time_to_impact(
            confirmation,
            capability_types
        )

        # Uncertainty Reduction scoring (from graph if available)
        uncertainty_reduction = 0.0
        if causal_graph:
            issue_id = issue.get("id", "unknown")
            # Find this issue in graph
            for node in causal_graph.get("nodes", []):
                if node.get("id") == issue_id:
                    # Uncertainty reduction = enablement score
                    uncertainty_reduction = min(10.0, node.get("enablement_score", 0.0))
                    break

        # Effort Eliminated scoring
        effort_eliminated = self._compute_effort_eliminated(
            issue,
            causal_graph
        )

        # Composite score (weighted sum)
        weights = CAPABILITY_MODEL_CONFIG
        priority_composite = (
            weights.time_to_impact_weight * time_to_impact +
            weights.uncertainty_reduction_weight * uncertainty_reduction +
            weights.effort_eliminated_weight * effort_eliminated
        )

        return {
            "time_to_impact": round(time_to_impact, 2),
            "uncertainty_reduction": round(uncertainty_reduction, 2),
            "effort_eliminated": round(effort_eliminated, 2),
            "priority_composite": round(priority_composite, 2),
        }

    def _compute_time_to_impact(
        self,
        confirmation: str,
        capability_types: List[str]
    ) -> float:
        """
        Score 0-10 based on how quickly attacker can act.

        Reference table from Design Proposal (Section 4.3):
        - Confirmed Access: 10.0
        - Confirmed Execution: 9.0
        - Confirmed Information: 8.0
        - Probable Execution: 6.0
        - Probable Information: 5.0
        - Hypothesized Execution: 3.0
        - Hypothesized Information: 2.0
        """
        if confirmation == "confirmed":
            if "access" in capability_types:
                return 10.0
            elif "execution" in capability_types:
                return 9.0
            elif "information" in capability_types:
                return 8.0
        elif confirmation == "probable":
            if "execution" in capability_types:
                return 6.0
            else:
                return 5.0
        elif confirmation == "hypothesized":
            if "execution" in capability_types:
                return 3.0
            else:
                return 2.0

        return 5.0  # Default

    def _compute_effort_eliminated(
        self,
        issue: dict,
        causal_graph: Optional[dict] = None
    ) -> float:
        """
        Score 0-10 based on effort replaced.

        Sums effort values from outbound enablement edges.
        Capped at 10.0 (not 30+).
        """
        if not causal_graph:
            return 0.0

        issue_id = issue.get("id", "unknown")
        total_effort = 0.0

        # Find edges originating from this issue
        for edge in causal_graph.get("edges", []):
            if edge.get("source") == issue_id and edge.get("type") == "enablement":
                effort = edge.get("effort_replaced", 0.0)
                total_effort += effort

        return min(10.0, total_effort)
```

#### Step 4.2: Update CausalGraph to compute combined_leverage

**File**: `core/cortex/causal_graph.py`

**Location**: Inside `get_attack_chains()` method, in node summary building

```python
def get_attack_chains(self) -> List[Dict[str, Any]]:
    """
    Get attack chains with all metrics.

    Returns list of chains, each with nodes containing:
    - centrality_score: exploit chain importance
    - enablement_score: information leverage (Phase 2)
    - cross_target_edge_count: cross-target reach (Phase 3)
    - combined_leverage: weighted sum of above (Phase 3)
    """
    # ... existing chain computation code ...

    # In the node_summary building section, add:

    cross_target_count = sum(
        1 for edge in node_edges
        if edge.get("cross_target") is True
    )

    # Combined leverage = exploit centrality + information leverage + cross-target reach
    # Weighted: centrality dominates, then enablement, then cross-target is bonus
    centrality = node_summary.get("centrality_score", 0.0)
    enablement = node_summary.get("enablement_score", 0.0)
    cross_target_bonus = cross_target_count * 0.25  # Lower weight for cross-target

    combined_leverage = (
        centrality * 0.50 +  # Exploit chains matter most
        enablement * 0.40 +  # Information leverage is secondary
        cross_target_bonus * 0.10  # Cross-target is bonus
    )

    node_summary["cross_target_edge_count"] = cross_target_count
    node_summary["combined_leverage"] = round(combined_leverage, 2)
```

---

### Step 5: Feature Flags and Gradual Rollout Infrastructure

**File**: `core/cortex/feature_flags.py` (new file)

```python
"""
Feature flags for Phase 3 capabilities.

These allow safe, gradual rollout of risky changes:
- Cross-target correlation (new graph complexity)
- Graph-informed confidence (new feedback source)
- Three-axis ranking (new priority model)
"""

from dataclasses import dataclass, field
from typing import Dict, Any
import os
import logging

logger = logging.getLogger(__name__)

@dataclass
class FeatureFlags:
    """Phase 3+ feature flags, controlled by environment variables."""

    # Cross-target enablement edges (Phase 3)
    cross_target_edges_enabled: bool = False
    cross_target_control: str = "disabled"  # or "credentials_only"

    # Graph-informed confidence adjustment (Phase 3)
    graph_confidence_enabled: bool = False
    graph_confidence_cap_boost: float = 0.10

    # Three-axis ranking (Phase 3)
    three_axis_ranking_enabled: bool = False

    # Combined leverage metrics (Phase 3)
    combined_leverage_enabled: bool = False

    @classmethod
    def from_environment(cls) -> "FeatureFlags":
        """Load feature flags from environment variables."""
        return cls(
            cross_target_edges_enabled=(
                os.getenv("SF_CROSS_TARGET_EDGES_ENABLED", "false").lower() in ("true", "1", "yes")
            ),
            cross_target_control=os.getenv("SF_CROSS_TARGET_CONTROL", "disabled"),
            graph_confidence_enabled=(
                os.getenv("SF_GRAPH_CONFIDENCE_ENABLED", "false").lower() in ("true", "1", "yes")
            ),
            graph_confidence_cap_boost=float(
                os.getenv("SF_GRAPH_CONFIDENCE_CAP_BOOST", "0.10")
            ),
            three_axis_ranking_enabled=(
                os.getenv("SF_THREE_AXIS_RANKING_ENABLED", "false").lower() in ("true", "1", "yes")
            ),
            combined_leverage_enabled=(
                os.getenv("SF_COMBINED_LEVERAGE_ENABLED", "false").lower() in ("true", "1", "yes")
            ),
        )

    def log_status(self):
        """Log current flag status for debugging."""
        logger.info(
            "Feature Flags: "
            f"cross_target={self.cross_target_edges_enabled} "
            f"({self.cross_target_control}), "
            f"graph_confidence={self.graph_confidence_enabled}, "
            f"three_axis={self.three_axis_ranking_enabled}, "
            f"combined_leverage={self.combined_leverage_enabled}"
        )

# Global instance
FEATURE_FLAGS = FeatureFlags.from_environment()
```

#### Step 5.1: Update code to use feature flags

**Location**: In CausalGraph._infer_dependencies()

```python
from core.cortex.feature_flags import FEATURE_FLAGS

def _infer_dependencies(self, findings: List[dict]) -> List[dict]:
    # ... existing code ...

    # Rule 6: Cross-target enablement edges (Phase 3, gated by feature flag)
    if FEATURE_FLAGS.cross_target_edges_enabled:
        cross_target_edges = self._infer_cross_target_enablement_edges(
            findings,
            FEATURE_FLAGS.cross_target_control
        )
        edges.extend(cross_target_edges)

    return edges
```

**Location**: In NexusContext._apply_graph_informed_confidence_boost()

```python
def _apply_graph_informed_confidence_boost(self, finding, base_confidence, causal_graph=None):
    from core.cortex.feature_flags import FEATURE_FLAGS

    if not FEATURE_FLAGS.graph_confidence_enabled:
        return base_confidence, None

    # ... rest of method ...
```

---

## 3. New Data Structures Summary

| Structure | File | Type | Purpose |
|-----------|------|------|---------|
| `CrossTargetControl` enum | causal_graph.py | Enum | Controls cross-target edge scope |
| `GraphConfidenceConfig` dataclass | nexus_context.py | Dataclass | Config for confidence boost |
| `ConfidenceBoostMetadata` dataclass | nexus_context.py | Dataclass | Tracks why/how confidence was boosted |
| `CapabilityModelConfig` dataclass | config.py | Dataclass | App-level configuration |
| `FEATURE_FLAGS` instance | feature_flags.py | FeatureFlags | Global feature flag state |
| Extended `PressurePoint` | causal_graph.py | Dataclass | Added cross_target_edges, combined_leverage, three-axis scores |

---

## 4. Deterministic Logic

### 4.1 Cross-Target Enablement Edge Creation

**Precondition**:
```
source_finding.confirmation_level == "confirmed"
AND ("access" in source.capability_types OR "information" in source.capability_types)
AND source.target != target.target
AND FEATURE_FLAGS.cross_target_edges_enabled == True
AND FEATURE_FLAGS.cross_target_control != "disabled"
```

**Edge creation heuristics** (based on cross_target_control):

| Control Mode | Allowed Sources | Allowed Targets |
|--------------|-----------------|-----------------|
| DISABLED | (none) | N/A |
| CREDENTIALS_ONLY | credential_exposure, source_code only | Any on different target |
| EXPLICIT_CORRELATION | Only via correlation rules | N/A |
| FULL_HEURISTIC | Any confirmed info/access | Any on different target |

**Deduplication**: One edge per (source_id, target_id) pair maximum.

**Rate limiting**: Max 5 edges per source finding (prevents graph explosion).

### 4.2 Graph-Informed Confidence Adjustment

**Precondition**:
```
FEATURE_FLAGS.graph_confidence_enabled == True
AND finding in causal_graph
AND finding.enablement_score >= GraphConfidenceConfig.enablement_weight_threshold
AND len(finding.downstream_findings) <= GraphConfidenceConfig.max_enabled_findings
```

**Calculation**:
```
raw_boost = min(
    GraphConfidenceConfig.cap_boost,
    finding.enablement_score / 10.0
)
boosted_confidence = min(1.0, base_confidence + raw_boost)
```

**Guarantee**: Confidence never exceeds 1.0. Boost capped at +0.10.

### 4.3 Three-Axis Ranking

**Time-to-Impact Score** (0-10):
| Scenario | Score |
|----------|-------|
| Confirmed Access (credentials, sessions) | 10.0 |
| Confirmed Execution (RCE, SQLi) | 9.0 |
| Confirmed Information (secrets) | 8.0 |
| Probable Execution | 6.0 |
| Probable Information | 5.0 |
| Hypothesized Execution | 3.0 |
| Hypothesized Information | 2.0 |

**Uncertainty Reduction Score** (0-10):
```
uncertainty_reduction = min(10.0, finding.enablement_score)
```
Directly maps enablement leverage to uncertainty reduction.

**Effort Eliminated Score** (0-10):
```
effort_eliminated = min(10.0, sum(effort_replaced for each outbound enablement edge))
```

**Priority Composite Score** (0-10):
```
priority_composite = (
    w_time * time_to_impact +
    w_uncertainty * uncertainty_reduction +
    w_effort * effort_eliminated
)
```
Where weights default to (0.40, 0.30, 0.30) from CapabilityModelConfig.

---

## 5. Integration Points

### 5.1 How Phase 3 Hooks Into Phase 1+2 Code

```
Phase 1 + 2 Data (confirmed/capability/base_score)
    ↓
Phase 3: RiskEngine.compute_three_axis_priority()
    ├─ Reads: confirmation_level, capability_types
    └─ Outputs: time_to_impact, uncertainty_reduction, effort_eliminated, priority_composite

Phase 3: CausalGraph._infer_cross_target_enablement_edges()
    ├─ Reads: confirmation_level, capability_types, target, enablement_class
    ├─ Feature gate: FEATURE_FLAGS.cross_target_edges_enabled
    └─ Creates: cross-target edges with strength and effort values

Phase 3: NexusContext._apply_graph_informed_confidence_boost()
    ├─ Reads: finding from graph snapshot
    ├─ Feature gate: FEATURE_FLAGS.graph_confidence_enabled
    ├─ Reads graph state: enablement_score, downstream_findings
    └─ Outputs: boosted_confidence (capped +0.10)

Phase 3: Config Infrastructure
    ├─ Reads: capability_model_config.yaml, environment variables
    └─ Controls: EFFORT_ELIMINATED, feature flags, weights
```

### 5.2 One-Way Data Flow (No Feedback Loops)

```
CausalGraph
  ├─ Rule 1-5: Single-target enablement edges (Phase 2)
  └─ Rule 6: Cross-target enablement edges (Phase 3)
       ↓ (one-shot read)
    NexusContext Rule 3 graph boost
       ↓
    RiskEngine
       ↓
    Strategos insights
```

**Critical design**: NexusContext reads graph ONCE (snapshot). Does not read again after emitting hypotheses. Prevents bidirectional feedback.

---

## 6. Backward Compatibility

### 6.1 Default Feature Flag State

All Phase 3 features are **OFF by default**:
```python
cross_target_edges_enabled: bool = False
graph_confidence_enabled: bool = False
three_axis_ranking_enabled: bool = False
combined_leverage_enabled: bool = False
```

Behavior before any environment variables set: **Identical to Phase 2**.

### 6.2 Safe Defaults for Missing Config

**If capability_model_config.yaml is missing**:
- Fall back to hardcoded EFFORT_ELIMINATED constant
- Log warning
- Continue processing

**If environment variables are missing**:
- Use defaults from FeatureFlags/CapabilityModelConfig dataclasses
- All Phase 3 features remain disabled
- Phase 1+2 behavior unchanged

### 6.3 Handling Old Findings

```python
# All new code uses .get() with safe defaults
confirmation = issue.get("confirmation_level", "probable")
capability_types = issue.get("capability_types", ["execution"])
cross_target_edges = issue.get("cross_target_edges", 0)

# If fields missing: safe defaults, no crashes
```

### 6.4 API Responses

API responses now optionally include Phase 3 fields:
```json
{
  "finding": {...},
  "phase3_metrics": {
    "time_to_impact": 9.0,
    "uncertainty_reduction": 5.0,
    "effort_eliminated": 6.0,
    "priority_composite": 6.7,
    "combined_leverage": 7.2,
    "confidence_boost": {
      "original": 0.85,
      "boosted": 0.92,
      "boost_reason": "graph_enablement_leverage"
    }
  }
}
```

Old clients ignore these fields. New clients read them. **Zero breaking changes**.

---

## 7. Test Plan

### Test Suite 1: Cross-Target Enablement Edges

#### Test 1.1: Cross-target edges only in credentials_only mode

```python
def test_cross_target_edges_disabled_by_default():
    """Verify cross-target edges don't exist if feature flag off."""
    findings = [
        {"id": "cred_1", "target": "monitor.example.com", "confirmation_level": "confirmed",
         "capability_types": ["access"], "type": "secret_leak"},
        {"id": "auth_1", "target": "prod.example.com", "confirmation_level": "confirmed",
         "capability_types": ["execution"], "type": "auth_bypass", "tags": ["auth"]},
    ]

    graph = CausalGraph(findings, cross_target_control="disabled")
    edges = graph.get_attack_chains()

    cross_target_edges = [e for e in edges if e.get("cross_target") is True]
    assert len(cross_target_edges) == 0, "No cross-target edges with feature disabled"
```

#### Test 1.2: Credentials create cross-target edges in credentials_only mode

```python
def test_credentials_enable_cross_target():
    """Credentials on target A unlock auth on target B."""
    findings = [
        {"id": "cred_1", "target": "monitor.example.com", "confirmation_level": "confirmed",
         "capability_types": ["access"], "type": "secret_leak", "value": "password=secret"},
        {"id": "auth_1", "target": "prod.example.com", "confirmation_level": "probable",
         "capability_types": ["execution"], "type": "login", "tags": ["auth"]},
    ]

    graph = CausalGraph(findings, cross_target_control="credentials_only")
    edges = graph.get_attack_chains()

    cross_target_edges = [e for e in edges if e.get("cross_target") is True]
    assert len(cross_target_edges) > 0, "Credentials should enable cross-target"
    assert cross_target_edges[0]["source"] == "cred_1"
    assert cross_target_edges[0]["target"] == "auth_1"
```

#### Test 1.3: Deduplication (only one edge per pair)

```python
def test_cross_target_edge_deduplication():
    """Same (source, target) pair creates at most one edge."""
    findings = [cred, auth]  # Same as 1.2

    graph = CausalGraph(findings)
    edges = graph.get_attack_chains()

    edge_pairs = {(e["source"], e["target"]) for e in edges if e.get("cross_target")}
    assert len(edge_pairs) == len([e for e in edges if e.get("cross_target")]),\
        "All cross-target edges have unique source/target pairs"
```

#### Test 1.4: Rate limiting (max 5 edges per source)

```python
def test_cross_target_edge_rate_limiting():
    """Single credential finding doesn't create >5 edges."""
    cred = {"id": "cred_1", "target": "A", "confirmation_level": "confirmed",
            "capability_types": ["access"], "type": "secret"}

    # 10 targets with auth findings
    auth_findings = [
        {"id": f"auth_{i}", "target": f"target_{i}", "confirmation_level": "probable",
         "capability_types": ["execution"], "type": "login", "tags": ["auth"]}
        for i in range(10)
    ]

    all_findings = [cred] + auth_findings
    graph = CausalGraph(all_findings)
    edges = graph.get_attack_chains()

    cred_edges = [e for e in edges if e.get("source") == "cred_1"]
    assert len(cred_edges) <= 5, "Rate limit: max 5 edges per source"
```

### Test Suite 2: Graph-Informed Confidence Adjustment

#### Test 2.1: Confidence boost applied when enabled

```python
def test_graph_confidence_boost_enabled():
    """Finding with high enablement gets confidence boost."""
    FEATURE_FLAGS.graph_confidence_enabled = True

    finding = {
        "id": "backup_1", "confirmation_level": "confirmed",
        "capability_types": ["information", "access"], "type": "backup_leak",
        "base_score": 9.5
    }

    # Mock graph where backup_1 enables 3 other findings
    graph = {
        "nodes": [{"id": "backup_1", "enablement_score": 2.0}]
    }

    context = NexusContext()
    base_conf = 0.90
    boosted_conf, metadata = context._apply_graph_informed_confidence_boost(
        finding, base_conf, graph
    )

    assert boosted_conf > base_conf, "Boost applied"
    assert boosted_conf <= base_conf + 0.10, "Boost capped at 0.10"
    assert metadata is not None
    assert metadata.boost_reason == "graph_enablement_leverage"
```

#### Test 2.2: Boost disabled when feature flag off

```python
def test_graph_confidence_boost_disabled():
    """No boost when feature flag off."""
    FEATURE_FLAGS.graph_confidence_enabled = False

    finding = {...}
    graph = {...}

    context = NexusContext()
    base_conf = 0.90
    boosted_conf, metadata = context._apply_graph_informed_confidence_boost(
        finding, base_conf, graph
    )

    assert boosted_conf == base_conf, "No boost applied"
    assert metadata is None
```

#### Test 2.3: Confidence never exceeds 1.0

```python
def test_graph_confidence_boost_capped_at_one():
    """Confidence cannot exceed 1.0 even with large boost."""
    FEATURE_FLAGS.graph_confidence_enabled = True

    finding = {"id": "f1"}
    graph = {"nodes": [{"id": "f1", "enablement_score": 10.0}]}  # Max leverage

    context = NexusContext()
    base_conf = 0.99  # Already high
    boosted_conf, metadata = context._apply_graph_informed_confidence_boost(
        finding, base_conf, graph
    )

    assert boosted_conf <= 1.0, "Never exceeds 1.0"
```

### Test Suite 3: Three-Axis Ranking

#### Test 3.1: Time-to-Impact scoring correct for all combos

```python
def test_time_to_impact_scoring():
    """Verify time_to_impact scores match reference table."""
    engine = RiskEngine()

    cases = [
        ("confirmed", ["access"], 10.0),
        ("confirmed", ["execution"], 9.0),
        ("confirmed", ["information"], 8.0),
        ("probable", ["execution"], 6.0),
        ("hypothesized", ["execution"], 3.0),
    ]

    for confirmation, capabilities, expected in cases:
        score = engine._compute_time_to_impact(confirmation, capabilities)
        assert score == expected, f"TTI({confirmation}, {capabilities}) = {score}, expected {expected}"
```

#### Test 3.2: Effort eliminated sums edge values

```python
def test_effort_eliminated_calculation():
    """Effort eliminated = sum of edge effort values."""
    engine = RiskEngine()

    issue = {"id": "cred_1", "base_score": 9.5}
    graph = {
        "edges": [
            {"source": "cred_1", "target": "auth_1", "type": "enablement", "effort_replaced": 9.0},
            {"source": "cred_1", "target": "db_1", "type": "enablement", "effort_replaced": 3.0},
            {"source": "other", "target": "foo", "type": "enablement", "effort_replaced": 5.0},  # ignored
        ]
    }

    effort = engine._compute_effort_eliminated(issue, graph)
    assert effort == min(10.0, 9.0 + 3.0), "Sums only outbound edges, capped at 10"
```

#### Test 3.3: Composite score is weighted sum

```python
def test_three_axis_composite_score():
    """Priority composite = 0.40 * TTI + 0.30 * UR + 0.30 * EE."""
    engine = RiskEngine()

    issue = {"id": "test", "confirmation_level": "confirmed",
             "capability_types": ["access"], "base_score": 9.0}

    graph = {
        "nodes": [{"id": "test", "enablement_score": 5.0}],
        "edges": [{"source": "test", "target": "other", "type": "enablement", "effort_replaced": 6.0}],
    }

    scores = engine.compute_three_axis_priority(issue, graph)

    # TTI(confirmed, access) = 10.0
    # UR = min(10, 5.0) = 5.0
    # EE = min(10, 6.0) = 6.0
    # Composite = 0.40 * 10 + 0.30 * 5 + 0.30 * 6 = 4 + 1.5 + 1.8 = 7.3

    expected_composite = 0.40 * 10.0 + 0.30 * 5.0 + 0.30 * 6.0
    assert scores["priority_composite"] == round(expected_composite, 2)
```

### Test Suite 4: Config Loading

#### Test 4.1: YAML config loads correctly

```python
def test_config_yaml_loading(tmp_path):
    """Effort elimination values load from YAML."""
    yaml_file = tmp_path / "capability.yaml"
    yaml_file.write_text("""
effort_eliminated:
  credential_exposure: 9.5
  source_code: 7.5
""")

    config = CapabilityModelConfig.from_env_and_file(yaml_file)
    assert config.effort_eliminated_by_capability["credential_exposure"] == 9.5
    assert config.effort_eliminated_by_capability["source_code"] == 7.5
```

#### Test 4.2: Environment variables override config

```python
def test_config_env_override(monkeypatch):
    """Environment variables take precedence over defaults."""
    monkeypatch.setenv("SENTINEL_CROSS_TARGET_CONTROL", "full_heuristic")
    monkeypatch.setenv("SENTINEL_GRAPH_CONFIDENCE_ENABLED", "true")

    config = CapabilityModelConfig.from_env_and_file()
    assert config.cross_target_control == "full_heuristic"
    assert config.graph_confidence_enabled is True
```

### Test Suite 5: End-to-End Scenario (Phase 3 Extension of Scenario A)

**Title**: Credentials on monitoring system unlock production auth

**Setup**:
1. Tool observes credentials on monitoring.example.com (API key for shared service)
2. Promote as CONFIRMED information/access capability
3. Tool observes authentication bypass on prod.example.com
4. Same service account enables it
5. Cross-target edge created: monitoring→prod
6. Combined leverage includes cross-target contribution
7. Priority ranking reflects both same-target and cross-target leverage

**Expected**:
- Cross-target edge: monitoring credentials → prod auth
- Enablement_score for credentials increased (includes 2+ downstream)
- Graph-informed boost: 0.90 → 0.95 (assuming enabled)
- Combined leverage high (all three dimensions)
- Priority composite: ~8.0+ (confirmed access + high uncertainty reduction + high effort elimination)
- Strategos routes both to CONFIRMED_EXPOSURE (access findings)

---

## 8. Edge Cases and Risk Mitigation

### 8.1 Cross-Target Graph Explosion

**Risk**: Too many findings + cross-target edges = O(n²) edges.

**Mitigation**:
- Rate limit: max 5 edges per source finding
- Control modes: start with "disabled", then "credentials_only"
- Feature flag: can disable entirely
- Monitoring: log edge creation counts per scan

### 8.2 Confidence Boost Cascade

**Risk**: Boosted confidence affects downstream scoring, which could affect other boosts (feedback loop).

**Mitigation**:
- ONE-SHOT: Read graph exactly once, then stop reading it
- Cap: +0.10 maximum per finding (not cumulative)
- Gate: only applies to Rule 3 confidence, not base_confidence
- Independent testing: test boost separately from Rule 3

### 8.3 Effort Elimination Miscalibration

**Risk**: Hardcoded or misconfigured effort values don't match reality.

**Mitigation**:
- Expose as YAML: teams can tune per engagement
- Conservative defaults: based on Design Proposal (tested with bug bounty logic)
- Logging: log actual effort calculations for visibility
- Monitoring: dashboard showing effort vs. actual remediation time

### 8.4 Missing Cross-Target Correlation Rules

**Risk**: Heuristic _cross_target_would_benefit() too simplistic.

**Mitigation**:
- Start conservative: only credentials in Phase 3
- Add explicit correlation rules in Phase 4+
- Log when heuristics create edges (for audit)
- Test heavily against real scan data

### 8.5 Combined Leverage Interpretation

**Risk**: Users confused by combined_leverage metric (what does 7.2 mean?).

**Mitigation**:
- Documentation: explain formula explicitly
- API response: include three-axis breakdown always
- UI: show "time-to-impact", "uncertainty", "effort" separately, then composite
- Explainability: "finding high leverage because: (1) immediate access, (2) enables 5 endpoints, (3) saves brute-force"

---

## 9. Execution Order and Dependency Graph

**Critical Path** (some tasks can parallelize):

1. **Step 1: Config Infrastructure** (2-3 days)
   - Add CapabilityModelConfig dataclass
   - Create capability_model_config.yaml template
   - Integrate with app startup
   - Dependencies: None

2. **Step 2: Cross-Target Enablement Edges** (3-4 days)
   - Add CrossTargetControl enum
   - Implement _infer_cross_target_enablement_edges()
   - Implement _cross_target_would_benefit() heuristics
   - Add deduplication and rate limiting
   - Integrate into _infer_dependencies()
   - Dependencies: Phase 2 complete, config infrastructure (Step 1)

3. **Step 3: Graph-Informed Confidence Boost** (2-3 days)
   - Add GraphConfidenceConfig dataclass
   - Implement _apply_graph_informed_confidence_boost()
   - Integrate into Rule 3 (one-shot graph snapshot)
   - Add ConfidenceBoostMetadata tracking
   - Dependencies: Phase 2 complete, config infrastructure (Step 1)

4. **Step 4: Three-Axis Ranking** (2-3 days)
   - Add three-axis scoring constants/weights
   - Implement compute_three_axis_priority() in RiskEngine
   - Implement _compute_time_to_impact(), _compute_effort_eliminated()
   - Update CausalGraph to compute combined_leverage
   - Dependencies: Phase 2 complete, config infrastructure (Step 1)

5. **Step 5: Feature Flags** (1-2 days)
   - Create feature_flags.py with FeatureFlags class
   - Add environment variable parsing
   - Gate all Phase 3 features behind flags
   - Log flag status on startup
   - Dependencies: All other steps

6. **Testing & Validation** (3-5 days)
   - Write test suites (all 5 suites above)
   - Integration testing with Phase 1+2
   - Backward compatibility verification
   - Real scan data validation
   - Dependencies: Steps 1-5 complete

**Total Effort**: 13-20 days (sequential)
**With Parallelization** (Steps 2, 3, 4 in parallel): 9-12 days

**Recommended Phasing**:
- Week 1: Steps 1 + (2 and 3 in parallel)
- Week 2: Step 4 + feature flags + early testing
- Week 3: Full test suite + validation + documentation

---

## 10. Per-Change Tradeoff Analysis

### Cross-Target Enablement Edges (Step 2)

| Aspect | Assessment |
|--------|-----------|
| **Complexity** | MEDIUM-HIGH. Heuristics, deduplication, rate limiting needed. |
| **Value** | HIGH. Credentials on monitoring system now unlock prod resources (realistic attack path). |
| **Risk** | MEDIUM. Can create false-positive edges if heuristics wrong. Mitigated by starting with "credentials_only" mode and feature flag. |
| **Testing** | HIGH. Needs 4+ test cases + validation with real scans. |
| **Future-proof** | HIGH. Explicit correlation rules can replace heuristics later. Cross-target control enum extensible. |
| **Tradeoff** | Value > Risk (with careful rollout). Worth doing after Phase 2 validated. |

### Graph-Informed Confidence Boost (Step 3)

| Aspect | Assessment |
|--------|-----------|
| **Complexity** | LOW-MEDIUM. One-shot graph read, simple boost formula, capped. |
| **Value** | MEDIUM. Findings with high enablement leverage get visible confidence boost (0.85 → 0.92). |
| **Risk** | LOW. One-shot design prevents feedback loops. Cap at +0.10 prevents runaway. Feature gate allows testing. |
| **Testing** | MEDIUM. 3-4 test cases. Independent of Rule 3. |
| **Future-proof** | HIGH. Can extend with different boost sources later. |
| **Tradeoff** | Value >> Complexity. Low-risk. Worth doing. |

### Three-Axis Ranking (Step 4)

| Aspect | Assessment |
|--------|-----------|
| **Complexity** | LOW-MEDIUM. Formula-based, no AI, deterministic. |
| **Value** | HIGH. Priority now reflects attacker decision-making (not just severity). Credential findings rank correctly vs. speculative execution. |
| **Risk** | LOW. Default weights based on Design Proposal (bug bounty logic). Exposed in YAML for tuning. |
| **Testing** | MEDIUM. Reference table test + formula validation. |
| **Future-proof** | HIGH. Weights tunable, axes extensible. |
| **Tradeoff** | Value >> Complexity. Worth doing. |

---

## 11. Feature Flag and Gradual Rollout Strategy

### Rollout Phases

**Phase 3.0: Internal Testing** (Week 1-2)
- All feature flags OFF
- Code merged to dev branch
- Run full test suite
- No user impact

**Phase 3.1: Beta (Opt-In)** (Week 3-4)
```bash
# Users can enable:
export SF_CROSS_TARGET_EDGES_ENABLED=true
export SF_CROSS_TARGET_CONTROL=credentials_only
```
- Start with "credentials_only" (least risky)
- Gather feedback
- Monitor for false-positive edges
- Use real scan data for validation

**Phase 3.2: Graph Confidence (Opt-In)** (Week 5)
```bash
export SF_GRAPH_CONFIDENCE_ENABLED=true
```
- Enable after cross-target edges stable
- Monitor confidence boosts
- Compare ranking before/after

**Phase 3.3: Three-Axis Ranking (Opt-In)** (Week 6)
```bash
export SF_THREE_AXIS_RANKING_ENABLED=true
```
- Can be enabled independently
- Compare composite scores with OMEGA scores
- Validate against bug bounty logic

**Phase 3.4: Production Default** (Week 8+)
- Flip all flags to True in main configuration
- Can still disable via environment
- Monitor in production
- Gradual rollout to customers

### Monitoring and Observability

**Metrics to track**:
- Cross-target edge count (should be 10-20% of single-target edges)
- Confidence boost distribution (max boost = 0.10, most < 0.05)
- Three-axis score correlation with OMEGA score (should be high)
- Finding ranking changes (compare before/after rollout)

**Alerts**:
- Cross-target edge count > N per finding (rate limit breach)
- Confidence boost > 0.10 (cap enforcement)
- Combined leverage NaN or infinite (calculation error)

---

## 12. Files Modified/Created (Summary)

| File | Changes | Type | Effort |
|------|---------|------|--------|
| `core/base/config.py` | Add CapabilityModelConfig dataclass with YAML loading | Additive | 1-2 days |
| `core/cortex/capability_model_config.yaml` | NEW: YAML template for effort elimination + feature config | New | 0.5 days |
| `core/cortex/causal_graph.py` | Add CrossTargetControl enum, _infer_cross_target_edges(), _cross_target_would_benefit(), extend get_attack_chains() for combined_leverage | Additive | 3-4 days |
| `core/cortex/nexus_context.py` | Add GraphConfidenceConfig, _apply_graph_informed_confidence_boost(), _get_causal_graph_snapshot(), update Rule 3 | Additive | 2-3 days |
| `core/cortex/feature_flags.py` | NEW: FeatureFlags class with environment variable parsing | New | 1 day |
| `core/data/risk.py` | Add compute_three_axis_priority(), _compute_time_to_impact(), _compute_effort_eliminated() | Additive | 2-3 days |
| `core/contracts/schemas.py` | Extend PressurePoint dataclass with cross_target_edge_count, combined_leverage, three-axis scores | Modificative | 1 day |

**Total Implementation Effort**: 11-16 days (with parallelization: 8-11 days)

---

## 13. Success Criteria

### Functional Criteria

- [ ] Cross-target enablement edges created for credential findings (when feature enabled)
- [ ] Cross-target edges weight correctly (DIRECT 2.0 for credentials)
- [ ] Deduplication works (max 1 edge per source/target pair)
- [ ] Rate limiting works (max 5 edges per source)
- [ ] Graph-informed confidence boost applied (one-shot, capped at +0.10)
- [ ] Three-axis ranking computed correctly (formula matches Design Proposal)
- [ ] Combined leverage metric computed and included in graph output
- [ ] YAML config loading works (effort values override hardcoded)
- [ ] All feature flags default to OFF (zero breaking changes)
- [ ] Scenario B test passes: credentials on monitoring unlock prod resources

### Backward Compatibility Criteria

- [ ] No existing tests fail
- [ ] Phase 2 behavior identical when feature flags OFF
- [ ] Old findings (missing Phase 3 fields) still process correctly
- [ ] No database migration required
- [ ] API responses backward compatible (new fields optional)

### Performance Criteria

- [ ] Cross-target edge inference: < 500ms for 1000 findings
- [ ] Confidence boost calculation: < 100ms
- [ ] Three-axis ranking: < 50ms per finding
- [ ] No regression in graph construction time

### Rollout Criteria

- [ ] All feature flags environment-variable controlled
- [ ] Feature flags logged on startup
- [ ] Monitoring metrics in place
- [ ] Alert thresholds defined
- [ ] Runbook for disabling features in production

---

## 14. Open Questions and Future Work

### For Phase 3 Implementation

1. **Heuristic calibration**: Are the _would_benefit_from() heuristics correct? Should be validated against real scan data.

2. **Effort value tuning**: Are the default EFFORT_ELIMINATED values from Design Proposal still accurate? May need adjustment per engagement.

3. **Cross-target control progression**: Should "credentials_only" mode auto-promote to "full_heuristic" after X scans with no issues? Or stay manual?

4. **Confidence boost visualization**: How should UI show the confidence boost reason? Tooltip? Bar chart decomposition?

### For Phase 4+ (Future)

1. **Explicit correlation rules**: Add DSL for defining cross-target enablement relationships (e.g., "shared account enables")

2. **Time-based effort elimination**: Credentials found 1 month ago have lower effort value (attacker may have reset password)

3. **Skill-based effort elimination**: Fuzzing (high effort) vs. script-based injection testing (low effort) — weight by attacker capability

4. **Lateral movement chaining**: Model how compromised host A enables pivot to host B (more sophisticated than Phase 3 credentials-based)

5. **Confidence boost from multiple sources**: If finding confirmed by BOTH tool AND human review, boost confidence even higher

---

## Appendix A: Reference Test Data

```python
# Standard test findings (reusable across test suites)

MONITORING_CREDENTIALS = {
    "id": "monitoring_creds_1",
    "target": "monitoring.example.com",
    "type": "secret_leak",
    "confirmation_level": "confirmed",
    "capability_types": ["access", "information"],
    "base_score": 9.5,
    "tags": ["secret-leak", "credentials"],
    "value": "api_key=sk_test_abc123..., password=SuP3rS3cr3t",
}

PROD_AUTH_BYPASS = {
    "id": "prod_auth_1",
    "target": "prod.example.com",
    "type": "auth_bypass",
    "confirmation_level": "probable",
    "capability_types": ["execution"],
    "base_score": 8.5,
    "tags": ["auth", "bypass"],
}

INTERNAL_IP_DISCLOSURE = {
    "id": "internal_ips_1",
    "target": "cdn.example.com",
    "type": "private_ip_disclosure",
    "confirmation_level": "confirmed",
    "capability_types": ["information"],
    "base_score": 6.0,
    "tags": ["private-ip", "topology"],
    "value": "Internal IPs: 10.0.0.0/8 range, database at 10.1.2.3",
}

SSRF_CLOUD_METADATA = {
    "id": "ssrf_metadata_1",
    "target": "api.example.com",
    "type": "ssrf",
    "confirmation_level": "hypothesized",
    "capability_types": ["execution"],
    "base_score": 9.2,
    "tags": ["ssrf", "cloud"],
}
```

---

## Appendix B: YAML Configuration Example

See: `core/cortex/capability_model_config.yaml` (created in Step 1.2)

For advanced usage, teams can create engagement-specific configs:

```yaml
# engagement_acme_2026.yaml - Acme Corp, Q1 2026
cross_target_control: full_heuristic  # Acme uses shared accounts extensively
graph_confidence_enabled: true
confidence_boost_cap: 0.15  # Slightly higher cap for this engagement

time_to_impact_weight: 0.35  # Acme values speed to impact more
uncertainty_reduction_weight: 0.35
effort_eliminated_weight: 0.30

effort_eliminated:
  credential_exposure: 9.5  # Acme has weak credential hygiene
  source_code: 7.0  # Code is less valuable (black-box testing rare)
  topology: 8.5  # Network pivoting is Acme's main risk
  confirmed_injection: 6.0
  stack_disclosure: 3.0
  port_disclosure: 2.5
  partial_info: 1.5
```

Then load with:
```bash
export SENTINEL_CONFIG_FILE=/path/to/engagement_acme_2026.yaml
```

---

**End of Phase 3 Implementation Plan**

This plan is comprehensive, implementable, and backward compatible. All Phase 3 features are gated behind feature flags and default to OFF, ensuring zero breaking changes for users running Phase 2.
