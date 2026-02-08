# Phase 3-Lite Implementation Plan: Config Externalization + Three-Axis Ranking

**Status**: PLAN ONLY — No Code
**Scope**: Config infrastructure and read-only three-axis scoring
**Prerequisite**: Phase 1 and Phase 2 must be complete

---

## Executive Summary

Phase 3-Lite is a conservative, focused extension of the capability model. It adds two things:

1. **Config externalization**: Move hardcoded effort values and model weights into YAML + env overrides, following the existing `SentinelConfig` pattern in `core/base/config.py`.
2. **Three-axis scoring**: Compute `time_to_impact`, `uncertainty_reduction`, and `effort_eliminated` as a read-only composite priority score in `RiskEngine`, gated behind a feature flag.

### What This Plan Does NOT Include

The following are **explicitly deferred** until real scan calibration data exists and tighter correlation rules are validated:

- **Cross-target enablement edges** — Heuristic-based cross-asset correlation has high false-positive risk without calibration data. Deferred to Phase 4+.
- **Graph-informed confidence boost** — NexusContext reading CausalGraph adds coupling and a feedback-loop risk that isn't justified without tighter correlation rules. Deferred to Phase 4+.
- **Combined leverage metric** — Depends on cross-target edges. Deferred with them.

### Why Phase 3-Lite Instead of Full Phase 3

Per review:
- Cross-target heuristics are high-risk for false positives without calibration data
- Graph-confidence boost adds coupling between modules that should stay independent
- Changing multiple critical systems at once increases blast radius
- Config + three-axis scoring deliver value independently with minimal risk

---

## Prerequisites (Phase 1+2 Completion Checklist)

### Phase 1: ConfirmationLevel + Capability Types (Required)

**Verify in code**:
```bash
grep -n "confirmation_level" core/epistemic/ledger.py | wc -l  # Should be 8+
grep -n "capability_types" core/toolkit/vuln_rules.py | wc -l  # Should be 30+
grep -n "CONFIRMATION_MULTIPLIERS" core/data/constants.py       # Should exist
```

**Verification checklist**:
- [ ] Finding.confirmation_level exists (default "probable")
- [ ] VulnRule.capability_types exists (default ["execution"])
- [ ] CREDENTIAL_INDICATORS defined in core/data/constants.py (shared)
- [ ] Content-aware escalation in _match_backup_rule()
- [ ] Confirmation multiplier applied in VulnRule.apply() and RiskEngine.recalculate()

### Phase 2: NexusContext + CausalGraph + Strategos (Required)

**Verify in code**:
```bash
grep -n "EnablementStrength" core/cortex/causal_graph.py        # Should exist (enum)
grep -n "INFORMATION_HYPOTHESIS_CONFIDENCE" core/data/constants.py  # Should exist (shared)
grep -n "CONFIRMED_EXPOSURE" core/contracts/schemas.py          # Should exist
```

**Verification checklist**:
- [ ] CausalGraph has EnablementStrength enum (DIRECT=2.0, INDIRECT=1.0, WEAK=0.5)
- [ ] CausalGraph has EFFORT_ELIMINATED_BY_CAPABILITY constant
- [ ] _infer_information_enablement_edges() implemented (including incremental Rule 5)
- [ ] NexusContext Rule 3 (information enablement synthesis) fires for confirmed info
- [ ] Strategos routes CONFIRMED + access → CONFIRMED_EXPOSURE action
- [ ] Strategos deprioritizes HYPOTHESIZED findings by +2 priority
- [ ] Shared constants module core/data/constants.py in use by all consumers

---

## Step 1: Config Externalization (CapabilityModelConfig)

### 1.1 Add CapabilityModelConfig Dataclass

**File**: `core/base/config.py`

**Location**: After `OmegaConfig`, before `SentinelConfig`

Follow the existing pattern: frozen dataclass + `from_env()` classmethod. This dataclass holds all tunable values for the attacker capability model.

```python
@dataclass(frozen=True)
class CapabilityModelConfig:
    """Configuration for attacker capability model.

    Controls effort elimination values, three-axis ranking weights,
    and feature flags for Phase 3+ capabilities.

    All values can be overridden by environment variables (SENTINEL_CM_*).
    Effort elimination values can additionally be loaded from a YAML file.
    """

    # ---- Three-Axis Ranking Weights (must sum to 1.0) ----
    time_to_impact_weight: float = 0.40
    uncertainty_reduction_weight: float = 0.30
    effort_eliminated_weight: float = 0.30

    # ---- Feature Flags ----
    three_axis_enabled: bool = False  # Gate: compute three-axis scores

    # ---- Effort Elimination Table ----
    # How much attacker work each finding type replaces (0-10 scale).
    # Loaded from YAML if available, otherwise uses these defaults.
    # These defaults come from the Design Proposal (Section 4.3).
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
```

**Design notes**:
- `frozen=True` like every other config sub-dataclass
- `Dict[str, float]` for effort table requires adding `Dict, Any` to the existing `from typing import Optional, List` import in config.py
- `field(default_factory=...)` because mutable default
- Feature flag defaults to OFF → zero behavioral change until explicitly enabled

### 1.2 Add `from_env_and_yaml()` Classmethod

**Location**: Inside `CapabilityModelConfig`

```python
@classmethod
def from_env_and_yaml(cls, yaml_path: Optional[Path] = None) -> "CapabilityModelConfig":
    """
    Load config from environment variables, optionally overlaying YAML values.

    Priority (highest wins):
      1. Environment variables (SENTINEL_CM_*)
      2. YAML file values
      3. Dataclass defaults

    Environment variables:
      SENTINEL_CM_THREE_AXIS_ENABLED  - "true"/"false"
      SENTINEL_CM_TTI_WEIGHT          - float (time-to-impact weight)
      SENTINEL_CM_UR_WEIGHT           - float (uncertainty reduction weight)
      SENTINEL_CM_EE_WEIGHT           - float (effort eliminated weight)
      SENTINEL_CM_CONFIG_FILE         - path to YAML file (alternative to yaml_path arg)
    """
    kwargs: Dict[str, Any] = {}

    # --- Load YAML base (if provided) ---
    config_file = yaml_path or _env_path("SENTINEL_CM_CONFIG_FILE")
    if config_file and config_file.exists():
        try:
            import yaml
            with open(config_file) as f:
                data = yaml.safe_load(f) or {}
            if "effort_eliminated" in data and isinstance(data["effort_eliminated"], dict):
                kwargs["effort_eliminated_by_capability"] = {
                    k: float(v) for k, v in data["effort_eliminated"].items()
                }
            for yaml_key, attr_name in [
                ("time_to_impact_weight", "time_to_impact_weight"),
                ("uncertainty_reduction_weight", "uncertainty_reduction_weight"),
                ("effort_eliminated_weight", "effort_eliminated_weight"),
                ("three_axis_enabled", "three_axis_enabled"),
            ]:
                if yaml_key in data:
                    val = data[yaml_key]
                    if isinstance(val, bool):
                        kwargs[attr_name] = val
                    else:
                        kwargs[attr_name] = float(val)
        except Exception as e:
            logging.getLogger(__name__).warning(
                f"[CapabilityModelConfig] Failed to load YAML from {config_file}: {e}"
            )

    # --- Environment overrides (highest priority) ---
    three_axis = os.getenv("SENTINEL_CM_THREE_AXIS_ENABLED", "").lower()
    if three_axis in ("true", "1", "yes"):
        kwargs["three_axis_enabled"] = True
    elif three_axis in ("false", "0", "no"):
        kwargs["three_axis_enabled"] = False

    for env_var, attr_name in [
        ("SENTINEL_CM_TTI_WEIGHT", "time_to_impact_weight"),
        ("SENTINEL_CM_UR_WEIGHT", "uncertainty_reduction_weight"),
        ("SENTINEL_CM_EE_WEIGHT", "effort_eliminated_weight"),
    ]:
        val = os.getenv(env_var)
        if val is not None:
            try:
                kwargs[attr_name] = float(val)
            except ValueError:
                pass  # Use default/YAML value

    return cls(**kwargs)
```

**Helper** (add near top of config.py, after imports):
```python
def _env_path(var_name: str) -> Optional[Path]:
    """Read an environment variable as a Path, or None."""
    val = os.getenv(var_name)
    return Path(val) if val else None
```

### 1.3 Wire Into SentinelConfig

**File**: `core/base/config.py`

Add `capability_model` field to `SentinelConfig`:

```python
@dataclass
class SentinelConfig:
    # ... existing fields ...

    # Attacker capability model settings (Phase 3+)
    capability_model: CapabilityModelConfig = field(
        default_factory=CapabilityModelConfig
    )
```

In `SentinelConfig.from_env()`, add before `return cls(...)`:

```python
capability_model = CapabilityModelConfig.from_env_and_yaml()
```

And add `capability_model=capability_model` to the `return cls(...)` call.

### 1.4 Weight Validation

Add a `__post_init__`-style check. Since the dataclass is frozen, do this as a validation classmethod called during loading:

```python
@staticmethod
def _validate_weights(tti: float, ur: float, ee: float) -> None:
    """Verify three-axis weights sum to 1.0 (within tolerance)."""
    total = tti + ur + ee
    if abs(total - 1.0) > 0.01:
        raise ValueError(
            f"Three-axis weights must sum to 1.0, got {total:.3f} "
            f"(tti={tti}, ur={ur}, ee={ee})"
        )
```

Call this at the end of `from_env_and_yaml()` before returning:

```python
instance = cls(**kwargs)
cls._validate_weights(
    instance.time_to_impact_weight,
    instance.uncertainty_reduction_weight,
    instance.effort_eliminated_weight,
)
return instance
```

### 1.5 Create Sample YAML Config File

**File**: `core/cortex/capability_model_config.yaml` (NEW)

```yaml
# SentinelForge: Capability Model Configuration
# =============================================
# This file defines tunable values for the attacker capability model.
# All values can be overridden by environment variables (SENTINEL_CM_*).
#
# To use this file, set:
#   SENTINEL_CM_CONFIG_FILE=/path/to/this/file.yaml
# Or pass it programmatically to CapabilityModelConfig.from_env_and_yaml().

# Feature flag: enable three-axis priority scoring in RiskEngine
# When false, RiskEngine behaves identically to Phase 2 (severity + confirmation only).
three_axis_enabled: false

# Three-axis ranking weights (must sum to 1.0)
# These control how the composite priority score is computed:
#   priority = (tti_weight * time_to_impact)
#            + (ur_weight * uncertainty_reduction)
#            + (ee_weight * effort_eliminated)
time_to_impact_weight: 0.40
uncertainty_reduction_weight: 0.30
effort_eliminated_weight: 0.30

# Effort elimination values: how much attacker work is replaced by each finding type
# Values are on a 0-10 scale (like severity scores).
# These map to the enablement_class values produced by CausalGraph._classify_enablement().
effort_eliminated:
  credential_exposure: 9.0      # Replaces brute-force authentication
  source_code: 8.0              # Replaces black-box code discovery
  topology: 7.0                 # Replaces network enumeration
  confirmed_injection: 6.0      # Replaces fuzzing for injection points
  stack_disclosure: 4.0         # Replaces fingerprinting
  port_disclosure: 3.0          # Replaces port scanning
  partial_info: 2.0             # Generic reconnaissance value
```

**Key name convention**: These keys MUST match the values returned by `CausalGraph._classify_enablement()`. Specifically: `"credential_exposure"`, `"source_code"`, `"topology"`, `"confirmed_injection"`, `"stack_disclosure"`, `"port_disclosure"`, `"partial_info"`. Do not confuse with `INFORMATION_HYPOTHESIS_CONFIDENCE` keys in `constants.py` (which use different naming like `"source_code_secrets"`, `"internal_topology"`).

---

## Step 2: Three-Axis Scoring in RiskEngine

### 2.1 Add Three-Axis Computation Method

**File**: `core/data/risk.py`

**Location**: Inside `RiskEngine` class, after `get_scores()`

This method is **read-only** — it computes scores but does not modify `self._scores` or emit signals. It's a pure function that consumers can call on demand.

```python
def compute_three_axis_priority(self, issue: dict) -> Dict[str, float]:
    """
    Compute priority using three axes:
      1. Time-to-Impact: how quickly an attacker can act on this finding
      2. Uncertainty Reduction: how many unknowns this finding eliminates
      3. Effort Eliminated: how much attacker work this finding replaces

    This method is READ-ONLY. It does not modify self._scores or emit
    signals. It computes the score from issue metadata only (no graph
    dependency — uncertainty_reduction comes from enablement_score on
    the issue dict if present, defaulting to 0.0).

    Args:
        issue: Dict with keys: confirmation_level, capability_types,
               enablement_score (optional), enablement_class (optional)

    Returns:
        {
            "time_to_impact": float (0-10),
            "uncertainty_reduction": float (0-10),
            "effort_eliminated": float (0-10),
            "priority_composite": float (0-10),
        }
    """
    from core.base.config import get_config
    cm = get_config().capability_model

    confirmation = issue.get("confirmation_level", "confirmed")
    capability_types = issue.get("capability_types", ["execution"])

    # Axis 1: Time-to-Impact
    time_to_impact = self._compute_time_to_impact(confirmation, capability_types)

    # Axis 2: Uncertainty Reduction
    # Reads enablement_score from issue metadata (set by CausalGraph if present).
    # Does NOT read the graph directly — stays decoupled.
    uncertainty_reduction = min(10.0, float(issue.get("enablement_score", 0.0)))

    # Axis 3: Effort Eliminated
    # Uses enablement_class from issue metadata (set by CausalGraph if present).
    enablement_class = issue.get("enablement_class", "partial_info")
    effort_eliminated = cm.effort_eliminated_by_capability.get(enablement_class, 2.0)

    # Composite
    priority_composite = (
        cm.time_to_impact_weight * time_to_impact
        + cm.uncertainty_reduction_weight * uncertainty_reduction
        + cm.effort_eliminated_weight * effort_eliminated
    )

    return {
        "time_to_impact": round(time_to_impact, 2),
        "uncertainty_reduction": round(uncertainty_reduction, 2),
        "effort_eliminated": round(effort_eliminated, 2),
        "priority_composite": round(priority_composite, 2),
    }
```

### 2.2 Add Time-to-Impact Helper

**File**: `core/data/risk.py`

**Location**: Inside `RiskEngine`, after `compute_three_axis_priority()`

```python
@staticmethod
def _compute_time_to_impact(
    confirmation: str,
    capability_types: list,
) -> float:
    """
    Score 0-10 based on how quickly an attacker can act.

    Reference table from Design Proposal (Section 4.3):
      Confirmed + access    → 10.0  (credentials = immediate use)
      Confirmed + execution → 9.0   (RCE = immediate exploit)
      Confirmed + information → 8.0 (secrets = fast lateral movement)
      Probable  + execution → 6.0
      Probable  + other     → 5.0
      Hypothesized + execution → 3.0
      Hypothesized + other  → 2.0
      Fallback              → 5.0
    """
    if confirmation == "confirmed":
        if "access" in capability_types:
            return 10.0
        if "execution" in capability_types:
            return 9.0
        if "information" in capability_types:
            return 8.0
        return 8.0  # Confirmed + unknown type → still high
    elif confirmation == "probable":
        if "execution" in capability_types:
            return 6.0
        return 5.0
    elif confirmation == "hypothesized":
        if "execution" in capability_types:
            return 3.0
        return 2.0
    return 5.0  # Fallback for unknown confirmation level
```

### 2.3 Feature-Gate the Three-Axis Score

Three-axis scoring is opt-in. Consumers check the feature flag before calling `compute_three_axis_priority()`.

**Convention** (not enforced in RiskEngine itself — consumers decide):

```python
from core.base.config import get_config

config = get_config()
if config.capability_model.three_axis_enabled:
    three_axis = risk_engine.compute_three_axis_priority(issue)
    # Use three_axis["priority_composite"] for ranking
else:
    # Use existing severity + confirmation scoring only
    pass
```

The feature gate is NOT inside `compute_three_axis_priority()` itself — this keeps the method testable without needing to mock config. Consumers decide when to call it.

### 2.4 Integration Point: CausalGraph Effort Values

Currently `CausalGraph` has `EFFORT_ELIMINATED_BY_CAPABILITY` as a hardcoded constant. Phase 3-Lite externalizes this.

**File**: `core/cortex/causal_graph.py`

**Change**: Replace the hardcoded `EFFORT_ELIMINATED_BY_CAPABILITY` dict with a function that reads from config, falling back to the current hardcoded values if config is unavailable.

```python
def _get_effort_eliminated_table() -> Dict[str, float]:
    """
    Get effort elimination values from config, with hardcoded fallback.

    This allows YAML/env overrides without breaking existing behavior
    if CapabilityModelConfig is not yet wired up.
    """
    try:
        from core.base.config import get_config
        return get_config().capability_model.effort_eliminated_by_capability
    except Exception:
        # Fallback to Phase 2 hardcoded values
        return {
            "credential_exposure": 9.0,
            "source_code": 8.0,
            "topology": 7.0,
            "confirmed_injection": 6.0,
            "stack_disclosure": 4.0,
            "port_disclosure": 3.0,
            "partial_info": 2.0,
        }
```

Then replace all references to the hardcoded `EFFORT_ELIMINATED_BY_CAPABILITY` with `_get_effort_eliminated_table()`.

---

## Step 3: Tests

### Test Suite 1: Config Loading

#### Test 1.1: Defaults are correct
```python
def test_capability_model_config_defaults():
    """Default config matches Phase 2 behavior."""
    config = CapabilityModelConfig()
    assert config.three_axis_enabled is False
    assert config.time_to_impact_weight == 0.40
    assert config.uncertainty_reduction_weight == 0.30
    assert config.effort_eliminated_weight == 0.30
    assert config.effort_eliminated_by_capability["credential_exposure"] == 9.0
```

#### Test 1.2: YAML loading
```python
def test_capability_model_config_yaml(tmp_path):
    """Effort values load from YAML."""
    yaml_file = tmp_path / "capability.yaml"
    yaml_file.write_text("""
effort_eliminated:
  credential_exposure: 9.5
  source_code: 7.5
""")
    config = CapabilityModelConfig.from_env_and_yaml(yaml_file)
    assert config.effort_eliminated_by_capability["credential_exposure"] == 9.5
    assert config.effort_eliminated_by_capability["source_code"] == 7.5
```

#### Test 1.3: Environment overrides beat YAML
```python
def test_capability_model_config_env_override(monkeypatch, tmp_path):
    """Env vars override YAML values."""
    yaml_file = tmp_path / "capability.yaml"
    yaml_file.write_text("time_to_impact_weight: 0.50\n")
    monkeypatch.setenv("SENTINEL_CM_TTI_WEIGHT", "0.35")
    monkeypatch.setenv("SENTINEL_CM_UR_WEIGHT", "0.35")
    monkeypatch.setenv("SENTINEL_CM_EE_WEIGHT", "0.30")
    config = CapabilityModelConfig.from_env_and_yaml(yaml_file)
    assert config.time_to_impact_weight == 0.35  # Env wins over YAML
```

#### Test 1.4: Weight validation rejects bad sums
```python
def test_capability_model_config_weight_validation(monkeypatch):
    """Weights that don't sum to 1.0 raise ValueError."""
    monkeypatch.setenv("SENTINEL_CM_TTI_WEIGHT", "0.50")
    monkeypatch.setenv("SENTINEL_CM_UR_WEIGHT", "0.50")
    monkeypatch.setenv("SENTINEL_CM_EE_WEIGHT", "0.50")
    with pytest.raises(ValueError, match="must sum to 1.0"):
        CapabilityModelConfig.from_env_and_yaml()
```

#### Test 1.5: Missing YAML is graceful
```python
def test_capability_model_config_missing_yaml():
    """Missing YAML file falls back to defaults."""
    config = CapabilityModelConfig.from_env_and_yaml(Path("/nonexistent.yaml"))
    assert config.three_axis_enabled is False  # Defaults preserved
    assert config.effort_eliminated_by_capability["credential_exposure"] == 9.0
```

### Test Suite 2: Three-Axis Scoring

#### Test 2.1: Time-to-Impact reference table
```python
def test_time_to_impact_scoring():
    """Verify TTI scores match reference table."""
    engine = RiskEngine()
    cases = [
        ("confirmed", ["access"], 10.0),
        ("confirmed", ["execution"], 9.0),
        ("confirmed", ["information"], 8.0),
        ("probable", ["execution"], 6.0),
        ("probable", ["information"], 5.0),
        ("hypothesized", ["execution"], 3.0),
        ("hypothesized", ["information"], 2.0),
    ]
    for confirmation, capabilities, expected in cases:
        score = engine._compute_time_to_impact(confirmation, capabilities)
        assert score == expected, f"TTI({confirmation}, {capabilities}) = {score}, expected {expected}"
```

#### Test 2.2: Composite score formula
```python
def test_three_axis_composite_formula():
    """priority = 0.40 * TTI + 0.30 * UR + 0.30 * EE."""
    engine = RiskEngine()
    issue = {
        "confirmation_level": "confirmed",
        "capability_types": ["access"],
        "enablement_score": 5.0,
        "enablement_class": "credential_exposure",
    }
    scores = engine.compute_three_axis_priority(issue)

    # TTI(confirmed, access) = 10.0
    # UR = min(10, 5.0) = 5.0
    # EE = 9.0 (credential_exposure default)
    # Composite = 0.40 * 10 + 0.30 * 5 + 0.30 * 9 = 4 + 1.5 + 2.7 = 8.2
    expected = 0.40 * 10.0 + 0.30 * 5.0 + 0.30 * 9.0
    assert scores["priority_composite"] == round(expected, 2)
```

#### Test 2.3: Missing enablement metadata defaults safely
```python
def test_three_axis_missing_metadata():
    """Issues without enablement metadata get safe defaults."""
    engine = RiskEngine()
    issue = {
        "confirmation_level": "confirmed",
        "capability_types": ["execution"],
        # No enablement_score, no enablement_class
    }
    scores = engine.compute_three_axis_priority(issue)
    assert scores["uncertainty_reduction"] == 0.0  # Default
    assert scores["effort_eliminated"] == 2.0  # partial_info default
    assert scores["time_to_impact"] == 9.0  # Confirmed execution
```

#### Test 2.4: Read-only — no side effects
```python
def test_three_axis_is_read_only():
    """compute_three_axis_priority() does not modify _scores or emit signals."""
    engine = RiskEngine()
    original_scores = dict(engine._scores)
    signal_fired = []
    engine.scores_changed.connect(lambda: signal_fired.append(True))

    engine.compute_three_axis_priority({
        "confirmation_level": "confirmed",
        "capability_types": ["access"],
    })

    assert engine._scores == original_scores
    assert len(signal_fired) == 0
```

### Test Suite 3: Effort Elimination Config Propagation

#### Test 3.1: CausalGraph reads config values
```python
def test_causal_graph_reads_config_effort(monkeypatch):
    """CausalGraph uses effort values from config, not hardcoded."""
    # Patch config to return custom effort values
    from core.base.config import set_config, SentinelConfig, CapabilityModelConfig

    custom_cm = CapabilityModelConfig(
        effort_eliminated_by_capability={
            "credential_exposure": 5.0,  # Changed from default 9.0
            "partial_info": 1.0,
        }
    )
    # ... set up config with custom_cm ...

    table = _get_effort_eliminated_table()
    assert table["credential_exposure"] == 5.0
```

#### Test 3.2: Fallback when config unavailable
```python
def test_effort_table_fallback():
    """Hardcoded fallback used when config loading fails."""
    # Simulate import failure
    table = _get_effort_eliminated_table()  # Should not raise
    assert "credential_exposure" in table
    assert table["credential_exposure"] == 9.0
```

### Test Suite 4: End-to-End Scenario

**Title**: Confirmed credential exposure correctly outranks hypothesized SSRF

**Setup**:
1. Issue A: Confirmed credential_exposure on example.com (enablement_score=4.0)
2. Issue B: Hypothesized SSRF on api.example.com (no enablement)
3. Three-axis scoring enabled

**Expected**:
- Issue A: TTI=10.0, UR=4.0, EE=9.0 → composite = 0.40×10 + 0.30×4 + 0.30×9 = 7.9
- Issue B: TTI=3.0, UR=0.0, EE=2.0 → composite = 0.40×3 + 0.30×0 + 0.30×2 = 1.8
- Issue A priority >> Issue B priority (4.4× higher)
- This matches the correct attacker mental model: known credentials are immediately actionable

---

## Deterministic Logic Summary

### Time-to-Impact Decision Table

| Confirmation | Capability | Score |
|-------------|-----------|-------|
| confirmed | access | 10.0 |
| confirmed | execution | 9.0 |
| confirmed | information | 8.0 |
| confirmed | (other) | 8.0 |
| probable | execution | 6.0 |
| probable | (other) | 5.0 |
| hypothesized | execution | 3.0 |
| hypothesized | (other) | 2.0 |
| (unknown) | (any) | 5.0 |

### Composite Formula

```
priority_composite = (
    time_to_impact_weight * time_to_impact
  + uncertainty_reduction_weight * uncertainty_reduction
  + effort_eliminated_weight * effort_eliminated
)
```

Where default weights are (0.40, 0.30, 0.30) and all axes are 0-10 scale.

### Config Priority Chain

```
Environment Variable (SENTINEL_CM_*)
        ↓ overrides
YAML file (effort_eliminated section)
        ↓ overrides
Dataclass defaults (hardcoded in CapabilityModelConfig)
```

---

## Backward Compatibility

### Feature Flag: OFF By Default

```python
three_axis_enabled: bool = False
```

When OFF:
- `compute_three_axis_priority()` exists but consumers don't call it
- `recalculate()` behavior unchanged
- `get_scores()` returns same values as Phase 2
- CausalGraph effort values unchanged (fallback to hardcoded)

### Safe Defaults for Missing Data

```python
# All new code uses .get() with safe defaults:
confirmation = issue.get("confirmation_level", "confirmed")  # Option A
capability_types = issue.get("capability_types", ["execution"])
enablement_score = issue.get("enablement_score", 0.0)
enablement_class = issue.get("enablement_class", "partial_info")
```

### No Database Migration

Three-axis scores are computed on-the-fly, not stored. No schema changes needed.

---

## Files Modified/Created Summary

| File | Changes | Type | Effort |
|------|---------|------|--------|
| `core/base/config.py` | Add `_env_path()` helper, `CapabilityModelConfig` dataclass with `from_env_and_yaml()`, add field to `SentinelConfig`, wire into `from_env()` | Additive | 1 day |
| `core/cortex/capability_model_config.yaml` | NEW: Sample YAML with effort values and weights | New | 0.5 days |
| `core/data/risk.py` | Add `compute_three_axis_priority()`, `_compute_time_to_impact()` to `RiskEngine` | Additive | 1 day |
| `core/cortex/causal_graph.py` | Replace hardcoded `EFFORT_ELIMINATED_BY_CAPABILITY` with `_get_effort_eliminated_table()` that reads config | Modificative | 0.5 days |
| `tests/unit/test_capability_model_config.py` | NEW: Test suites 1, 3 (config loading, propagation) | New | 1 day |
| `tests/unit/test_three_axis_scoring.py` | NEW: Test suites 2, 4 (scoring, end-to-end) | New | 1 day |

**Total Effort**: 5 days (sequential), ~3-4 days with parallelization

---

## Execution Order

```
Step 1.1-1.4: CapabilityModelConfig dataclass + validation
    │
    ├─── Step 1.5: Sample YAML file (parallel, no deps)
    │
    ├─── Step 2.1-2.3: Three-axis scoring in RiskEngine (depends on 1.1-1.4)
    │
    └─── Step 2.4: CausalGraph effort config (depends on 1.1-1.4)
              │
              └─── Step 3: All tests (depends on all above)
```

**Recommended sequence**:
- Day 1: Steps 1.1-1.5 (config infrastructure)
- Day 2: Steps 2.1-2.4 (scoring + effort propagation)
- Day 3-4: Step 3 (tests + validation)

---

## Explicitly Deferred (Phase 4+)

These items were in the original Phase 3 plan and are intentionally excluded:

1. **Cross-target enablement edges** — `_infer_cross_target_enablement_edges()`, `CrossTargetControl` enum, `_cross_target_would_benefit()` heuristics. Reason: High false-positive risk without real scan calibration data. Needs tighter correlation rules first.

2. **Graph-informed confidence boost** — `_apply_graph_informed_confidence_boost()`, `GraphConfidenceConfig`, `ConfidenceBoostMetadata`. Reason: NexusContext reading CausalGraph creates coupling that isn't justified without validated correlation rules.

3. **Combined leverage metric** — `combined_leverage` field on PressurePoint. Reason: Depends on cross-target edges.

4. **Feature flags module** — `core/cortex/feature_flags.py` with `FeatureFlags` class. Reason: Phase 3-Lite has only one flag (`three_axis_enabled`) which lives in `CapabilityModelConfig`. A separate module is over-engineering for one flag.

### What Would Unblock These

- Real scan calibration data showing cross-target correlation accuracy
- Tighter enablement classification rules (beyond current heuristic-based approach)
- Validated edge-case coverage for graph feedback loops
- Successful deployment and tuning of Phase 3-Lite three-axis scoring

---

## Success Criteria

### Functional

- [ ] `CapabilityModelConfig` loads from defaults, YAML, and env vars (in correct priority)
- [ ] Weight validation rejects sums != 1.0
- [ ] `compute_three_axis_priority()` returns correct scores for all confirmation × capability combinations
- [ ] Composite formula matches: `w_tti * TTI + w_ur * UR + w_ee * EE`
- [ ] CausalGraph reads effort values from config (with hardcoded fallback)
- [ ] Feature flag OFF → zero behavioral change from Phase 2
- [ ] End-to-end: confirmed credentials outrank hypothesized SSRF by >4× in composite score

### Backward Compatibility

- [ ] All existing tests pass with feature flag OFF
- [ ] No changes to `recalculate()` behavior
- [ ] No changes to `get_scores()` return values
- [ ] No database migration required
- [ ] API responses unchanged when flag OFF

### Performance

- [ ] `compute_three_axis_priority()`: < 1ms per issue (no I/O, pure computation)
- [ ] Config loading: < 50ms (YAML parse + env reads)
- [ ] No regression in existing RiskEngine performance

---

**End of Phase 3-Lite Implementation Plan**

This plan delivers config externalization and three-axis ranking while explicitly deferring higher-risk features until calibration data justifies them.
