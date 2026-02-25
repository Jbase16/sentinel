# Phase 1 Implementation Plan: ConfirmationLevel + Capability Types + Confirmation-Weighted Scoring

**Status**: PLAN ONLY — No Code (Rev 2: incorporates review feedback)
**Scope**: Changes 1, 2, and 5 from the Design Proposal
**Out of Scope**: NexusContext, CausalGraph, Strategos (Phase 2)

---

## 0. Verified Data Flow (What We're Modifying)

The complete scoring pipeline, traced from code:

```
Tool runs → raw stdout/stderr
    ↓
AIEngine.process_tool_output()              [core/ai/ai_engine.py]
    ↓  creates FindingProposal(source="ai"|"heuristic", citations=[...])
EvidenceLedger.evaluate_and_promote()       [core/epistemic/ledger.py]
    ↓  validates citations, creates Finding, pushes to findings_store
findings_store (global read model)          [core/data/findings_store.py]
    ↓  scanner_engine calls apply_rules(self._last_results)
apply_rules(findings) → enriched issues     [core/toolkit/vuln_rules.py]
    ↓  VulnRule.apply() wraps matched findings with severity/score/impact
issues_store (global issue store)           [core/data/issues_store.py]
    ↓
RiskEngine.recalculate()                    [core/data/risk.py]
    ↓  sums SEVERITY_WEIGHTS per asset
per-asset risk scores → UI / Reports

OMEGA Calculator (parallel path)            [core/omega/risk_calculator.py]
    ↓  PillarScore inputs from cronus/mimic/nexus phase computations
    ↓  weighted sum → OMEGARiskScore
```

**Key observation**: `apply_rules()` in `scanner_engine.py:1131` is called with `self._last_results`, which is the findings list from `findings_store`. So any new field we add to findings in the Ledger flows through to VulnRules matchers automatically.

---

## 1. Step-by-Step Implementation Plan (Dependency Order)

### Step 1.1: Add ConfirmationLevel enum to ledger.py

**File**: `core/epistemic/ledger.py`
**Location**: After `LifecycleState` enum (line 27), before `ToolContext` (line 36)
**Type**: ADDITIVE (new enum, no existing code changes)

Add:
```python
class ConfirmationLevel(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    HYPOTHESIZED = "hypothesized"
```

**Rationale**: `str, Enum` so it serializes cleanly to JSON (same pattern as `LifecycleState`).

### Step 1.2: Add confirmation_level field to Finding dataclass

**File**: `core/epistemic/ledger.py`
**Location**: `Finding` dataclass (line 70)
**Type**: ADDITIVE (new optional field with default)

Add field after `metadata`:
```python
confirmation_level: str = "probable"  # Default preserves existing behavior
```

**Why `str` not `ConfirmationLevel`**: The `Finding` dataclass is converted to dict via `asdict()` and pushed to `findings_store`. Using a plain string avoids serialization issues with downstream consumers that don't import the enum. The enum is used for derivation logic; the field stores the string value.

**Backward compatibility**: Default `"probable"` means all existing Findings (created without this field) are treated as moderately confirmed — not penalized as hypothesized, not boosted as confirmed. This is the correct conservative default.

### Step 1.3: Add confirmation_level to FindingProposal dataclass

**File**: `core/epistemic/ledger.py`
**Location**: `FindingProposal` dataclass (line 113)
**Type**: ADDITIVE (new optional field with default)

Add field after `metadata`:
```python
confirmation_level: Optional[str] = None  # Derived by Ledger if not set
```

**Why Optional/None**: Most callers (AIEngine, heuristics) won't set this. The Ledger derives it during `evaluate_and_promote()`. But callers CAN set it explicitly if they have better knowledge (e.g., a tool wrapper that knows it confirmed the finding).

### Step 1.4: Derive ConfirmationLevel in evaluate_and_promote()

**File**: `core/epistemic/ledger.py`
**Function**: `evaluate_and_promote()` (line 246)
**Type**: MODIFICATIVE (adds derivation logic before existing promotion call)

**Derivation logic** (deterministic, no AI involvement):

```
INPUT: proposal.source, proposal.citations, valid_citations, self._observations

RULE 1 — CONFIRMED:
  proposal.source NOT IN ("ai", "heuristic", "neural_strategy")
  AND len(valid_citations) >= 1
  AND at least one cited observation was recorded by a known tool
      (observation.tool.name is not empty/None)
  → CONFIRMED

RULE 2 — HYPOTHESIZED:
  proposal.source IN ("ai", "neural_strategy")
  → HYPOTHESIZED

RULE 3 — PROBABLE (default):
  Everything else:
  - source == "heuristic" (pattern match, not AI, not tool-confirmed)
  - source is unknown but has citations
  - proposal.confirmation_level was explicitly set by caller
  → PROBABLE
```

**Implementation location**: Insert between the existing citation validation (line 269 "if not valid_citations") and the existing promotion call (line 274 "return self.promote_finding(...)").

```python
# After valid_citations check, before promote_finding call:

# Derive confirmation level
#
# IMPORTANT (Rev 2 — epistemic rigor):
# The source check fires BEFORE the citation quality check. This is deliberate.
# Even if an AI proposal cites a valid tool observation, the CLAIM is still
# speculative. The tool observation is confirmed evidence, but the AI's
# interpretation of what that evidence means is a hypothesis.
# ConfirmationLevel refers to CLAIM certainty, not EVIDENCE existence.
# Do not reorder these checks.
#
if proposal.confirmation_level:
    # Caller explicitly set it — trust it
    derived_confirmation = proposal.confirmation_level
elif proposal.source in ("ai", "neural_strategy"):
    derived_confirmation = ConfirmationLevel.HYPOTHESIZED.value
elif proposal.source == "heuristic":
    derived_confirmation = ConfirmationLevel.PROBABLE.value
else:
    # Source is a tool name or unknown — check if citations reference real tool observations
    has_tool_observation = any(
        self._observations.get(c.observation_id) is not None
        and self._observations[c.observation_id].tool.name
        for c in valid_citations
    )
    derived_confirmation = (
        ConfirmationLevel.CONFIRMED.value if has_tool_observation
        else ConfirmationLevel.PROBABLE.value
    )
```

### Step 1.5: Pass confirmation_level through promote_finding()

**File**: `core/epistemic/ledger.py`
**Function**: `promote_finding()` (line 282)
**Type**: MODIFICATIVE (add parameter, pass to Finding constructor)

Add `confirmation_level: str = "probable"` parameter to `promote_finding()`.

In `evaluate_and_promote()`, pass it:
```python
return self.promote_finding(
    title=proposal.title,
    severity=proposal.severity,
    citations=valid_citations,
    description=proposal.description,
    confirmation_level=derived_confirmation,  # NEW
    **proposal.metadata
)
```

In `promote_finding()`, set it on the Finding:
```python
finding = Finding(
    id=find_id,
    title=title,
    severity=severity,
    citations=citations,
    description=description,
    metadata=kwargs,
    confirmation_level=confirmation_level,  # NEW
)
```

**Critical**: `confirmation_level` must NOT be in `**kwargs` (metadata). It's a first-class parameter. Extract it from kwargs if needed to avoid duplication:
```python
def promote_finding(self, title, severity, citations, description,
                    confirmation_level="probable",
                    timestamp_override=None, **kwargs):
```

### Step 1.6: Include confirmation_level in _update_findings_store()

**File**: `core/epistemic/ledger.py`
**Function**: `_update_findings_store()` (line 539)
**Type**: MODIFICATIVE (add field to dict)

Add to the `finding_dict`:
```python
finding_dict = {
    "id": finding.id,
    "title": finding.title,
    "type": finding.metadata.get("type", "General"),
    "severity": finding.severity,
    "value": finding.description,
    "description": finding.description,
    "citations": [asdict(c) for c in finding.citations],
    "metadata": finding.metadata,
    "confirmation_level": finding.confirmation_level,  # NEW
}
```

**Backward compatibility**: Existing findings in findings_store that lack this field will return `None` from `.get("confirmation_level")`. All downstream consumers must handle this with a default.

### Step 1.7: Include confirmation_level in PROMOTED event payload

**File**: `core/epistemic/ledger.py`
**Function**: `promote_finding()`, inside `_emit_event()` call (line 311)
**Type**: MODIFICATIVE (add field to payload dict)

Add `"confirmation_level": confirmation_level` to the payload dict passed to `_emit_event()`. This ensures the audit log and event listeners see the confirmation level.

---

### Step 2.1: Add capability_types to VulnRule dataclass

**File**: `core/toolkit/vuln_rules.py`
**Location**: `VulnRule` dataclass (line 331)
**Type**: ADDITIVE (new field with default)

Add after `matcher`:
```python
capability_types: List[str] = field(default_factory=lambda: ["execution"])
```

**Default `["execution"]`**: Every existing rule implicitly models exploit/execution capabilities. This default means zero existing rules need modification unless we want to reclassify them.

### Step 2.2: Set capability_types on relevant existing rules

**File**: `core/toolkit/vuln_rules.py`
**Location**: `_LEGACY_RULES` list (line 1245)
**Type**: MODIFICATIVE (add field to specific rule definitions)

Rules to explicitly annotate:

| Rule ID | Current Type (implicit) | New capability_types | Rationale |
|---------|------------------------|---------------------|-----------|
| BACKUP_EXPOSURE | execution (wrong) | `["information", "access"]` | Backup/source artifacts expose data and may contain credentials |
| SECRET_LEAK | execution (wrong) | `["access"]` | Leaked credentials = direct access capability |
| PRIVATE_IP_LEAK | execution (wrong) | `["information"]` | Internal topology info, not execution |
| VERBOSE_ERRORS | execution (wrong) | `["information"]` | Stack traces = information disclosure |
| DEV_SURFACE | execution (wrong) | `["information", "execution"]` | Dev endpoints can reveal AND execute |
| GRAPHQL_INTROSPECTION | execution (wrong) | `["information"]` | Schema disclosure |
| CLOUD_METADATA | execution (implicit OK) | `["execution", "access"]` | SSRF to metadata = access to cloud creds |
| SSRF_CHAIN | execution (implicit OK) | `["execution"]` | Keep default |

All other rules: keep default `["execution"]`. The default is conservative — it doesn't change any existing scoring behavior.

### Step 2.3: Propagate capability_types through VulnRule.apply()

**File**: `core/toolkit/vuln_rules.py`
**Function**: `VulnRule.apply()` (line 375)
**Type**: MODIFICATIVE (add field to enriched issue dict)

In the enriched dict (line 414), add:
```python
"capability_types": self.capability_types,
```

This makes capability_types available on every enriched issue. Phase 2 consumers (NexusContext, CausalGraph, Strategos) will read it from here.

### Step 2.4: Add content-aware escalation to _match_backup_rule()

**File**: `core/toolkit/vuln_rules.py`
**Function**: `_match_backup_rule()` (line 1201)
**Type**: MODIFICATIVE (replace flat tag-match with content-inspecting logic)

**Current code** (lines 1201-1213):
```python
def _match_backup_rule(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["backup-leak"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault("impact", "Backup or source artifacts...")
        match.setdefault("severity", "HIGH")
        match.setdefault("score", 7.7)
    return matches
```

**New code**: After the existing tag match, inspect the content of supporting findings for credential indicators. If credentials are found, escalate severity and score.

```python
CREDENTIAL_INDICATORS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "aws_access_key", "aws_secret", "private_key", "authorization",
    "database_url", "db_password", "smtp_password", "redis_url",
    "mongodb_uri", "connection_string", "client_secret",
    "jdbc:", "mysql://", "postgres://", "mongodb+srv://",
]

def _match_backup_rule(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["backup-leak"])
    matches = matcher(findings)
    for match in matches:
        # Content-aware escalation: inspect evidence for credential indicators
        content = _build_content_string(match.get("evidence", []))
        has_credentials = any(ind in content for ind in CREDENTIAL_INDICATORS)

        if has_credentials:
            match["severity"] = "CRITICAL"
            match["score"] = 9.5
            match["impact"] = (
                "Backup or source artifacts expose credentials or secrets, "
                "enabling direct unauthorized access to backend systems."
            )
            match.setdefault("tags", []).append("credential-in-backup")
        else:
            match.setdefault("severity", "HIGH")
            match.setdefault("score", 7.7)
            match.setdefault("impact",
                "Backup or source artifacts exposed publicly provide "
                "full application source and secrets.")
    return matches
```

### Step 2.5: Add _build_content_string() helper

**File**: `core/toolkit/vuln_rules.py`
**Location**: After `_pluck_text()` (line 142)
**Type**: ADDITIVE (new helper function)

```python
def _build_content_string(evidence: List[dict]) -> str:
    """Concatenate all text fields from evidence findings for content inspection."""
    parts = []
    for item in evidence:
        for key in ("type", "message", "proof", "evidence", "value",
                     "description", "technical_details"):
            val = item.get(key)
            if isinstance(val, str):
                parts.append(val)
        # Also check nested metadata
        meta = item.get("metadata", {})
        if isinstance(meta, dict):
            for val in meta.values():
                if isinstance(val, str):
                    parts.append(val)
    return " ".join(parts).lower()
```

**Why separate from `_pluck_text()`**: `_pluck_text()` examines a single finding with 4 specific keys. `_build_content_string()` examines a list of evidence findings with a broader key set including `value`, `description`, `technical_details`, and metadata values. Content inspection needs to cast a wider net.

**Rev 2 — lowercase note**: `_build_content_string()` calls `.lower()` exactly once on the final joined string. All `CREDENTIAL_INDICATORS` entries are lowercase constants. There is no double-lowering.

### Step 2.6: Apply confirmation multiplier in VulnRule.apply()

**File**: `core/toolkit/vuln_rules.py`
**Function**: `VulnRule.apply()` (line 375)
**Type**: MODIFICATIVE (multiply score by confirmation weight)

**Confirmation multiplier map** (defined as module constant):
```python
CONFIRMATION_MULTIPLIERS = {
    "confirmed": 1.0,
    "probable": 0.7,
    "hypothesized": 0.4,
}
```

In `VulnRule.apply()`, after computing the base enriched dict, derive the confirmation level from the supporting findings and apply the multiplier:

```python
def apply(self, findings: List[dict]) -> List[dict]:
    matches = self.matcher(findings)
    enriched = []
    for idx, match in enumerate(matches, start=1):
        target = match.get("target", "unknown")
        evidence = match.get("evidence", [])
        issue_id = match.get("id") or f"{self.id}:{target}:{idx}"

        # Derive confirmation from supporting findings
        confirmation = _derive_issue_confirmation(evidence)
        multiplier = CONFIRMATION_MULTIPLIERS.get(confirmation, 0.7)

        raw_score = match.get("score", self.base_score)
        effective_score = round(raw_score * multiplier, 2)

        # COMPOUND MULTIPLIER NOTE (Rev 2):
        # This multiplier applies to ISSUE-LEVEL ranking (which issue outranks which).
        # RiskEngine.recalculate() applies a SEPARATE multiplier to ASSET-LEVEL
        # ranking (which target needs attention first). These serve different
        # consumers and are intentionally independent. Both are needed because
        # a hypothesized CRITICAL should be deprioritized in both views.
        # Do not remove one thinking the other covers it.

        enriched.append({
            "id": issue_id,
            "rule_id": self.id,
            "title": self.title,
            "severity": match.get("severity", self.severity),
            "score": effective_score,                   # CHANGED: was raw_score
            "raw_score": raw_score,                     # NEW: preserve original
            "confirmation_level": confirmation,          # NEW
            "confirmation_multiplier": multiplier,       # NEW: for explainability
            "capability_types": self.capability_types,   # NEW (from Step 2.3)
            "target": target,
            # ... rest unchanged ...
        })
    return enriched
```

### Step 2.7: Add _derive_issue_confirmation() helper

**File**: `core/toolkit/vuln_rules.py`
**Location**: After `_build_content_string()`
**Type**: ADDITIVE (new helper function)

```python
def _derive_issue_confirmation(evidence: List[dict]) -> str:
    """
    Derive the confirmation level of an issue from its supporting findings.

    Uses the LOWEST confirmation level among supporting findings
    (conservative: an issue is only as confirmed as its weakest evidence).

    Falls back to "probable" if no confirmation data exists on any finding.
    """
    LEVEL_ORDER = {"confirmed": 2, "probable": 1, "hypothesized": 0}
    min_level = 2  # Start at highest (confirmed)
    has_any = False

    for item in evidence:
        cl = item.get("confirmation_level")
        if cl and cl in LEVEL_ORDER:
            has_any = True
            min_level = min(min_level, LEVEL_ORDER[cl])

    if not has_any:
        return "confirmed"  # Rev 2: Option A locked in — legacy findings without
                            # confirmation data were implicitly confirmed. Defaulting
                            # to anything else silently regresses historical scores.

    REVERSE = {2: "confirmed", 1: "probable", 0: "hypothesized"}
    return REVERSE[min_level]
```

**Why lowest**: If an issue is supported by one confirmed finding and one hypothesized finding, the issue's confidence is limited by its weakest link. This is conservative and prevents a single confirmed finding from "laundering" hypothesized ones.

---

### Step 3.1: Apply confirmation multiplier in RiskEngine.recalculate()

**File**: `core/data/risk.py`
**Function**: `recalculate()` (line 61)
**Type**: MODIFICATIVE (multiply weight by confirmation factor)

**Current code**:
```python
def recalculate(self):
    raw = issues_store.get_all()
    scores = defaultdict(float)
    for issue in raw:
        asset = issue.get("target") or issue.get("asset") or "unknown"
        severity = str(issue.get("severity", "INFO")).upper()
        weight = SEVERITY_WEIGHTS.get(severity, 0.5)
        scores[asset] += weight
    self._scores = dict(scores)
    self.scores_changed.emit()
```

**New code**:
```python
CONFIRMATION_MULTIPLIERS = {
    "confirmed": 1.0,
    "probable": 0.7,
    "hypothesized": 0.4,
}

def recalculate(self):
    raw = issues_store.get_all()
    scores = defaultdict(float)
    for issue in raw:
        asset = issue.get("target") or issue.get("asset") or "unknown"
        severity = str(issue.get("severity", "INFO")).upper()
        weight = SEVERITY_WEIGHTS.get(severity, 0.5)

        # Confirmation-weighted scoring
        # COMPOUND MULTIPLIER NOTE (Rev 2):
        # This multiplier applies to ASSET-LEVEL ranking (which target needs
        # attention first). VulnRule.apply() applies a SEPARATE multiplier to
        # ISSUE-LEVEL ranking. Both are needed — see note in VulnRule.apply().
        confirmation = issue.get("confirmation_level")
        multiplier = CONFIRMATION_MULTIPLIERS.get(confirmation, 1.0) if confirmation else 1.0

        scores[asset] += weight * multiplier
    self._scores = dict(scores)
    self.scores_changed.emit()
```

**Backward compatibility (Rev 2 — Option A locked in)**: Issues without `confirmation_level` key get multiplier 1.0, identical to pre-Phase-1 behavior. Only issues that explicitly carry a `confirmation_level` (i.e., those promoted through the updated Ledger) get the multiplier applied. Zero regression.

### Step 3.2: Use PillarScore.confidence in OMEGA calculate()

**File**: `core/omega/risk_calculator.py`
**Function**: `calculate()` (line 117)
**Type**: MODIFICATIVE (factor confidence into weighted sum)

**Current calculation** (line 170):
```python
omega_score = (
    w_cronus * cronus_score.value +
    w_mimic * mimic_score.value +
    w_nexus * nexus_score.value
)
```

**New calculation**:
```python
# NOTE (Rev 2): Phase 1 does NOT modify pillar confidence values.
# Confirmation weighting is handled at issue level (VulnRule.apply)
# and asset level (RiskEngine.recalculate) ONLY.
# This formula change is a preparatory hook for Phase 2.
# Since all PillarScore.confidence values remain 1.0 in Phase 1,
# this multiplication is a no-op. Do not set pillar confidence < 1.0
# until Phase 2 NexusContext changes are in place.
omega_score = (
    w_cronus * cronus_score.value * cronus_score.confidence +
    w_mimic * mimic_score.value * mimic_score.confidence +
    w_nexus * nexus_score.value * nexus_score.confidence
)
```

**Why this works**: `PillarScore.confidence` already exists and defaults to `1.0`. No existing callers set it to anything else, so current behavior is preserved exactly. Phase 2 can update the NEXUS phase computation to set `confidence` based on the aggregate confirmation level of findings in its chains. For now, all pillars remain at confidence 1.0 — no regression.

**What this enables**: Any future code that computes a pillar score from hypothesized findings can set `confidence < 1.0`, and the OMEGA score automatically reflects it. This is a zero-risk preparatory change.

**Rev 2 — Compound multiplier architecture**: Confirmation multipliers are applied at exactly two active levels in Phase 1: issue-level (`VulnRule.apply()`) and asset-level (`RiskEngine`). OMEGA pillar-level is a dormant third level that activates in Phase 2. This is intentional, not accidental triple-discounting. See comments in both VulnRule.apply() and RiskEngine.recalculate() for rationale.

### Step 3.3: Add confirmation_level to OMEGA event payloads

**File**: `core/omega/risk_calculator.py`
**Function**: `calculate()` (line 117)
**Type**: MODIFICATIVE (add to log events for auditability)

Add `"confidence_applied": True` to the LOG event payload so the audit trail shows that confidence is now factored in:
```python
self.event_bus.emit(GraphEvent(
    type=GraphEventType.LOG,
    payload={
        "message": "[OMEGA] Calculating risk score",
        "cronus": cronus_score.value,
        "cronus_confidence": cronus_score.confidence,  # NEW
        "mimic": mimic_score.value,
        "mimic_confidence": mimic_score.confidence,     # NEW
        "nexus": nexus_score.value,
        "nexus_confidence": nexus_score.confidence,     # NEW
        "nexus_fired": nexus_fired,
    },
))
```

---

## 2. New Data Fields Summary

| Dataclass | Field | Type | Default | File |
|-----------|-------|------|---------|------|
| `ConfirmationLevel` | (enum) | `str, Enum` | N/A | `ledger.py` |
| `Finding` | `confirmation_level` | `str` | `"probable"` | `ledger.py` |
| `FindingProposal` | `confirmation_level` | `Optional[str]` | `None` | `ledger.py` |
| `VulnRule` | `capability_types` | `List[str]` | `["execution"]` | `vuln_rules.py` |
| Enriched issue dict | `confirmation_level` | `str` | `"probable"` | `vuln_rules.py` |
| Enriched issue dict | `confirmation_multiplier` | `float` | `0.7` | `vuln_rules.py` |
| Enriched issue dict | `raw_score` | `float` | (copy of base_score) | `vuln_rules.py` |
| Enriched issue dict | `capability_types` | `List[str]` | `["execution"]` | `vuln_rules.py` |

**Module-level constants added**:

| Constant | Value | File |
|----------|-------|------|
| `CREDENTIAL_INDICATORS` | List of 21 credential/connection-string keywords | `vuln_rules.py` |
| `CONFIRMATION_MULTIPLIERS` | `{"confirmed": 1.0, "probable": 0.7, "hypothesized": 0.4}` | `vuln_rules.py`, `risk.py` |

---

## 3. ConfirmationLevel Derivation (Deterministic Rules)

**Location**: `EvidenceLedger.evaluate_and_promote()`, executed once per proposal.

### Decision Table

| Condition | Result | Rationale |
|-----------|--------|-----------|
| `proposal.confirmation_level` is set (not None) | Use as-is | Caller has explicit knowledge |
| `proposal.source` in `("ai", "neural_strategy")` | `HYPOTHESIZED` | AI-generated, not tool-verified |
| `proposal.source == "heuristic"` | `PROBABLE` | Pattern match without direct observation |
| `proposal.source` is anything else AND at least one valid_citation references an observation with a non-empty `tool.name` | `CONFIRMED` | Tool-generated evidence with real observation |
| `proposal.source` is anything else AND no cited observations have a tool name | `PROBABLE` | Evidence exists but provenance unclear |

### Current source values in the codebase

Traced from actual `FindingProposal` constructor calls:

| File | source value | Expected ConfirmationLevel |
|------|-------------|---------------------------|
| `ai_engine.py:648` (LLM analysis) | `"ai"` | HYPOTHESIZED |
| `ai_engine.py:799` (heuristic open port) | `"heuristic"` | PROBABLE |
| `ai_engine.py:810` (heuristic tech stack) | `"heuristic"` | PROBABLE |
| `ai_engine.py:821` (heuristic tool error) | `"heuristic"` | PROBABLE |
| Any future tool-generated proposal | tool name string | CONFIRMED (if observation has tool.name) |

### Properties of this derivation

- **Deterministic**: Same inputs always produce same output. No randomness, no AI.
- **Monotonic**: A finding's confirmation level never decreases unless explicitly invalidated.
- **Conservative**: Unknown sources default to PROBABLE, not CONFIRMED.
- **Overridable**: Callers can bypass derivation by setting `proposal.confirmation_level` explicitly.

---

## 4. Backward Compatibility Guarantees

### 4a. Finding dataclass

`confirmation_level` has default `"probable"`. Any code that constructs a `Finding` without this field gets a reasonable default. `asdict(finding)` will include it automatically.

### 4b. findings_store consumers

All consumers that read from findings_store use `.get()` on dicts. New fields are simply ignored by consumers that don't read them. No consumer crashes on an unexpected key.

### 4c. VulnRule dataclass

`capability_types` has default `["execution"]`. All 30 existing rules work without modification (they get `["execution"]` implicitly). Only rules we explicitly annotate (Step 2.2) get different values.

### 4d. Enriched issue dicts

New keys (`confirmation_level`, `confirmation_multiplier`, `raw_score`, `capability_types`) are additive. `issues_store.add_issue()` stores dicts as-is — no schema validation rejects unknown keys.

### 4e. RiskEngine

Default handling:
```python
confirmation = issue.get("confirmation_level")
multiplier = CONFIRMATION_MULTIPLIERS.get(confirmation, 1.0) if confirmation else 1.0
```
Issues without the field → multiplier 1.0 → **identical to current behavior**.

### 4f. OMEGA Calculator

`PillarScore.confidence` already defaults to 1.0. Multiplying by 1.0 is a no-op. Current behavior is preserved exactly until Phase 2 code sets confidence < 1.0.

### 4g. VulnRule.apply() score computation (Rev 2 — Option A locked in)

The effective_score = raw_score × multiplier. `_derive_issue_confirmation()` returns `"confirmed"` when no confirmation data exists on evidence findings. This means: legacy findings without the field → multiplier 1.0 → **identical to current behavior**. Score changes only activate for findings promoted through the updated Ledger, which explicitly tags them with a confirmation level.

### 4h. promote_finding() signature

The new `confirmation_level` parameter has a default (`"probable"`). Any existing callers of `promote_finding()` that don't pass it will work unchanged.

**One hazard**: `promote_finding()` uses `**kwargs` for metadata. If any caller passes `confirmation_level` in kwargs, it would be captured there instead of the new explicit parameter. **Check**: Grep for all callers of `promote_finding()` to verify none pass `confirmation_level` in kwargs. Since this is a new field, no existing caller can pass it.

---

## 5. Minimal Test Plan

### Test A: .git/config with credentials outranks speculative SSRF

**Setup**:
1. Create an `EvidenceLedger` instance
2. Record an observation from tool `httpx` targeting `example.com` with raw output containing `.git/config` content including `password=s3cret` and `aws_access_key_id=AKIA...`
3. Create a `FindingProposal` with source=`"httpx"` (a tool), severity=`"HIGH"`, tags=`["backup-leak"]`, citations referencing the observation
4. Call `evaluate_and_promote()` → assert confirmation_level = `"confirmed"`
5. Record a second observation (from httpx) with output containing `http://localhost` in a URL parameter
6. Create a `FindingProposal` with source=`"ai"`, severity=`"CRITICAL"`, tags=`["ssrf-source", "cloud"]`, citations referencing that observation
7. Call `evaluate_and_promote()` → assert confirmation_level = `"hypothesized"`
8. Run `apply_rules()` with both findings in findings_store

**Expected results**:
- .git/config finding: BACKUP_EXPOSURE rule fires with content-aware escalation → severity=`"CRITICAL"`, raw_score=9.5, confirmation=`"confirmed"`, effective score = 9.5 × 1.0 = **9.5**
- SSRF finding: SSRF_CHAIN rule fires → severity=`"CRITICAL"`, raw_score=9.2, confirmation=`"hypothesized"`, effective score = 9.2 × 0.4 = **3.68**
- **Assert**: .git/config score (9.5) > SSRF score (3.68)

**RiskEngine check**:
- Both issues are CRITICAL → base weight = 10
- .git/config: 10 × 1.0 = **10.0** (confirmed)
- SSRF: 10 × 0.4 = **4.0** (hypothesized)
- **Assert**: .git/config contributes more to per-asset risk

### Test B: Confirmed SSRF promotion scenario

**Setup**:
1. Record observation from tool `nmap` with open port 80
2. Create FindingProposal (source=`"ai"`, type=`"ssrf"`, tags=`["ssrf-source", "cloud"]`) → promoted with confirmation=`"hypothesized"`
3. Later: Record observation from tool `wraith` with confirmed SSRF response (200 from 169.254.169.254)
4. Create new FindingProposal (source=`"wraith"`, severity=`"CRITICAL"`, tags=`["ssrf-source", "cloud"]`, citation to wraith observation) → promoted with confirmation=`"confirmed"`
5. Run `apply_rules()` with the now-confirmed SSRF finding

**Expected results**:
- Confirmed SSRF: SSRF_CHAIN fires → severity=`"CRITICAL"`, raw_score=9.2, confirmation=`"confirmed"`, effective score = 9.2 × 1.0 = **9.2**
- **Assert**: Confirmed SSRF outranks hypothesized SSRF (9.2 vs 3.68)
- **Assert**: Confirmed SSRF still correctly scores lower than .git/config with credentials (9.2 < 9.5) — credentials = direct access > network pivot

### Test C: Backward compatibility — no confirmation data

**Setup**:
1. Create findings directly in findings_store (bypassing Ledger) — simulating pre-existing data
2. These findings have no `confirmation_level` field
3. Run `apply_rules()` and `RiskEngine.recalculate()`

**Expected results**:
- `_derive_issue_confirmation()` returns `"confirmed"` (Option A default)
- Effective score = raw_score × 1.0 = raw_score (no change)
- RiskEngine: multiplier = 1.0 (no change)
- **Assert**: All existing scores identical to pre-Phase-1 behavior

### Test D: .git/config without credentials stays HIGH

**Setup**:
1. Record observation with .git/config output containing only `[core]\nrepositoryformatversion = 0` (no credentials)
2. Create FindingProposal with source=`"httpx"`, tags=`["backup-leak"]`
3. Promote and run `apply_rules()`

**Expected results**:
- BACKUP_EXPOSURE fires, content inspection finds no credential indicators
- severity=`"HIGH"`, raw_score=7.7, confirmation=`"confirmed"`, effective score = 7.7 × 1.0 = **7.7**
- **Assert**: No escalation when credentials aren't present

### Test E: capability_types propagation

**Setup**:
1. Create findings that trigger BACKUP_EXPOSURE and SSRF_CHAIN rules
2. Run `apply_rules()`

**Expected results**:
- BACKUP_EXPOSURE issue has `capability_types: ["information", "access"]`
- SSRF_CHAIN issue has `capability_types: ["execution"]`
- **Assert**: capability_types present and correct on all enriched issues

---

## 6. Edge Cases and Refactors

### Edge Case 1: FindingProposal with source="ai" but valid tool observation

An AI might cite a real tool observation. The current derivation logic checks `proposal.source` first, so `source="ai"` → HYPOTHESIZED regardless of citation quality.

**Is this correct?** Yes. The AI's *interpretation* of tool output is still a hypothesis. The tool output (observation) is confirmed, but the AI's conclusion about what it means is not. The confirmation level represents the *claim's* certainty, not the *evidence's* certainty.

**Future improvement** (not Phase 1): If AI claims are later validated by a separate tool (e.g., Wraith confirms the SSRF), a new CONFIRMED finding should be created. The original HYPOTHESIZED finding can be INVALIDATED or left as-is.

### Edge Case 2: Multiple findings support one issue with mixed confirmation

`_derive_issue_confirmation()` returns the LOWEST level. This means one hypothesized finding in a chain drags the whole issue to HYPOTHESIZED.

**Is this too conservative?** Possibly. But it's safe. A chain is only as strong as its weakest link. If one component is speculative, the whole chain is speculative.

**Alternative** (not recommended for Phase 1): Use weighted average or majority vote. This adds complexity and makes the logic harder to explain.

### Edge Case 3: VulnRule matcher returns severity/score overrides

Several matchers (e.g., `_match_business_logic`, `_match_metadata`) use `setdefault()` to set severity/score on matches. These interact with content-aware escalation:

- `_match_backup_rule()` currently uses `setdefault("severity", "HIGH")` and `setdefault("score", 7.7)`
- Content-aware escalation (Step 2.4) directly sets `match["severity"]` and `match["score"]` for credential cases
- Since direct assignment overrides `setdefault`, the escalation wins correctly

**No refactor needed** — the `setdefault` pattern naturally allows overrides.

### Edge Case 4: YAML-loaded rules don't have capability_types

`load_rules_from_yaml()` (line 1579) creates VulnRules from YAML. These won't have `capability_types` in the YAML.

**Fix**: The `VulnRule` dataclass default `["execution"]` handles this automatically. YAML-loaded rules get `["execution"]` unless the YAML explicitly sets it.

**Optional enhancement**: Support `capability_types` in `rules.yaml` schema. Add to `load_rules_from_yaml()`:
```python
loaded.append(VulnRule(
    ...
    capability_types=rule_def.get("capability_types", ["execution"]),
))
```

### Edge Case 5: race condition in findings_store

`_update_findings_store()` pushes a dict with `confirmation_level`. If `apply_rules()` runs before this push completes (in concurrent scans), it might see findings without the field.

**Mitigation**: `_derive_issue_confirmation()` already handles missing fields by returning `"confirmed"` (Option A default). No race condition risk.

### Edge Case 6: CONFIRMATION_MULTIPLIERS defined in two files

Both `vuln_rules.py` and `risk.py` define `CONFIRMATION_MULTIPLIERS`. If values diverge, scoring becomes inconsistent.

**Refactor recommendation**: Extract to a shared constants module (e.g., `core/data/constants.py` or `core/epistemic/constants.py`). Both files import from there. This is a small, safe refactor that should happen in the implementation PR.

### Edge Case 7: promote_finding() kwargs collision

`promote_finding()` signature is `def promote_finding(self, title, severity, citations, description, timestamp_override=None, **kwargs)`. The new `confirmation_level` parameter is inserted before `timestamp_override`. Verify no existing caller passes positional args beyond `description`.

**Check result from code**: `evaluate_and_promote()` calls `promote_finding()` with keyword args:
```python
return self.promote_finding(
    title=proposal.title,
    severity=proposal.severity,
    citations=valid_citations,
    description=proposal.description,
    **proposal.metadata
)
```
If `proposal.metadata` contains a key `confirmation_level`, it would collide with the new explicit parameter. **Fix**: Pop it from metadata before passing:
```python
meta = dict(proposal.metadata)
meta.pop("confirmation_level", None)  # Avoid collision with explicit param
return self.promote_finding(
    ...,
    confirmation_level=derived_confirmation,
    **meta
)
```

---

## 7. Files Modified (Summary)

| File | Changes | Type |
|------|---------|------|
| `core/epistemic/ledger.py` | Add `ConfirmationLevel` enum, `confirmation_level` field on `Finding` and `FindingProposal`, derivation logic in `evaluate_and_promote()`, passthrough in `promote_finding()`, include in `_update_findings_store()` and event payload | Additive + Modificative |
| `core/toolkit/vuln_rules.py` | Add `capability_types` to `VulnRule`, annotate 8 rules, add `CREDENTIAL_INDICATORS` + `CONFIRMATION_MULTIPLIERS` constants, add `_build_content_string()` + `_derive_issue_confirmation()` helpers, modify `_match_backup_rule()` for content-awareness, modify `VulnRule.apply()` for confirmation multiplier + new fields | Additive + Modificative |
| `core/data/risk.py` | Add `CONFIRMATION_MULTIPLIERS`, modify `recalculate()` to apply confirmation multiplier | Modificative |
| `core/omega/risk_calculator.py` | Modify `calculate()` to multiply by `PillarScore.confidence`, add confidence to log events | Modificative |

**Files NOT modified** (confirming scope):
- `core/cortex/nexus_context.py` — Phase 2
- `core/cortex/causal_graph.py` — Phase 2
- `core/scheduler/strategos.py` — Phase 2
- `core/cal/*` — Explicitly out of scope
- `core/ai/ai_engine.py` — No changes needed (source field already set correctly)
- `core/ai/strategy.py` — No changes needed
