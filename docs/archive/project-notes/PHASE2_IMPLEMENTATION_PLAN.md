# Phase 2 Implementation Plan: NexusContext + CausalGraph + Strategos Intelligence Layer

**Status**: PLAN ONLY — No Code
**Scope**: Changes 3, 4, and 6 from the Design Proposal
**Prerequisite**: Phase 1 (ConfirmationLevel + Capability Types + Confirmation-Weighted Scoring) MUST be complete

---

## 0. Executive Summary

Phase 2 extends SentinelForge's capability model to the graph and insight layers. While Phase 1 taught the system to distinguish confirmed findings from speculative ones and to classify capabilities (execution, information, access, evasion), Phase 2 teaches the system to:

1. **Synthesize confirmed information findings into actionable hypotheses** (NexusContext Rule 3)
2. **Model enablement relationships between capabilities** (CausalGraph Rule 5)
3. **Route insights with confirmation-aware priority** (Strategos unified insight action types)

The result: The system now ranks confirmed .git/config with AWS credentials higher than speculative SSRF indicators, not through arbitrary severity boosting, but through graph centrality, confirmation weighting, and enablement modeling.

### Key Changes
- **NexusContext**: Adds information-enablement synthesis rule (Rule 3)
- **CausalGraph**: Adds enablement edge inference (Rule 5) with weighted edges
- **Strategos**: Adds `InsightActionType.CONFIRMED_EXPOSURE` for access capabilities + deprioritizes hypothesized findings

### Impact on Users
- Confirmed information findings (credentials, source code, topology) now generate NEXUS hypotheses with appropriate confidence
- Cross-finding correlation becomes visibility into the graph — enablement edges show what each finding unlocks
- Insights route to both asset-inventory AND vulnerability-exploitation handlers for findings with access capabilities
- Hypothesized findings are deprioritized by +2 priority levels (still processed, just after confirmed ones)

---

## 1. Prerequisites (Phase 1 Completion Checklist)

Before starting Phase 2, verify:

### 1.1 EvidenceLedger (core/epistemic/ledger.py)
- [ ] ConfirmationLevel enum exists (CONFIRMED, PROBABLE, HYPOTHESIZED)
- [ ] Finding.confirmation_level field exists (default "probable")
- [ ] FindingProposal.confirmation_level field exists (Optional, None)
- [ ] evaluate_and_promote() derives confirmation_level from source + citations
- [ ] promote_finding() accepts confirmation_level parameter
- [ ] _update_findings_store() includes confirmation_level in dict
- [ ] Event payloads include confirmation_level

**Verification**: `grep -n "confirmation_level" core/epistemic/ledger.py | wc -l` should show 8+ matches

### 1.2 VulnRule (core/toolkit/vuln_rules.py)
- [ ] VulnRule.capability_types field exists (List[str], default ["execution"])
- [ ] CREDENTIAL_INDICATORS constant defined (21 items)
- [ ] CONFIRMATION_MULTIPLIERS constant defined
- [ ] _build_content_string() helper exists
- [ ] _derive_issue_confirmation() helper exists
- [ ] _match_backup_rule() implements content-aware escalation
- [ ] VulnRule.apply() multiplies score by confirmation multiplier
- [ ] Enriched issues include capability_types, confirmation_level, confirmation_multiplier

**Verification**: `grep -n "capability_types" core/toolkit/vuln_rules.py | wc -l` should show 30+ matches

### 1.3 RiskEngine (core/data/risk.py)
- [ ] CONFIRMATION_MULTIPLIERS constant defined (same as vuln_rules.py)
- [ ] recalculate() applies confirmation multiplier to asset-level scores

**Verification**: `grep -n "confirmation_multiplier" core/data/risk.py` should show at least 2 matches

### 1.4 OMEGARiskCalculator (core/omega/risk_calculator.py)
- [ ] calculate() multiplies by PillarScore.confidence (even if 1.0)
- [ ] Event payloads include cronus_confidence, mimic_confidence, nexus_confidence

**Verification**: `grep -n "confidence" core/omega/risk_calculator.py | wc -l` should show 10+ matches

---

## 2. New Data Structures (Shared Types)

These are new enums, dataclasses, and type hints needed by Phase 2 components.

### 2.1 Enablement Edge Weights (Enum)

**File**: `core/cortex/causal_graph.py` (new, at module top)

```python
class EnablementStrength(float, Enum):
    """Strength of enablement relationship between capabilities."""
    DIRECT = 2.0      # Credential exposure → auth-gated resource (high confidence)
    INDIRECT = 1.0    # Topology exposure → targeted exploitation (moderate confidence)
    WEAK = 0.5        # Generic config → general knowledge (weak enablement)
```

### 2.2 Hypothesis Confidence Mapping (Constant)

**File**: `core/cortex/nexus_context.py` (new, at module top)

```python
INFORMATION_HYPOTHESIS_CONFIDENCE = {
    "credential_exposure": 0.95,        # API keys, passwords, tokens
    "source_code_secrets": 0.90,        # .git/config with secrets, .env files
    "internal_topology": 0.80,          # IP disclosure, internal endpoints
    "backup_config": 0.70,              # Generic backup/config with no secrets
}
```

### 2.3 NexusContext Correlation Dataclass

**File**: `core/cortex/nexus_context.py` (extend existing NexusContext)

Add to NexusContext:

```python
@dataclass
class NexusCorrelation:
    """
    A finding-to-finding correlation for hypothesis synthesis.

    Used by information-enablement rule to track which findings enable others
    and what chain they belong to.
    """
    source_finding_id: str
    source_finding_type: str
    target_finding_id: Optional[str]  # None if this is a standalone finding
    correlation_type: str  # "enablement", "chain", "singleton"
    confidence: float  # 0.0-1.0
    enabled_actions: List[str]  # e.g., ["auth_bypass", "targeted_exploitation"]
    enablement_edges: List[str]  # IDs of findings enabled by source_finding
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### 2.4 CausalGraph Enablement Edge

**File**: `core/cortex/causal_graph.py` (extend existing graph edge representation)

Add to graph edge dict representation (returned by _infer_dependencies):

```python
# Existing fields (unchanged):
# "source": finding_id or target_name
# "target": finding_id or target_name
# "strength": numeric weight
# "type": "chain" | "information" | "exploit"

# NEW fields for enablement edges:
enablement_edge = {
    "source": finding_id,  # Information/access finding
    "target": finding_id,  # Capability being enabled
    "strength": 2.0 | 1.0 | 0.5,  # EnablementStrength value
    "type": "enablement",  # NEW: distinguishes from "chain" and "exploit"
    "enablement_class": "credential" | "topology" | "code" | "generic",
    "effort_replaced": float,  # From effort elimination table (0.0-9.0)
    "enabled_at": float,  # Timestamp when edge was inferred
}
```

### 2.5 InsightActionType Extension

**File**: `core/contracts/schemas.py` (extend existing InsightActionType enum)

Add to InsightActionType:

```python
class InsightActionType(str, Enum):
    # ... existing types ...
    CONFIRMED_EXPOSURE = "confirmed_exposure"  # NEW: Access capability (credentials, sessions)
    HIGH_VALUE_TARGET = "high_value_target"   # Existing (for information-only)
    CONFIRMED_VULN = "confirmed_vuln"         # Existing (for execution)
    CRITICAL_PATH = "critical_path"           # Existing
    WAF_DETECTED = "waf_detected"             # Existing
    AUTH_REQUIRED = "auth_required"           # Existing
    RATE_LIMIT = "rate_limit"                 # Existing
```

---

## 3. Step-by-Step Implementation (Dependency Order)

Implementation order: Steps 3.1 (CausalGraph) and 3.2 (NexusContext) are independent and can
be implemented in parallel — NexusContext is graph-agnostic in Phase 2. Step 3.3 (Strategos)
reads from Phase 1 fields and can start after Phase 1 is verified, but should be implemented
last to benefit from any learnings during 3.1/3.2.

### Step 3.1: CausalGraph — Add Enablement Edge Inference Rule (Change 4)

**File**: `core/cortex/causal_graph.py`
**Location**: Extend class CausalGraph
**Type**: ADDITIVE (new heuristic rule + helper methods)

#### 3.1.1 Add EnablementStrength enum (module top)

```python
class EnablementStrength(float, Enum):
    DIRECT = 2.0
    INDIRECT = 1.0
    WEAK = 0.5
```

#### 3.1.2 Add effort replacement mapping (module constant)

```python
# How much attacker effort is replaced by discovering each finding type
EFFORT_ELIMINATED_BY_CAPABILITY = {
    "credential_exposure": 9.0,      # Replaces brute-forcing
    "source_code": 8.0,              # Replaces black-box fuzzing
    "topology": 7.0,                 # Replaces network mapping
    "confirmed_injection": 6.0,      # Replaces fuzzing for injection points
    "stack_disclosure": 4.0,         # Replaces fingerprinting
    "port_disclosure": 3.0,          # Replaces port scanning
    "partial_info": 2.0,             # Generic reconnaissance value
}
```

#### 3.1.3 Add enablement edge inference method

**Method**: `_infer_information_enablement_edges(findings: List[dict]) -> List[dict]`

**Location**: Inside CausalGraph class, after existing `_infer_dependencies()` method

**Logic**:

```python
def _infer_information_enablement_edges(self, findings: List[dict]) -> List[dict]:
    """
    Create enablement edges FROM information/access findings
    TO capabilities they enable.

    Returns list of edge dicts:
    {
        "source": finding_id,
        "target": finding_id,
        "type": "enablement",
        "strength": float,
        "enablement_class": str,
        "effort_replaced": float,
    }

    Rules:
    1. Source finding must be CONFIRMED and have capability_types including
       "information" or "access"
    2. Target findings are on same target and could benefit from source info
    3. Only create edges within single target (no cross-target inference)
    4. Edge strength based on information type:
       - Credentials → auth resources: 2.0 (direct)
       - Topology → SSRF targets: 1.0 (indirect)
       - Code → injection points: 1.0 (indirect)
       - Generic config → general: 0.5 (weak)
    """
    edges = []

    # Index findings by target and capability type
    by_target = {}
    for finding in findings:
        target = finding.get("target", "unknown")
        by_target.setdefault(target, []).append(finding)

    # For each target, find information findings and link them
    for target, target_findings in by_target.items():
        info_findings = [
            f for f in target_findings
            if f.get("confirmation_level") == "confirmed"
            and any(cap in f.get("capability_types", [])
                   for cap in ["information", "access"])
        ]

        for info_finding in info_findings:
            source_id = info_finding.get("id", "unknown")
            capability_types = info_finding.get("capability_types", [])

            # Determine enablement class from finding content/type
            enablement_class = self._classify_enablement(info_finding)
            strength = self._enablement_strength(capability_types, enablement_class)
            effort = EFFORT_ELIMINATED_BY_CAPABILITY.get(enablement_class, 2.0)

            # Find target findings that could benefit
            target_findings_for_edge = [
                f for f in target_findings
                if f.get("id") != source_id
                and self._would_benefit_from(f, enablement_class, capability_types)
            ]

            for target_finding in target_findings_for_edge:
                target_id = target_finding.get("id", "unknown")
                edges.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "enablement",
                    "strength": float(strength),
                    "enablement_class": enablement_class,
                    "effort_replaced": float(effort),
                    "enabled_at": time.time(),
                })

    return edges
```

#### 3.1.4 Add helper: _classify_enablement()

```python
def _classify_enablement(self, finding: dict) -> str:
    """
    Classify what type of enablement this finding provides.

    Returns one of: "credential_exposure", "source_code", "topology",
    "confirmed_injection", "stack_disclosure", "port_disclosure", "partial_info"
    """
    finding_type = finding.get("type", "").lower()
    tags = set(finding.get("tags", []))
    value = finding.get("value", "") or finding.get("description", "")

    # Credential-class findings
    if "secret-leak" in tags or "credential" in finding_type:
        return "credential_exposure"
    if "backup-leak" in tags and any(ind in value.lower()
                                      for ind in ["password", "api_key", "secret"]):
        return "credential_exposure"

    # Source code findings
    if "git" in finding_type or "source" in finding_type:
        return "source_code"

    # Topology findings
    if "private-ip" in tags or "topology" in finding_type:
        return "topology"

    # Injection findings
    if any(tag in tags for tag in ["sqli", "injection", "rce"]):
        return "confirmed_injection"

    # Stack disclosure
    if "error-leakage" in tags or "stack" in finding_type:
        return "stack_disclosure"

    # Port findings
    if "port" in finding_type or "service" in finding_type:
        return "port_disclosure"

    # Default
    return "partial_info"
```

#### 3.1.5 Add helper: _enablement_strength()

```python
def _enablement_strength(self, capability_types: List[str],
                        enablement_class: str) -> EnablementStrength:
    """
    Determine edge strength based on capability type and enablement class.

    Access capabilities have stronger enablement than information.
    Credentials and source code unlock more than topology.
    """
    has_access = "access" in capability_types

    # Credentials/source code to anything: DIRECT (2.0)
    if enablement_class in ("credential_exposure", "source_code"):
        return EnablementStrength.DIRECT

    # Topology to targeted findings: INDIRECT (1.0)
    if enablement_class in ("topology", "confirmed_injection"):
        return EnablementStrength.INDIRECT

    # Everything else: WEAK (0.5)
    return EnablementStrength.WEAK
```

#### 3.1.6 Add helper: _would_benefit_from()

```python
def _would_benefit_from(self, target_finding: dict,
                       enablement_class: str,
                       source_capability_types: List[str]) -> bool:
    """
    Determine if target_finding would benefit from this enablement.

    Heuristic matching:
    - Credentials enable auth-gated resources (login, admin panels)
    - Topology enables targeted exploitation (SSRF with known targets)
    - Source code enables injection attacks (known endpoints)
    """
    target_type = target_finding.get("type", "").lower()
    target_tags = set(target_finding.get("tags", []))

    if enablement_class == "credential_exposure":
        # Auth findings benefit from credentials
        return any(tag in target_tags for tag in ["auth", "login", "admin"])

    if enablement_class == "topology":
        # SSRF findings benefit from known topology
        return "ssrf" in target_tags or "cloud" in target_tags

    if enablement_class == "source_code":
        # Injection findings benefit from known endpoints
        return any(tag in target_tags for tag in ["injection", "sqli", "rce"])

    # Default: information/access enables all findings on target
    if "access" in source_capability_types:
        return True

    return False
```

#### 3.1.7 Integrate into _infer_dependencies()

**Location**: End of `_infer_dependencies()` method (after all existing rules)

```python
def _infer_dependencies(self, findings: List[dict]) -> List[dict]:
    """
    Infer dependencies between findings.

    Rules 1-4: Existing chain rules (port → service → vuln)
    Rule 5: NEW Enablement edges (information → capabilities)
    """
    # ... existing Rules 1-4 code ...

    # Rule 5: Information enablement edges
    enablement_edges = self._infer_information_enablement_edges(findings)
    edges.extend(enablement_edges)

    return edges
```

#### 3.1.8 Add separate enablement_score metric (do NOT overload centrality)

**IMPORTANT**: `centrality_score` means "choke point in exploit chains." Enablement
edges measure a different concept: "attacker leverage from information." Overloading
centrality with enablement weight changes the semantic of an existing metric — future
debugging becomes impossible when one number means two things.

**Add a new metric** in `get_attack_chains()` return dict:

```python
# NEW: enablement_score is SEPARATE from centrality_score.
# centrality_score = choke-point in exploit chains (unchanged)
# enablement_score = attacker leverage from information findings
enablement_score = sum(
    edge.get("strength", 0.0)
    for edge in node_edges
    if edge.get("type") == "enablement"
)

node_summary["enablement_score"] = enablement_score
# centrality_score is computed exactly as before — DO NOT modify it.
```

**Consumers** can combine these scores at read-time if needed:
```python
combined = node["centrality_score"] + node["enablement_score"]
```

But the two metrics remain independently queryable and independently debuggable.

**PHASE 3 NOTE**: If a combined ranking is needed, introduce `combined_leverage`
as a third derived metric. Never collapse two semantically distinct scores into one.

---

### Step 3.2: NexusContext — Add Information Enablement Synthesis Rule (Change 3)

**File**: `core/cortex/nexus_context.py`
**Location**: Extend class NexusContext, inside `synthesize_attack_paths()`
**Type**: ADDITIVE (new synthesis rule)

#### 3.2.1 Add hypothesis confidence mapping (module top)

```python
INFORMATION_HYPOTHESIS_CONFIDENCE = {
    "credential_exposure": 0.95,
    "source_code_secrets": 0.90,
    "internal_topology": 0.80,
    "backup_config": 0.70,
}
```

#### 3.2.2 Add Rule 3: Information Enablement

**Location**: Inside `synthesize_attack_paths()`, after existing Rule 2 (`rule_critical_isolated`)

```python
def synthesize_attack_paths(self):
    """
    Synthesize hypotheses from findings.

    Rule 1: Web exposure chain (port + web vuln)
    Rule 2: Critical isolated (HIGH/CRITICAL finding alone)
    Rule 3: NEW - Information enablement (confirmed info/access finding)
    """
    # ... existing Rule 1 and Rule 2 code ...

    # Rule 3: Information Enablement Synthesis
    # Emit NEXUS_HYPOTHESIS_FORMED for confirmed information/access findings
    rule_3_findings = [
        f for f in self.findings
        if f.get("confirmation_level") == "confirmed"
        and any(cap in f.get("capability_types", [])
               for cap in ["information", "access"])
        and float(f.get("base_score", 0)) >= 5.0  # Avoid noise
    ]

    for finding in rule_3_findings:
        finding_id = finding.get("id", "unknown")
        finding_type = finding.get("type", "").lower()
        base_score = finding.get("base_score", 5.0)

        # Determine confidence tier
        confidence = self._confidence_for_information_finding(finding)

        # Hypothesis explanation (what this enables, not what was found)
        explanation = self._enablement_explanation(finding)

        # Emit hypothesis event
        hypothesis_id = self._generate_hypothesis_id(
            finding_ids=[finding_id],
            rule_id="rule_information_enablement",
            rule_version=1
        )

        # Only emit if not seen before
        if hypothesis_id not in self._seen_hypothesis_ids:
            self._emit_hypothesis_event(
                event_type=NexusEventType.NEXUS_HYPOTHESIS_FORMED,
                hypothesis_id=hypothesis_id,
                finding_ids=[finding_id],
                confidence=confidence,
                explanation=explanation,
                rule="information_enablement",
                finding_type=finding_type,
                base_score=base_score,
            )
            self._seen_hypothesis_ids.add(hypothesis_id)
```

#### 3.2.3 Add helper: _confidence_for_information_finding()

```python
def _confidence_for_information_finding(self, finding: dict) -> float:
    """
    Map finding content to hypothesis confidence.
    """
    finding_type = finding.get("type", "").lower()
    tags = set(finding.get("tags", []))

    # Credentials are most reliable
    if "secret-leak" in tags or "credential" in finding_type:
        return INFORMATION_HYPOTHESIS_CONFIDENCE.get("credential_exposure", 0.95)

    # Source code with secrets is highly reliable
    if "backup-leak" in tags and any(ind in (finding.get("value", "") or "").lower()
                                      for ind in ["password", "api_key", "secret"]):
        return INFORMATION_HYPOTHESIS_CONFIDENCE.get("source_code_secrets", 0.90)

    # Internal topology is moderately reliable
    if "private-ip" in tags or any(tag in tags for tag in ["topology", "internal"]):
        return INFORMATION_HYPOTHESIS_CONFIDENCE.get("internal_topology", 0.80)

    # Generic backup/config is less reliable
    if "backup-leak" in tags:
        return INFORMATION_HYPOTHESIS_CONFIDENCE.get("backup_config", 0.70)

    # Default to conservative
    return 0.70
```

#### 3.2.4 Add helper: _enablement_explanation()

```python
def _enablement_explanation(self, finding: dict) -> str:
    """
    Generate hypothesis explanation describing what this finding enables.

    NOT: "We found a .git/config file"
    YES: "This finding grants read access to [N] authenticated endpoints
          and reveals source code structure for targeted exploitation"
    """
    finding_type = finding.get("type", "").lower()
    tags = set(finding.get("tags", []))
    target = finding.get("target", "unknown")

    if "secret-leak" in tags or "credential" in finding_type:
        return (f"Discovered credentials on {target} enable direct authentication bypass. "
               "Attacker can immediately access credential-protected resources without brute-forcing.")

    if "backup-leak" in tags:
        return (f"Backup/source artifact exposure on {target} reveals application structure, "
               "secret keys, and code patterns. Enables targeted exploitation of known endpoints.")

    if "private-ip" in tags:
        return (f"Internal IP disclosure on {target} enables SSRF targeting and lateral movement "
               "to private infrastructure.")

    if "git" in finding_type:
        return (f"Git configuration exposure on {target} reveals repository structure, "
               "commit history, and embedded secrets. Enables code review and targeted attacks.")

    # Default
    return (f"Information finding on {target} reduces attacker uncertainty and enables "
           "more targeted follow-up exploitation.")
```

#### 3.2.5 Update _emit_hypothesis_event() signature (if needed)

If the existing `_emit_hypothesis_event()` method doesn't support all fields, extend it:

```python
def _emit_hypothesis_event(self,
                          event_type: NexusEventType,
                          hypothesis_id: str,
                          finding_ids: List[str],
                          confidence: float,
                          explanation: str,
                          rule: str,
                          finding_type: str,
                          base_score: float) -> None:
    """
    Emit a hypothesis event with enriched context.
    """
    payload = {
        "hypothesis_id": hypothesis_id,
        "finding_ids": finding_ids,
        "confidence": confidence,
        "explanation": explanation,
        "rule": rule,
        "finding_type": finding_type,
        "base_score": base_score,
        "timestamp": time.time(),
    }

    event = NexusEvent(
        type=event_type,
        payload=payload,
    )

    self._event_bus.emit(event)
```

---

### Step 3.3: Strategos — Unified Insight Action Types (Change 6)

**File**: `core/scheduler/strategos.py`
**Location**: Extend method `_generate_insights_from_finding()` and add handler
**Type**: MODIFICATIVE (enhance routing logic + new handler)

#### 3.3.1 Add CONFIRMED_EXPOSURE to InsightActionType enum

**File**: `core/contracts/schemas.py`

```python
class InsightActionType(str, Enum):
    # ... existing types ...
    CONFIRMED_EXPOSURE = "confirmed_exposure"  # NEW
```

#### 3.3.2 Update _generate_insights_from_finding() logic

**File**: `core/scheduler/strategos.py`
**Method**: `_generate_insights_from_finding()` (line ~1276)

**Current code** (simplified):
```python
if finding_type in ["admin_panel", "config_exposure", "git_exposure"]:
    action_type = InsightActionType.HIGH_VALUE_TARGET
    confidence = 0.9
    priority = 0
elif finding_type in ["sqli", "rce", "lfi", "ssrf"]:
    action_type = InsightActionType.CONFIRMED_VULN
    confidence = 0.8
    priority = 0
```

**New code**:
```python
# Extract confirmation and capability info
confirmation_level = finding.get("confirmation_level", "probable")
capability_types = finding.get("capability_types", [])

# NEW: Deprioritize hypothesized findings by +2 priority
priority_adjustment = 2 if confirmation_level == "hypothesized" else 0

# Route based on capability type + confirmation
if confirmation_level == "confirmed" and "access" in capability_types:
    # NEW: Confirmed access capability (credentials, sessions)
    action_type = InsightActionType.CONFIRMED_EXPOSURE
    confidence = 0.95
    summary = f"Confirmed Access Capability: {finding_type} at {target}"
    priority = 0 + priority_adjustment

elif confirmation_level == "confirmed" and "information" in capability_types and "access" not in capability_types:
    # Confirmed information-only (no access)
    action_type = InsightActionType.HIGH_VALUE_TARGET
    confidence = 0.9
    summary = f"High Value Information Target: {finding_type} at {target}"
    priority = 0 + priority_adjustment

elif confirmation_level == "confirmed" and "execution" in capability_types:
    # Confirmed execution capability (RCE, SQLi, SSRF)
    action_type = InsightActionType.CONFIRMED_VULN
    confidence = 0.85
    summary = f"Confirmed Vulnerability: {finding_type} at {target}"
    priority = 0 + priority_adjustment

elif confirmation_level == "hypothesized":
    # AI-generated, unconfirmed finding — deprioritized
    if "execution" in capability_types:
        action_type = InsightActionType.CONFIRMED_VULN  # Still route as vuln, just lower priority
        confidence = 0.4  # Lower confidence for hypothesized
        summary = f"Possible Vulnerability (unconfirmed): {finding_type} at {target}"
        priority = 2 + priority_adjustment
    else:
        action_type = InsightActionType.HIGH_VALUE_TARGET
        confidence = 0.5
        summary = f"Possible Information Target (unconfirmed): {finding_type} at {target}"
        priority = 2 + priority_adjustment

else:  # PROBABLE confirmation
    # Falls between confirmed and hypothesized
    action_type = InsightActionType.HIGH_VALUE_TARGET if "information" in capability_types else InsightActionType.CONFIRMED_VULN
    confidence = 0.7
    priority = 1 + priority_adjustment
```

#### 3.3.3 Add handler for CONFIRMED_EXPOSURE

**File**: `core/scheduler/strategos.py`
**Location**: In `_route_insight_to_handler()` method, add case

```python
async def _route_insight_to_handler(self, insight: InsightPayload) -> None:
    action_type = insight.action_type

    if action_type == InsightActionType.HIGH_VALUE_TARGET:
        await self._handle_high_value_target(insight)
    elif action_type == InsightActionType.CONFIRMED_EXPOSURE:  # NEW
        await self._handle_confirmed_exposure(insight)
    elif action_type == InsightActionType.CRITICAL_PATH:
        await self._handle_critical_path(insight)
    # ... rest unchanged ...
```

#### 3.3.4 Implement _handle_confirmed_exposure()

**File**: `core/scheduler/strategos.py`
**Location**: After `_handle_high_value_target()` method

```python
async def _handle_confirmed_exposure(self, insight: InsightPayload) -> None:
    """
    Handle confirmed access/credential findings.

    Routes to BOTH:
    1. Asset inventory (for exposed credentials/tokens)
    2. Vulnerability escalation (credentials enable auth bypass)
    """
    if not self.context:
        return

    async with self.context.lock:
        self.context.knowledge.setdefault("confirmed_exposures", [])
        self.context.knowledge["confirmed_exposures"].append(
            {
                "target": insight.target,
                "insight_id": insight.insight_id,
                "finding_type": insight.details.get("finding_type"),
                "confidence": insight.confidence,
                "discovered_at": insight.created_at,
                "details": insight.details,
            }
        )

    await self._emit_reaction_decision(insight)

    # Log with emphasis (access findings are critical)
    self._emit_log(
        f"[Strategos] 🔓 CONFIRMED EXPOSURE on {insight.target}: "
        f"{insight.details.get('finding_type', 'access capability')} "
        f"(confidence: {insight.confidence})"
    )

    # Trigger both asset-inventory and vulnerability-exploitation logic
    # (In production, this might dispatch to additional tools or handlers)
```

---

## 4. Data Flow and Integration Points

### 4.1 Phase 1 → Phase 2 Data Flow

```
Finding (from Phase 1)
├── confirmation_level: str          ← Phase 1
├── capability_types: List[str]      ← Phase 1
├── base_score: float                ← Phase 1
├── raw_score: float                 ← Phase 1
└── confirmation_multiplier: float   ← Phase 1

↓ (read by Phase 2)

CausalGraph._infer_dependencies()          NexusContext.synthesize_attack_paths()
├── Reads: confirmation_level,              ├── Reads: confirmation_level,
│   capability_types                        │   capability_types, base_score
├── Creates: enablement edges               ├── Rule 3: Information-enablement synthesis
│   (type="enablement")                     │   (graph-agnostic — reads findings only)
└── Returns: edges + enablement_score       └── Emits: NEXUS_HYPOTHESIS_FORMED
                                                with confidence tier
    ↓                                           ↓
    └──────────── BOTH feed into ───────────────┘
                        ↓
Strategos._generate_insights_from_finding()
├── Reads: confirmation_level, capability_types (from Phase 1 fields)
├── Routes to: CONFIRMED_EXPOSURE | HIGH_VALUE_TARGET | CONFIRMED_VULN
└── Adjusts priority: +2 for hypothesized
```

### 4.2 Key Integration Points

#### 4.2.1 CausalGraph → NexusContext (ONE-DIRECTIONAL, no feedback loop)

**Phase 2 design**: NexusContext does NOT read CausalGraph. Data flows in one direction:

```
findings → CausalGraph (edges)
findings → NexusContext (hypotheses)  ← graph-agnostic
both    → Strategos (insights)
```

**Why**: If NexusContext reads graph state, and hypotheses influence future graph
construction (via events), you get a bidirectional dependency:
  graph → hypotheses → graph → hypotheses → ...

This is where subtle feedback loops are born. Phase 2 avoids this entirely.

Rule 3 derives hypothesis confidence from finding content + confirmation level ONLY.
No graph topology, no edge counts, no centrality.

**PHASE 3 NOTE**: "Graph-informed confidence adjustment" is a legitimate future
enhancement. When introduced, it should be:
  1. A new, named concept (not a multiplier buried in Rule 3)
  2. Tested independently of Rule 3
  3. One-shot (read graph once, don't re-read after hypothesis emission)

#### 4.2.2 NexusContext ↔ Strategos

**Timing**: After NexusContext emits NEXUS_HYPOTHESIS_FORMED events, Strategos ingests findings and generates insights from them.

**Interface**:
```python
# Strategos._generate_insights_from_finding() reads finding fields set by NexusContext
confirmation_level = finding.get("confirmation_level")
capability_types = finding.get("capability_types")

# Routes based on these fields
if confirmation_level == "confirmed" and "access" in capability_types:
    action_type = InsightActionType.CONFIRMED_EXPOSURE
```

#### 4.2.3 OMEGA Calculator ← Strategos (via event bus)

**Timing**: Strategos emits insight events with confirmation-aware priority. OMEGA uses these to weight findings in NEXUS pillar.

**Interface**:
```python
# Strategos emits events with priority
event = GraphEvent(
    type=EventType.NEXUS_INSIGHT_FORMED,
    payload={
        "priority": 0,  # Confirmed finding
        "confidence": 0.95,
        "action_type": "CONFIRMED_EXPOSURE",
    }
)

# OMEGA reads priority to weight findings
if insight.priority < 2:  # Confirmed findings
    nexus_score += insight.confidence * finding.base_score
else:  # Hypothesized findings
    nexus_score += insight.confidence * 0.4 * finding.base_score
```

---

## 5. Deterministic Logic (Rules and Heuristics)

### 5.1 CausalGraph Rule 5: Information Enablement

**Rule ID**: `information_enablement`

**Precondition**:
```
finding.confirmation_level == "confirmed"
AND ("information" in finding.capability_types OR "access" in finding.capability_types)
AND finding.base_score >= 5.0
AND finding.target == target_finding.target  (single-target only)
```

**Action**:
```
For each target_finding on same target:
  IF would_benefit_from(target_finding, enablement_class):
    Create edge:
      source = finding.id
      target = target_finding.id
      type = "enablement"
      strength = EnablementStrength[enablement_class]
      enablement_class = _classify_enablement(finding)
      effort_replaced = EFFORT_ELIMINATED[enablement_class]
```

**Edge Creation Heuristics**:

| Source Finding Type | Enablement Class | Target Finding Types | Edge Strength |
|-------------------|-----------------|----------------------|---------------|
| API Key, Password | credential_exposure | Login, Auth, Admin | 2.0 (DIRECT) |
| .git/config (with secrets) | source_code_secrets | SQLi, RCE, Injection | 2.0 (DIRECT) |
| Internal IP disclosure | internal_topology | SSRF, Cloud metadata | 1.0 (INDIRECT) |
| Generic backup/config | backup_config | Any on same target | 0.5 (WEAK) |
| Stack trace | stack_disclosure | Version-specific exploits | 0.5 (WEAK) |

### 5.2 NexusContext Rule 3: Information Enablement Synthesis

**Rule ID**: `rule_information_enablement`

**Precondition**:
```
finding.confirmation_level == "confirmed"
AND ("information" in finding.capability_types OR "access" in finding.capability_types)
AND finding.base_score >= 5.0
AND finding.id NOT IN _seen_hypothesis_ids
```

**Action**:
```
confidence = _confidence_for_information_finding(finding)
explanation = _enablement_explanation(finding)

Emit NEXUS_HYPOTHESIS_FORMED:
  hypothesis_id = SHA256(finding_id + "rule_information_enablement" + "v1")
  confidence = confidence  (see mapping below)
  explanation = explanation
  rule = "information_enablement"
```

**Confidence Mapping**:

| Finding Type | Confidence | Rationale |
|------------|-----------|-----------|
| Credential/Secret leak | 0.95 | Direct access, tool-verified |
| Source code with secrets | 0.90 | Reveals infrastructure, tool-verified |
| Internal topology | 0.80 | Enables targeted attacks, but indirect |
| Generic backup/config | 0.70 | Has value but limited actionability |

### 5.3 Strategos Insight Routing Logic

**Decision Table**:

| Confirmation Level | Capability Types | Action Type | Confidence | Priority | Handler |
|-------------------|-----------------|------------|-----------|----------|---------|
| CONFIRMED | includes "access" | CONFIRMED_EXPOSURE | 0.95 | 0 | _handle_confirmed_exposure |
| CONFIRMED | "information" only | HIGH_VALUE_TARGET | 0.90 | 0 | _handle_high_value_target |
| CONFIRMED | includes "execution" | CONFIRMED_VULN | 0.85 | 0 | _handle_confirmed_vuln |
| PROBABLE | includes "access" | CONFIRMED_EXPOSURE | 0.75 | 1 | _handle_confirmed_exposure |
| PROBABLE | "information" only | HIGH_VALUE_TARGET | 0.70 | 1 | _handle_high_value_target |
| PROBABLE | includes "execution" | CONFIRMED_VULN | 0.65 | 1 | _handle_confirmed_vuln |
| HYPOTHESIZED | includes "access" | CONFIRMED_EXPOSURE | 0.50 | 2 | _handle_confirmed_exposure |
| HYPOTHESIZED | "information" only | HIGH_VALUE_TARGET | 0.50 | 2 | _handle_high_value_target |
| HYPOTHESIZED | includes "execution" | CONFIRMED_VULN | 0.40 | 2 | _handle_confirmed_vuln |

---

## 6. Backward Compatibility Guarantees

### 6.1 CausalGraph Changes

**No breaking changes**:
- Existing `_infer_dependencies()` rules (1-4) remain unchanged
- New Rule 5 is appended to edge list
- New edge fields (`enablement_class`, `effort_replaced`) are additive
- Existing code reading edges can ignore unknown fields

**Handling old data**:
```python
# Existing code that reads edges:
for edge in graph.get_attack_chains():
    strength = edge.get("strength", 1.0)  # Works with/without enablement edges
    weight = strength  # Uses default if "strength" missing
```

### 6.2 NexusContext Changes

**No breaking changes**:
- Existing rules 1 and 2 unmodified
- Rule 3 is opt-in (only fires if findings have new Phase 1 fields)
- New NEXUS_HYPOTHESIS_FORMED events carry old + new fields (backward compatible)

**Handling old data**:
```python
# If findings lack confirmation_level or capability_types, Rule 3 quietly doesn't fire
# Existing findings without these fields skip the new logic entirely
if not finding.get("confirmation_level"):
    # Skip Rule 3 for this finding
    continue
```

### 6.3 Strategos Changes

**No breaking changes**:
- Existing insight handlers unchanged
- New `_handle_confirmed_exposure()` is purely additive
- Existing findings route through old logic if missing new fields

**Handling old findings**:
```python
confirmation_level = finding.get("confirmation_level", "probable")  # Default
capability_types = finding.get("capability_types", ["execution"])  # Conservative default

# Old findings (missing these fields) get default routing
# Old logic paths still work
```

### 6.4 InsightActionType Enum

**No breaking changes**:
- New `CONFIRMED_EXPOSURE` action type is additive
- Existing action types unchanged
- Generic fallback handler in `_route_insight_to_handler()` catches unknown types

---

## 7. Deterministic Correctness & Edge Cases

### 7.1 Hypothesis Deduplication

**Problem**: Rule 3 might emit duplicate hypotheses if same finding is processed twice.

**Solution**: Existing `_seen_hypothesis_ids` set (Phase 1) already deduplicates.

```python
hypothesis_id = self._generate_hypothesis_id(
    finding_ids=[finding_id],
    rule_id="rule_information_enablement",
    rule_version=1
)
if hypothesis_id not in self._seen_hypothesis_ids:
    # Emit only once
```

**Test**: Process same finding twice, verify only one hypothesis emitted.

### 7.2 Cross-Target Enablement Edges

**Problem**: Should .git/config on target A enable credentials to unlock target B?

**Design Decision**: NO. Phase 2 limits enablement edges to single-target scope.

**Rationale**:
- Cross-target inference requires correlation rules (future phase)
- Single-target is conservative and avoids false positives
- Reduces graph explosion for multi-target scans

**Implementation guard**:
```python
# In _infer_information_enablement_edges():
if info_finding.get("target") != target_finding.get("target"):
    continue  # Skip cross-target
```

### 7.3 Enablement Edge Cycles

**Problem**: Can information findings create cycles? (e.g., Finding A enables B, B enables A)

**Design**: No cycle risk because enablement edges are uni-directional (info → capability).

**Verification**: CausalGraph already uses `nx.all_simple_paths()` which handles cycles gracefully.

### 7.4 Confidence Boost from Enablement Edges — DEFERRED TO PHASE 3

**Problem**: If an information finding has enablement edges, should its hypothesis confidence increase?

**Phase 2 Design**: NO. NexusContext is graph-agnostic in Phase 2.

Reading graph state from NexusContext creates a bidirectional dependency
(graph ↔ hypotheses) that introduces feedback-loop risk. This was explicitly
removed during plan review.

**Phase 3 Design** (when this is safe to introduce):
  1. Introduce "graph-informed confidence adjustment" as a named concept
  2. Read graph state once (snapshot), don't re-read after hypothesis emission
  3. Test independently of Rule 3
  4. Cap boost at +0.10 to prevent runaway confidence inflation

### 7.5 Missing capability_types Field

**Problem**: What if Phase 1 didn't run, and findings lack capability_types?

**Design**: All checks use `.get("capability_types", ["execution"])` with safe default.

**Verification**:
```python
# This doesn't break:
capability_types = finding.get("capability_types", ["execution"])
if "information" in capability_types:  # Works even if field missing
    ...
```

### 7.6 Base Score Edge Case

**Problem**: Information findings should require base_score >= 5.0 to avoid noise, but what if a critical secret has low score?

**Design**: Minimum of 5.0 is conservative. In Phase 1, credential findings escalate to 9.5 automatically, so this isn't a problem in practice.

**Verification**: Run test with low-score credential finding, verify it gets escalated by Phase 1 content-aware logic.

---

## 8. Test Plan

### Test Suite 1: CausalGraph Enablement Edges

#### Test 1.1: Enablement edges created for confirmed info findings

**Setup**:
1. Create finding F1: .git/config, confirmed, capability_types=["information", "access"], base_score=9.5
2. Create finding F2: SQLi on /login, probable, capability_types=["execution"], base_score=7.0
3. Both findings target example.com

**Execution**:
```python
graph = CausalGraph([F1, F2])
edges = graph.get_attack_chains()
```

**Expected**:
- One enablement edge from F1.id to F2.id
- edge["type"] == "enablement"
- edge["strength"] == 2.0 (DIRECT)
- edge["enablement_class"] == "source_code" (inferred from F1 type)

#### Test 1.2: Cross-target enablement edges NOT created

**Setup**:
1. Finding F1: credentials on target A
2. Finding F2: login endpoint on target B

**Execution**:
```python
edges = graph._infer_information_enablement_edges([F1, F2])
```

**Expected**:
- No edges created (cross-target blocked)

#### Test 1.3: Weak findings don't create edges

**Setup**:
1. Finding F1: .git/config, hypothesized (not confirmed), base_score=9.5

**Execution**:
```python
edges = graph._infer_information_enablement_edges([F1, ...])
```

**Expected**:
- No edges from F1 (precondition: confirmation_level != "confirmed")

### Test Suite 2: NexusContext Information Enablement Rule

#### Test 2.1: Rule 3 fires for confirmed info findings

**Setup**:
1. Finding F1: API key leak, confirmed, base_score=9.5
2. Finding F2: Generic port scan, probable, base_score=3.0

**Execution**:
```python
context = NexusContext([F1, F2])
context.synthesize_attack_paths()
```

**Expected**:
- One NEXUS_HYPOTHESIS_FORMED event emitted for F1
- confidence = 0.95 (from INFORMATION_HYPOTHESIS_CONFIDENCE["credential_exposure"])
- explanation contains "enables" language (not just "found")
- F2 generates no hypothesis (base_score < 5.0)

#### Test 2.2: Rule 3 doesn't fire for hypothesized findings

**Setup**:
1. Finding F1: SSRF indicator, hypothesized, base_score=9.2

**Execution**:
```python
context = NexusContext([F1])
context.synthesize_attack_paths()
```

**Expected**:
- No Rule 3 event for F1 (precondition failed)
- Rule 2 (critical isolated) may still fire if base_score >= 7.0

#### Test 2.3: Hypothesis deduplication works

**Setup**:
1. Finding F1: credentials, confirmed, base_score=9.5
2. Process findings twice (simulate replay)

**Execution**:
```python
context = NexusContext([F1])
context.synthesize_attack_paths()
# Later, reprocess same findings
context.synthesize_attack_paths()
```

**Expected**:
- Only ONE NEXUS_HYPOTHESIS_FORMED event total
- Deduplication via `_seen_hypothesis_ids`

### Test Suite 3: Strategos Insight Routing

#### Test 3.1: CONFIRMED + access → CONFIRMED_EXPOSURE action

**Setup**:
1. Finding F1: API key, confirmed, capability_types=["access"], base_score=9.5

**Execution**:
```python
insight = strategos._generate_insights_from_finding(F1)
```

**Expected**:
- insight.action_type == InsightActionType.CONFIRMED_EXPOSURE
- insight.confidence == 0.95
- insight.priority == 0

#### Test 3.2: HYPOTHESIZED deprioritized by +2

**Setup**:
1. Finding F1: SSRF indicator, hypothesized, capability_types=["execution"], base_score=9.2

**Execution**:
```python
insight = strategos._generate_insights_from_finding(F1)
```

**Expected**:
- insight.action_type == InsightActionType.CONFIRMED_VULN
- insight.priority == 2 (hypothesized adjustment)
- insight.confidence == 0.40 (hypothesized multiplier)

#### Test 3.3: CONFIRMED_EXPOSURE handler triggers

**Setup**:
1. Create insight with action_type=CONFIRMED_EXPOSURE
2. Set up mock event bus and context

**Execution**:
```python
strategos._route_insight_to_handler(insight)
```

**Expected**:
- _handle_confirmed_exposure() called
- "confirmed_exposures" list updated in context.knowledge
- Event emitted to _event_bus

### Test Suite 4: End-to-End Scenario (Scenario A from Design Proposal)

**Title**: .git/config with AWS credentials outranks speculative SSRF

**Setup**:
1. Record httpx observation with .git/config content (includes aws_access_key_id=AKIA...)
2. Create Finding F1: BACKUP_EXPOSURE, source="httpx", severity=CRITICAL
3. Promote F1 in Ledger → confirmation_level=CONFIRMED (tool source)
4. Record ai observation with localhost in URL
5. Create Finding F2: SSRF_CHAIN, source="ai", severity=CRITICAL
6. Promote F2 in Ledger → confirmation_level=HYPOTHESIZED (ai source)
7. Apply VulnRules
8. Build CausalGraph
9. Synthesize NexusContext hypotheses
10. Generate Strategos insights

**Expected Results**:

| Component | F1 (.git/config) | F2 (SSRF) |
|-----------|-----------------|-----------|
| Phase 1: VulnRule.apply() | score=9.5×1.0=9.5 | score=9.2×0.4=3.68 |
| RiskEngine: asset-level | 10×1.0=10.0 | 10×0.4=4.0 |
| CausalGraph edges | enablement edges created | no enablement (source) |
| NexusContext Rule 3 | hypothesis emitted (conf=0.95) | no hypothesis (not info) |
| Strategos routing | CONFIRMED_EXPOSURE, priority=0 | CONFIRMED_VULN, priority=2 |
| OMEGA pillar contribution | HIGH (confirmed weight) | LOW (hypothesized weight) |
| **Final ranking** | **Higher** | **Lower** |

---

## 9. Edge Cases and Risk Mitigation

### 9.1 Information Finding Without Enablement Edges

**Scenario**: Confirmed .git/config with no auth-gated findings on same target.

**Current Behavior**:
- Finding still generates NEXUS hypothesis (Rule 3 doesn't require edges)
- Hypothesis confidence is from INFORMATION_HYPOTHESIS_CONFIDENCE mapping
- No enablement edges created (no targets to enable)

**Risk**: Might prioritize information finding higher than deserved if it truly unlocks nothing.

**Mitigation**: By design. Confirmed information has inherent value even without edges. In attacker reality, .git/config is valuable for code review regardless of what endpoints are present.

### 9.2 False Positive Enablement Edges

**Scenario**: Topology disclosure (internal IPs) creates edges to unrelated findings.

**Current Behavior**:
- _would_benefit_from() heuristic checks target tags (ssrf, cloud, etc.)
- Generic information findings (WEAK strength 0.5) match broadly

**Risk**: Graph becomes noisy with low-weight edges.

**Mitigation**:
1. WEAK edges (0.5 strength) have minimal impact on centrality
2. Test heuristics heavily
3. Require confirmation_level=CONFIRMED (no speculative edges)

### 9.3 Hypothesis Confidence Inflation

**Scenario**: Too many hypotheses at 0.95 confidence dilutes the signal.

**Current Behavior**:
- Rule 3 only fires for confirmed findings (already filtered by Phase 1)
- base_score >= 5.0 gate prevents low-impact noise
- _confidence_for_information_finding() maps conservatively

**Mitigation**:
1. Phase 1 content-aware scoring only escalates to 9.5 when credentials present
2. Generic backups stay at 7.7 (don't trigger Rule 3 unless found to contain credentials)
3. Test with real tool output

### 9.4 Missing confirmation_level on Old Findings

**Scenario**: Pre-Phase-1 findings in database lack confirmation_level field.

**Current Behavior**:
- All checks use `.get("confirmation_level", "probable")` default
- Old findings treated as PROBABLE (conservative)
- Old findings missing capability_types get `["execution"]` default
- No crashes

**Mitigation**:
1. Ledger migration: If reading old findings from DB, backfill confirmation_level=PROBABLE
2. VulnRule output: Always include both fields in enriched dict
3. Test with mixed old/new findings

---

## 10. Execution Order and Dependency Graph

**Critical Path** (sequential dependencies):

1. **Step 3.1 (CausalGraph enablement edges)** — No dependencies
   - Effort: 3-4 days
   - Creates infrastructure for NexusContext to read

2. **Step 3.2 (NexusContext Rule 3)** — Depends on Step 3.1 (optional)
   - Effort: 2-3 days
   - Can be done in parallel with Step 3.1 (Rule 3 doesn't require edges)

3. **Step 3.3 (Strategos routing)** — Depends on Steps 3.1 and 3.2 (optional)
   - Effort: 1-2 days
   - Reading from Phase 1 fields, no hard dependency on 3.1/3.2
   - Works with or without them

**Parallel Tasks**:
- Steps 3.1 and 3.2 can be implemented in parallel
- Step 3.3 can start after Phase 1 is verified

**Total Effort**: 6-9 days (with parallelization)

---

## 11. Per-Change Tradeoff Analysis

### Change 3: NexusContext Information Enablement Rule

| Aspect | Assessment |
|--------|-----------|
| **Complexity** | LOW-MEDIUM. Simple rule logic, reuses existing _emit_hypothesis_event(). |
| **Value** | HIGH. Confirmed information findings now generate hypotheses (fixes major gap). |
| **Risk** | LOW. Opt-in via confirmation_level check. Old data unaffected. |
| **Testing** | MEDIUM. 3-4 test cases needed. |
| **Future-proof** | HIGH. Confidence mapping is extensible. |
| **Tradeoff** | Value >> Complexity. Worth doing. |

### Change 4: CausalGraph Enablement Edges

| Aspect | Assessment |
|--------|-----------|
| **Complexity** | MEDIUM. Requires heuristic matching for _would_benefit_from(). |
| **Value** | HIGH. Graph centrality now reflects information value (fixes ranking). |
| **Risk** | MEDIUM. Heuristics could create false-positive edges. Mitigated by base_score gate + confirmation check. |
| **Testing** | HIGH. 5-6 test cases + validation with real scans. |
| **Future-proof** | HIGH. Edge weights are tunable, enablement_class is extensible. |
| **Tradeoff** | Value >> Complexity (with care on heuristics). Worth doing. |

### Change 6: Strategos Unified Insight Routing

| Aspect | Assessment |
|--------|-----------|
| **Complexity** | LOW-MEDIUM. Mostly refactoring existing _generate_insights_from_finding(). |
| **Value** | MEDIUM-HIGH. Confirmed access findings get special handling, hypothesized findings deprioritized. |
| **Risk** | LOW. New action type is additive, old code path still works. |
| **Testing** | MEDIUM. 5-6 test cases for routing logic. |
| **Future-proof** | HIGH. New action type is easily extensible. |
| **Tradeoff** | Value >> Complexity. Worth doing, can defer if needed. |

---

## 12. Files Modified (Summary)

| File | Changes | Type | Effort |
|------|---------|------|--------|
| `core/cortex/causal_graph.py` | Add EnablementStrength enum, EFFORT_ELIMINATED, _infer_information_enablement_edges(), _classify_enablement(), _enablement_strength(), _would_benefit_from(), integrate into _infer_dependencies() | Additive | 3-4 days |
| `core/cortex/nexus_context.py` | Add INFORMATION_HYPOTHESIS_CONFIDENCE, Rule 3 in synthesize_attack_paths(), _confidence_for_information_finding(), _enablement_explanation(), extend _emit_hypothesis_event() | Additive | 2-3 days |
| `core/scheduler/strategos.py` | Update _generate_insights_from_finding() routing logic, add _handle_confirmed_exposure(), update _route_insight_to_handler() | Modificative | 1-2 days |
| `core/contracts/schemas.py` | Add CONFIRMED_EXPOSURE to InsightActionType enum | Additive | 0.5 days |

**Total Implementation Effort**: 6-10 days (with parallelization: 4-6 days)

---

## 13. Success Criteria

### 13.1 Functional Criteria

- [ ] CausalGraph creates enablement edges for confirmed info/access findings
- [ ] Enablement edges weight correctly (2.0 for credentials, 1.0 for topology, 0.5 for generic)
- [ ] NexusContext Rule 3 emits hypotheses for confirmed info findings (only once per finding)
- [ ] Strategos routes CONFIRMED + access findings to CONFIRMED_EXPOSURE action
- [ ] Strategos deprioritizes HYPOTHESIZED findings by +2 priority
- [ ] Scenario A test passes: .git/config ranks higher than speculative SSRF

### 13.2 Backward Compatibility Criteria

- [ ] No existing tests fail
- [ ] Old findings (without Phase 1 fields) still process correctly
- [ ] Existing graph consumers still work (don't break on new edge fields)
- [ ] No database migration required (Phase 1 handled this)

### 13.3 Performance Criteria

- [ ] CausalGraph._infer_information_enablement_edges() completes in < 100ms for 1000 findings
- [ ] NexusContext Rule 3 synthesis completes in < 50ms for 100 info findings
- [ ] Strategos insight routing adds < 5ms per finding

---

## 14. Open Questions for Implementation

1. **Confidence boost from enablement edges**: DEFERRED TO PHASE 3. NexusContext is graph-agnostic in Phase 2. Graph-informed confidence adjustment will be introduced as a named concept in Phase 3 with independent testing.

2. **Cross-target correlation**: NO for Phase 2. Single-target only. Defer to future correlation rule phase.

3. **Visualization of enablement edges**: YES, in post-Phase-2 UI work. Expose enablement_score separately from centrality_score.

4. **EFFORT_ELIMINATED calibration**: Hardcode for Phase 2. Expose as YAML config in Phase 3.

5. **Rule 3 confidence tie-in to graph**: DEFERRED TO PHASE 3. Explicitly removed during plan review to prevent bidirectional NexusContext ↔ CausalGraph dependency.

