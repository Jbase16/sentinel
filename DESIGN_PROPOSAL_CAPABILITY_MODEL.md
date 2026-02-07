# Design Proposal: Unified Attacker Capability Model for SentinelForge

**Author**: Senior Security Systems Architect
**Status**: PLANNING ONLY — No Code
**Date**: 2026-02-06
**Prerequisite Reading**: `PRIORITIZATION_AUDIT.md`

---

## 1. Conceptual Model: Attacker Capabilities

### 1.1 The Core Problem with the Current Model

SentinelForge's reasoning system implicitly partitions findings into two categories:

- **Exploit primitives** (SSRF, SQLi, RCE): Treated as active threats. They chain, they form graph edges, they dominate NEXUS scoring (50% of OMEGA), and they generate hypothesis events in NexusContext.
- **Information primitives** (.git/config, leaked credentials, internal topology): Treated as passive observations. They sit as terminal nodes in the CausalGraph, qualify only for the CRONUS pillar (20% of OMEGA), and never generate hypothesis events unless pre-tagged HIGH/CRITICAL.

This partition is wrong. In attacker reality, information IS capability. An exposed .git/config containing database credentials eliminates more attacker effort than a speculative SSRF indicator. The system needs a unified model.

### 1.2 Unified Model: "Attacker Capability"

**Definition**: An *Attacker Capability* is any finding that changes what an attacker can do, know, or reach. It is the atomic unit of attacker advantage.

Every finding — exploit or information — is modeled as a Capability with three orthogonal dimensions:

| Dimension | Definition | Examples |
|-----------|-----------|---------|
| **Type** | What kind of advantage does this grant? | `execution`, `information`, `access`, `evasion` |
| **Confirmation** | How certain are we this capability exists? | `confirmed` (tool-verified), `probable` (correlated), `hypothesized` (AI-speculated) |
| **Leverage** | What does this enable the attacker to do next? | Enables auth bypass, enables lateral movement, enables targeted exploitation |

The key insight: **Leverage is not exclusive to execution capabilities.** Information capabilities have leverage too:

- `.git/config` with AWS keys → enables authenticated cloud access (HIGH leverage)
- `.git/config` with repo structure → enables targeted code review (MEDIUM leverage)
- Internal IP disclosure → enables SSRF targeting (MEDIUM leverage)
- Speculative SSRF indicator → enables *potential* cloud metadata access (leverage CONDITIONAL on confirmation)

### 1.3 Capability Type Taxonomy

Replace the implicit exploit-vs-information split with an explicit four-type taxonomy:

| Capability Type | Definition | Current Examples | Attacker Value |
|----------------|-----------|-----------------|---------------|
| **Execution** | Ability to run arbitrary or constrained commands/queries on a target | RCE, SQLi, SSRF, XSS | Varies by scope and confirmation |
| **Information** | Knowledge that reduces attacker uncertainty or effort | .git/config, source code, error messages with stack traces, internal IPs | Varies by content sensitivity |
| **Access** | Ability to authenticate or reach otherwise-restricted resources | Leaked credentials, session tokens, exposed admin panels, open management ports | Typically HIGH — direct access bypass |
| **Evasion** | Ability to avoid detection or bypass controls | WAF bypass technique, rate-limit gap, timing side-channel | Force multiplier on other capabilities |

These types are NOT mutually exclusive. A finding can grant multiple capability types. Example: `.git/config` with database credentials is both `Information` (source code structure) AND `Access` (database credentials).

### 1.4 The Enablement Graph (Replacing "Chain-Only" Thinking)

The current CausalGraph only models exploit chains: `port → service → vulnerability`. Information findings are dead ends.

**Proposed change**: Model *enablement relationships* between capabilities, regardless of type.

An enablement edge means: "Capability A makes Capability B cheaper, faster, or more likely to succeed."

Examples the current system cannot model:

```
.git/config (Information) ──enables──> authenticated API access (Access)
.git/config (Information) ──enables──> targeted SQLi on known endpoints (Execution)
internal IP (Information) ──enables──> SSRF to specific service (Execution)
admin panel (Access) ──enables──> RCE via admin shell (Execution)
WAF bypass (Evasion) ──enables──> SQLi succeeds undetected (Execution)
```

This is strictly additive to the existing chain model. Existing `recon → service → vuln` edges remain valid. We're adding a new edge type: `information ──enables──> *`.

### 1.5 How This Resolves the .git/config vs SSRF Problem

Under the current model:
- SSRF: chains from port → service → ssrf → cloud metadata. High centrality, NEXUS-dominant.
- .git/config: terminal node. Zero centrality, CRONUS-only.

Under the proposed model:
- SSRF (hypothesized): Execution capability, confirmation=`hypothesized`, leverage=conditional on validation. Chains exist but are speculative.
- .git/config with credentials (confirmed): Information+Access capability, confirmation=`confirmed`, leverage=HIGH (enables authenticated access, targeted exploitation). Enablement edges to multiple downstream capabilities.

The confirmed .git/config now has:
1. Higher confirmation weight (tool-verified vs AI-speculated)
2. Non-zero graph centrality (enablement edges exist)
3. Multi-type scoring (Information + Access)
4. Concrete leverage (credentials = immediate access)

No severity numbers were "boosted." The model simply represents reality more accurately.

---

## 2. Minimum Architectural Changes

Six subsystems need modification. I've ordered them by dependency (upstream first) and marked each as either **additive** (new code alongside existing) or **modificative** (changes existing behavior).

### Change 1: EvidenceLedger — Add Confirmation Provenance [ADDITIVE]

**Subsystem**: `core/epistemic/ledger.py`
**What changes**: The `FindingProposal` and `Finding` dataclasses gain a `confirmation_level` field. The `evaluate_and_promote()` method sets this field based on source provenance.

**Current state**: `FindingProposal` has `source: str` (set to "ai" or "heuristic") and `citations: List[Citation]`. But `evaluate_and_promote()` only checks whether citations exist — it doesn't score the quality of evidence or tag the resulting Finding with how it was confirmed.

**Proposed addition**:
- New enum `ConfirmationLevel`: `CONFIRMED`, `PROBABLE`, `HYPOTHESIZED`
- `evaluate_and_promote()` derives `confirmation_level` from:
  - Source is a tool + citations reference specific observation → `CONFIRMED`
  - Source is a correlation rule with multiple supporting findings → `PROBABLE`
  - Source is "ai" or "heuristic" with no direct observation → `HYPOTHESIZED`
- The `Finding` dataclass carries `confirmation_level` forward into all downstream consumers.

**What incorrect assumption this fixes**: The Ledger currently treats "has a citation" as binary proof of validity. In reality, an AI that cites its own observation ID is self-referential — it's not the same as a tool that cites raw HTTP response data.

**Why it aligns with bug bounty reasoning**: Bug bounty hunters distinguish "I see this in Burp" (confirmed) from "the AI thinks this might be vulnerable" (hypothesis). Triage teams discount unverified reports.

**New failure modes**:
- If tool-generated proposals don't properly populate `source`, they could be misclassified as HYPOTHESIZED. **Mitigation**: Default to PROBABLE (not HYPOTHESIZED) when source is ambiguous, and log a warning.
- Over-reliance on `source` string matching. **Mitigation**: Use an explicit `ToolContext` reference rather than string matching. The Ledger already has `ToolContext` — use it.

### Change 2: VulnRules — Add Capability Type and Content-Aware Scoring [MODIFICATIVE]

**Subsystem**: `core/toolkit/vuln_rules.py`
**What changes**: The `VulnRule` dataclass gains a `capability_types: List[str]` field. Matchers that handle information-type findings (backup, secret, config) gain content inspection logic to escalate severity based on what was actually exposed.

**Current state**: `VulnRule` has `severity`, `base_score`, and a `matcher` function that returns an optional dict. The `BACKUP_EXPOSURE` rule returns a flat HIGH/7.7 regardless of content. The `_match_backup_rule` does a simple tag check on "backup-leak."

**Proposed changes**:
- Add `capability_types` to `VulnRule` dataclass (default: `["execution"]` for backward compatibility).
- SSRF_CHAIN gets `capability_types=["execution"]`
- BACKUP_EXPOSURE gets `capability_types=["information", "access"]`
- SECRET_LEAK gets `capability_types=["access"]`
- `_match_backup_rule()` inspects finding content (`value`, `technical_details`) for credential indicators, internal URLs, and code patterns. Returns escalated severity/score when high-value content is detected.
- Matcher return dicts gain an optional `leverage_description` field explaining what the finding enables.

**What incorrect assumption this fixes**: The current rules assume severity is a function of finding *type* alone. In reality, severity of information findings is a function of *content*. Two .git/config exposures can have radically different attacker value.

**Why it aligns with bug bounty reasoning**: A bounty hunter who finds .git/config with plaintext AWS keys submits a CRITICAL report. One who finds .git/config with just a repo name submits LOW/informational. Same finding type, different content, different severity.

**New failure modes**:
- Content inspection adds regex/string matching that could false-positive on benign content. **Mitigation**: Use a conservative allowlist of credential indicators (aws_access_key, password=, private_key, etc.) rather than broad pattern matching.
- Content may not be available in the finding dict at rule evaluation time (if the tool output was truncated or summarized). **Mitigation**: Fall back to existing flat scoring when content fields are empty. This is no worse than current behavior.

### Change 3: NexusContext — Add Information Enablement Synthesis Rule [ADDITIVE]

**Subsystem**: `core/cortex/nexus_context.py`
**What changes**: Add a third synthesis rule alongside the existing two (web_exposure_chain, critical_isolated). The new rule synthesizes hypotheses for confirmed information/access capabilities.

**Current state**: `synthesize_attack_paths()` has exactly two rules:
1. `rule_web_exposure_chain`: Matches `open_port × web_vuln` combinations.
2. `rule_critical_isolated`: Matches HIGH/CRITICAL findings in isolation.

Information findings only reach Rule 2, and only if already tagged HIGH/CRITICAL by VulnRules. They never generate hypothesis events otherwise.

**Proposed addition**:
- **Rule 3** (`rule_information_enablement`): Matches any finding with `capability_types` containing "information" or "access" AND `confirmation_level` = CONFIRMED.
- Emits `NEXUS_HYPOTHESIS_FORMED` with confidence derived from content sensitivity:
  - Credential exposure: confidence 0.95
  - Source code / config with secrets: confidence 0.90
  - Internal topology / architecture: confidence 0.80
  - Generic backup/config: confidence 0.70
- The hypothesis explanation describes *what the information enables*, not just what was found.

**What incorrect assumption this fixes**: NexusContext assumes only chain-forming findings are worth synthesizing into hypotheses. Information findings that don't chain (in the exploit sense) are ignored, even when they represent immediate attacker advantage.

**Why it aligns with bug bounty reasoning**: A bug bounty hunter who discovers leaked credentials doesn't think "this doesn't chain to anything, so it's low priority." They think "this IS the chain — credentials → access → game over."

**New failure modes**:
- Over-emission of hypotheses for low-value information findings (e.g., generic tech stack disclosure). **Mitigation**: Gate on `confirmation_level=CONFIRMED` AND `base_score >= 5.0`. This prevents INFO-level findings from generating noise.
- Hypothesis deduplication may not cover the new rule's ID space. **Mitigation**: The existing `_generate_hypothesis_id()` uses SHA256 of finding_ids + rule_id + rule_version. As long as the new rule has a unique rule_id, deduplication works automatically.

### Change 4: CausalGraph — Add Enablement Edges [ADDITIVE]

**Subsystem**: `core/cortex/causal_graph.py`
**What changes**: `_infer_dependencies()` gains a new heuristic (Rule 5) that creates edges FROM information/access findings TO the capabilities they enable.

**Current state**: `_infer_dependencies()` has four rules, all modeling the `recon → service → vulnerability` chain. Information findings match none of the vulnerability keywords (`vuln`, `injection`, `xss`, `rce`, `exploit`), so they get zero inbound or outbound edges and zero centrality.

**Proposed addition**:
- **Rule 5** (`information_enablement`): For findings with `capability_types` containing "information" or "access":
  - Create outbound edges to findings on the same target that could benefit from the exposed information.
  - Example: .git/config (with credentials) → edges to all authentication-related findings on same target.
  - Example: internal IP disclosure → edges to SSRF findings (the SSRF now has a concrete target).
- Edge weight reflects the enablement strength:
  - Credential exposure → auth-gated resources: weight 2.0 (direct enablement)
  - Topology exposure → targeted exploitation: weight 1.0 (indirect enablement)
  - Generic config → general knowledge: weight 0.5 (weak enablement)

**What incorrect assumption this fixes**: The CausalGraph assumes dependencies only flow along the `recon → service → exploit` axis. This makes graph centrality a proxy for "how many exploit chains pass through this node" rather than "how much attacker advantage does this node represent."

**Why it aligns with bug bounty reasoning**: An attacker who finds credentials doesn't see a dead end — they see a shortcut that bypasses entire attack chains. The graph should reflect that `.git/config` with keys *enables* everything behind auth, which is often more findings than any single SSRF enables.

**New failure modes**:
- Overly aggressive edge creation could inflate centrality of low-value information findings. **Mitigation**: Only create enablement edges when (a) the source finding is CONFIRMED and (b) the target finding is on the same target/asset. Cross-target enablement edges should require explicit correlation rule support, not heuristic inference.
- Graph cycle risk: if an information finding enables a vuln that enables an information finding. **Mitigation**: The existing `get_attack_chains()` uses `nx.all_simple_paths()` which already handles cycle avoidance. No change needed.

### Change 5: OMEGA Risk Calculator — Confirmation-Weighted Scoring [MODIFICATIVE]

**Subsystem**: `core/omega/risk_calculator.py`
**What changes**: Introduce a confirmation multiplier that applies to all pillar scores, so confirmed findings contribute more to the final OMEGA score than hypothesized ones.

**Current state**: OMEGA weights are static: CRONUS 0.20, MIMIC 0.30, NEXUS 0.50. There is no mechanism to discount speculative findings or boost confirmed ones. A hypothesized SSRF and a confirmed SSRF contribute identically to NEXUS.

**Proposed change**:
- Keep the 3-pillar structure and keep NEXUS at high weight (exploitability SHOULD matter — the issue is that speculation shouldn't count the same as confirmation).
- Apply a **confirmation multiplier** to individual finding contributions before pillar aggregation:
  - CONFIRMED: 1.0x (full weight)
  - PROBABLE: 0.7x
  - HYPOTHESIZED: 0.4x
- This is applied at the finding level, not the pillar level. A pillar can have a mix of confirmed and hypothesized findings.

**Adjusted weights** (minor rebalance):
- CRONUS: 0.25 (was 0.20) — exposure matters more than the current weights suggest
- MIMIC: 0.25 (was 0.30) — slight reduction; latent code risk is less actionable
- NEXUS: 0.50 (unchanged) — exploitability should be top-weighted

Net effect: A confirmed .git/config scores `base_score × 1.0 × 0.25` through CRONUS. A hypothesized SSRF scores `base_score × 0.4 × 0.50`. If .git/config's content-escalated base_score is 9.5 and SSRF's base_score is 9.2:
- .git/config effective: 9.5 × 1.0 × 0.25 = 2.375
- SSRF effective: 9.2 × 0.4 × 0.50 = 1.840

The confirmed finding now outscores the speculative one. If the SSRF gets confirmed by a tool later, it jumps to 9.2 × 1.0 × 0.50 = 4.60 — correctly outscoring a config leak. This is exactly the behavior we want.

**What incorrect assumption this fixes**: The current OMEGA calculator treats all findings equally regardless of evidence quality. This means the system's risk assessment doesn't reflect the actual certainty of the threat — a fundamental violation of epistemic rigor.

**Why it aligns with bug bounty reasoning**: Triage teams weight confirmed, reproducible reports higher than theoretical ones. A P1 with PoC beats a P2 without one. The scoring should reflect this.

**New failure modes**:
- If most findings in a scan are AI-generated (e.g., during Ghost proxy interception), the overall OMEGA score could be artificially depressed. **Mitigation**: The existing fallback behavior (when NEXUS doesn't fire, redistribute to CRONUS 40% / MIMIC 60%) already handles low-finding scenarios. Additionally, the `HYPOTHESIZED` multiplier (0.4) still contributes meaningful signal — it doesn't zero out.
- Gaming: A tool that marks all its output as "confirmed" would inflate scores. **Mitigation**: Confirmation is derived from the Ledger's provenance chain, not self-reported by tools. The Ledger validates citations exist and reference real observations.

### Change 6: Strategos — Unify Insight Action Types [MODIFICATIVE]

**Subsystem**: `core/scheduler/strategos.py`
**What changes**: `_generate_insights_from_finding()` stops treating information findings as a fundamentally different category from vulnerability findings.

**Current state**: The method maps:
- `"git_exposure"` → `InsightActionType.HIGH_VALUE_TARGET` (confidence 0.9, priority 0)
- `"ssrf"` → `InsightActionType.CONFIRMED_VULN` (confidence 0.8, priority 0)

Both get priority 0, but different action types route to different handlers. `HIGH_VALUE_TARGET` feeds into asset-inventory logic; `CONFIRMED_VULN` feeds into vulnerability-exploitation logic. This means .git/config never triggers the vuln-exploitation handler, even when it contains credentials that are themselves a vulnerability.

**Proposed change**:
- Add `InsightActionType.CONFIRMED_EXPOSURE` — a new action type for confirmed information/access capabilities.
- `_generate_insights_from_finding()` checks `capability_types` from the enriched finding:
  - If capability includes "access" AND confirmation is CONFIRMED → `CONFIRMED_EXPOSURE` (priority 0, confidence 0.95)
  - If capability is "information" only AND confirmation is CONFIRMED → `HIGH_VALUE_TARGET` (priority 0, confidence 0.9) — unchanged
  - If capability includes "execution" AND confirmation is CONFIRMED → `CONFIRMED_VULN` (priority 0, confidence 0.85) — unchanged
  - If confirmation is HYPOTHESIZED → deprioritize by +2 (priority 2 instead of 0)
- Add a `_handle_confirmed_exposure()` method that triggers both asset-inventory AND vulnerability-response logic.

**What incorrect assumption this fixes**: The current system assumes that findings divide cleanly into "assets to inventory" and "vulnerabilities to exploit." Exposed credentials are both — they're an asset discovery AND a vulnerability.

**Why it aligns with bug bounty reasoning**: When a bug bounty hunter finds leaked credentials, they don't file it under "interesting recon." They escalate it as a finding that directly enables account takeover. The scheduler should reflect this urgency.

**New failure modes**:
- Adding a new InsightActionType requires a new handler. If the handler isn't implemented, insights queue up and get processed by the generic fallback handler. **Mitigation**: The existing `_route_insight_to_handler()` already has a fallback for unknown action types. The new handler is additive.
- Hypothesized findings getting deprioritized by +2 could delay valid AI insights when tool confirmation is slow. **Mitigation**: Priority 2 is still processed — it's just after priority 0 and 1. The circuit breaker and backoff logic in InsightQueue already handle processing delays gracefully.

---

## 3. Distinguishing Speculative vs. Confirmed, AI vs. Tool, Execution vs. Information

### 3.1 Confirmation Level (Speculative vs. Confirmed)

**Where it's set**: `EvidenceLedger.evaluate_and_promote()` (Change 1)

**How it propagates**: The `Finding` dataclass carries `confirmation_level` as a first-class field. All downstream consumers (VulnRules, NexusContext, CausalGraph, OMEGA, Strategos) can read it without additional lookups.

**Decision logic**:

```
if finding.source in known_tool_sources AND finding.citations reference raw observations:
    confirmation_level = CONFIRMED
elif finding has multiple independent citations OR comes from correlation rule:
    confirmation_level = PROBABLE
else:
    confirmation_level = HYPOTHESIZED
```

**Why not just use confidence?** The CAL system already has a `confidence` field on Evidence and Claims. But confidence is a continuous value used for Bayesian convergence — it's meant to change over time as evidence accumulates. `confirmation_level` is a discrete classification of the *evidence quality at promotion time*. They serve different purposes:

- `confidence` = "how sure are we this is true?" (dynamic, converges)
- `confirmation_level` = "what kind of evidence backs this up?" (static at promotion, describes provenance)

### 3.2 Source Authority (AI vs. Tool)

**Where it's set**: Already present in `FindingProposal.source` ("ai", "heuristic", tool name) and `Evidence.provenance.source` ("StrategyEngine:AI", "GhostProxy", tool name).

**What's missing**: These source fields are set but never *used* for authority differentiation. No downstream consumer checks them.

**Proposed change**: `confirmation_level` (from 3.1) implicitly encodes source authority:
- Tool sources with valid observation citations → CONFIRMED
- AI sources with self-referential citations → HYPOTHESIZED
- Heuristic sources with partial evidence → PROBABLE

This avoids creating a separate "authority" dimension. Authority is a factor in determining confirmation, not a separate scoring axis. This keeps the model simpler and avoids double-counting (penalizing AI findings for being AI AND for being unconfirmed — they're the same thing).

**Exception**: When an AI hypothesis is later validated by a tool (e.g., AI says "might be SSRF," Wraith confirms it), the finding should be re-promoted with `confirmation_level=CONFIRMED`. This happens naturally through the CAL convergence mechanism — supporting evidence from a tool triggers `_check_convergence()`, which can flip the Claim to VALIDATED status.

### 3.3 Capability Type (Execution vs. Information)

**Where it's set**: `VulnRule.capability_types` (Change 2)

**How it propagates**: When `apply_rules()` enriches a finding, the resulting issue dict includes `capability_types`. This flows into NexusContext (for synthesis rule selection), CausalGraph (for edge inference), and Strategos (for insight routing).

**Why on VulnRule and not on Finding?** Because capability type is a property of the *interpreted finding* (the enriched issue), not the raw finding. The same raw tool output might be classified as different capability types depending on which VulnRule matches it. Putting it on VulnRule means the classification logic is centralized and auditable.

---

## 4. Attacker-Realistic Ranking Mechanism

### 4.1 Three Ranking Dimensions

The current system ranks by a single axis: severity score (base_score × OMEGA weights). The proposed system ranks on three axes that reflect attacker decision-making:

| Dimension | Question It Answers | How It's Computed |
|-----------|-------------------|------------------|
| **Time-to-Impact** | How quickly can an attacker leverage this? | Derived from capability type + confirmation level. Confirmed access capabilities = fastest. Hypothesized execution capabilities = slowest (need validation + exploitation). |
| **Uncertainty Reduction** | How much does this finding reduce the attacker's unknowns? | Derived from enablement edge count in CausalGraph. More outbound enablement edges = more uncertainty eliminated. |
| **Effort Eliminated** | How much work does the attacker skip? | Derived from what the finding replaces. Credentials skip auth brute-forcing. Source code skips black-box fuzzing. Computed as the sum of "replaced effort" weights on enablement edges. |

### 4.2 Composite Priority Score

Each finding gets a `priority_score` computed as:

```
priority_score = (
    w_time * time_to_impact_score +
    w_uncertainty * uncertainty_reduction_score +
    w_effort * effort_eliminated_score
) * confirmation_multiplier
```

**Proposed weights**:
- `w_time` = 0.40 (immediacy matters most — an attacker always exploits the fastest path)
- `w_uncertainty` = 0.30 (reducing unknowns accelerates the entire kill chain)
- `w_effort` = 0.30 (effort elimination is a direct cost saving)

**Confirmation multiplier** (same as Change 5):
- CONFIRMED: 1.0
- PROBABLE: 0.7
- HYPOTHESIZED: 0.4

### 4.3 Time-to-Impact Scoring

| Capability Type + Confirmation | Time-to-Impact Score (0-10) | Rationale |
|-------------------------------|---------------------------|-----------|
| Confirmed Access (credentials, sessions) | 10.0 | Immediate use. No exploitation needed. |
| Confirmed Execution (validated RCE, SQLi) | 9.0 | Requires payload delivery but confirmed. |
| Confirmed Information (secrets, source code) | 8.0 | Requires analysis but data is in hand. |
| Probable Execution (correlated chain) | 6.0 | Likely exploitable but not validated. |
| Probable Information (config exposure, no secrets) | 5.0 | Useful but requires further investigation. |
| Hypothesized Execution (AI-suggested SSRF) | 3.0 | Requires validation, then exploitation. Two steps away. |
| Hypothesized Information (inferred topology) | 2.0 | Uncertain and requires investigation. |

### 4.4 Uncertainty Reduction Scoring

Derived from the CausalGraph:

```
uncertainty_reduction = min(10.0, outbound_enablement_edges * 2.0 + enablement_weight_sum * 1.5)
```

This naturally rewards findings that unlock multiple downstream capabilities. A .git/config with credentials that enables auth bypass across 5 endpoints scores `min(10.0, 5 * 2.0 + 10.0 * 1.5)` = 10.0. A speculative SSRF with no confirmed enablement targets scores `min(10.0, 0 * 2.0 + 0)` = 0.0.

### 4.5 Effort Eliminated Scoring

Predefined "effort replacement" values based on what the finding makes unnecessary:

| What the Finding Replaces | Effort Score |
|--------------------------|-------------|
| Authentication brute-forcing (credentials found) | 9.0 |
| Black-box endpoint discovery (source code found) | 8.0 |
| Network mapping (internal topology found) | 7.0 |
| Fuzzing for injection points (confirmed injection) | 6.0 |
| Technology fingerprinting (stack disclosure) | 4.0 |
| Port scanning (known services) | 3.0 |
| Generic reconnaissance (partial info) | 2.0 |

These values are set on the enablement edges in the CausalGraph and summed for the finding.

### 4.6 Worked Example: .git/config vs Speculative SSRF

**.git/config with AWS credentials (CONFIRMED)**:
- Time-to-impact: 10.0 (confirmed access capability)
- Uncertainty reduction: 8.0 (enables auth to cloud, enables targeted exploitation of known endpoints)
- Effort eliminated: 9.0 (replaces credential brute-forcing and cloud enumeration)
- Confirmation multiplier: 1.0
- **Priority score**: (0.40 × 10.0 + 0.30 × 8.0 + 0.30 × 9.0) × 1.0 = **9.10**

**Speculative SSRF indicator (HYPOTHESIZED)**:
- Time-to-impact: 3.0 (needs validation, then needs cloud metadata endpoint, then needs credentials in metadata)
- Uncertainty reduction: 0.0 (no confirmed enablement targets — SSRF target unknown)
- Effort eliminated: 0.0 (nothing is replaced until SSRF is confirmed)
- Confirmation multiplier: 0.4
- **Priority score**: (0.40 × 3.0 + 0.30 × 0.0 + 0.30 × 0.0) × 0.4 = **0.48**

**Result**: Confirmed .git/config (9.10) naturally outscores speculative SSRF (0.48) by ~19x. No special-case hacks. No severity boosting. The model just represents reality accurately.

**If SSRF is later confirmed by a tool** (Wraith validates it):
- Time-to-impact: 9.0 (confirmed execution)
- Uncertainty reduction: 4.0 (enables cloud metadata access on confirmed endpoint)
- Effort eliminated: 6.0 (replaces cloud enumeration)
- Confirmation multiplier: 1.0
- **Priority score**: (0.40 × 9.0 + 0.30 × 4.0 + 0.30 × 6.0) × 1.0 = **6.60**

Confirmed SSRF (6.60) still scores lower than .git/config with credentials (9.10) — which is correct. Direct credential access is more valuable than a network-pivot primitive that still requires further exploitation.

---

## 5. Per-Change Tradeoff Analysis

### Summary Matrix

| Change | Subsystem | Type | Fixes Assumption | Aligns With | New Failure Mode | Severity |
|--------|-----------|------|-----------------|-------------|-----------------|----------|
| 1 | Ledger | Additive | "Citation exists = proof" | Evidence quality matters | Source misclassification | LOW |
| 2 | VulnRules | Modificative | "Severity = f(type only)" | Content determines value | False-positive content matching | LOW |
| 3 | NexusContext | Additive | "Only chains form hypotheses" | Information = capability | Hypothesis noise for low-value info | MEDIUM |
| 4 | CausalGraph | Additive | "Dependencies = exploit chains" | Information enables exploitation | Centrality inflation | MEDIUM |
| 5 | OMEGA | Modificative | "All findings equally certain" | Confirmation matters | Score depression for AI-heavy scans | LOW |
| 6 | Strategos | Modificative | "Findings are either assets or vulns" | Credentials are both | New handler needed for new action type | LOW |

### Dependency Order

Changes must be implemented in this order due to data flow dependencies:

```
Change 1 (Ledger: confirmation_level)
    ↓
Change 2 (VulnRules: capability_types + content-aware scoring)
    ↓
Change 3 (NexusContext: information enablement rule)     ← reads confirmation_level + capability_types
Change 4 (CausalGraph: enablement edges)                 ← reads capability_types
    ↓
Change 5 (OMEGA: confirmation-weighted scoring)           ← reads confirmation_level
Change 6 (Strategos: unified insight routing)             ← reads capability_types + confirmation_level
```

Changes 3 and 4 can be implemented in parallel. Changes 5 and 6 can be implemented in parallel.

### What This Does NOT Change

- **CAL argumentation engine** (`core/cal/engine.py`): No changes. Claims, Evidence, and convergence logic remain untouched. The CAL system already supports the evidence provenance tracking we need.
- **ArbitrationEngine** (`core/cortex/arbitration.py`): No changes. Policy enforcement (veto/approve/modify) is orthogonal to capability modeling.
- **NarratorEngine** (`core/cortex/narrator.py`): No changes to the deterministic narrative templates. The reporting layer (`core/ai/reporting.py`) will naturally tell better stories because the CausalGraph now has enablement edges for information findings.
- **Existing chain-based reasoning**: Fully preserved. Exploit chains still form, still score high in NEXUS. We're extending the model, not replacing it.

---

## 6. Testability and Explainability

### 6.1 Test Scenarios

Each change should be validated against these scenarios:

**Scenario A** (the original bug): Scan discovers .git/config with AWS credentials AND a speculative SSRF indicator on the same target. Expected: .git/config outranks SSRF in final priority.

**Scenario B** (chain wins when confirmed): Scan discovers confirmed SSRF → confirmed cloud metadata → confirmed credential theft chain. Expected: The chain outranks a standalone .git/config with generic config data (no credentials).

**Scenario C** (confirmation upgrade): AI hypothesizes SSRF. Tool later confirms it. Expected: SSRF's priority score increases significantly after confirmation. Finding shows up in both "speculative" and "confirmed" views with appropriate timestamps.

**Scenario D** (information-only scan): Scan discovers only information findings (tech stack, headers, backup files). Expected: Findings are ranked by content value, not all treated as LOW because nothing "chains."

**Scenario E** (no regression): Existing test cases for exploit chain detection continue to pass. Chain-forming confirmed vulns still score high.

### 6.2 Explainability

Every `priority_score` must be decomposable into its constituent dimensions. The API response for any finding should include:

```json
{
  "finding_id": "...",
  "priority_score": 9.10,
  "breakdown": {
    "time_to_impact": {"score": 10.0, "reason": "Confirmed access capability (credentials)"},
    "uncertainty_reduction": {"score": 8.0, "reason": "Enables 4 downstream capabilities"},
    "effort_eliminated": {"score": 9.0, "reason": "Replaces credential brute-forcing"},
    "confirmation": {"level": "CONFIRMED", "multiplier": 1.0, "source": "tool:httpx"}
  },
  "capability_types": ["information", "access"],
  "enablement_edges": ["→ auth_bypass_api_v1", "→ admin_panel_access"]
}
```

This makes every ranking decision auditable and debuggable. If a user asks "why was this ranked higher?", the system can point to exact dimensions and values.

---

## 7. Terminology Reference

| Term | Definition |
|------|-----------|
| **Attacker Capability** | Any finding that changes what an attacker can do, know, or reach |
| **Capability Type** | Classification: execution, information, access, evasion |
| **Confirmation Level** | Evidence quality: CONFIRMED, PROBABLE, HYPOTHESIZED |
| **Enablement Edge** | Directed graph edge meaning "Capability A makes Capability B cheaper/faster/more likely" |
| **Leverage** | The degree to which a capability reduces attacker cost or increases attacker reach |
| **Time-to-Impact** | How quickly an attacker can use this capability to cause harm |
| **Uncertainty Reduction** | How much attacker unknowns are eliminated by this finding |
| **Effort Eliminated** | How much attacker work is skipped by this finding |
| **Priority Score** | Composite ranking metric: f(time, uncertainty, effort) × confirmation |
| **Content-Aware Scoring** | Severity assignment based on what a finding contains, not just its type |

---

## 8. Open Questions for Implementation Phase

1. **Enablement edge inference scope**: Should enablement edges be inferred only within a single target, or cross-target? Cross-target edges (e.g., "credentials from target A enable access to target B") are realistic but dramatically increase graph complexity. **Recommendation**: Start single-target only. Add cross-target in a follow-up.

2. **Retroactive re-scoring**: When a finding's confirmation level changes (hypothesis → confirmed), should all downstream scores be recalculated? **Recommendation**: Yes, via the existing event bus. Emit a `FINDING_CONFIRMATION_UPGRADED` event that triggers CausalGraph rebuild and OMEGA recalculation. The Ledger's event-sourcing architecture makes this natural.

3. **Effort Eliminated calibration**: The predefined effort scores (Section 4.5) are heuristic. Should they be configurable per engagement? **Recommendation**: Hardcode sensible defaults. Expose as YAML config for advanced users. Don't add a UI for this.

4. **Multiple capability types scoring**: When a finding has multiple capability types (e.g., "information" + "access"), how does it score across OMEGA pillars? **Recommendation**: It contributes to the highest-applicable pillar. Don't double-count. An "information + access" finding contributes to NEXUS (as access = exploitability) at its full confirmation-weighted score, not to both CRONUS and NEXUS.
