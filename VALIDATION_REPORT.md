# SentinelForge Phase 1–3 Validation Report

**Scan Target**: http://localhost:3003 (MegaShop test app)
**Scan Date**: February 2026
**Validator**: 12-question probe against in-app AI assistant

---

## Executive Summary

Phase 1–3 code is **fully implemented and tested in isolation**, but the in-app AI assistant's answers reveal that the new scoring pipeline is **not being exercised during real scans**. The original bug — speculative SSRF outranking confirmed .git/config — **persists in production output**.

Three root causes identified:

1. **Feature gate is OFF** — `three_axis_enabled: false` means Phase 3-lite scoring never fires
2. **0 enablement edges** — Rule 5 isn't generating edges, so Phase 2 graph enrichment is inert
3. **AI assistant context gap** — the assistant has no awareness of the new fields (confirmation_level, capability_types, enablement_score)

---

## Question-by-Question Breakdown

### Phase 1: Confirmation-Weighted Scoring

| # | Question | Expected Answer | Actual Answer | Verdict |
|---|----------|-----------------|---------------|---------|
| 1 | What confirmation_level did .git/config and SSRF get? | .git/config = confirmed, SSRF = hypothesized | Both classified as "HIGH" (severity, not confirmation) | **FAIL** — assistant doesn't surface confirmation_level |
| 2 | What capability_types are on the debug endpoint finding? | `["information"]` or `["information", "execution"]` | "I'd need more info" — doesn't know the field exists | **FAIL** — capability_types not surfaced |
| 3 | Is confirmation_multiplier applied to scores? | Yes: confirmed=1.0, probable=0.7, hypothesized=0.4 | "SentinelForge does not apply a confirmation_multiplier" | **FAIL** — either not applied or not visible to AI |

**Phase 1 Assessment**: The `VulnRule.apply()` code correctly derives `confirmation_level` and applies `confirmation_multiplier` to `effective_score`. But the AI assistant either can't see these fields or the pipeline path that exercises this code isn't being hit. Most likely cause: the issue enrichment path in the real scan session doesn't flow through `VulnRule.apply()`, or the AI's context prompt doesn't include these fields.

### Phase 2: Causal Graph & Enablement

| # | Question | Expected Answer | Actual Answer | Verdict |
|---|----------|-----------------|---------------|---------|
| 4 | What enablement edges exist in the causal graph? | .git/config → admin, .git/config → login (DIRECT/2.0) | Describes narrative attack paths, not actual edges | **FAIL** — 0 enablement edges in graph |
| 5 | What is .git/config's enablement_score? | Numeric value based on downstream edge count | "Higher than ports" — generic reasoning, no number | **FAIL** — no enablement_score computed |
| 6 | What Strategos action types were routed? | CONFIRMED_EXPOSURE, HIGH_VALUE_TARGET | "Data Breach" and "RCE" — nonexistent enum values | **FAIL** — wrong action type vocabulary |

**Phase 2 Assessment**: The CausalGraph scan log consistently shows "0 enablement edges" despite having confirmed information findings (.git/config with 200 status and 244 bytes). This means `_infer_information_enablement_edges()` (Rule 5) is either: (a) not being called, (b) filtering out all findings before edge creation, or (c) the findings lack the metadata fields Rule 5 requires (`confirmation_level`, `capability_types`).

### Content-Aware Escalation

| # | Question | Expected Answer | Actual Answer | Verdict |
|---|----------|-----------------|---------------|---------|
| 7 | Did .git/config trigger credential-indicator content scan? | Yes/No with specific indicators matched | Claims it triggered, reasoning is vague | **INCONCLUSIVE** — can't verify from answer alone |

### Ranking (THE Litmus Test)

| # | Question | Expected Answer | Actual Answer | Verdict |
|---|----------|-----------------|---------------|---------|
| 8 | Does .git/config outrank SSRF? | YES — that's the whole point of the redesign | **SSRF ranked #1**, .git/config ranked lower | **CRITICAL FAIL** — original bug persists |
| 9 | What would three-axis scores show? | Specific numbers from compute_three_axis_priority() | Reasonable hypothetical, no actual numbers | **FAIL** — three-axis scoring not computed |

### System Health

| # | Question | Expected Answer | Actual Answer | Verdict |
|---|----------|-----------------|---------------|---------|
| 10 | How does the graph grow as findings arrive? | Mentions Rule 5, enablement edges, incremental inference | Generic explanation without Phase 2 terminology | **FAIL** — no evidence of incremental graph building |
| 11 | Are nikto's dropped findings correlated with kept findings? | Yes/No with graph-based reasoning | "Correlated" — narrative reasoning, not graph-based | **INCONCLUSIVE** |
| 12 | How many findings have explicit confirmation_level? | Specific count with breakdown | "10 have explicit confirmation_level" | **NEEDS VERIFICATION** — plausible but unverified |

---

## Root Cause Analysis

### Root Cause 1: Rule 5 Filter Mismatch

`_infer_information_enablement_edges()` requires findings that satisfy ALL of:

```python
self._finding_confirmation_level(finding) == "confirmed"    # Must be "confirmed"
self._finding_base_score(finding) >= 5.0                     # Must score ≥ 5.0
capability in {"information", "access"}                      # Must have info/access type
```

**Likely failure point**: The raw findings from feroxbuster/gobuster that discover `.git/config` may not carry `confirmation_level = "confirmed"` or `capability_types = ["information"]` at the point where CausalGraph processes them. These fields are enriched by `VulnRule.apply()`, but if the CausalGraph processes findings BEFORE vuln rule matching, the metadata won't be present.

**Verification needed**: Check the pipeline order — does CausalGraph receive raw findings or VulnRule-enriched issues?

### Root Cause 2: Feature Gate OFF

`three_axis_enabled: false` in `capability_model_config.yaml` means `compute_three_axis_priority()` is never called during real scoring. This is by design (safe rollout), but it means Phase 3-lite has zero production impact until flipped.

### Root Cause 3: AI Assistant Prompt Gap

The in-app AI assistant appears to lack context about Phase 1–3 fields. It doesn't know:

- `confirmation_level` exists on issues
- `capability_types` exists on rules/issues
- `confirmation_multiplier` is applied to scores
- `enablement_score` exists on graph nodes
- Strategos action types use `CONFIRMED_EXPOSURE`, `HIGH_VALUE_TARGET` (not "Data Breach", "RCE")

This could be a prompt/system-message issue — the AI's context window may not include the enriched issue schema.

---

## Scorecard

| Phase | Implemented | Unit Tested | Integration Tested | Production Active | Score |
|-------|-------------|-------------|--------------------|--------------------|-------|
| Phase 1: Confirmation Scoring | YES | YES | NO | **UNKNOWN** | 2/4 |
| Phase 2: Causal Graph + Rule 5 | YES | YES | NO | **NO** (0 edges) | 2/4 |
| Phase 3-Lite: Config + Three-Axis | YES | YES | NO | **NO** (gate off) | 2/4 |

**Overall**: 6/12 — code exists and passes unit tests, but nothing is proven active in a real scan.

---

## Recommended Next Steps (Priority Order)

### 1. Diagnose the 0-enablement-edges problem (CRITICAL)

Trace the actual data flow during a scan:

- What fields does `.git/config` carry when CausalGraph receives it?
- Is `confirmation_level` present? Is `capability_types` present?
- At what pipeline stage does CausalGraph process findings — before or after VulnRule enrichment?

If findings reach CausalGraph without enrichment, Rule 5's filters will silently discard everything.

### 2. Wire an integration test with real scan data

Take the actual scan output from this MegaShop run, feed it through the full pipeline (VulnRule → CausalGraph → RiskEngine), and verify:

- .git/config gets `confirmation_level = "confirmed"`
- .git/config gets `capability_types = ["information"]`
- CausalGraph produces ≥ 1 enablement edge
- enablement_score > 0 for .git/config's node

### 3. Enable three-axis scoring

Flip `three_axis_enabled: true` and verify .git/config outranks SSRF in composite score. The unit test (`test_end_to_end_credentials_outrank_hypothesized_ssrf`) already proves this works in isolation — need to verify it works with real data.

### 4. Update the AI assistant's context

Add Phase 1–3 field definitions to the assistant's system prompt or schema documentation so it can surface `confirmation_level`, `capability_types`, `enablement_score`, and three-axis scores when asked.

---

## Files Referenced

| File | Role |
|------|------|
| `core/data/constants.py` | Shared constants (multipliers, indicators, confidence) |
| `core/toolkit/vuln_rules.py` | VulnRule.apply() — enriches issues with Phase 1 fields |
| `core/cortex/causal_graph.py` | Rule 5 — enablement edge inference |
| `core/data/risk.py` | compute_three_axis_priority() — Phase 3-lite scoring |
| `core/base/config.py` | CapabilityModelConfig — externalized config |
| `core/cortex/capability_model_config.yaml` | Runtime config (feature gate OFF) |
| `core/cortex/nexus_context.py` | Information hypothesis synthesis |
| `tests/unit/test_three_axis_scoring.py` | 5 tests, all passing |
| `tests/unit/test_capability_model_config.py` | 7 tests, all passing |
