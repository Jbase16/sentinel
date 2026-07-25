# SentinelForge Reasoning-System Audit: SSRF vs. Data Exposure Prioritization

**Auditor Role**: Senior Systems Engineer (Reasoning-System Audit)
**Date**: 2026-02-05
**Scope**: Why speculative SSRF indicators outrank confirmed .git/config exposure

---

## Executive Summary (≤10 bullets)

- **The system is behaving as designed, but the design encodes a threat model that values exploitability chains over confirmed data exposure.** This is an architectural choice, not a bug—but it's a misaligned choice.
- **`core/toolkit/vuln_rules.py` hardcodes SSRF_CHAIN at CRITICAL/9.2 and BACKUP_EXPOSURE at HIGH/7.7.** This 1.5-point gap is the single largest explicit scoring disparity driving the behavior.
- **The OMEGA risk calculator (`core/omega/risk_calculator.py`) assigns 50% weight to NEXUS (adversarial exploitability/chains), 30% to MIMIC (code risk), and only 20% to CRONUS (exposure).** Chain-forming findings like SSRF structurally dominate standalone exposures like .git/config.
- **NexusContext (`core/cortex/nexus_context.py`) has only two synthesis rules, both biased toward chain formation.** .git/config doesn't form chains, so it only qualifies as an "isolated critical"—and only if already tagged HIGH/CRITICAL.
- **The CausalGraph (`core/cortex/causal_graph.py`) ranks findings by centrality.** SSRF gets inbound edges from port/service findings; .git/config has zero outbound edges and zero centrality.
- **The EvidenceLedger (`core/epistemic/ledger.py`) promotes findings with a binary gate (has citations → promoted).** There is no "confirmed exposure" vs. "speculative indicator" differentiation at promotion time.
- **AI-generated SSRF hypotheses (`core/ai/strategy.py`) enter the CAL pipeline at confidence 0.5—identical authority to tool-generated findings.** The system cannot distinguish AI speculation from tool confirmation.
- **Report prompts (`core/ai/reporting.py`) explicitly ask for attack chain narratives**, marginalizing standalone findings that don't chain.
- **Strategos (`core/scheduler/strategos.py`) classifies SSRF as `CONFIRMED_VULN` and .git/config as `HIGH_VALUE_TARGET`**—both priority 0, but different action types that feed into different downstream processing paths.
- **Fix surface is small**: 3-4 targeted changes in vuln_rules.py, risk_calculator.py, nexus_context.py, and ledger.py would resolve the misalignment.

---

## Detailed Code-Referenced Analysis

### Question 1: Where does the code implicitly assign higher importance to SSRF over confirmed data exposure?

There are **five distinct code locations** that compound to create the prioritization gap:

#### 1a. Explicit Severity Scoring — `core/toolkit/vuln_rules.py`

This is the most direct cause. The file defines `VulnRule` objects with hardcoded `base_score` values:

```
SSRF_CHAIN:       severity="CRITICAL", base_score=9.2, matcher=_match_ssrf_chain
CLOUD_METADATA:   severity="CRITICAL", base_score=9.0, matcher=_match_metadata
BACKUP_EXPOSURE:  severity="HIGH",     base_score=7.7, matcher=_match_backup_rule
```

The `_match_ssrf_chain()` function triggers on tags `["ssrf-source", "cloud"]`. The `_match_backup_rule()` triggers on tag `["backup-leak"]`. An exposed .git/config would need the `backup-leak` tag to match, capping it at HIGH/7.7 regardless of what it actually exposes (credentials, internal URLs, deployment paths).

**The implicit assumption**: Any SSRF indicator + cloud context is 1.5 points more severe than any backup/source artifact exposure, irrespective of what the backup contains.

#### 1b. OMEGA Weight Distribution — `core/omega/risk_calculator.py`

Lines 32-34:
```python
WEIGHT_CRONUS = 0.20  # Exposure & attack surface
WEIGHT_MIMIC  = 0.30  # Latent code-level risk
WEIGHT_NEXUS  = 0.50  # Adversarial exploitability
```

The code comment on line 11 states: *"NEXUS dominates because exploitability > exposure."*

.git/config is exposure (CRONUS domain, 20% weight). SSRF is exploitability (NEXUS domain, 50% weight). Even if both scored identically on a 0-10 scale, SSRF's contribution to the final OMEGA score would be **2.5x** that of .git/config.

#### 1c. Attack Path Synthesis — `core/cortex/nexus_context.py`

`synthesize_attack_paths()` (line 227) contains exactly two rules:

- **Rule 1** (`rule_web_exposure_chain`): Matches open web ports × web vulnerabilities (XSS, SQL). SSRF-adjacent findings chain here.
- **Rule 2** (`rule_critical_isolated`): Matches HIGH/CRITICAL severity findings in isolation.

.git/config only reaches Rule 2, and only if already tagged HIGH or CRITICAL. SSRF reaches Rule 1 by chaining with port findings, generating hypothesis events with confidence 0.8. The hypothesis emission also registers the finding in `_active_hypotheses`, making it visible to the entire event-driven reasoning pipeline.

#### 1d. Causal Graph Centrality — `core/cortex/causal_graph.py`

`_infer_dependencies()` creates directed edges: `recon → service → vulnerability`. SSRF (as a vulnerability type containing "vuln" or "injection" keywords) receives inbound edges from port/service findings. This inflates its `centrality_score` in pressure point analysis.

.git/config (typed as "config_exposure" or "git_exposure") matches none of the vulnerability keywords. It gets zero inbound edges, zero centrality, and is invisible to the pressure point ranking.

#### 1e. Strategos Action Typing — `core/scheduler/strategos.py`

`_generate_insights_from_finding()` maps:
```python
"git_exposure" → InsightActionType.HIGH_VALUE_TARGET, confidence=0.9
"ssrf"         → InsightActionType.CONFIRMED_VULN,    confidence=0.8
```

Both get priority 0, but `CONFIRMED_VULN` triggers different downstream processing than `HIGH_VALUE_TARGET`. The naming itself reveals the bias: SSRF is treated as a "confirmed vulnerability" while .git/config is a "high value target" (an asset, not a vuln). This means SSRF feeds directly into vulnerability-focused reasoning loops while .git/config feeds into asset-inventory logic.

---

### Question 2: Is there explicit severity ranking logic?

**Yes, in `core/toolkit/vuln_rules.py`** — this is the only file with explicit, static severity assignments. Each `VulnRule` has a hardcoded `severity` string and `base_score` float. There are ~30 rules.

**But this is not the whole story.** Prioritization also emerges implicitly through:

1. **OMEGA pillar weighting** (risk_calculator.py): Chain-forming findings get 50% weight via NEXUS.
2. **NexusContext hypothesis emission** (nexus_context.py): Only chain-forming or HIGH/CRITICAL findings generate hypothesis events.
3. **CausalGraph centrality** (causal_graph.py): Graph position amplifies findings with dependencies.
4. **AI severity assignment** (ai_engine.py): The LLM assigns severity unconstrained by evidence strength. System prompt says "Extract concrete security findings" with severity levels but provides no calibration rubric.
5. **Risk engine weighting** (risk.py): `CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1, INFO=0.5` — a 1.67x multiplier between CRITICAL and HIGH.

The combined effect: a CRITICAL SSRF finding scores `9.2 × 10 × 0.50` through the vuln_rules → risk.py → OMEGA pipeline, while a HIGH .git/config scores `7.7 × 6 × 0.20`. That's a **~7.7x effective priority gap** (46.0 vs 9.24 in arbitrary units).

---

### Question 3: How do AI-generated claims differ from tool-generated findings?

**They don't differ enough.** This is a core architectural flaw.

In `core/ai/strategy.py`, `propose_attacks()`:
```python
self.session.findings.add_finding({
    "tool": "neural_strategy",
    "type": f"hypothesis::{vec.vuln_class.lower()}",
    "severity": "MEDIUM",   # ALL AI hypotheses hardcoded MEDIUM
    ...
})
```

And in `_analyze_with_ai()`:
```python
ai_evidence = Evidence(..., confidence=0.5)  # AI suspicion, not confirmed
```

In `core/cortex/reasoning.py`, `assert_claim()`:
```python
def assert_claim(self, statement, source, evidence_content, confidence=0.5, ...):
    # No severity check, no source-authority differentiation
```

**The problem**: Both AI-generated and tool-generated findings enter the CAL pipeline via `assert_claim()` with the same default confidence (0.5). The `source` field is set but never checked during promotion or prioritization. The EvidenceLedger's `evaluate_and_promote()` validates only that citations exist—not who produced them or how.

So when AI says "this target might be vulnerable to SSRF" (speculative), it enters the same reasoning pipeline as a tool confirming ".git/config returns 200 with credentials" (confirmed). The AI hypothesis then gets picked up by vuln_rules.py's SSRF_CHAIN matcher (if tagged appropriately), elevated to CRITICAL/9.2, and chains through NexusContext—all without ever being validated by an actual tool.

---

### Question 4: Why does SSRF fit better into attack-path reasoning than .git/config?

**Three structural reasons:**

1. **SSRF is a transitive vulnerability.** It chains: `open port → web service → SSRF → cloud metadata → credential theft`. NexusContext Rule 1 matches `open_port × web_vuln`, and the CausalGraph creates edges `port → ssrf`. Every link in this chain increases SSRF's graph centrality and generates hypothesis events.

2. **.git/config is a terminal finding.** It doesn't enable further exploitation in the system's model. There are no VulnRules that chain FROM .git/config TO another finding type. The CausalGraph has no edge template for "data exposure → X". It's a dead end in the graph.

3. **The reporting layer amplifies this.** `_prompt_attack_narrative()` in reporting.py literally asks: *"Tell the story of the attack. How does one finding lead to another?"* A standalone .git/config finding doesn't tell a story. SSRF does.

**What's missing**: The system has no concept of "confirmed data exposure severity escalation." An exposed .git/config containing AWS credentials should score higher than a speculative SSRF indicator, but the system has no rule that inspects the *content* of a backup exposure to escalate severity. The `_match_backup_rule()` in vuln_rules.py does a flat tag match—it doesn't examine what was actually exposed.

---

### Question 5: What exact architectural/reasoning assumptions cause this outcome?

Five assumptions are encoded in the architecture:

1. **"Exploitability > Exposure" (risk_calculator.py, line 11)**: The OMEGA model assumes that what an attacker *can do* (chains) matters more than what's *already leaked* (exposure). This is defensible for active threats but wrong for passive data breaches.

2. **"Chains are inherently more severe than isolated findings" (nexus_context.py)**: The hypothesis engine only emits events for chain-forming findings or isolated HIGH/CRITICAL. A MEDIUM-severity finding that chains gets more attention than a HIGH-severity finding that doesn't.

3. **"All findings enter the reasoning pipeline with equal authority" (reasoning.py, ledger.py)**: The EvidenceLedger makes no distinction between AI speculation and tool confirmation. The CAL system's `assert_claim()` accepts all sources at confidence 0.5.

4. **"Vulnerability classification is static and tag-based" (vuln_rules.py)**: Severity is determined by matching tags, not by analyzing the *content* or *evidence strength* of a finding. .git/config exposing credentials and .git/config exposing a README get the same HIGH/7.7.

5. **"Graph centrality correlates with risk importance" (causal_graph.py)**: Findings with more dependencies are treated as more important pressure points. This systematically disadvantages standalone findings regardless of their actual severity.

---

### Question 6: Recommended Fixes (5 minimal, high-leverage changes)

#### Fix 1: Content-Aware Severity Escalation in vuln_rules.py

**File**: `core/toolkit/vuln_rules.py`
**Change**: Modify `_match_backup_rule()` to inspect finding content for credential indicators.

```python
def _match_backup_rule(finding: dict) -> Optional[dict]:
    tags = finding.get("tags", [])
    if "backup-leak" not in tags:
        return None

    # NEW: Content-aware escalation
    value = str(finding.get("value", "")).lower()
    details = str(finding.get("technical_details", "")).lower()
    content = value + " " + details

    credential_indicators = ["password", "secret", "token", "aws_", "api_key",
                            "private_key", "credential", "authorization"]
    has_credentials = any(ind in content for ind in credential_indicators)

    if has_credentials:
        return {"severity": "CRITICAL", "base_score": 9.5,
                "impact": "Confirmed credential exposure via backup artifact"}

    return {"severity": "HIGH", "base_score": 7.7,
            "impact": "Backup/source artifact exposure"}
```

**Impact**: .git/config with credentials jumps from HIGH/7.7 to CRITICAL/9.5, outscoring SSRF_CHAIN's 9.2.

#### Fix 2: Evidence-Strength Multiplier in the EvidenceLedger

**File**: `core/epistemic/ledger.py`
**Change**: Add an `evidence_strength` field to promoted findings based on source authority.

In `evaluate_and_promote()`, after citation validation:
```python
# NEW: Evidence strength based on source
source = proposal.source or ""
if source in ("neural_strategy", "ai_engine", "debate"):
    evidence_strength = 0.5  # AI-speculated
elif source.startswith("tool:"):
    evidence_strength = 0.9  # Tool-confirmed
else:
    evidence_strength = 0.7  # Default

finding.metadata["evidence_strength"] = evidence_strength
```

Then in vuln_rules.py, apply the multiplier to base_score:
```python
effective_score = base_score * finding.metadata.get("evidence_strength", 1.0)
```

**Impact**: AI-speculated SSRF drops from 9.2 to 4.6 effective score. Tool-confirmed .git/config stays at ~7.0.

#### Fix 3: Add "Confirmed Exposure" Synthesis Rule in NexusContext

**File**: `core/cortex/nexus_context.py`
**Change**: Add a third synthesis rule in `synthesize_attack_paths()` for confirmed data exposure.

```python
# Rule 3: Confirmed Data Exposure (standalone but high-impact)
RULE_ID_EXPOSURE = "rule_confirmed_data_exposure"
RULE_VERSION_EXPOSURE = "1.0"

data_exposures = [
    f for f in findings
    if any(kw in str(f.get("type", "")).lower()
           for kw in ["git_exposure", "config_exposure", "backup", "secret_leak"])
]

for exposure in data_exposures:
    finding_ids = self._extract_finding_ids([exposure])
    if not finding_ids:
        continue
    hyp_id = self._generate_hypothesis_id(
        finding_ids, RULE_ID_EXPOSURE, RULE_VERSION_EXPOSURE)
    if hyp_id in self._emitted_hypotheses:
        continue

    sev = str(exposure.get("severity", "HIGH")).upper()
    conf = 0.95 if sev == "CRITICAL" else 0.85

    self._emit_hypothesis_formed(
        hypothesis_id=hyp_id,
        constituent_finding_ids=finding_ids,
        rule_id=RULE_ID_EXPOSURE,
        rule_version=RULE_VERSION_EXPOSURE,
        confidence=conf,
        explanation=f"Confirmed data exposure ({exposure.get('type')}) represents immediate information leakage.",
    )
    self._emitted_hypotheses.add(hyp_id)
    self._active_hypotheses[hyp_id] = set(finding_ids)
```

**Impact**: .git/config now generates hypothesis events (confidence 0.85-0.95), making it visible to the full reasoning pipeline instead of being a graph dead-end.

#### Fix 4: Reduce NEXUS Weight Dominance with Confirmation Bonus

**File**: `core/omega/risk_calculator.py`
**Change**: Adjust weights and add a "confirmed evidence" bonus.

```python
# Revised weights (still sum to 1.0)
WEIGHT_CRONUS = 0.25  # Exposure (was 0.20)
WEIGHT_MIMIC  = 0.30  # Code risk (unchanged)
WEIGHT_NEXUS  = 0.45  # Exploitability (was 0.50)

# In calculate():
# NEW: Confirmed-evidence bonus
confirmation_bonus = 0.0
if any(p.details.get("evidence_strength", 0) > 0.8
       for p in [cronus_score, mimic_score, nexus_score]):
    confirmation_bonus = 0.5  # Bonus for tool-confirmed findings
omega_score = (w_cronus * cronus_score.value +
               w_mimic * mimic_score.value +
               w_nexus * nexus_score.value +
               confirmation_bonus)
```

**Impact**: Confirmed findings get a flat bonus, and exposure findings get 25% weight (up from 20%).

#### Fix 5: Source Authority in CausalGraph Edge Creation

**File**: `core/cortex/causal_graph.py`
**Change**: In `_infer_dependencies()`, add edges for data exposure findings.

```python
# NEW Rule: Data exposures are pressure points regardless of chaining
exposure_findings = [f for f in target_findings if any(
    word in f.type.lower() for word in
    ['exposure', 'leak', 'backup', 'config', 'secret'])]

for exp in exposure_findings:
    # Self-edge with high weight to boost centrality
    self.graph.add_node(exp.id, finding=exp, weight=2.0)
```

**Impact**: Data exposure findings gain non-zero centrality in pressure point analysis.

---

## Verdict

**The system is behaving exactly as designed.** The design simply encodes a threat model where "what can be exploited next" matters more than "what has already been exposed." This is a reasonable model for active penetration testing but a poor model for security posture assessment.

The prioritization of speculative SSRF over confirmed .git/config is not a single bug—it's the emergent result of five compounding biases: explicit severity scores, OMEGA weight distribution, chain-only synthesis rules, centrality-based ranking, and source-blind evidence promotion. Fixing any one of these helps; fixing the top three (Fixes 1, 2, 3) would resolve the core misalignment.
