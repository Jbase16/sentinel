# CAL Learning Guide (Legacy)
This file has been superseded by the split documentation set in `docs/cal/`.

Start here: `docs/cal/README.md`

Version: 0.1 (Design Draft)
Date: December 12, 2025

## Who this is for
CAL is designed for engineers building cybersecurity automation where multiple components (scanners, pattern engines, LLM reasoners, exploit validators) must collaborate on *claims* about security posture.

This guide teaches CAL as if you’re going to write real programs (“missions”) that:
- create hypotheses (claims)
- attach evidence
- coordinate agent review + validation
- produce explainable outputs

## What makes CAL different
Most languages treat security tooling as:
- procedures (“run A then B”) or
- workflows (“step1 → step2 → step3”)

CAL treats security findings as:
- *beliefs that evolve*, not booleans
- *argumentation between agents*, not ad-hoc orchestration
- *evidence-first*, with provenance and explainability as runtime guarantees

You write:
- **Agents** (who can do what, with what authority)
- **Claim types** (what can be asserted)
- **Evidence types** (what can support/refute claims)
- **Rules** (how collaboration must happen)
- **Missions** (phased programs)

The runtime does:
- track claim history and evidence lineage automatically
- enforce authority, validation requirements, and scope constraints
- surface conflicts rather than burying them

---

# 1) A first mental model
Think of CAL as:
- a reactive system (event-driven)
- with an explicit epistemic state (claims + confidence + evidence)
- governed by policy (rules)

Instead of writing imperative glue like:
- “if regex found X, call LLM; if LLM says yes, run validator”

you write:
- “when Regex asserts a claim, LLM must review; when confidence crosses a threshold, Validator must validate.”

That’s the essence.

---

# 2) Quickstart by example (read this first)
This section is intentionally minimal. You can skim it, then jump to deeper chapters.

## 2.1 Define agents
Agents are first-class. You declare their role, authority, trust, capabilities, and constraints.

```cal
agent Detector::Regex {
  role: pattern_detector
  authority: [assert_hypothesis]
  trust: 0.50

  capabilities {
    scan(response: Observation<HTTPResponse>, patterns: PatternSet) -> List<PatternMatch>
  }
}

agent Reasoner::Sentinel {
  role: semantic_reasoner
  authority: [review, strengthen, weaken, challenge]
  trust: 0.75
  model: "sentinel-vuln-v3"

  capabilities {
    review(claim: Claim) -> ReviewResult
    explain(claim: Claim) -> Narrative
  }

  constraints {
    requires_evidence: true
    max_tokens_per_call: 4096
  }
}

agent Validator::ExploitRunner {
  role: validator
  authority: [validate, invalidate, confirm]
  trust: 0.95

  capabilities {
    validate(claim: Claim) -> ValidationResult
  }

  constraints {
    requires_authorization: true
    execution_sandbox: true
  }
}
```

## 2.2 Define claim types
Claim types define the structure of a hypothesis and its policy requirements.

```cal
claim_type PotentialSQLi {
  endpoint: Endpoint
  parameter: String
  indicator: String

  severity_range: [MEDIUM, CRITICAL]
  requires_validation: true
}

claim_type ConfirmedSQLi {
  endpoint: Endpoint
  parameter: String
  technique: String

  severity_range: [HIGH, CRITICAL]
  requires_validation: true
}
```

## 2.3 Define rules (collaboration policy)
Rules express collaboration declaratively.

```cal
rule Regex_Creates_Initial_Hypothesis {
  when Detector::Regex observes PatternMatch as m {
    Detector::Regex may assert claim PotentialSQLi {
      endpoint: m.location.endpoint,
      parameter: m.location.parameter,
      indicator: m.matched_text,
      confidence: 0.35,
      evidence: [m]
    }
  }
}

rule LLM_Must_Review_Regex_Claims {
  when Detector::Regex asserts claim PotentialSQLi as c {
    Reasoner::Sentinel must review(c) within 30s

    on review_complete(r) {
      if r.likely_true_positive {
        Reasoner::Sentinel.strengthen(c, by: r.boost, reason: r.reason)
      } else {
        Reasoner::Sentinel.weaken(c, by: r.penalty, reason: r.reason)
      }
    }
  }
}

rule Validate_When_Confident {
  when claim PotentialSQLi as c
   and c.confidence >= 0.65
   and c.status not in [VALIDATED, INVALIDATED] {

    Validator::ExploitRunner must validate(c) within 120s

    on validation_success(v) {
      let confirmed = claim ConfirmedSQLi {
        endpoint: c.endpoint,
        parameter: c.parameter,
        technique: v.technique,
        confidence: 0.95,
        evidence: c.evidence + [v]
      }
      emit claim_upgraded(from: c, to: confirmed)
    }

    on validation_failure(v) {
      Validator::ExploitRunner.invalidate(c, reason: "Validation failed", evidence: v)
    }
  }
}
```

## 2.4 Define a mission (program)
Missions are phased programs. Rules fire during mission execution.

```cal
mission WebAssessment(target: Host, scope: Scope) {
  phase Recon {
    Scanner::Httpx.probe(target)
    await all_observations_processed
  }

  phase Detect {
    Detector::Regex.scan(all_http_responses, sqli_patterns)
    await claims.stable(timeout: 60s)
  }

  phase Validate when query claims PotentialSQLi where confidence >= 0.65 exists {
    await all_validations_complete(timeout: 300s)
  }

  phase Report {
    let confirmed = query claims ConfirmedSQLi where status == CONFIRMED
    emit artifact(confirmed, type: "findings")
  }
}
```

That’s the “shape” of CAL.

---

# 3) Core concepts (the vocabulary you’ll use)

## 3.1 Agents
Agents are subjects with explicit:
- role
- authority
- trust
- capabilities
- constraints

### Roles (conceptual)
Typical roles in Sentinel:
- `observer`: runs deterministic scanners and emits observations
- `pattern_detector`: regex/signature engines, cheap but noisy
- `semantic_reasoner`: LLM-based reasoning, higher-level interpretation
- `validator`: proof executor (PoCs, sqlmap, auth tests)
- `orchestrator`: governs policy enforcement, escalation, persistence

### Authority
Authority is what an agent is allowed to do to the epistemic state.
Common authorities:
- `assert_observation`
- `assert_hypothesis`
- `review`
- `strengthen` / `weaken`
- `challenge`
- `validate` / `invalidate`
- `confirm`
- `retract`

Authority is meant to be compiler- and runtime-enforced.

### Constraints
Constraints express limits and safeguards:
- rate limits
- requires authorization
- requires scope containment
- sandbox requirements
- “requires evidence” gating for LLM calls

Constraints are not “comments”; they are part of the execution contract.

---

## 3.2 Observations vs Evidence vs Claims
CAL distinguishes three things people often collapse:

### Observations
Raw facts emitted by scanners or sensors.
Examples:
- “port 443 open”
- “HTTP response has header Server: nginx”
- “response time increased by 3 seconds for payload X”

Observations are not beliefs. They’re *inputs*.

### Evidence
Artifacts that support or refute claims and can be audited later.
Examples:
- raw tool output
- parsed match results
- LLM analysis output (with prompt hash)
- validation results (proof)

Evidence is provenance-bearing. Evidence can be cryptographically hashed for tamper detection.

### Claims
Versioned hypotheses with confidence and status.
Examples:
- “Potential SQL injection on /login parameter username”
- “Confirmed SSRF via out-of-band callback”

Claims are what you ultimately report.

---

## 3.3 Claim lifecycle
A claim should move through explicit states.
Recommended states:
- `HYPOTHESIZED`
- `PENDING_REVIEW`
- `CHALLENGED` / `CONTESTED`
- `PENDING_VALIDATION`
- `VALIDATED` / `INVALIDATED`
- `CONFIRMED` / `REFUTED` / `DISMISSED`

Key idea: **confirmation is not the same as validation**.
- Validation means “we tested and got evidence.”
- Confirmation means “policy allows us to escalate/report as true.”

---

## 3.4 Confidence is computed, not overwritten
In CAL, confidence is intended to be:
- bounded (0.0 to 1.0)
- auditable (who changed it and why)
- explainable (breakdown by contributions)

CAL encourages:
- monotonic evidence collection (evidence only added)
- non-monotonic belief (confidence can increase or decrease)

---

# 4) Language structure
A CAL program typically has:
- `agent` declarations
- `claim_type` declarations
- `evidence_type` declarations
- `rule` declarations
- `mission` declarations
- optionally a `confidence_model`

Order should not matter (compiler resolves symbols), but humans usually read:
1) agents
2) types
3) rules
4) missions

---

# 5) Agents: deep dive

## 5.1 Declaring an agent
```cal
agent Namespace::Name {
  role: semantic_reasoner
  authority: [review, strengthen, weaken]
  trust: 0.75

  capabilities {
    review(claim: Claim) -> ReviewResult
  }

  constraints {
    requires_evidence: true
  }
}
```

## 5.2 Capabilities
Capabilities are typed function-like declarations.
They’re how CAL calls out to the world.

Good capability design:
- keep inputs explicit and structured
- return structured results that can become evidence or claim updates
- avoid “stringly-typed” blobs

## 5.3 Binding model (how agents run)
CAL itself is the language; actual execution is performed by a runtime that binds:
- `Scanner::*` agents → Sentinel tool runners
- `Reasoner::*` agents → AIEngine / Synapse / model router
- `Validator::*` agents → Forge / PoC runner / sqlmap/auth test harness

Bindings are where policy meets implementation.

---

# 6) Claims and types

## 6.1 Declaring claim types
Claim types are schemas for hypotheses.

```cal
claim_type OpenPort {
  target: Host
  port: PortNumber
  service: String?

  severity_range: [INFO, LOW]
  requires_validation: false
}
```

### Design guidelines
- Claim types should be **about a single assertion**.
- Avoid “kitchen sink” claims.
- Use correlation rules to combine multiple claims into higher-level ones.

## 6.2 Creating claims
Claims are created by assertions, usually inside rules.

```cal
Detector::Regex may assert claim PotentialSQLi {
  endpoint: endpoint("/login"),
  parameter: "username",
  confidence: 0.35,
  evidence: [match_01]
}
```

## 6.3 Updating claims
Claims evolve via operations:
- `strengthen(claim, by: x, reason: y)`
- `weaken(claim, by: x, reason: y)`
- `challenge(claim, reason: y)`
- `validate(claim)` / `invalidate(claim)`
- `confirm(claim)`

Updates should create new claim versions (temporal / audit).

---

# 7) Evidence and provenance

## 7.1 Declaring evidence types
```cal
evidence_type RawOutput {
  tool: String
  stdout: String
  stderr: String
  exit_code: Int
  captured_at: Timestamp
}

evidence_type ValidationResult {
  validator: String
  success: Bool
  proof: String
}
```

## 7.2 Attaching evidence
Evidence is attached when creating or updating a claim.

```cal
Validator::ExploitRunner.invalidate(c, reason: "No exploitation", evidence: v)
```

## 7.3 Provenance guarantees
The runtime should automatically record:
- which agent captured evidence
- time captured
- integrity hash
- link from evidence → claim versions that it affected

CAL expects evidence to be queryable and reproducible.

---

# 8) Rules: the heart of collaboration

## 8.1 Rule shape
Rules are reactive.

```cal
rule Name {
  when <condition> {
    <actions>
  }
}
```

Rules typically trigger on:
- observations emitted by agents
- new claims asserted
- claim confidence crossing a threshold
- claim status transitions
- conflicts between claims
- timeouts

## 8.2 `may` vs `must`
- `may` expresses a permitted action (optional).
- `must` expresses a required action (policy obligation).

This distinction is critical for correctness and auditing:
- “Regex may assert” means it’s allowed, not guaranteed.
- “Validator must validate” means system is obligated (or it must record why it didn’t).

## 8.3 Time constraints
Time is explicit.

```cal
Reasoner::Sentinel must review(c) within 30s

on timeout(30s) {
  c.status = UNVALIDATED
  emit warning("Review timeout")
}
```

## 8.4 Conflict surfacing
CAL’s philosophy: do not silently resolve contradictions.

```cal
rule Surface_Conflicts {
  when exists claim c1
   and exists claim c2
   and c1.subject == c2.subject
   and c1.assertion != c2.assertion {

    emit conflict_detected([c1, c2])
    mark_contested([c1, c2])
  }
}
```

---

# 9) Missions: programs with phases

## 9.1 Mission structure
Missions define program flow, but the “intelligence” comes from rules.

```cal
mission Name(args...) {
  phase PhaseName {
    ...
  }
}
```

Phases are useful to:
- group activities
- provide UI structure (“Recon / Detect / Validate / Report”)
- enforce gating (“don’t validate until detection stabilizes”)

## 9.2 Waiting primitives
CAL uses `await` for key convergence points:
- `await all_observations_processed`
- `await claims.stable(timeout: 60s)`
- `await all_validations_complete(timeout: 300s)`

These are semantic waits (runtime-provided), not just sleeping.

---

# 10) Queries
CAL should have first-class queries over the belief/evidence state.

Examples:

```cal
let high = query claims where confidence >= 0.8
let confirmed = query claims where status == CONFIRMED
let sqli = query claims PotentialSQLi where target.host == target_host
```

Query design goals:
- deterministic
- explainable
- compatible with backing stores (knowledge graph + SQLite)

---

# 11) Dual execution model: reasoning vs execution
CAL supports the same program running in two modes.

## 11.1 Reasoning mode
Reasoning mode is for:
- simulation
- planning
- “what-if” analyses
- using cached evidence and prior runs

## 11.2 Execution mode
Execution mode is for:
- real scanning
- real model inference
- real validation and proof collection

## 11.3 Why dual mode matters
It enables:
- reproducible reasoning artifacts (same CAL source, different backend)
- safe previews (see what would run before running it)
- explainability (show plan and justification)

---

# 12) Confidence models (high-level)
CAL should allow pluggable confidence computation.

```cal
confidence_model Default {
  compute(claim) = clamp(0.0, 1.0,
    base_trust(claim) + evidence_weight(claim) + corroboration(claim)
  )
}
```

Design advice:
- keep the default model simple
- record contributions as “confidence sources” for explainability
- avoid allowing arbitrary agents to directly set confidence; prefer operations with bounded deltas and logged rationale

---

# 13) Safety, scope, and authorization
This is not optional in cybersecurity.

## 13.1 Scope containment
Targets must be in declared scope.
Out-of-scope actions should:
- fail closed
- record an audit event

## 13.2 Authorization gates
Validators often run intrusive behavior.
CAL should model “requires authorization” as:
- an agent constraint
- enforceable by runtime
- visible in UI

## 13.3 Preventing premature escalation
Use rules like:
- “must validate before CONFIRMED”
- “must have corroboration sources before CRITICAL escalation”

---

# 14) Error handling and failure surfacing
CAL is designed to avoid “silent failure.”

Recommended error classes:
- `AuthorityError`: agent tried forbidden action
- `ScopeError`: target out of scope
- `ValidationRequiredError`: attempted to confirm without required proof
- `TimeoutError`: obligations not met within time
- `ConflictError`: contradictory claims exist

A good runtime:
- records these as audit events
- exposes them in UI
- allows policies for fallback behavior

---

# 15) Patterns and idioms (how to write good CAL)

## 15.1 Start low-confidence, then earn certainty
- Regex assertions should start low.
- LLM review should move confidence moderately.
- Validation should move confidence sharply.

## 15.2 Keep claim types composable
Prefer many small claims + correlation rules over giant claim schemas.

## 15.3 Separate detection from validation
Write rules so “detection” produces hypotheses and “validation” produces proof.

## 15.4 Surface uncertainty
Use tags like:
- `high_uncertainty`
- `needs_human_review`
- `blind_possible`

…and make the UI show them.

## 15.5 Treat LLM outputs as evidence, not truth
Store:
- prompt hash
- model name
- structured response

…and treat it as *supporting evidence*, not as confirmation.

---

# 16) Reference: minimal syntax sketch
This section is a compact reference (not a full formal grammar).

## 16.1 Top-level declarations
- `agent Name { ... }`
- `claim_type Name { ... }`
- `evidence_type Name { ... }`
- `rule Name { when ... { ... } }`
- `mission Name(args...) { phase ... }`
- `confidence_model Name { ... }`

## 16.2 Common keywords
- `agent`, `role`, `authority`, `trust`, `capabilities`, `constraints`
- `claim_type`, `evidence_type`
- `rule`, `when`, `may`, `must`, `within`, `on timeout`
- `mission`, `phase`, `await`, `for`, `if`, `match`
- `query`, `emit`

---

# 17) Sentinel integration (conceptual)
CAL is intended to be Sentinel’s cognitive layer.

Mapping targets:
- CAL runtime drives existing scanners/LLMs/validators via bindings.
- CAL writes:
  - claims to `findings_store` (for UI + persistence)
  - evidence to `evidence_store`
  - relationships to `KnowledgeGraph`

What CAL replaces:
- imperative “glue code” and ad-hoc orchestration

What CAL keeps:
- deterministic scanners and PoC execution code
- existing storage, UI, and analysis engines

---

# 18) What’s still open / intentionally hard
CAL is ambitious. Some non-trivial problems are part of the design space:

- Efficient rule evaluation at scale
- Preventing “confidence gaming” by agents
- Formal semantics for non-monotonic reasoning
- Good defaults for confidence algebra across diverse vulnerability classes
- A robust replay model (reproduce a mission against the same evidence)

CAL should make these issues visible, not hide them.

---

# 19) Glossary
- Agent: first-class actor that can observe/reason/validate under constraints
- Observation: raw fact emitted by an agent
- Evidence: provenance-bearing artifact supporting/refuting a claim
- Claim: versioned hypothesis with confidence and lifecycle status
- Rule: declarative collaboration/policy statement triggered by state changes
- Mission: CAL program (phased) that drives a security assessment
- Provenance: lineage metadata (who/when/how) for evidence and claim evolution

---

# 20) Next recommended docs to write (if you want)
If you want this to become a complete “language website” set of docs, split this guide into:
- Getting Started
- Language Tour
- Agent Binding Author Guide (Python)
- Rule Author Guide
- Security & Safeguards
- Reference Manual
- Cookbook (SSRF, IDOR, SQLi, auth bypass chains)
- Debugging / Replay

If you tell me whether you want CAL to be more “typed functional” vs “declarative logic with imperative escape hatches”, I can refine the guide and tighten the syntax into a coherent v0 grammar.
