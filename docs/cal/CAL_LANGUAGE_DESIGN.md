# CAL: Collaborative Agent Language
## A Programming Language for Multi-Agent Cybersecurity Reasoning

**Version:** 0.1 (Design Draft)  
**Author:** Sentinel Development Team  
**Date:** December 2025

---

# 1. Language Purpose & Philosophy

## 1.1 What Makes CAL a Language (Not a Framework)

CAL is a **new programming language** because the problem domain requires primitives that cannot be elegantly expressed in existing languages:

| Concept | Python/JS Expression | CAL Expression |
|---------|---------------------|----------------|
| Belief | `confidence = 0.7` (loses history) | `claim.confidence` (immutable audit trail) |
| Agent collaboration | Callbacks, queues, if-else | First-class `when` rules |
| Evidence lineage | Manual logging | Automatic provenance graph |
| Hypothesis evolution | State mutation | Temporal claim versioning |

**CAL is not:**
- A DSL embedded in Python (no `exec()` tricks)
- A configuration language (it has control flow and computation)
- A workflow engine (agents reason, not just execute)

**CAL is:**
- A language where **beliefs are values** (not booleans)
- A language where **agents are subjects** (not objects/services)
- A language where **evidence is first-class** (not logging side-effects)

## 1.2 Mental Model

Users should think of CAL programs as **argumentation protocols** between specialized agents, not procedural code.

```
Traditional: "Execute A, then B, then decide C"
CAL:         "Agent A observes X. Agent B challenges. Agent C validates. Belief emerges."
```

The programmer's job is to:
1. Define agents and their authorities
2. Declare what claims can be made
3. Specify collaboration rules (when agents must engage)
4. Let the runtime handle evidence tracking, conflict resolution, and audit trails

## 1.3 Core Insight

Security findings are not booleans—they are **contested beliefs** that evolve through:
- **Observation** (scanner sees something)
- **Interpretation** (AI assigns meaning)
- **Challenge** (another agent disagrees)
- **Validation** (exploit confirms or refutes)
- **Adjudication** (confidence settles to a stable value)

CAL makes this explicit in the language itself.

---

# 2. Core Abstractions

## 2.1 Agents

Agents are the primary actors in CAL. Each agent has:

```cal
agent Scanner::Nmap {
    role: observer
    authority: [assert_observation]
    trust: 0.6
    
    capabilities {
        port_scan(target: Host) -> Observation
        service_detect(target: Host, port: Port) -> Observation
    }
    
    constraints {
        max_concurrent: 10
        requires_scope: true
    }
}

agent Reasoner::LLM {
    role: semantic_reasoner
    authority: [interpret, strengthen, weaken]
    trust: 0.7
    model: "sentinel-vuln-v3"
    
    capabilities {
        interpret(obs: Observation) -> Hypothesis
        correlate(claims: Claim[]) -> AttackPath
        explain(claim: Claim) -> Narrative
    }
    
    constraints {
        max_tokens_per_call: 4096
        requires_evidence: true  // Cannot reason without grounding
    }
}

agent Validator::ExploitRunner {
    role: validator
    authority: [validate, invalidate, confirm]
    trust: 0.95
    
    capabilities {
        validate(claim: Claim) -> ValidationResult
        generate_poc(vuln: VulnType, target: Target) -> Exploit
    }
    
    constraints {
        requires_authorization: true
        execution_sandbox: true
    }
}
```

### Agent Properties

| Property | Type | Description |
|----------|------|-------------|
| `role` | enum | One of: `observer`, `pattern_detector`, `semantic_reasoner`, `validator`, `orchestrator` |
| `authority` | Permission[] | What belief operations the agent can perform |
| `trust` | float (0.0-1.0) | Base trust coefficient for confidence calculations |
| `capabilities` | function[] | What the agent can do |
| `constraints` | rule[] | Limits on agent behavior |

### Authority Permissions

- `assert_observation` — Can create raw observations
- `assert_hypothesis` — Can create initial claims
- `interpret` — Can assign semantic meaning to observations
- `strengthen` — Can increase confidence in a claim
- `weaken` — Can decrease confidence in a claim
- `challenge` — Can mark a claim as contested
- `validate` — Can perform validation (requires proof)
- `invalidate` — Can mark a claim as false (requires proof)
- `confirm` — Can mark a claim as confirmed (requires validation)
- `retract` — Can remove their own assertions

## 2.2 Claims & Hypotheses

Claims are the central data type in CAL. They are **immutable versioned records** of beliefs.

```cal
// Declaring a claim type
claim_type SQLInjection {
    target: Endpoint
    parameter: String
    payload: String?
    
    severity_range: [MEDIUM, CRITICAL]
    requires_validation: true
}

claim_type OpenPort {
    target: Host
    port: PortNumber
    service: Service?
    
    severity_range: [INFO, LOW]
    requires_validation: false
}

// Creating a claim (runtime)
let sqli_claim = claim SQLInjection {
    target: endpoint("/login"),
    parameter: "username",
    confidence: 0.35,
    asserted_by: agent::Regex,
    evidence: [regex_match_001]
}
```

### Claim Lifecycle

```
HYPOTHESIZED → STRENGTHENED → CHALLENGED → VALIDATED → CONFIRMED
                    ↓              ↓            ↓
                 WEAKENED      CONTESTED    INVALIDATED
                    ↓              ↓            ↓
                DISMISSED      PENDING      REFUTED
```

### Claim Properties (Built-in)

Every claim automatically has:

```cal
claim.id: UUID                      // Immutable identifier
claim.version: Int                  // Increments on each modification
claim.status: ClaimStatus           // Current lifecycle state
claim.confidence: Confidence        // Computed from evidence
claim.asserted_by: Agent            // Who made the initial claim
claim.evidence: Evidence[]          // All supporting/refuting evidence
claim.history: ClaimEvent[]         // Full audit trail
claim.created_at: Timestamp
claim.updated_at: Timestamp
```

## 2.3 Confidence

Confidence is not a raw float—it's a **computed, auditable value**.

```cal
type Confidence {
    value: Float[0.0, 1.0]          // Current confidence
    components: ConfidenceSource[]  // How it was computed
    
    // Confidence is computed from:
    // - Agent trust (who asserted)
    // - Evidence weight (what supports it)
    // - Corroboration (other claims that align)
    // - Validation status (has it been tested)
}

type ConfidenceSource {
    agent: Agent
    contribution: Float
    evidence: Evidence?
    reason: String
}
```

### Confidence Algebra

Confidence combines using explicit rules:

```cal
// Default confidence computation (can be overridden)
confidence_model Default {
    // Base confidence from asserting agent's trust
    base(claim) = claim.asserted_by.trust * 0.5
    
    // Evidence contribution
    evidence_boost(claim) = sum(
        for e in claim.evidence:
            e.weight * e.source.trust
    ) / max_evidence_weight
    
    // Corroboration from other claims
    corroboration(claim) = 
        let related = claims_supporting(claim)
        in 0.1 * min(len(related), 3)
    
    // Validation multiplier
    validation_mult(claim) = match claim.status {
        VALIDATED => 1.5
        INVALIDATED => 0.1
        _ => 1.0
    }
    
    // Final computation
    compute(claim) = clamp(0.0, 1.0,
        (base(claim) + evidence_boost(claim) + corroboration(claim)) 
        * validation_mult(claim)
    )
}
```

## 2.4 Evidence

Evidence is a first-class citizen that links observations to claims.

```cal
evidence_type RawOutput {
    tool: ToolName
    stdout: String
    stderr: String
    exit_code: Int
    captured_at: Timestamp
}

evidence_type PatternMatch {
    pattern: Regex
    matched_text: String
    location: SourceLocation
    context: String
}

evidence_type LLMAnalysis {
    model: ModelName
    prompt_hash: Hash
    response: String
    reasoning_trace: String[]
}

evidence_type ValidationResult {
    exploit_id: String
    executed: Bool
    success: Bool
    proof: Artifact?
}

// Creating evidence
let e1 = evidence RawOutput {
    tool: "nmap",
    stdout: raw_nmap_output,
    stderr: "",
    exit_code: 0
}

// Evidence automatically tracks provenance
e1.provenance.captured_by    // Agent that created it
e1.provenance.timestamp      // When
e1.provenance.integrity_hash // Tamper detection
```

### Evidence Weight

Evidence has weight based on its type and source:

```cal
evidence_weights {
    ValidationResult.success   => 0.9   // Exploit confirmed
    ValidationResult.failure   => -0.3  // Exploit failed
    PatternMatch              => 0.3    // Pattern matched
    LLMAnalysis               => 0.4    // AI interpreted
    RawOutput                 => 0.1    // Raw observation
}
```

## 2.5 Observations

Observations are raw facts before interpretation. They are distinct from claims.

```cal
observation_type PortOpen {
    host: IP
    port: PortNumber
    protocol: Protocol
}

observation_type HTTPResponse {
    url: URL
    status: Int
    headers: Map<String, String>
    body_preview: String
}

observation_type PatternFound {
    source: String
    pattern: Regex
    matches: String[]
    locations: SourceLocation[]
}
```

Observations become claims through **interpretation**:

```cal
rule Interpret_PortScan {
    when observation PortOpen(host, port, proto) by Scanner {
        // Scanner can create a basic claim
        Scanner may assert claim OpenPort {
            target: host,
            port: port,
            service: infer_service(port),
            confidence: 0.8
        }
    }
}
```

## 2.6 Rules & Policies

Rules define **when agents must interact**. This is declarative, not imperative.

```cal
// Collaboration rule
rule Require_LLM_Review {
    when Regex asserts claim[severity >= MEDIUM] {
        LLM must review within 10s
        claim.status = PENDING_REVIEW until reviewed
    }
}

// Validation rule  
rule Require_Validation_Before_Confirm {
    when claim.confidence >= 0.7 
     and claim.type.requires_validation 
     and claim.status != VALIDATED {
        
        Validator must validate before claim reaches CONFIRMED
        
        on timeout(60s) {
            claim.status = UNVALIDATED
            emit warning("Validation timeout for ${claim.id}")
        }
    }
}

// Escalation rule
rule Escalate_Critical {
    when claim.severity == CRITICAL 
     and claim.confidence >= 0.8 {
        
        Orchestrator must notify within 5s
        claim.escalated = true
    }
}

// Conflict resolution rule
rule Resolve_Conflicting_Agents {
    when exists claim c1 by Agent1
     and exists claim c2 by Agent2
     and c1.conflicts_with(c2) {
        
        // Higher trust agent wins, or escalate to human
        if Agent1.trust > Agent2.trust {
            weaken(c2, by: 0.2, reason: "lower trust agent")
        } else if Agent2.trust > Agent1.trust {
            weaken(c1, by: 0.2, reason: "lower trust agent")
        } else {
            mark_contested([c1, c2])
            Human must adjudicate
        }
    }
}
```

### Rule Semantics

Rules are evaluated **reactively** when their conditions become true. They are not procedural code.

| Keyword | Meaning |
|---------|---------|
| `when` | Trigger condition |
| `may` | Permission (optional action) |
| `must` | Requirement (mandatory action) |
| `before` | Temporal constraint (action required before state transition) |
| `within` | Time constraint |
| `on timeout` | Fallback if constraint violated |

---

# 3. Execution Model

## 3.1 Dual-Mode Execution

CAL programs can run in two modes:

### Reasoning Mode (Simulation)
```cal
mode reasoning {
    // No actual scans executed
    // External tools are mocked
    // LLM calls may use cached responses
    // Evidence is synthetic
    // Purpose: plan, analyze, what-if scenarios
}
```

### Execution Mode (Live)
```cal
mode execution {
    // Real tools run against targets
    // Real LLM inference
    // Real evidence collection
    // Real exploits (with safeguards)
    // Purpose: active security testing
}
```

The same program logic works in both modes:

```cal
@mode(reasoning)
mission TestSQL(target: Endpoint) {
    // In reasoning mode: simulates what would happen
    // In execution mode: actually runs scans
    
    let scan_result = Scanner.probe(target)
    // ...
}
```

## 3.2 Event-Driven Reactive Core

CAL's runtime is not a traditional imperative executor. It's an **event loop** that:

1. Receives events (observations, claims, agent actions)
2. Evaluates rules against current state
3. Triggers required agent actions
4. Updates the belief state
5. Records everything to the audit log

```
┌─────────────────────────────────────────────────────────────┐
│                     CAL Runtime                              │
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  Event   │───▶│   Rule   │───▶│  Agent   │              │
│  │  Queue   │    │  Engine  │    │ Dispatch │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       ▲               │               │                     │
│       │               ▼               ▼                     │
│       │         ┌──────────┐    ┌──────────┐              │
│       │         │  Belief  │    │ Evidence │              │
│       └─────────│  State   │◀───│   Store  │              │
│                 └──────────┘    └──────────┘              │
│                       │                                     │
│                       ▼                                     │
│                 ┌──────────┐                               │
│                 │  Audit   │                               │
│                 │   Log    │                               │
│                 └──────────┘                               │
└─────────────────────────────────────────────────────────────┘
```

## 3.3 Temporal Semantics

Claims exist in time. CAL supports temporal queries:

```cal
// Current confidence
claim.confidence

// Confidence at a specific time
claim.confidence @ timestamp("2024-01-15T10:30:00Z")

// Confidence history
claim.confidence.history

// When confidence crossed a threshold
claim.confidence.when(>= 0.7)

// Claims that existed at a point in time
claims @ timestamp("2024-01-15T10:30:00Z")
```

## 3.4 Missions (Programs)

A **mission** is a CAL program that orchestrates a security assessment:

```cal
mission FullAssessment(target: Target, scope: Scope) {
    
    // Phase 1: Reconnaissance
    phase Recon {
        Scanner::Nmap.port_scan(target)
        Scanner::Httpx.probe(target.http_endpoints)
        
        await all_observations_processed
    }
    
    // Phase 2: Analysis
    phase Analyze {
        Reasoner::LLM.correlate(current_claims)
        
        // Rules automatically trigger based on findings
        await claims.stable  // Wait for confidence to settle
    }
    
    // Phase 3: Validation (conditional)
    phase Validate when high_confidence_claims.exists {
        for claim in high_confidence_claims {
            if claim.type.requires_validation {
                Validator.validate(claim)
            }
        }
        
        await all_validations_complete
    }
    
    // Phase 4: Reporting
    phase Report {
        let report = Reasoner::LLM.generate_report(confirmed_claims)
        emit artifact(report, type: "assessment_report")
    }
}
```

---

# 4. Type System

## 4.1 Base Types

```cal
// Primitives
type Int, Float, Bool, String

// Security-specific primitives
type IP          // Validated IP address
type Host        // IP or hostname
type Port        // 0-65535
type URL         // Validated URL
type Endpoint    // URL + method + parameters
type Hash        // Cryptographic hash

// Constrained types
type PortNumber = Int where 0 <= self <= 65535
type Confidence = Float where 0.0 <= self <= 1.0
type Severity = enum { INFO, LOW, MEDIUM, HIGH, CRITICAL }

// Collection types
type List<T>
type Set<T>
type Map<K, V>
```

## 4.2 Security-Specific Types

```cal
type Target = Host | Endpoint | Network | Application

type VulnType = enum {
    SQLInjection,
    XSS,
    SSRF,
    IDOR,
    AuthBypass,
    RCE,
    InfoDisclosure,
    // ... extensible
}

type ClaimStatus = enum {
    HYPOTHESIZED,
    STRENGTHENED,
    WEAKENED,
    CHALLENGED,
    CONTESTED,
    PENDING_REVIEW,
    PENDING_VALIDATION,
    VALIDATED,
    INVALIDATED,
    CONFIRMED,
    REFUTED,
    DISMISSED
}
```

## 4.3 Type Safety Rules

The compiler enforces:

1. **Agent authority matching**: An agent cannot perform actions outside its authority
   ```cal
   // Compile error: Regex does not have 'confirm' authority
   Regex.confirm(some_claim)
   ```

2. **Evidence grounding**: Claims with `requires_validation: true` cannot reach CONFIRMED without validation evidence
   ```cal
   // Compile error: SQLInjection requires validation evidence
   claim.status = CONFIRMED  // Only allowed after Validator attaches evidence
   ```

3. **Confidence bounds**: Confidence is always in [0.0, 1.0]
   ```cal
   // Compile error: confidence out of bounds
   claim.confidence = 1.5
   ```

4. **Scope enforcement**: Targets must be within declared scope
   ```cal
   mission Test(scope: Scope) {
       // Runtime error if target not in scope
       Scanner.scan(out_of_scope_host)  
   }
   ```

## 4.4 Type Inference

CAL infers types where unambiguous:

```cal
let claim = claim SQLInjection { ... }  // Type: Claim<SQLInjection>
let claims = query claims where severity >= HIGH  // Type: List<Claim>
```

---

# 5. Minimal Grammar Sketch

## 5.1 EBNF Grammar (Simplified)

```ebnf
program        = declaration* ;

declaration    = agent_decl 
               | claim_type_decl 
               | evidence_type_decl
               | rule_decl 
               | mission_decl
               | confidence_model_decl ;

agent_decl     = "agent" IDENT "::" IDENT "{" agent_body "}" ;
agent_body     = ("role:" role_type)?
                 ("authority:" "[" IDENT ("," IDENT)* "]")?
                 ("trust:" FLOAT)?
                 ("capabilities" "{" capability* "}")?
                 ("constraints" "{" constraint* "}")? ;

claim_type_decl = "claim_type" IDENT "{" field* claim_meta* "}" ;
field          = IDENT ":" type ;
claim_meta     = "severity_range:" "[" severity "," severity "]"
               | "requires_validation:" BOOL ;

evidence_type_decl = "evidence_type" IDENT "{" field* "}" ;

rule_decl      = "rule" IDENT "{" "when" condition "{" action* "}" "}" ;
condition      = expr ;
action         = agent_ref ("may" | "must") verb expr ("within" duration)?
               | "on" "timeout" "(" duration ")" "{" action* "}"
               | assignment
               | "emit" emit_type "(" expr ")" ;

mission_decl   = "mission" IDENT "(" params ")" "{" phase* "}" ;
phase          = "phase" IDENT ("when" condition)? "{" statement* "}" ;

statement      = let_stmt | expr_stmt | await_stmt | for_stmt | if_stmt ;
let_stmt       = "let" IDENT "=" expr ;
await_stmt     = "await" expr ;
for_stmt       = "for" IDENT "in" expr "{" statement* "}" ;
if_stmt        = "if" expr "{" statement* "}" ("else" "{" statement* "}")? ;

expr           = literal | IDENT | expr "." IDENT | expr "(" args ")"
               | "claim" IDENT "{" field_init* "}"
               | "evidence" IDENT "{" field_init* "}"
               | "query" query_expr
               | expr binop expr
               | "match" expr "{" match_arm* "}" ;

query_expr     = "claims" ("where" condition)? ("by" agent_ref)?
               | "evidence" ("where" condition)? ("for" claim_ref)? ;

type           = "Int" | "Float" | "Bool" | "String" 
               | "Claim" ("<" IDENT ">")? 
               | "Evidence" ("<" IDENT ">")?
               | "Agent"
               | IDENT
               | "List" "<" type ">"
               | "Map" "<" type "," type ">" ;
```

## 5.2 Complete Example: SQL Injection Detection Flow

```cal
// === Agent Definitions ===

agent Scanner::Httpx {
    role: observer
    authority: [assert_observation]
    trust: 0.7
    
    capabilities {
        probe(target: Host) -> List<Observation<HTTPResponse>>
    }
}

agent Detector::Regex {
    role: pattern_detector
    authority: [assert_hypothesis]
    trust: 0.5
    
    capabilities {
        scan(response: HTTPResponse, patterns: PatternSet) -> List<PatternMatch>
    }
}

agent Reasoner::Sentinel {
    role: semantic_reasoner
    authority: [interpret, strengthen, weaken, challenge]
    trust: 0.75
    model: "sentinel-vuln-v3"
    
    capabilities {
        analyze_sqli(matches: List<PatternMatch>, context: HTTPResponse) -> SQLiAnalysis
        explain(claim: Claim) -> Narrative
    }
}

agent Validator::SQLMap {
    role: validator
    authority: [validate, invalidate]
    trust: 0.95
    
    capabilities {
        test_injection(endpoint: Endpoint, parameter: String) -> ValidationResult
    }
    
    constraints {
        requires_authorization: true
        max_requests_per_target: 100
    }
}

// === Claim Types ===

claim_type PotentialSQLi {
    endpoint: Endpoint
    parameter: String
    evidence_pattern: String
    
    severity_range: [MEDIUM, CRITICAL]
    requires_validation: true
}

claim_type ConfirmedSQLi {
    endpoint: Endpoint
    parameter: String
    injection_type: String  // "error-based", "blind", "union", etc.
    database_type: String?
    
    severity_range: [HIGH, CRITICAL]
    requires_validation: true
}

// === Collaboration Rules ===

rule Regex_Asserts_Potential_SQLi {
    when Detector::Regex observes PatternMatch(
        pattern: sqli_patterns,
        matched_text: text,
        location: loc
    ) {
        Detector::Regex may assert claim PotentialSQLi {
            endpoint: loc.endpoint,
            parameter: loc.parameter,
            evidence_pattern: text,
            confidence: 0.35
        }
    }
}

rule LLM_Reviews_SQLi_Claims {
    when Detector::Regex asserts claim PotentialSQLi as c {
        Reasoner::Sentinel must review(c) within 30s
        
        on review_complete(analysis) {
            if analysis.likely_true_positive {
                Reasoner::Sentinel.strengthen(c, 
                    by: analysis.confidence_boost,
                    reason: analysis.reasoning
                )
            } else {
                Reasoner::Sentinel.weaken(c,
                    by: 0.2,
                    reason: analysis.reasoning
                )
            }
        }
    }
}

rule Validate_High_Confidence_SQLi {
    when claim PotentialSQLi as c 
     and c.confidence >= 0.65
     and c.status not in [VALIDATED, INVALIDATED] {
        
        Validator::SQLMap must validate(c) within 120s
        
        on validation_success(result) {
            // Upgrade to ConfirmedSQLi
            let confirmed = claim ConfirmedSQLi {
                endpoint: c.endpoint,
                parameter: c.parameter,
                injection_type: result.injection_type,
                database_type: result.database_type,
                confidence: 0.95,
                evidence: c.evidence + [result.proof]
            }
            
            emit claim_upgraded(from: c, to: confirmed)
        }
        
        on validation_failure(result) {
            Validator::SQLMap.invalidate(c, 
                reason: "Exploit attempt failed",
                evidence: result
            )
        }
        
        on timeout {
            c.status = UNVALIDATED
            emit warning("SQLi validation timed out for ${c.endpoint}")
        }
    }
}

rule Escalate_Confirmed_SQLi {
    when claim ConfirmedSQLi as c
     and c.status == VALIDATED
     and c.confidence >= 0.9 {
        
        Orchestrator must notify(
            severity: CRITICAL,
            claim: c,
            message: "Confirmed SQL Injection vulnerability"
        )
        
        c.status = CONFIRMED
    }
}

// === Mission Definition ===

mission SQLiAssessment(target: Host, scope: Scope) {
    
    phase Discovery {
        // Enumerate endpoints
        let responses = Scanner::Httpx.probe(target)
        
        // Run regex patterns on all responses
        for resp in responses {
            Detector::Regex.scan(resp, sqli_patterns)
        }
        
        await all_observations_processed
    }
    
    phase Analysis {
        // Rules automatically trigger LLM review
        // Wait for confidence to stabilize
        await claims.stable(timeout: 60s)
    }
    
    phase Validation when query claims PotentialSQLi 
                          where confidence >= 0.65 
                          exists {
        // Rules automatically trigger validation
        await all_validations_complete(timeout: 300s)
    }
    
    phase Reporting {
        let confirmed = query claims ConfirmedSQLi where status == CONFIRMED
        let potential = query claims PotentialSQLi where status != REFUTED
        
        let report = Reasoner::Sentinel.generate_report(
            confirmed: confirmed,
            potential: potential,
            include_evidence: true
        )
        
        emit artifact(report, type: "sqli_assessment")
    }
}
```

---

# 6. Runtime Architecture

## 6.1 Compilation Pipeline

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   .cal      │────▶│   Parser    │────▶│   Type      │────▶│  Optimizer  │
│   Source    │     │   (LALR)    │     │   Checker   │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                   │
                                                                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Runtime    │◀────│   Linker    │◀────│  Codegen    │◀────│    IR       │
│  (Python)   │     │  (FFI Bind) │     │  (Python)   │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

### Compilation Stages

1. **Parsing**: CAL source → AST
2. **Type Checking**: Validate types, authorities, constraints
3. **Optimization**: Rule deduplication, dead code elimination
4. **IR Generation**: CAL IR (intermediate representation)
5. **Code Generation**: Generate Python orchestration code
6. **Linking**: Bind to Sentinel's existing Python agents

## 6.2 Runtime Components

```python
# Conceptual Python runtime structure

class CALRuntime:
    def __init__(self):
        self.belief_state = BeliefState()      # All current claims
        self.evidence_store = EvidenceStore()  # All evidence
        self.audit_log = AuditLog()            # Immutable history
        self.rule_engine = RuleEngine()        # Evaluates rules
        self.agent_registry = AgentRegistry()  # Maps agent specs to implementations
        self.event_queue = EventQueue()        # Pending events
    
    def run_mission(self, mission: Mission, mode: ExecutionMode):
        """Execute a CAL mission."""
        for phase in mission.phases:
            if self._evaluate_phase_condition(phase):
                self._execute_phase(phase)
    
    def _execute_phase(self, phase: Phase):
        """Execute a mission phase."""
        for statement in phase.statements:
            self._execute_statement(statement)
            self._process_events()  # Process any triggered rules
    
    def _process_events(self):
        """Main event loop - evaluate rules and dispatch agent actions."""
        while not self.event_queue.empty():
            event = self.event_queue.pop()
            
            # Record to audit log
            self.audit_log.record(event)
            
            # Find matching rules
            triggered_rules = self.rule_engine.match(event, self.belief_state)
            
            # Execute rule actions
            for rule in triggered_rules:
                self._execute_rule(rule)
```

## 6.3 Agent Binding (FFI)

CAL agents map to Python implementations through a binding layer:

```python
# In Sentinel's Python codebase

from cal_runtime import AgentBinding, capability

@AgentBinding("Scanner::Nmap")
class NmapAgent:
    
    @capability("port_scan")
    async def port_scan(self, target: str) -> List[Observation]:
        """Maps to CAL's Scanner::Nmap.port_scan()"""
        # Actual nmap execution
        result = await self.scanner.run_nmap(target)
        
        # Convert to CAL observations
        observations = []
        for port in result.open_ports:
            observations.append(Observation(
                type="PortOpen",
                data={"host": target, "port": port.number, "protocol": port.proto}
            ))
        
        return observations


@AgentBinding("Reasoner::Sentinel")
class SentinelLLMAgent:
    
    @capability("analyze_sqli")
    async def analyze_sqli(self, matches: List[PatternMatch], context: HTTPResponse):
        """Maps to CAL's Reasoner::Sentinel.analyze_sqli()"""
        prompt = self._build_sqli_prompt(matches, context)
        response = await self.llm.generate(prompt)
        return self._parse_analysis(response)
```

## 6.4 Integration with Sentinel

CAL integrates with Sentinel's existing components:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            Sentinel                                      │
│                                                                          │
│  ┌─────────────┐   ┌─────────────────────────────────────────────────┐ │
│  │   SwiftUI   │   │              Python Backend                      │ │
│  │     UI      │   │                                                  │ │
│  │             │   │  ┌─────────────────────────────────────────┐    │ │
│  │  ┌───────┐  │   │  │           CAL Runtime                   │    │ │
│  │  │Report │  │◀──│──│  ┌──────────┐  ┌──────────┐            │    │ │
│  │  │Viewer │  │   │  │  │  Belief  │  │  Audit   │            │    │ │
│  │  └───────┘  │   │  │  │  State   │  │   Log    │            │    │ │
│  │             │   │  │  └────┬─────┘  └──────────┘            │    │ │
│  │  ┌───────┐  │   │  │       │                                 │    │ │
│  │  │ Graph │  │◀──│──│───────┘                                 │    │ │
│  │  │ View  │  │   │  │  ┌──────────────────────────────────┐  │    │ │
│  │  └───────┘  │   │  │  │       Agent Bindings             │  │    │ │
│  │             │   │  │  │  ┌────────┐ ┌────────┐ ┌───────┐ │  │    │ │
│  │  ┌───────┐  │   │  │  │  │Scanner │ │Reasoner│ │Validtr│ │  │    │ │
│  │  │Claims │  │◀──│──│  │  │ Nmap   │ │  LLM   │ │SQLMap │ │  │    │ │
│  │  │ View  │  │   │  │  │  └───┬────┘ └───┬────┘ └───┬───┘ │  │    │ │
│  │  └───────┘  │   │  │  └──────┼──────────┼──────────┼─────┘  │    │ │
│  │             │   │  └─────────┼──────────┼──────────┼────────┘    │ │
│  └─────────────┘   │            │          │          │             │ │
│                    │            ▼          ▼          ▼             │ │
│                    │  ┌─────────────┐ ┌─────────┐ ┌─────────┐       │ │
│                    │  │ScannerEngine│ │AIEngine │ │  Forge  │       │ │
│                    │  │  (Existing) │ │(Existing│ │(Existing│       │ │
│                    │  └─────────────┘ └─────────┘ └─────────┘       │ │
│                    │                                                 │ │
│                    │  ┌─────────────────────────────────────────┐   │ │
│                    │  │  KnowledgeGraph  (NetworkX - Existing)  │   │ │
│                    │  └─────────────────────────────────────────┘   │ │
│                    └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Migration Path

1. **Phase 1**: CAL runtime runs alongside existing Python orchestration
2. **Phase 2**: CAL programs compile to calls into existing ScannerEngine, AIEngine
3. **Phase 3**: Gradually replace imperative glue code with CAL rules
4. **Phase 4**: Full CAL-native operation with Python as the execution substrate

---

# 7. Failure Modes & Safeguards

## 7.1 False Positive Prevention

### Multi-Agent Consensus
Claims don't become CONFIRMED based on a single agent's opinion:

```cal
rule Require_Multiple_Sources {
    when claim c 
     and c.evidence.distinct_sources < 2
     and c.confidence >= 0.8 {
        
        // Prevent premature confirmation
        c.max_status = PENDING_VALIDATION
        emit warning("High confidence claim lacks corroborating sources")
    }
}
```

### Confidence Decay
Unvalidated claims decay over time:

```cal
confidence_model WithDecay {
    // ... base computation ...
    
    decay(claim) = match claim.age {
        < 1h => 1.0
        < 24h => 0.95
        < 7d => 0.8
        _ => 0.6
    }
    
    compute(claim) = base_compute(claim) * decay(claim)
}
```

### Pattern-Based False Positive Suppression

```cal
rule Suppress_Known_FP {
    when claim c matches known_false_positive_patterns {
        weaken(c, by: 0.5, reason: "Matches known FP pattern: ${pattern}")
        c.tags += ["potential_fp"]
    }
}
```

## 7.2 Scope & Authorization Enforcement

```cal
// Mission-level scope declaration
mission Assessment(target: Target, scope: Scope) {
    // Compile-time: All operations checked against scope
    // Runtime: Out-of-scope targets rejected
    
    constraints {
        scope.includes(target)  // Must be true
        scope.authorized_actions: [scan, probe, validate]  // Allowed actions
        scope.forbidden_actions: [exploit_for_impact]  // Never allowed
    }
}

// Agent-level authorization
agent Validator::ExploitRunner {
    constraints {
        requires_authorization: true
        authorization_callback: request_human_approval
    }
}

// Rule-level safeguards
rule Prevent_Unauthorized_Exploitation {
    when Validator attempts action 
     and action.type == "exploit"
     and not action.authorized {
        
        block action
        emit authorization_request(action)
        await human_decision(timeout: 300s)
    }
}
```

## 7.3 Reasoning Error Surfacing

CAL never hides reasoning failures—it makes them explicit:

### Conflict Detection

```cal
rule Surface_Conflicts {
    when exists claim c1 by Agent1
     and exists claim c2 by Agent2
     and c1.subject == c2.subject
     and c1.assertion != c2.assertion {
        
        // Don't silently resolve—surface the conflict
        emit conflict_detected(
            claims: [c1, c2],
            agents: [Agent1, Agent2],
            subject: c1.subject
        )
        
        mark_contested([c1, c2])
    }
}
```

### Uncertainty Tracking

```cal
// Claims track their own uncertainty
claim.uncertainty = {
    epistemic: Float,     // Lack of knowledge
    aleatoric: Float,     // Inherent randomness
    model: Float          // Model limitations
}

rule Flag_High_Uncertainty {
    when claim c
     and (c.uncertainty.epistemic > 0.5 
          or c.uncertainty.model > 0.4) {
        
        c.tags += ["high_uncertainty"]
        emit needs_human_review(c, reason: "High uncertainty")
    }
}
```

### Audit Trail Queries

```cal
// Why does this claim exist?
query claim.history where action in [assert, strengthen, weaken]

// What evidence supports this?
query claim.evidence

// What agent actions led to this state?
query audit_log where affects(claim.id) order by timestamp

// Reproduce the reasoning chain
Reasoner::Sentinel.explain(claim)
```

## 7.4 Runtime Invariants

The CAL runtime enforces these invariants:

1. **Monotonic Evidence**: Evidence can only be added, never deleted
2. **Immutable History**: Claim history cannot be modified
3. **Authority Enforcement**: Agents cannot exceed their authority
4. **Scope Containment**: All operations stay within declared scope
5. **Confidence Bounds**: Confidence is always in [0.0, 1.0]
6. **Temporal Consistency**: Events are ordered; no causal paradoxes

Violations cause runtime errors, not silent failures:

```cal
// This throws RuntimeError, not silent corruption
claim.history.pop()  // Error: Immutable history

// This throws AuthorityError
Detector::Regex.confirm(claim)  // Error: Regex lacks 'confirm' authority
```

---

# 8. Integration with Sentinel

## 8.1 Mapping to Existing Components

| CAL Concept | Sentinel Component | Integration |
|-------------|-------------------|-------------|
| Belief State | `findings_store` | CAL writes claims to findings_store |
| Evidence Store | `evidence_store` | CAL writes evidence to evidence_store |
| Knowledge Graph | `cortex/memory.py` | CAL syncs claims to KnowledgeGraph nodes |
| Agent::Scanner | `ScannerEngine` | CAL binds to existing tool runners |
| Agent::Reasoner | `AIEngine` | CAL binds to existing LLM integration |
| Agent::Validator | `forge/compiler.py` | CAL binds to exploit validation |
| Rule Engine | (New) | Replaces imperative orchestration |
| Audit Log | (New) | New component for lineage tracking |

## 8.2 Example: Converting Current Flow to CAL

**Current (Python imperative):**
```python
# orchestrator.py
async def _mission_loop(self, target, mission_id):
    await self._run_recon(target)
    analysis = reasoning_engine.analyze()
    opportunities = analysis.get("opportunities", [])
    await self._engage_targets(target, opportunities)
```

**CAL equivalent:**
```cal
mission Standard(target: Target) {
    phase Recon {
        Scanner::Nmap.port_scan(target)
        Scanner::Httpx.probe(target)
        await all_observations_processed
    }
    
    phase Analyze {
        Reasoner::Sentinel.correlate(current_claims)
        await claims.stable
    }
    
    phase Engage when opportunities.exists {
        for op in opportunities {
            match op.tool {
                "nikto" => Scanner::Nikto.scan(op.target)
                "nuclei" => Scanner::Nuclei.scan(op.target, op.templates)
                "sqlmap" => Validator::SQLMap.test(op.target)
            }
        }
    }
}
```

## 8.3 UI Integration

CAL's audit log and belief state enable new UI capabilities:

### Claim Timeline View
```
[10:30:15] Regex asserted PotentialSQLi (confidence: 0.35)
[10:30:18] LLM reviewed → strengthened to 0.68
[10:30:45] SQLMap validation started
[10:31:22] SQLMap validation succeeded → upgraded to ConfirmedSQLi (0.95)
[10:31:23] Claim confirmed, notification sent
```

### Evidence Provenance Graph
```
ConfirmedSQLi (confidence: 0.95)
├── Evidence: ValidationResult (SQLMap, success=true, weight=0.9)
├── Evidence: LLMAnalysis (reasoning trace, weight=0.4)
└── Evidence: PatternMatch (sqli_pattern, weight=0.3)
    └── Source: HTTPResponse from Scanner::Httpx
```

### Explainability Panel
```
Why does this claim exist?

1. Scanner::Httpx observed HTTP response at /login (10:30:12)
2. Detector::Regex matched pattern: .*error.*SQL.* (10:30:15)
3. Reasoner::Sentinel analyzed: "Error message reveals SQL syntax, 
   suggesting unsanitized input" (10:30:18)
4. Validator::SQLMap confirmed: Union-based injection successful (10:31:22)

Confidence breakdown:
- Base trust (Regex): 0.175
- Evidence weight: 0.425
- Corroboration: 0.1
- Validation multiplier: 1.5
- Final: 0.95
```

---

# 9. Critical Assessment: Risks & Unknowns

## 9.1 Technical Risks

### Risk: Performance of Rule Evaluation
**Severity: Medium**

Reactive rule evaluation could become a bottleneck with many claims and complex rules.

**Mitigation:**
- Rule indexing by trigger type
- Incremental evaluation (only re-evaluate affected rules)
- Rule compilation to efficient match predicates
- Configurable rule evaluation limits

### Risk: LLM Latency in Critical Paths
**Severity: High**

If rules require LLM reasoning, mission execution could be slow.

**Mitigation:**
- Async rule evaluation (don't block on LLM)
- Tiered rules: fast heuristic rules first, LLM rules async
- Caching of LLM analyses for similar contexts
- Configurable timeouts with fallback actions

### Risk: State Explosion in Belief Store
**Severity: Medium**

Long-running assessments could accumulate thousands of claims.

**Mitigation:**
- Claim archiving (old, low-confidence claims moved to cold storage)
- Garbage collection for refuted/dismissed claims
- Bounded history depth with summarization

## 9.2 Semantic Risks

### Risk: Confidence Model Gaming
**Severity: Medium**

Agents could theoretically manipulate confidence through strategic assertions.

**Mitigation:**
- Authority limits (agents can only boost confidence by limited amounts)
- Anomaly detection on confidence changes
- Human oversight requirements for critical claims

### Risk: Rule Deadlocks
**Severity: Low**

Circular rule dependencies could cause infinite loops.

**Mitigation:**
- Compile-time cycle detection
- Runtime evaluation depth limits
- Deadlock detection and circuit breaking

### Risk: Agent Trust Drift
**Severity: Medium**

If an agent (especially an LLM) becomes unreliable, trust scores may not reflect reality.

**Mitigation:**
- Continuous trust calibration based on validation outcomes
- Trust decay for agents that aren't validated
- Manual trust overrides

## 9.3 Integration Risks

### Risk: Impedance Mismatch with Python
**Severity: Medium**

CAL's reactive model may not map cleanly to Python's imperative style.

**Mitigation:**
- Generate idiomatic Python (async/await, callbacks)
- Provide clear debugging tools (step-through execution)
- Allow escape hatches to raw Python for edge cases

### Risk: Migration Complexity
**Severity: High**

Converting existing Sentinel logic to CAL is non-trivial.

**Mitigation:**
- Gradual migration: CAL and Python coexist
- Start with new features in CAL
- Provide migration tooling (Python → CAL patterns)

## 9.4 Open Research Questions

1. **Optimal Confidence Algebra**: How should confidence combine from multiple sources? Current model is a heuristic; may need formal grounding.

2. **Temporal Claim Reasoning**: How to handle claims about past states? (e.g., "This was vulnerable last week")

3. **Multi-Target Correlation**: How to express claims that span multiple targets? (e.g., "SSRF on A can reach internal service B")

4. **Adversarial Robustness**: Can an adversary manipulate scan results to cause false negatives?

5. **Formal Verification**: Can we prove that certain rule sets guarantee desired properties?

---

# 10. Implementation Roadmap

## Phase 1: Foundation (Weeks 1-4)
- [ ] CAL lexer and parser (Python, using PLY or Lark)
- [ ] AST definition and type checker
- [ ] Basic runtime with belief state and evidence store
- [ ] Single-agent execution (no collaboration rules yet)

## Phase 2: Core Language (Weeks 5-8)
- [ ] Rule engine with reactive evaluation
- [ ] Multi-agent collaboration
- [ ] Confidence computation
- [ ] Audit log implementation

## Phase 3: Sentinel Integration (Weeks 9-12)
- [ ] Agent bindings for ScannerEngine, AIEngine
- [ ] KnowledgeGraph synchronization
- [ ] UI integration (claim view, timeline, provenance)
- [ ] First real mission: port scan → analysis → report

## Phase 4: Production Hardening (Weeks 13-16)
- [ ] Performance optimization
- [ ] Error handling and recovery
- [ ] Documentation and examples
- [ ] Migration tooling for existing Sentinel logic

---

# Appendix A: Comparison with Existing Approaches

| Approach | Strengths | Weaknesses | CAL Improvement |
|----------|-----------|------------|-----------------|
| **Python orchestration** | Flexible, familiar | No epistemic model, imperative glue | Claims, evidence, rules |
| **YAML workflows** | Declarative | No reasoning, no confidence | Full language with computation |
| **Prolog/Datalog** | Logic programming | No agents, no time | Agent-first, temporal |
| **BPMN/workflow engines** | Visual, enterprise | No security semantics | Domain-specific abstractions |
| **LLM agents (AutoGPT)** | Autonomous | Opaque, no auditability | Explainable, auditable |

---

# Appendix B: Glossary

- **Agent**: A specialized actor that can observe, reason, or validate
- **Claim**: A versioned, confidence-bearing assertion about a security property
- **Confidence**: A computed value representing belief strength
- **Evidence**: Grounding data that supports or refutes a claim
- **Mission**: A CAL program that orchestrates a security assessment
- **Observation**: A raw fact before interpretation
- **Rule**: A declarative specification of when agents must interact
- **Belief State**: The current set of all claims and their statuses

---

# Appendix C: Full Type Reference

```cal
// Base types
type Int
type Float
type Bool
type String
type Timestamp
type Duration
type UUID
type Hash

// Constrained types
type PortNumber = Int where 0 <= self <= 65535
type Confidence = Float where 0.0 <= self <= 1.0
type Trust = Float where 0.0 <= self <= 1.0

// Enums
type Severity = enum { INFO, LOW, MEDIUM, HIGH, CRITICAL }
type ClaimStatus = enum { 
    HYPOTHESIZED, STRENGTHENED, WEAKENED, CHALLENGED, CONTESTED,
    PENDING_REVIEW, PENDING_VALIDATION, VALIDATED, INVALIDATED,
    CONFIRMED, REFUTED, DISMISSED, UNVALIDATED
}
type Role = enum { observer, pattern_detector, semantic_reasoner, validator, orchestrator }
type ExecutionMode = enum { reasoning, execution }

// Collections
type List<T>
type Set<T>
type Map<K, V>
type Option<T> = T | None

// Security primitives
type IP
type Host = IP | String
type Port = PortNumber
type Protocol = enum { tcp, udp }
type URL
type Endpoint = { url: URL, method: String, params: Map<String, String> }
type Target = Host | Endpoint | Network | Application
type Network = { cidr: String }
type Application = { name: String, version: String? }

// Core CAL types
type Agent = { id: String, role: Role, authority: List<Permission>, trust: Trust }
type Permission = enum { 
    assert_observation, assert_hypothesis, interpret, 
    strengthen, weaken, challenge, validate, invalidate, confirm, retract 
}

type Claim<T> = {
    id: UUID,
    version: Int,
    type: T,
    status: ClaimStatus,
    confidence: Confidence,
    asserted_by: Agent,
    evidence: List<Evidence>,
    history: List<ClaimEvent>,
    tags: Set<String>,
    created_at: Timestamp,
    updated_at: Timestamp
}

type Evidence<T> = {
    id: UUID,
    type: T,
    data: T,
    weight: Float,
    provenance: Provenance,
    integrity_hash: Hash
}

type Provenance = {
    captured_by: Agent,
    timestamp: Timestamp,
    source: String
}

type ClaimEvent = {
    timestamp: Timestamp,
    agent: Agent,
    action: ClaimAction,
    before: ClaimSnapshot,
    after: ClaimSnapshot,
    reason: String
}

type ClaimAction = enum { 
    asserted, strengthened, weakened, challenged, reviewed,
    validated, invalidated, confirmed, refuted, retracted 
}

type Observation<T> = {
    id: UUID,
    type: T,
    data: T,
    observed_by: Agent,
    timestamp: Timestamp
}
```

---

**End of CAL Language Design Document**
