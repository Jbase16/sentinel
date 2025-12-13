# CAL Examples
## Real-World Security Assessment Scenarios in CAL

---

## Example 1: SSRF Detection with Confidence Evolution

This example shows how a potential SSRF vulnerability evolves from initial detection to confirmed finding.

```cal
// === Claim Types ===

claim_type PotentialSSRF {
    endpoint: Endpoint
    parameter: String
    observed_behavior: String
    
    severity_range: [MEDIUM, HIGH]
    requires_validation: true
}

claim_type ConfirmedSSRF {
    endpoint: Endpoint
    parameter: String
    reachable_targets: List<String>
    impact: String
    
    severity_range: [HIGH, CRITICAL]
    requires_validation: true
}

// === Evidence Types ===

evidence_type OutOfBandInteraction {
    callback_id: String
    source_ip: IP
    timestamp: Timestamp
    request_data: String
}

evidence_type InternalServiceResponse {
    target_url: URL
    response_code: Int
    response_body_preview: String
}

// === Collaboration Rules ===

rule Detect_SSRF_Indicators {
    when Detector::Regex observes PatternMatch(
        pattern: ssrf_patterns,
        matched_text: text,
        location: loc
    ) {
        // Low initial confidence - regex alone isn't conclusive
        Detector::Regex may assert claim PotentialSSRF {
            endpoint: loc.endpoint,
            parameter: loc.parameter,
            observed_behavior: text,
            confidence: 0.25
        }
    }
}

rule LLM_Analyzes_SSRF_Context {
    when Detector::Regex asserts claim PotentialSSRF as c {
        Reasoner::Sentinel must analyze_ssrf(c) within 45s
        
        on analysis_complete(result) {
            if result.indicates_user_controlled_url {
                Reasoner::Sentinel.strengthen(c,
                    by: 0.25,
                    reason: "Parameter appears to accept user-controlled URLs"
                )
            }
            
            if result.indicates_internal_routing {
                Reasoner::Sentinel.strengthen(c,
                    by: 0.15,
                    reason: "Response suggests internal service routing"
                )
            }
            
            if result.likely_false_positive {
                Reasoner::Sentinel.weaken(c,
                    by: 0.3,
                    reason: result.fp_reason
                )
            }
        }
    }
}

rule Validate_SSRF_With_Callback {
    when claim PotentialSSRF as c
     and c.confidence >= 0.5
     and c.status not in [VALIDATED, INVALIDATED] {
        
        Validator::CallbackServer must test_oob(c) within 60s
        
        on callback_received(evidence: OutOfBandInteraction) {
            // Strong evidence - we got an out-of-band callback
            c.evidence += [evidence]
            Validator::CallbackServer.strengthen(c,
                by: 0.4,
                reason: "Received out-of-band HTTP callback"
            )
            c.status = VALIDATED
        }
        
        on timeout {
            // No callback doesn't mean no SSRF - could be blind
            c.tags += ["blind_ssrf_possible"]
        }
    }
}

rule Validate_SSRF_Internal_Access {
    when claim PotentialSSRF as c
     and c.status == VALIDATED
     and c.confidence >= 0.75 {
        
        Validator::SSRFProber must probe_internal(c) within 120s
        
        on internal_access_confirmed(evidence: InternalServiceResponse) {
            // Upgrade to confirmed SSRF
            let confirmed = claim ConfirmedSSRF {
                endpoint: c.endpoint,
                parameter: c.parameter,
                reachable_targets: evidence.discovered_services,
                impact: classify_impact(evidence),
                confidence: 0.95,
                evidence: c.evidence + [evidence]
            }
            
            emit claim_upgraded(from: c, to: confirmed)
        }
    }
}

// === Mission ===

mission SSRFAssessment(target: Host, scope: Scope) {
    
    phase Crawl {
        let endpoints = Scanner::Crawler.discover_endpoints(target)
        let parameterized = endpoints.filter(e => e.has_url_parameters)
        
        await all_observations_processed
    }
    
    phase Detect {
        for endpoint in parameterized_endpoints {
            Detector::Regex.scan(endpoint.responses, ssrf_patterns)
        }
        
        await claims.stable(timeout: 60s)
    }
    
    phase Validate when query claims PotentialSSRF where confidence >= 0.5 exists {
        // Spawn callback server
        let callback_server = Validator::CallbackServer.start()
        
        // Rules handle validation automatically
        await all_validations_complete(timeout: 180s)
        
        callback_server.stop()
    }
    
    phase DeepDive when query claims ConfirmedSSRF exists {
        // For confirmed SSRF, probe for cloud metadata
        for claim in confirmed_ssrf_claims {
            Validator::SSRFProber.probe_cloud_metadata(claim)
        }
        
        await all_probes_complete
    }
}
```

### Claim Evolution Timeline

```
T+0s:    Regex matches URL parameter pattern
         → PotentialSSRF asserted (confidence: 0.25)

T+5s:    LLM analyzes request/response context
         → Strengthened by 0.25 ("user-controlled URL")
         → Confidence now: 0.50

T+10s:   Callback test initiated

T+35s:   Out-of-band callback received
         → Strengthened by 0.40, status = VALIDATED
         → Confidence now: 0.90

T+45s:   Internal service probe discovers metadata endpoint
         → Upgraded to ConfirmedSSRF (confidence: 0.95)
         → Impact: "Cloud metadata accessible"
```

---

## Example 2: Authentication Bypass Chain

This example shows multi-claim correlation where multiple weak signals combine into a strong finding.

```cal
// === Claim Types ===

claim_type WeakSessionHandling {
    target: Host
    observation: String
    severity_range: [LOW, MEDIUM]
    requires_validation: false
}

claim_type InsecureCookieConfig {
    target: Host
    cookie_name: String
    missing_flags: List<String>
    severity_range: [LOW, MEDIUM]
    requires_validation: false
}

claim_type SessionFixation {
    target: Host
    endpoint: Endpoint
    severity_range: [MEDIUM, HIGH]
    requires_validation: true
}

claim_type AuthenticationBypass {
    target: Host
    bypass_method: String
    affected_endpoints: List<Endpoint>
    severity_range: [HIGH, CRITICAL]
    requires_validation: true
}

// === Correlation Rules ===

// When we see multiple weak signals, correlate them
rule Correlate_Auth_Weaknesses {
    when exists claim WeakSessionHandling as c1 on target T
     and exists claim InsecureCookieConfig as c2 on target T
     and c1.confidence >= 0.5
     and c2.confidence >= 0.5 {
        
        // Ask LLM to analyze the combination
        Reasoner::Sentinel must correlate_auth_signals([c1, c2]) within 30s
        
        on correlation_found(attack_path) {
            // Create hypothesis about session fixation
            Reasoner::Sentinel may assert claim SessionFixation {
                target: T,
                endpoint: attack_path.entry_point,
                confidence: 0.6,  // Higher than individual claims
                evidence: [c1, c2, attack_path]
            }
        }
    }
}

rule Escalate_To_Auth_Bypass {
    when exists claim SessionFixation as c1
     and c1.status == VALIDATED
     and exists claim InsecureCookieConfig as c2
     where c2.missing_flags contains "HttpOnly" {
        
        // This combination often means full auth bypass
        Reasoner::Sentinel must analyze_bypass_potential([c1, c2]) within 45s
        
        on bypass_likely(analysis) {
            Reasoner::Sentinel may assert claim AuthenticationBypass {
                target: c1.target,
                bypass_method: analysis.method,
                affected_endpoints: analysis.endpoints,
                confidence: 0.7,
                evidence: [c1, c2, analysis]
            }
        }
    }
}

rule Validate_Auth_Bypass {
    when claim AuthenticationBypass as c
     and c.confidence >= 0.7
     and c.status != VALIDATED {
        
        Validator::AuthTester must test_bypass(c) within 180s
        
        on bypass_successful(proof) {
            c.evidence += [proof]
            c.confidence = 0.95
            c.status = VALIDATED
            
            emit critical_finding(c, 
                message: "Authentication bypass confirmed"
            )
        }
        
        on bypass_failed(result) {
            Validator::AuthTester.weaken(c,
                by: 0.3,
                reason: "Bypass attempt unsuccessful"
            )
        }
    }
}

// === Confidence Model for Correlated Claims ===

confidence_model AuthCorrelation {
    // Correlated claims get confidence boost
    correlation_boost(claims) = 
        let overlap = claims.filter(c => c.target == claims[0].target)
        let boost = 0.1 * min(len(overlap), 4)
        in boost
    
    // Claims on the same attack chain reinforce each other
    attack_chain_boost(claim) =
        let chain = find_attack_chain(claim)
        in if len(chain) >= 3 then 0.2 else 0.0
    
    compute(claim) = clamp(0.0, 1.0,
        base_compute(claim) 
        + correlation_boost(related_claims(claim))
        + attack_chain_boost(claim)
    )
}
```

### Multi-Claim Correlation Visualization

```
        WeakSessionHandling           InsecureCookieConfig
        (confidence: 0.6)             (confidence: 0.7)
                    \                    /
                     \                  /
                      ▼                ▼
               ┌─────────────────────────┐
               │    LLM Correlation      │
               │    "These combine to    │
               │    enable attack X"     │
               └───────────┬─────────────┘
                           │
                           ▼
                  SessionFixation
                  (confidence: 0.6)
                           │
                    [VALIDATED]
                           │
                           ▼
               ┌─────────────────────────┐
               │   Combined with         │
               │   missing HttpOnly      │
               └───────────┬─────────────┘
                           │
                           ▼
               AuthenticationBypass
               (confidence: 0.7 → 0.95 after validation)
```

---

## Example 3: API Security Assessment

Comprehensive API testing with multiple agent types.

```cal
// === Agent Definitions ===

agent Scanner::OpenAPIParser {
    role: observer
    authority: [assert_observation]
    trust: 0.8
    
    capabilities {
        parse_spec(url: URL) -> APISpecification
        discover_undocumented(base_url: URL) -> List<Endpoint>
    }
}

agent Detector::APIAnalyzer {
    role: pattern_detector
    authority: [assert_hypothesis]
    trust: 0.6
    
    capabilities {
        check_auth(endpoints: List<Endpoint>) -> List<AuthIssue>
        check_idor(endpoints: List<Endpoint>) -> List<IDORCandidate>
        check_mass_assignment(endpoints: List<Endpoint>) -> List<MassAssignCandidate>
    }
}

agent Reasoner::APISecurity {
    role: semantic_reasoner
    authority: [interpret, strengthen, weaken, challenge]
    trust: 0.75
    model: "sentinel-api-v2"
    
    capabilities {
        analyze_auth_model(spec: APISpecification) -> AuthModelAnalysis
        identify_sensitive_fields(schema: JSONSchema) -> List<SensitiveField>
        correlate_endpoints(endpoints: List<Endpoint>) -> List<DataFlow>
    }
}

// === Claim Types ===

claim_type BrokenObjectLevelAuth {
    endpoint: Endpoint
    parameter: String
    object_type: String
    
    severity_range: [HIGH, CRITICAL]
    requires_validation: true
}

claim_type ExcessiveDataExposure {
    endpoint: Endpoint
    exposed_fields: List<String>
    sensitive_fields: List<String>
    
    severity_range: [MEDIUM, HIGH]
    requires_validation: false
}

claim_type MassAssignment {
    endpoint: Endpoint
    injectable_fields: List<String>
    impact: String
    
    severity_range: [MEDIUM, CRITICAL]
    requires_validation: true
}

// === Collaboration Rules ===

rule Parse_API_Specification {
    when Scanner::OpenAPIParser observes APISpecification as spec {
        // Immediately analyze auth model
        Reasoner::APISecurity must analyze_auth_model(spec) within 30s
        
        // Tag endpoints by auth requirements
        for endpoint in spec.endpoints {
            if endpoint.requires_auth {
                endpoint.tags += ["authenticated"]
            }
            if endpoint.uses_object_id {
                endpoint.tags += ["bola_candidate"]
            }
        }
    }
}

rule Detect_BOLA_Candidates {
    when endpoint tagged "bola_candidate" {
        Detector::APIAnalyzer must check_idor([endpoint]) within 20s
        
        on candidates_found(results) {
            for result in results {
                Detector::APIAnalyzer may assert claim BrokenObjectLevelAuth {
                    endpoint: result.endpoint,
                    parameter: result.id_param,
                    object_type: result.object_type,
                    confidence: 0.45
                }
            }
        }
    }
}

rule LLM_Reviews_BOLA {
    when Detector::APIAnalyzer asserts claim BrokenObjectLevelAuth as c {
        Reasoner::APISecurity must review_bola(c) within 30s
        
        on review_complete(analysis) {
            if analysis.auth_check_missing {
                Reasoner::APISecurity.strengthen(c,
                    by: 0.25,
                    reason: "No apparent authorization check for object access"
                )
            }
            
            if analysis.predictable_ids {
                Reasoner::APISecurity.strengthen(c,
                    by: 0.15,
                    reason: "Object IDs appear sequential/predictable"
                )
            }
        }
    }
}

rule Validate_BOLA {
    when claim BrokenObjectLevelAuth as c
     and c.confidence >= 0.65 {
        
        Validator::IDORTester must test_horizontal_access(c) within 90s
        
        on unauthorized_access_confirmed(proof) {
            c.evidence += [proof]
            c.confidence = 0.95
            c.status = VALIDATED
            
            // Check for vertical escalation too
            Validator::IDORTester.test_vertical_access(c)
        }
        
        on access_denied(result) {
            Validator::IDORTester.weaken(c,
                by: 0.4,
                reason: "Access control appears effective"
            )
        }
    }
}

rule Detect_Data_Exposure {
    when Reasoner::APISecurity observes DataFlow(
        endpoint: e,
        response_fields: fields
    ) {
        let sensitive = Reasoner::APISecurity.identify_sensitive_fields(fields)
        
        if len(sensitive) > 0 {
            Reasoner::APISecurity may assert claim ExcessiveDataExposure {
                endpoint: e,
                exposed_fields: fields,
                sensitive_fields: sensitive,
                confidence: 0.7
            }
        }
    }
}

// === Mission ===

mission APISecurityAssessment(api_spec_url: URL, scope: Scope) {
    
    phase Discovery {
        // Parse OpenAPI/Swagger spec
        let spec = Scanner::OpenAPIParser.parse_spec(api_spec_url)
        
        // Look for undocumented endpoints
        let undocumented = Scanner::OpenAPIParser.discover_undocumented(spec.base_url)
        
        await all_observations_processed
    }
    
    phase AuthAnalysis {
        Reasoner::APISecurity.analyze_auth_model(spec)
        
        await analysis_complete
    }
    
    phase Detection {
        // Run all detectors in parallel
        parallel {
            Detector::APIAnalyzer.check_auth(all_endpoints)
            Detector::APIAnalyzer.check_idor(all_endpoints)
            Detector::APIAnalyzer.check_mass_assignment(all_endpoints)
        }
        
        await claims.stable(timeout: 120s)
    }
    
    phase Validation when high_confidence_claims.exists {
        // Rules handle validation automatically
        await all_validations_complete(timeout: 300s)
    }
    
    phase Correlation {
        // Find attack chains across claims
        let chains = Reasoner::APISecurity.correlate_findings(all_claims)
        
        for chain in chains {
            emit attack_chain_discovered(chain)
        }
    }
    
    phase Report {
        let report = Reasoner::APISecurity.generate_api_report(
            spec: spec,
            claims: all_claims,
            attack_chains: chains
        )
        
        emit artifact(report, type: "api_security_assessment")
    }
}
```

---

## Example 4: File Creation and System Actions

CAL can also orchestrate file creation and system-level outputs.

```cal
// === Action Types ===

action_type CreateFile {
    path: String
    content: String
    permissions: String?
}

action_type WriteToKnowledgeGraph {
    node_type: NodeType
    data: Map<String, Any>
    edges: List<Edge>?
}

action_type SendNotification {
    channel: String
    severity: Severity
    message: String
}

// === Rules for Actions ===

rule Persist_Confirmed_Findings {
    when claim c
     and c.status == CONFIRMED {
        
        // Write to knowledge graph
        Orchestrator must action WriteToKnowledgeGraph {
            node_type: NodeType.FINDING,
            data: {
                "claim_id": c.id,
                "type": c.type.name,
                "confidence": c.confidence,
                "severity": c.severity,
                "target": c.target
            },
            edges: [
                Edge(from: c.target, to: c.id, type: EdgeType.HAS_FINDING)
            ]
        }
    }
}

rule Generate_POC_For_Critical {
    when claim c
     and c.status == CONFIRMED
     and c.severity == CRITICAL
     and c.type in [SQLInjection, RCE, AuthBypass] {
        
        Validator::POCGenerator must generate_poc(c) within 60s
        
        on poc_generated(poc) {
            // Save POC to evidence directory
            Orchestrator must action CreateFile {
                path: "/evidence/${c.id}/poc.py",
                content: poc.code,
                permissions: "600"
            }
            
            c.evidence += [poc]
            c.tags += ["has_poc"]
        }
    }
}

rule Notify_On_Critical {
    when claim c
     and c.status == CONFIRMED
     and c.severity == CRITICAL {
        
        Orchestrator must action SendNotification {
            channel: "slack",
            severity: CRITICAL,
            message: "Critical vulnerability confirmed: ${c.type.name} on ${c.target}"
        } within 10s
    }
}

rule Generate_Report_Section {
    when claim c
     and c.status in [CONFIRMED, VALIDATED]
     and not c.tags contains "reported" {
        
        Reasoner::ReportWriter must generate_section(c) within 30s
        
        on section_complete(section) {
            Orchestrator must action CreateFile {
                path: "/reports/draft/${c.id}.md",
                content: section.markdown
            }
            
            c.tags += ["reported"]
        }
    }
}
```

---

## Example 5: Reasoning Mode (Simulation)

Running a "what-if" analysis without live execution.

```cal
@mode(reasoning)
mission WhatIfAnalysis(hypothetical_target: Target) {
    
    // In reasoning mode, all scanners return synthetic data
    // based on similar targets in the knowledge graph
    
    phase SimulateRecon {
        // Uses cached/historical data for similar targets
        let simulated_scan = Scanner::Nmap.port_scan(hypothetical_target)
        
        // Reasoning mode: LLM predicts likely findings
        let predicted_services = Reasoner::Sentinel.predict_services(
            target_type: hypothetical_target.classification,
            industry: hypothetical_target.industry
        )
        
        await predictions_complete
    }
    
    phase AnalyzeLikelihood {
        // Estimate what vulnerabilities would likely exist
        let likely_vulns = Reasoner::Sentinel.estimate_vulnerabilities(
            services: predicted_services,
            based_on: historical_data
        )
        
        for vuln in likely_vulns {
            // Create hypothetical claims
            Reasoner::Sentinel may assert claim Hypothetical(vuln.type) {
                target: hypothetical_target,
                likelihood: vuln.probability,
                based_on: vuln.similar_cases,
                confidence: vuln.probability * 0.5  // Discount for being hypothetical
            }
        }
    }
    
    phase PlanAttack {
        // Generate attack plan for review
        let plan = Reasoner::Sentinel.generate_attack_plan(
            hypothetical_claims: all_claims,
            constraints: scope.constraints
        )
        
        emit artifact(plan, type: "attack_plan_draft")
    }
}
```

---

## Evidence Lineage Example

Every claim carries its full provenance:

```cal
// Query the evidence chain for a confirmed finding
let claim = query claims ConfirmedSQLi where id == "abc123"

// Full evidence tree
claim.evidence
// → [
//     ValidationResult { exploit_id: "sqli-001", success: true, ... },
//     LLMAnalysis { model: "sentinel-vuln-v3", reasoning_trace: [...] },
//     PatternMatch { pattern: "sql_error", matched_text: "..." }
// ]

// Trace back to raw observations
for e in claim.evidence {
    print(e.provenance)
    // → Provenance { 
    //       captured_by: Agent("Validator::SQLMap"),
    //       timestamp: 2024-01-15T10:31:22Z,
    //       source: "live_validation"
    //   }
}

// Full history of claim evolution
claim.history
// → [
//     ClaimEvent { action: asserted, agent: "Detector::Regex", confidence: 0.35 },
//     ClaimEvent { action: strengthened, agent: "Reasoner::Sentinel", confidence: 0.68 },
//     ClaimEvent { action: validated, agent: "Validator::SQLMap", confidence: 0.95 },
//     ClaimEvent { action: confirmed, agent: "Orchestrator", confidence: 0.95 }
// ]

// Generate human-readable explanation
let explanation = Reasoner::Sentinel.explain(claim)
// → "This SQL injection was detected by regex pattern matching on the /login 
//    endpoint, reviewed by the AI reasoning model which found the error message
//    indicative of unsanitized SQL, and confirmed through successful exploitation
//    using union-based injection technique."
```

---

## Bug Bounty Report Generation

CAL can generate report artifacts that include full evidence lineage:

```cal
rule Generate_BugBounty_Report {
    when mission.phase == Reporting
     and confirmed_claims.count > 0 {
        
        let report = Reasoner::ReportWriter.generate_report(
            format: "hackerone",
            claims: confirmed_claims,
            include: {
                executive_summary: true,
                technical_details: true,
                evidence_chain: true,
                reproduction_steps: true,
                remediation: true
            }
        )
        
        // Report includes cryptographic proof of evidence
        let proof = generate_evidence_proof(confirmed_claims)
        
        emit artifact(report, type: "bug_bounty_report", proof: proof)
    }
}
```

The generated report includes:
- **Executive Summary**: AI-generated narrative
- **Evidence Chain**: Full provenance for each finding
- **Confidence Breakdown**: How confidence was computed
- **Reproduction Steps**: Generated from validation evidence
- **Proof Artifact**: Cryptographic hash of all evidence for verification

---

**End of Examples**
