# Getting Started
This guide teaches you to write a small but realistic CAL flow: *detect → review → validate → confirm*.

## 1) The smallest useful CAL program
A realistic minimum needs:
- one detector agent (cheap signal)
- one reasoner agent (semantic review)
- one validator agent (proof)
- one claim type
- rules that force collaboration
- a mission that triggers activity

## 2) Step 1: Define agents
```cal
agent Detector::Regex {
  role: pattern_detector
  authority: [assert_hypothesis]
  trust: 0.50
}

agent Reasoner::Sentinel {
  role: semantic_reasoner
  authority: [review, strengthen, weaken, challenge]
  trust: 0.75
  constraints {
    requires_evidence: true
  }
}

agent Validator::ExploitRunner {
  role: validator
  authority: [validate, invalidate, confirm]
  trust: 0.95
  constraints {
    requires_authorization: true
    execution_sandbox: true
  }
}
```

## 3) Step 2: Define the claim type
```cal
claim_type PotentialSQLi {
  endpoint: Endpoint
  parameter: String
  indicator: String
  severity_range: [MEDIUM, CRITICAL]
  requires_validation: true
}
```

## 4) Step 3: Add collaboration rules
Rules are where CAL stops being “workflow” and becomes “policy.”

```cal
rule Regex_Asserts_Hypothesis {
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

rule Reasoner_Must_Review {
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

rule Validator_Must_Validate_When_Confident {
  when claim PotentialSQLi as c
   and c.confidence >= 0.65
   and c.status not in [VALIDATED, INVALIDATED] {

    Validator::ExploitRunner must validate(c) within 120s

    on validation_success(v) {
      Validator::ExploitRunner.confirm(c, evidence: v)
    }

    on validation_failure(v) {
      Validator::ExploitRunner.invalidate(c, reason: "Validation failed", evidence: v)
    }
  }
}
```

## 5) Step 4: Write a mission
Missions start work; rules do most of the control.

```cal
mission WebAssessment(target: Host, scope: Scope) {
  phase Detect {
    Scanner::Httpx.probe(target)
    Detector::Regex.scan(all_http_responses, sqli_patterns)
    await claims.stable(timeout: 60s)
  }

  phase Validate when query claims PotentialSQLi where confidence >= 0.65 exists {
    await all_validations_complete(timeout: 300s)
  }

  phase Report {
    let confirmed = query claims where status == CONFIRMED
    emit artifact(confirmed, type: "findings")
  }
}
```

## 6) What you should expect at runtime
You should get a timeline like:
- Regex asserted PotentialSQLi @ 0.35
- Reasoner reviewed → confidence changes
- Validator validated → CONFIRMED/INVALIDATED

If you *don’t* see a clear audit trail, the runtime is not satisfying CAL’s core promise.
