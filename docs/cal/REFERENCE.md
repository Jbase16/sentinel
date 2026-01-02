# CAL Reference Manual (Python DSL)

**Collaborative Agent Language (CAL)** is an argumentation protocol for security reasoning.
This implementation provides a Python DSL for defining Claims, Evidence, and Debate Rules.

## 1. Core Primitives (`core.cal.types`)

### 1.1 `Evidence`
An immutable fact accumulated from the environment.
```python
ev = Evidence(
    content={"port": 80, "state": "open"},
    provenance=Provenance("Scanner:Nmap", confidence=0.9)
)
```

### 1.2 `Claim`
A hypothesis subject to debate.
```python
claim = Claim(
    statement="Host is vulnerable to XSS",
    metadata={"type": "vuln_xss", "target": "127.0.0.1"}
)
```
- **Statuses**: `PENDING` -> `VALIDATED` | `DISPUTED` | `REJECTED`

## 2. Argumentation Engine (`core.cal.engine`)

### 2.1 `ReasoningSession`
The container for a specific debate (e.g., a single scan context).
```python
session = ReasoningSession(session_id="uuid", topic="MyTarget")

# Assert a claim
c = session.assert_claim("SQLi Detected", evidence=ev_sqli)

# Dispute it
session.dispute_claim(c.id, evidence=ev_waf, reason="Blocked by WAF")
```

## 3. Fluent Rules API (`core.cal.interface`)

Use the `@cal_rule` decorator to define reactive logic.

```python
from core.cal.interface import cal_rule

@cal_rule(on_claim_type="vuln_sqli")
def verify_waf_bypass(claim, session):
    """
    When an SQLi claim is made, check if we have WAF evidence.
    If so, dispute the claim unless we have a bypass proof.
    """
    # Check session evidence for WAF
    waf_evidence = [e for e in session.evidence.values() if "WAF" in e.description]
    
    if waf_evidence and not claim.metadata.get("bypass_verified"):
        claim.add_dispute(
            Evidence(content="WAF Present", description="WAF likely blocks this")
        )
```

## 4. Integration Guide

### Emitting Claims (From Tools)
Tools should no longer just "log" findings. They should emit Evidence, then assert Claims.
```python
# In a tool wrapper
ev = Evidence(output)
session.assert_claim(f"{tool} found X", ev)
```

### Consuming Decisions
The UI or Reporting engine listens for `DECISION_MADE` events via the EventBus.
```python
event_bus.subscribe(lambda e: print(f"New Decision: {e.payload}"))
```
