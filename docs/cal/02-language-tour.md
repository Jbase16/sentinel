# Language Tour
This is a guided tour of CAL features and idioms.

## 1) Declarations at a glance
Top-level constructs:
- `agent`
- `claim_type`
- `evidence_type`
- `rule`
- `mission`
- `confidence_model` (optional)

## 2) Observations → claims
A common pattern:
1) scanners emit observations
2) detectors interpret observations and assert hypotheses
3) reasoners strengthen/weaken/challenge
4) validators produce proof

## 3) `may` vs `must` matters
- `may` = permission
- `must` = obligation

CAL is designed to make obligations auditable:
- if a `must` wasn’t satisfied (timeout, denied auth, scope violation), the runtime should record *why*.

## 4) Time is explicit
You can and should bound operations:
```cal
Reasoner::Sentinel must review(c) within 30s
on timeout(30s) { emit warning("Review timed out") }
```

## 5) Confidence is not a variable you casually set
Prefer:
- bounded deltas + reasons
- evidence-based adjustments
- validation as a privileged confidence source

## 6) Correlation as a first-class technique
CAL is strongest when you avoid giant claims and instead correlate many small claims.

Example:
- `InsecureCookieConfig` + `WeakSessionHandling` + `PredictableIDs` ⇒ hypothesize `AuthBypass`

## 7) Dual mode execution
The same mission should run:
- in reasoning mode (simulation, cached data)
- in execution mode (real tools)

This enables safe previews and reproducible reports.
