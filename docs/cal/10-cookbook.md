# Cookbook
Practical patterns you can copy/paste and adapt.

## 1) Pattern: detector → reasoner review → validator
Use this when:
- you have cheap noisy signal
- you want the reasoner to filter
- you require proof before escalation

Skeleton:
```cal
rule Detect { when Detector observes X { Detector may assert claim Y { confidence: 0.3 } } }
rule Review { when Detector asserts claim Y as c { Reasoner must review(c) ... } }
rule Validate { when claim Y as c and c.confidence >= 0.65 { Validator must validate(c) ... } }
```

## 2) SSRF (OOB callback)
Key evidence:
- out-of-band interaction
- internal service response

Policy:
- don’t confirm without callback or equivalent proof

## 3) IDOR / BOLA
Key evidence:
- unauthorized access with different user context

Policy:
- require validator that can swap identities/roles

## 4) Auth bypass chains
Pattern:
- many small claims (cookie flags, session rotation, predictable IDs)
- correlate into a stronger hypothesis
- validate via dedicated auth tester

## 5) File generation (PoC artifacts)
Policy:
- only generate PoCs for validated/confirmed high severity
- enforce sandbox + authorization

(See also `../CAL_EXAMPLES.md` for longer end-to-end examples.)
