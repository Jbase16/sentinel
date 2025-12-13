# Claims, Evidence, and Confidence
This chapter is the epistemic core of CAL.

## 1) Claims are versioned hypotheses
A claim is not “a record.” It’s a *versioned belief*.
Each update creates a new version and appends to history.

Recommended built-ins per claim:
- `id`, `version`
- `status`
- `confidence`
- `asserted_by`
- `evidence[]`
- `history[]`

## 2) Evidence is first-class and monotonic
Evidence should:
- be append-only
- have provenance (agent, timestamp, source)
- carry integrity hashes
- link to the claim versions it influenced

Examples of evidence types:
- `RawOutput` (tool stdout/stderr)
- `PatternMatch`
- `LLMAnalysis` (model, prompt_hash, response)
- `ValidationResult` (success/failure + proof)

## 3) Confidence philosophy
Confidence should be:
- bounded [0.0, 1.0]
- explainable (breakdown)
- robust against “gaming”

Recommended practice:
- detectors start low confidence
- reasoners adjust moderately
- validators adjust strongly

## 4) Validation vs confirmation
- Validation: “we tested and got evidence”
- Confirmation: “policy allows us to escalate/report as true”

Don’t collapse these.

## 5) Conflict and uncertainty
CAL should represent uncertainty explicitly:
- contested claims
- high-uncertainty tags
- required human adjudication when needed
