# Introduction
CAL (Collaborative Agent Language) is a programming language for cybersecurity systems where multiple specialized components collaborate to reason about security claims.

CAL exists because typical orchestration code fails in three ways:
- It treats findings as booleans instead of evolving hypotheses.
- It treats collaboration as procedure (callbacks/queues) instead of argumentation.
- It loses epistemology (who believed what, why, and based on which evidence).

## What CAL programs *are*
A CAL program is a *policy-constrained argumentation protocol*.

You declare:
- **Agents**: who can do what (authority, trust, constraints)
- **Claim types**: the shapes of hypotheses
- **Evidence types**: the shapes of proof artifacts
- **Rules**: declarative collaboration policy (`when` / `must` / `may`)
- **Missions**: phased programs that initiate activity and wait for convergence

The runtime provides:
- a belief state (claims + versions)
- an evidence store (with provenance)
- an audit log (claim events)
- a rule engine (reactive)

## The key distinction
Traditional:
- “run scanner; parse; if match then call LLM; if LLM says yes then validate”

CAL:
- “when evidence arrives and a claim is asserted, other agents are obligated to review/validate before the claim can escalate.”

## The design stance
- Evidence is monotonically collected (added, never deleted).
- Belief is non-monotonic (confidence can increase/decrease).
- Conflicts are surfaced, not silently resolved.
- Validation is privileged: proof beats opinions.
