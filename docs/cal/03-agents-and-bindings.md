# Agents and Bindings
Agents are CAL’s primary abstraction.

## 1) Agent design goals
A good agent declaration makes these explicit:
- what it can do (capabilities)
- what it is allowed to do (authority)
- how much the system should trust it (trust)
- what safety limits apply (constraints)

## 2) Authorities (recommended set)
- `assert_observation`
- `assert_hypothesis`
- `review`
- `strengthen` / `weaken`
- `challenge`
- `validate` / `invalidate`
- `confirm`
- `retract`

Your compiler/runtime should forbid actions outside authority.

## 3) Constraints you’ll want in cybersecurity
- `requires_scope: true`
- `requires_authorization: true`
- `execution_sandbox: true`
- `max_concurrent: N`
- `max_requests_per_target: N`
- `requires_evidence: true` (for LLMs)

## 4) Binding model (Sentinel)
CAL code declares *interfaces*. Sentinel provides *implementations*.

Typical mapping:
- `Scanner::*` → `core/scanner_engine.py` or tool shims
- `Reasoner::*` → `core/ai_engine.py` + `core/cortex/synapse.py`
- `Validator::*` → Forge/PoC runner or sqlmap-like validator wrappers

## 5) Good binding hygiene
- Convert tool output into typed observations/evidence.
- Always attach raw output as evidence.
- Store LLM prompt hashes + model ID as evidence.
- Never allow bindings to silently discard errors; instead emit evidence + audit events.
