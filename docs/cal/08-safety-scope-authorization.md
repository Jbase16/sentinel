# Safety, Scope, and Authorization
CAL is explicitly designed for security tooling. Safety is part of the language semantics.

## 1) Scope containment
Actions must be constrained to declared scope.
A scope violation should:
- block the action
- emit an audit event
- be visible to the user

## 2) Authorization gates
Validators and intrusive tools frequently require explicit approval.
Model this as:
- agent constraint (`requires_authorization: true`)
- runtime gate that can pause or deny

## 3) False positive prevention patterns
- require multi-agent corroboration for escalation
- require validation before CONFIRMED for critical claim types
- implement confidence decay for unvalidated hypotheses
- maintain known false-positive suppression rules

## 4) Failure surfacing
Do not hide failures behind “fallback heuristics.”
Instead:
- attach failure evidence
- record a reason
- propagate status that the UI can display (`UNVALIDATED`, `CONTESTED`, etc.)
