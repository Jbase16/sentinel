# Reference
This is a compact reference for day-to-day authoring.

## 1) Top-level constructs
- `agent`
- `claim_type`
- `evidence_type`
- `rule`
- `mission`
- `confidence_model`

## 2) Common keywords
- `role`, `authority`, `trust`
- `capabilities`, `constraints`
- `when`, `may`, `must`, `within`, `on timeout`
- `phase`, `await`, `for`, `if`, `match`
- `query`, `emit`

## 3) Recommended statuses
- `HYPOTHESIZED`
- `PENDING_REVIEW`
- `CHALLENGED` / `CONTESTED`
- `PENDING_VALIDATION`
- `VALIDATED` / `INVALIDATED`
- `CONFIRMED` / `REFUTED` / `DISMISSED`

## 4) Authoring style
- keep claim types small and composable
- avoid direct confidence assignment after creation; prefer operations with reasons
- attach evidence everywhere
- treat LLM output as evidence, not proof
