# Reference

> **Archived design reference (2026-10-28).** The `core/cal/` runtime has been removed from the current tree. The syntax, examples, and integration paths below are historical proposals, not runnable Sentinel interfaces.

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
