# Sentinel Integration
This document explains the intended integration shape between CAL and Sentinel.

## 1) What CAL should integrate with
- Evidence storage (`core/evidence_store.py`)
- Findings store (`core/findings_store.py`) for UI + persistence
- Knowledge graph (`core/cortex/memory.py`) for relationships
- Scanner orchestration (`core/scanner_engine.py`, `core/scan_orchestrator.py`)
- AI reasoning (`core/ai_engine.py`, `core/cortex/synapse.py`)

## 2) What CAL replaces
- imperative glue code (callbacks/event bus logic that encodes policy)

## 3) Binding architecture
CAL agents are declared in `.cal` source and bound to Python implementations via a runtime binding layer.

## 4) Recommended migration path
- Run CAL alongside existing orchestrators first.
- Port collaboration policy (review/validate/escalate) into CAL rules.
- Gradually move orchestration decisions into CAL missions.

## 5) See also
- `../CAL_INTEGRATION.md` for the longer integration draft.
- `../CAL_LANGUAGE_DESIGN.md` for the deep design spec.
