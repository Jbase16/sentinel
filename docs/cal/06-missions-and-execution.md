# Missions and Execution
Missions are CAL programs. They usually define phases, but rules drive most behavior.

## 1) Mission structure
```cal
mission Name(args...) {
  phase Recon { ... }
  phase Detect { ... }
  phase Validate when <condition> { ... }
  phase Report { ... }
}
```

## 2) Await semantics
CAL uses semantic awaits (runtime-defined):
- `await all_observations_processed`
- `await claims.stable(timeout: 60s)`
- `await all_validations_complete(timeout: 300s)`

These are convergence points for a reactive system.

## 3) Dual execution model
A CAL mission should run in:
- reasoning mode: no real scans, cached/mock backends
- execution mode: real scans, real LLM inference, real validation

The point is reproducibility and safe previews.

## 4) Determinism boundaries
Expect:
- scanner agents can be deterministic
- LLM reasoners are non-deterministic unless you cache/seed
- validators depend on target state

CAL’s job is to preserve lineage so you can still explain and reproduce as much as possible.
