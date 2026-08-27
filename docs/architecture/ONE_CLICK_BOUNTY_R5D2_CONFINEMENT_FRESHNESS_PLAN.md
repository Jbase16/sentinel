# OCB-R5D2 Confined-Presentation Freshness Plan

Status: suite-proved as a passive, unwired design slice; the exact pushed delivery
SHA is recorded in the implementation handoff

Base: SentinelForge `main` at `2bf2e1b0ae900f48b9c1f0a9240c4d629e65ec95`

Canonical stage: OCB-R5 Family D, slice `R5D2`. The registered downstream scenario
is `OCB-S17`; R5D2 does not implement or claim that scenario.

## 1. Bounded outcome

R5D1 defines the immutable issued-capability authority tuple and classifies its
logical bounds. R5D2 adds a separate evidence contract in
`core/behavior/capability_confinement_freshness.py`. It binds one R5D1 capability to:

1. the exact unqualified owned-account world whose persona is both the capability
   subject and audience;
2. the same owned-tenant and tenant-ownership references already validated by the
   R5D1 contract;
3. one canonical HTTP(S) target origin; and
4. an operator-supplied capture whose normalized structure and record count were
   revalidated against a prior capture.

R5D1 has no target-origin field. R5D2 therefore does not pretend to recover an origin
from the R5D1 source-evidence hash. Instead, the R5D2 binding is the content-addressed
evidence-axis extension that confines that exact `capability_ref` to one canonical
origin. Changing the issued-capability contract or inferring an origin from a hash
would exceed this slice.

The module is intentionally passive and unwired. No API router, Foundry path, Scan
profile, scheduler, or production coordinator imports it. It performs no target I/O,
does not reserve budget, persist use state, write a receipt, provision a callback,
evaluate a target effect, or promote a finding.

## 2. Confined-presentation binding

`ConfinedPresentationBinding` is immutable and content-addressed. Its public evidence
contains only typed hashes, one logical record count, and fixed passive bounds:

| Bound fact | Public representation |
|---|---|
| R5D1 capability | `capability_ref` with the `issued_capability_contract` type |
| Exact owned world | `confined_world_ref`, the complete `ExperimentWorldBinding` content address |
| Owned tenant | `confined_tenant_ref` plus `confined_tenant_ownership_ref` |
| Canonical origin | `target_origin_ref`, a `behavioral_capture_target` hash of lowercased `scheme://netloc` |
| Revalidated current capture | `presentation_capture_ref`, produced by `graph_bound_capture_artifact_ref` |
| Value-independent structure | `presentation_snapshot_ref`, produced by the existing capture `_snapshot` helper |
| Capture extent | `presentation_record_count` |
| Revalidation claim | `current_capture_revalidated = true` |
| Passive boundary | zero requests and false dispatch, promotion, finding, and retry authority |

The binding ID is exactly
`stable_hash("capability_confinement_freshness", payload)`, where `payload` contains
all public references, the count, the revalidation bound, and every passive flag but
excludes the ID, mode, schema version, and private validation context.

Construction requires the explicit `capability_ref` to equal the supplied R5D1
contract ID. The confined world must be the exact `actor` binding retained by that
contract, of kind `OWNED_ACCOUNT`, with persona and ownership evidence and without
role, lifecycle, callback, or fresh-anonymous qualification. The contract subject and
audience are rechecked against the world persona. The supplied tenant and ownership
references must equal both the contract's public tenant fields and its validated
owned-world tenant context. A malformed reference, different capability, non-owned
world, cross-account world, or cross-tenant context fails closed.

The validated contract, world, and canonical origin are retained only as private,
non-repr construction context so frozen-dataclass substitution can recheck the complete
binding. They are not serialized or included as raw public evidence.

## 3. Confinement and capture freshness

R5D2 reuses the existing capture-freshness implementation instead of defining a
second normalizer or hash format:

- `_canonical_origin` validates and lowercases the exact HTTP(S) origin;
- `_snapshot` calls `normalize_exchange` for every record, rejects any normalized
  origin outside the confined origin, and returns the value-independent structural
  snapshot plus record count; and
- `graph_bound_capture_artifact_ref` hashes the complete private capture without
  returning or storing any captured value.

Both the prior and current operator-supplied captures must normalize entirely to the
confined origin. Any out-of-origin record is a confinement escape and construction is
denied. Their snapshot references and counts must be equal; otherwise construction is
denied as `capability_presentation_capture_is_stale`. Dynamic object IDs, bearer values,
and other values may rotate when the normalized action/state structure remains the
same. The binding retains only the hash of the revalidated current capture, the shared
snapshot reference, and the current count.

This is current-evidence revalidation, not durable replay control. R5D2 has no use
ledger, consumed marker, compare-and-swap claim, cross-presentation replay state, or
persistent storage.

## 4. Typed presentation and pure evaluator

`ConfinementPresentation` describes one attempted evidence use. It carries the
presented world, tenant, tenant-ownership, and target-origin references plus the
current capture artifact, normalized snapshot, and record count. Its builder accepts
operator-supplied records only long enough to reuse the same capture helpers; no raw
record becomes a field or appears in serialization or repr output.

`evaluate_confinement()` is total for valid typed inputs and uses this fixed order:

1. `ESCAPED_CONFINEMENT` if any presented world, tenant, tenant-ownership, or origin
   reference differs from the binding;
2. `STALE_CAPTURE` if confinement matches but the current snapshot or record count
   differs from the revalidated binding; and
3. `CONFINED_FRESH` otherwise.

Confinement is primary because out-of-world evidence violates the ownership boundary
regardless of age. A presentation that is both escaped and stale must therefore be
classified `ESCAPED_CONFINEMENT`, never merely `STALE_CAPTURE`.

The evaluator deliberately does not require the complete capture artifact hash to
remain identical. Dynamic values can rotate while the normalized snapshot and count
remain current. Every decision contains the evaluated `capability_ref`, binding ID,
presentation ID, outcome, a typed machine-reason reference, and its own content
address. The evaluator performs no dispatch, I/O, mutation, receipt write, or finding
promotion and does not consult the target.

## 5. Composition with R5D1

R5D1 and R5D2 are independent axes:

```text
fully admissible = R5D1 logical outcome VALID
               and R5D2 evidence outcome CONFINED_FRESH
```

A logically valid capability can still present cross-account, cross-tenant,
out-of-origin, or stale evidence. Conversely, R5D2 does not inspect or override R5D1
revocation, expiry, binding, or use-index outcomes. It creates no durable meaning for
R5D1's caller-supplied `use_index`.

## 6. Evidence and focused proof

`tests/unit/test_behavior_capability_confinement_freshness.py` collects 46 cases. It
covers:

- deterministic `CONFINED_FRESH` construction and reproducible binding/decision IDs;
- dynamic-value rotation with stable normalized structure;
- origin, account, tenant, and tenant-ownership escapes;
- stale snapshot and record-count refusal in both the evaluator and binding builder;
- the load-bearing escape-over-stale precedence;
- non-owned, role-qualified, cross-account, cross-tenant, malformed, and unbound
  construction failures;
- direct-construction revalidation of every typed field, content address, count, and
  passive flag;
- raw capture exclusion from dataclass fields, serialization, and repr output; and
- explicit R5D1/R5D2 independence: an R5D1 `VALID` presentation can still be escaped
  or stale on the evidence axis.

The registry contract now represents the previously missing `R5D1` slice and the new
`R5D2` slice, with one focused validator regression. The combined R5D2 and registry
checkpoint is 49 passing cases. Targeted Ruff passes all changed Python files, and the
full Python suite passes `2842 passed, 1 skipped, 3 warnings`: 47 additional passes
over the R5D1 baseline, with skip and warning counts unchanged.

The repository security script remains red on its documented pre-existing broad-text
matchers and repository-wide Ruff debt. R5D2 adds no violation; changed-file Ruff and
the focused tests are green.

## 7. Default-off authority and cleanup

The binding is default-off because it has no production caller. It adds no origin,
identity, action class, request budget, feature flag, backend, or execution path. It
sends zero requests and grants no dispatch, promotion, finding, retry, or execution
authority.

No setup or target mutation occurs, so R5D2 creates no residue and has no orphan risk.
There is no cleanup executor and no teardown claim. The owned-account world is merely
validated as disposable/reversible context inherited from the R5D1 fixture contract.

Offensive capability, target traffic, and execution authority are unchanged.

## 8. External gate and deferred work

There is no external gate for R5D2. A lab or native run would not make this passive
classifier executable, and no lab artifact is produced or claimed.

R5D2 does not add durable one-time consumption, cross-presentation replay refusal,
expiry enforcement against a running target, an executable capability backend,
receipt completion/abort semantics, an independent effect oracle, verified cleanup,
or finding construction. `OCB-S17` remains open.

The planned next Family-D slice is separately scoped durable one-time consumption and
replay refusal. Its canonical slice ID is not assigned by R5D2. Later slices must also
add running-target expiry enforcement, effect proof, receipts, cleanup, and the
`OCB-S17` acceptance matrix before Family D can close.
