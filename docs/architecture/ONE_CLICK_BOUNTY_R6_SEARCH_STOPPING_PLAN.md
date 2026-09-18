# OCB-R6 Coverage Search and Honest Stopping

Status: suite-proved as a passive, unwired planning slice. Implementation commit:
`36f3749db8570ff2dbce8ad6a3b371be3cc8c1bc`. The commit is local: publishing was rejected
by the task execution approval policy, and no remote branch was present on the
subsequent read-only check. The pushed-SHA delivery requirement, mediator
verification, and Jason's separate merge authorization remain open. This document
does not accept the slice.

Base: SentinelForge `origin/main` at
`0743106f6aac4227e83ad05cdcc468661424de2d`.

Branch: `ocb/r6-search-stopping`.

Canonical stage: `OCB-R6`. Exit gate: `OCB-S18`.

## 1. Bounded outcome and authority

`core/behavior/search_stopping.py` adds `HighValueSinkLedger`, immutable input
snapshots, `MarginalValueScheduler`, family coverage, and `SearchStopCertificate`.
There is no production caller, package-level export, Scan/UI selection, transport,
receipt writer, budget reservation, database, or persistent planner state. The only
consumers are the focused tests. The explicit `enabled` argument defaults to false
and gates planning only; it is not an environment flag or a traffic permission.

The admission invariant is:

```text
ledger candidates = admissible OCB-R1 A-D candidates
                    intersect observed, selected-world OCB-R2 operations
scheduled candidates subset ledger candidates
scheduled complete proof costs <= all remaining OCB-R3-era ProofBudget ceilings
replanning authority = prior authority, or less
```

The ledger binds complete existing payout-plan and semantic-catalog snapshots. It
rechecks the payout context, candidate blockers, target, selected owned world,
backend, workflows, topology, and exact operation membership. Ambiguous operation
projections are refused. At most 128 payout candidates and 8192 catalog operations
are accepted. It does not add an identity, origin, operation, action class, proof
mode, request, or budget.

OCB-R5 families A-D, their oracles, receipt schemas, capability gates, and acceptance
targets are unchanged. The Lab is uninvolved. Prior native artifacts at `f45e037`
remain evidence for that historical shipping build only; this changed build claims
local suite proof, not a renewed native or external gate.

## 2. Inputs, cost completeness, and six recorded signals

`SearchBudget.capture()` reads the existing `ProofBudget` under its existing lock.
It records every ceiling, cumulative consumed count, outstanding reservation count,
permission bit, and per-endpoint count. Endpoint keys are hashed with the existing
`experiment_endpoint_key` domain. It never reserves, releases, or consumes a unit.
The snapshot must be taken at a quiescent coordinator boundary. The private counter
read is isolated to this adapter because the existing public `snapshot()` omits
reservations and per-endpoint counters. No upstream budget contract was modified.

Every evaluated ledger row records the six signals used by the scheduler:

| Signal | Existing source |
|---|---|
| Payout relevance | OCB-R1 goal `impact_weight` |
| Reachability gain | Distinct capabilities produced by the bounded OCB-R3 path over admitted OCB-R2 operations |
| Information gain | OCB-R1 witness requirements plus relevant OCB-R3 hypothesis count; hypotheses affect ranking only |
| Proof cost | OCB-R2 operation costs over the OCB-R3 path; replaced by the complete existing proof-manifest cost when available |
| Remaining budget | Existing total ceiling less consumed and outstanding reserved units, clamped at zero |
| Cleanup risk | Non-read-only operations in the existing OCB-R3 path; the terminal operation is used when no path is available |

An operation-path estimate is insufficient to authorize even a passive scheduling
choice. Scheduling additionally requires `SearchProof`: an existing complete
`ProofExperimentManifest` with its existing `ExperimentRuntimeActionBinding` tuple.
These are read-only OCB-R4 contracts already compiled for the admitted candidate;
the scheduler does not build an experiment, reserve its budget, or create a lease.
This dependency supplies the actual complete cost, including controls, treatment,
witnesses, and cleanup, instead of pretending that one terminal operation is one
complete proof request.

The adapter rechecks candidate/goal/target, world requirement, backend, oracle,
witness requirements, evidence overlap, action/operation membership, request method,
read-only action classes, actual origin, and endpoint-bucket binding. Actor and
owner identity digests must correspond to the admitted worlds. The existing
`stable_hash` hashes the same scalar independently of its output prefix, allowing
comparison of world and runtime-identity digests without recovering any identity.

Candidates without a complete bound proof remain accounted for as `never_explored`
with `proof_budget_unavailable`. A complete manifest does not replace any existing
policy, ownership, provenance, fresh-state, receipt, or human-control execution gate.

## 3. Deterministic marginal-value order

For payout relevance P, reachability R, information I, proof cost C, remaining budget
B, and cleanup risk K, the score is the exact rational number:

```text
(P + R + I) * B / (C * (1 + K) * (B + C))
```

Candidates sort by descending score, then ascending full candidate ID. `Fraction`
arithmetic avoids floating-point ties. The ordered pass includes a complete proof
only when its whole action sequence fits the total, cross-object, privilege,
creation, and shared per-endpoint ceilings after all earlier selected proofs.
Outstanding reservations count against those ceilings. Methods using the same
endpoint share one bucket. No partial proof enters the order.

The returned object records the input snapshots and ordering. Equal recorded inputs
produce equal ordering and equal certificate bytes. Input order is canonicalized
for execution records and proof manifests. The ledger's candidate IDs are sorted.

## 4. Failure-driven replanning and stale state

The scheduler invokes the existing passive `ConstraintReplanner` only when enabled
and supplied constraints are valid. It restricts the compiler to operations already
attached to admitted candidates. It neither acquires a prerequisite nor dispatches a
replacement action. Structured failure facts can block a candidate or exhaust the
existing bounded search, and the remaining feasible frontier is then reordered.

A continuation retains the same ledger, complete proof set, known facts, blockers,
and execution records. It refuses larger ceilings, increased permission bits,
regressed consumed counters, increased remaining budget, or increased compiler
search limits. Releasing an unrelated reservation can therefore require a new
planning run; it cannot silently enlarge this continuation. Facts disappearing from
a newer snapshot are rejected. Explicit invalidation is sticky within the run.
OCB-R3 has no clock-based freshness field: the planner does not invent a freshness
oracle. A future coordinator must supply current state and retain the previous plan.

A newly learned fact affecting an existing proof's actions prevents reuse of that
old proof, even if a different passive prerequisite path becomes reachable. Proof
re-admission belongs to a separate run through the established gates.

## 5. Coverage and recorded outcomes

Every admitted candidate occurs exactly once in one family and one category:

- `proved`: a supported recorded authorization outcome is oracle-confirmed.
- `blocked`: an existing constraint prevents progress, the constraint snapshot was
  invalidated, or a supported recorded outcome is refuted/inconclusive. The original
  oracle verdict is preserved; secure denial is never a vulnerability proof.
- `exhausted`: the existing OCB-R3 compiler actually exhausted its bounded search.
- `never_explored`: no recorded execution or terminal constraint outcome exists.
  Lack of budget does not turn an untouched candidate into an executed one.

A-D are selected from the existing security-property enum, not supplied family
labels. Empty families contain four empty lists and make no family-completeness
claim. The denominator is this admitted candidate set, not all possible target
operations or vulnerabilities.

`RecordedSearchExecution` currently imports only the existing OCB-R4 authorization
receipt kind. It validates the stored receipt and complete manifest, reconstructs
`ExperimentOracleEvaluation`, verifies its content address, and binds root receipt
target/personas to the manifest. Refuted-to-confirmed relabeling, root-context
substitution, and foreign candidates are refused. It does not write a receipt or
promote a finding. Other receipt kinds are unsupported rather than guessed; their
candidates remain subject to truthful constraint/unexplored accounting.

The genuine local execution test uses the existing four-read executor with an
injected in-memory target and its real receipt store. Its document operation needs
an initial identifier capability that this planner does not infer. Consequently its
pre-outcome plan is blocked, and its recorded outcome subsequently establishes the
coverage category. Separate real OCB-R1/OCB-R2 derivation fixtures establish positive
ordering, complete budget bounds, deterministic ties, and failure-driven replanning.

## 6. Immutable stop certificate and cleanup

The certificate is canonical compact sorted JSON plus
`search_stop_certificate:<sha256>`, using the existing `stable_hash`. It includes:
input and ledger identities; canonical phase/gate; admitted IDs; exact per-family
partition; per-candidate reasons, evidence references, oracle verdict and signals;
frontier order; full budget snapshot; planned complete cost; cumulative consumed
requests; and explicit zero planner requests/false execution and finding authority.

Stop reasons distinguish disabled planning, invalidated constraints, remaining
frontier, unavailable proof budget, exhausted budget, and exhausted frontier. A
certificate with `frontier_remaining` is explicitly not a claim that exploration is
complete. Cumulative budget consumption belongs to the supplied existing budget;
the planner itself consumes zero request units.

`SearchStopCertificate` retains canonical immutable bytes. Construction independently
re-derives the complete payload from its private, non-serialized plan context; even
a rehashed false partition is rejected. `verify(plan)` checks the certificate against
retained input state. A hash proves content integrity, not target truth or acceptance.

One actual confirmed `OCB-S18` specimen from the full checkpoint is retained at:

```text
/tmp/sentinel-ocb-r6-checkpoint-20260918/test_ocb_s18_recorded_outcomes0/search-stop-certificate.json
/tmp/sentinel-ocb-r6-checkpoint-20260918/test_ocb_s18_recorded_outcomes0/search-inputs.json
```

Its generated identity is
`search_stop_certificate:855bde36f146336c8938d90197a447e0d338af4f6636b6f7c36752f16dd2d7c8`.
It records one admitted family-A candidate proved by the existing local oracle,
zero candidates in families B-D, four existing execution request units consumed,
zero planner requests, and `frontier_exhausted`. This says nothing about unadmitted
candidates or target-wide coverage. The input digest and certificate content address
were independently recomputed from these retained JSON files. The other scenario's
certificate records a blocked A candidate and never-explored A/C/D candidates.
These files are local temporary checkpoint outputs; rerunning the scenario generates
new specimens, with fresh execution identities in the actual-outcome cases.

The planner persists nothing and has no teardown obligation or orphaned resources.
Test executors create only their owned disposable `tmp_path` stores; planner calls
leave those receipts and budgets unchanged. Scenario certificates/input snapshots
are generated by the tests, never hand-authored or edited. Retained checkpoint
outputs are operator evidence files, not a live evidence root or native artifact.

## 7. Proof surface and checkpoint

Focused tests: **41 passed in 0.46s** on Python 3.12.14.

```text
.venv/bin/python -m pytest -q tests/unit/test_behavior_search_stopping.py tests/unit/test_behavior_search_execution.py
```

`OCB-S18` is the combined scenario surface:

- `test_ocb_s18_order_replan_coverage_and_honest_stop` derives the admitted frontier,
  reorders after an extracted failure, preserves unattempted truth at budget stop,
  checks the exact partition, and emits its certificate and recorded inputs.
- `test_ocb_s18_recorded_outcomes_without_dispatch` runs confirmed, denied, and
  inconclusive existing local proofs and emits each resulting certificate/input pair.
- Narrow tests additionally cover tie-breaking, disabled behavior, non-admission,
  all relevant proof budgets, reservations, search exhaustion, stale/invalidation
  refusal, all four family rows, origin/identity/method substitution, receipt
  tampering, and rehashed certificate fabrication.

Use Python **3.12.14** through `.venv/bin/python`. The master ledger records the
executed full checkpoint using the repository's complementary unmarked and
`subprocess_spawn` invocations. The work order's 231-test figure was not the actual
Sentinel checkpoint; the inherited tree collected 3382 items before this slice.

The inherited repository-wide security-check baseline and six web-schema drift
snapshots remain separate maintenance debts. No gate, security script, historical
snapshot, model, prompt, or dependency is changed by this slice.

## 8. Delivery boundary and next work

Deliver the pushed branch, exact implementation SHA, focused/full proof results,
this document, master-ledger update, and an actual scenario certificate to the
mediator. Local passing tests are not mediator acceptance. No merge is authorized
by this implementation handoff.

The plan-derived next slice is `OCB-R7` candidate assembly and report boundary,
with `OCB-S19`; it needs a separate work order. Live orchestration and native proof
remain `OCB-R8` / `OCB-S20`. Families E/F and `OCB-R9` remain outside this slice.
