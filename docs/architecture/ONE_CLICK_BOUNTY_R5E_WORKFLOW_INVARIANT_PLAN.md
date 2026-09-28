# OCB-R5 Family E Workflow-Invariant Passive Spine

Status: R5E1–R5E5 implemented, focused-tested and suite-proved; locally committed,
push blocked by execution approval policy. Passive/unwired only. `OCB-S21` is registered and deferred, not
implemented or accepted.

Base: SentinelForge `main` at
`6a54d30df8488f4d8cdaa4fbafc7b7600d865a62`.
Branch: `ocb/r5e-workflow-invariant-spine`.

## 1. Entry gate and bounded outcome

The Family-E work order explicitly authorizes this passive foundation ahead of the
ordinary A–D-loop-measured milestone, by program-authority decision. This changes
the priority of the passive foundation only; it does not satisfy that milestone or
authorize the active tail. The work order also overrides the usual review stop
between layers: E1 through E5 were built continuously, with one focused proof and
local commit per layer, then one documentation commit and one split repository gate.

Family E declares a typed pure business invariant over terminal state. Its bounded
counterexample is a single-threaded deterministic sequence in which every operation
belongs to the same owned account, is present in declared order, and satisfies its
own operation precondition, yet the terminal numeric/relational invariant fails.
This is distinct from lifecycle omission/reordering (Family B), capability use or
expiry (Family D), identity/authority monotonicity (Families A/C), and concurrency
(Family F). No scheduling or target concurrency oracle is added.

The only implemented shape is aggregate-limit violation through per-operation-only
validation. For initial `consumed = 0`, `declared_limit = 10`, `per_op_cap = 6`:

| Twin | Declared operations and guard | Offline terminal result |
|---|---|---|
| Vulnerable | Two distinct `consume(6)` operations; each checks only `6 <= 6` | Both apply in order, consumed is 12, `INVARIANT_VIOLATED` |
| Secure | Same ordered consumes; each also checks `consumed + 6 <= 10` | Second operation is refused, consumed remains 6, `OPERATION_REFUSED`; invariant holds |
| Secure boundary | `consume(4)`, then `consume(6)`, same aggregate guard | Both apply, consumed is 10, `INVARIANT_HELD` |

These twins are pure semantics, not running targets. No target state is provisioned.

## 2. R5E1 — typed contract, owned fixture, pure classifier

Module: `core/behavior/workflow_invariant_contract.py`.

`WorkflowInvariantContract` seals a typed state schema, an initially-held declared
invariant, an ordered immutable tuple of typed consume operations, and a bounded
whole-sequence operation allowance. Each operation declares a typed pure guard and
transition as data. No callable, expression text, arbitrary code, or model predicate
is admitted. Separate schema/predicate/precondition/transition enums leave named
extension points without implementing other shapes.

Numbers are exact integers (booleans/floats refused), nonnegative and bounded by
`2**63 - 1`; caps are positive. Sequences contain 1–64 uniquely referenced operations,
with contiguous zero-based indices and one account. Every admitted operation is
single-application. The allowance is 1–64; a longer sequence can declare a smaller
allowance and then deterministically fail closed at exhaustion. Overflow is refused.

`WorkflowOwnedFixture` requires the OCB-R4 SDK's exact
`ProofTopology.SINGLE_OWNED_ACCOUNT` / `ExperimentWorldKind.OWNED_ACCOUNT` actor,
unqualified by role/lifecycle/callback, with exact persona and owned-tenant context.
It revalidates the SDK world rather than building another provisioning system.

`classify_sequence(contract, initial_state, operations)` accepts only the exact
declared initial state and complete ordered operation tuple. It returns
`INVARIANT_HELD`, `INVARIANT_VIOLATED`, `OPERATION_REFUSED`, or a redacted `MALFORMED`
decision. Omission, reordering, negative/malformed values and forged addresses fail
closed. Refusals retain the reached prefix state and identify the unapplied operation.

The identity convention is the existing `normalize.stable_hash` with the SDK's
`_hash_ref` helper and `^[a-z][a-z0-9_]*:[0-9a-f]{64}$` typed-hash shape. Contract
identity covers the public payload excluding the outer ID/schema-version fields,
as in R5D1. Nested values and reloads are revalidated, not trusted on hash shape alone.

`evaluate_invariant(predicate, terminal_state)` reads only typed terminal state and
does not call operation guards or transitions. Exactly as R5D1's classifier honesty
boundary: **this is a deterministic outcome evaluator, not independent evidence of
an observed target-side effect.** The genuine independent effect-occurrence oracle
against a running workflow belongs to the deferred active tail.

Caller: **passive/unwired**; no API router, Foundry path, Scan profile, scheduler or
production coordinator imports R5E1. Authority: adds no origin, identity, action
class, budget reservation, transport or execution/finding authority. Cleanup:
fixture disposable/reversible by construction, no residue or teardown, honest
`orphan_risk = false`; no cleanup operation is claimed.

## 3. R5E2 — owned provenance and logical freshness

Module: `core/behavior/workflow_invariant_binding.py`.

`WorkflowCaptureProvenance` retains typed operator-supplied source commitments for
every ordered operation, a capture-generation reference, the exact contract/world,
persona/tenant/tenant-ownership/origin, and an inclusive-capture/exclusive-expiry
logical window. `WorkflowInvariantBinding` binds these to the E1 fixture and one
canonical-origin commitment. No raw HTTP body, credential, or request is retained.

Freshness means exact capture commitment equality and
`captured_at_index <= at_index < valid_until_index`, with the index injected by the
operator. It is not a trusted target clock or independent evidence acquisition.
Changed source, operation order, generation, account, world, tenant or origin is
refused. A refreshed capture creates a new binding; it cannot reset an existing
sequence ledger. `evaluate_offline()` composes fresh owned context with E1 and
recomputes the decision when constructing the immutable result.

Caller: **passive/unwired**; no router/Foundry/Scan/scheduler/coordinator import.
Authority: no added origin, identity, action class, budget, transport or execution
authority; no finding or promotion. Cleanup: same disposable fixture, no target
residue, no cleanup claimed, orphan-risk false. The evaluator retains the E1
deterministic-outcome honesty boundary.

## 4. R5E3 — immutable transition ledger and pure sequence semantics

Module: `core/behavior/workflow_invariant_ledger.py`.

`WorkflowTransitionLedger` pins one binding and an immutable ordered tuple of
`WorkflowTransitionEntry` values. Each entry retains operation identity, index and
typed before/after states. Construction/reload recomputes every guard and transition,
the contiguous prefix, and the whole-sequence allowance.

`evaluate_operation()` first validates owned/current context and exact contract
operation, then uses replay → order → budget → operation guard → first application
precedence. Replay wins even at exhaustion; malformed or reordered requests are
denied. `FIRST_APPLICATION` returns a new ledger. `REPLAY_REFUSED`,
`BUDGET_EXHAUSTED`, and `OPERATION_REFUSED` return the exact input ledger with no
transition. The allowance counts applied operations, not offline refusal attempts;
it reserves no mutable target proof budget.

`evaluate_sequence()` starts or resumes the prefix through that one transition
definition. `WorkflowSequenceResult` rechecks the terminal ledger and independently
evaluated E1 decision; a partial prefix cannot claim a complete counterexample.

Caller: **passive/unwired**; no router/Foundry/Scan/scheduler/coordinator import.
Authority: no added origin, identity, action class, budget, transport or execution
authority. Cleanup: no target mutation, teardown or orphan risk. This remains pure
sequence semantics and a deterministic outcome evaluator, not observed effects.

## 5. R5E4 — durable atomic local sequence store

Module: `core/behavior/workflow_invariant_store.py`.

`WorkflowInvariantSequenceStore` mirrors the durable capability-consumption pattern:
one canonical full-ledger JSON snapshot per successful applied slot, append-only
exclusive-create publication, contiguous chain validation, and bounded collision
retry through E3 reload/re-evaluation. It reuses `BehavioralReceiptStore` root/file
validation, full-write/fsync/exclusive-hard-link publication and directory fsync;
the frozen receipt implementation/schema is unchanged.

The stream key binds the E1 owned fixture, not capture generation. A changed capture
therefore cannot start a second application history for that fixture. This bounded
version pins one capture through the sequence and refuses rebinding; fresh-world
sequence/reset orchestration is not implemented.

Files are euid-owned regular files of mode `0600`, rooted in an owned non-symlink
`0700` directory. Reads use `O_NOFOLLOW`, a 1 MiB size cap and exact canonical JSON.
Missing slots, filename/key substitution, forged/rehashed false transitions, unsafe
ownership/modes, symlinks and publication failure fail closed. A concurrent loser
revalidates durable state and refuses replay, including after process restart.
Refusals never append or alter bytes/mtimes. A filesystem error after publication
does not assert success; retained state is authoritative on the next reload.

Roots: explicit root; then `SENTINELFORGE_WORKFLOW_INVARIANT_SEQUENCES`; then
`SENTINEL_DATA_DIR/workflow_invariant_sequences`; otherwise
`~/.sentinelforge/workflow_invariant_sequences`.

Caller: **passive/unwired**; no router/Foundry/Scan/scheduler/coordinator import.
Authority: bounded local filesystem I/O only; no origin, identity, action class,
budget, transport or target execution authority. Cleanup: retained local files are
intentional evidence, not target residue; disposable fixture/orphan-risk false and
no target cleanup operation claimed.

## 6. R5E5 — retained inert evidence and offline eligibility

Module: `core/behavior/workflow_invariant_evidence.py`.

`WorkflowInvariantEvidenceStore` exclusively publishes a content-addressed completed
`WorkflowSequenceResult`, and verifies canonical encoding, filename/content identity,
owned provenance, E3 transitions and E1 decision on reload. Identical collisions are
idempotent and preserve file bytes/mtime. It stores positive and negative offline
outcomes. E4 can supply the durable ledger, as exercised by the end-to-end unit proof;
E5 also permits an already-completed pure E3 result because this is offline evidence.

Reload returns a distinct `StoredWorkflowInvariantEvidence`, with a private marker
minted only after the store's validated read. An ephemeral result, JSON projection,
or manually constructed value cannot assert successful retention through the public
API. This is a local storage boundary, not cryptographic authentication against code
running as the same operator or an observed target-effect attestation.

`offline_promotion_eligibility()` performs no I/O. It revalidates retained integrity,
the exact owned binding and operator-supplied current capture at a newly supplied
logical index. Only a retained, fresh `INVARIANT_VIOLATED` result is eligible. Secure
refusal/held results, stale/mismatched/cross-world provenance, forged inputs and
unretained results are ineligible. Its answer is Family E's own inert
`WorkflowPromotionEligibility`: offline-only, promotion/finding/execution authority
false. No canonical finding or OCB-R7 candidate is assembled.

Roots: explicit root; then `SENTINELFORGE_WORKFLOW_INVARIANT_EVIDENCE`; then
`SENTINEL_DATA_DIR/workflow_invariant_evidence`; otherwise
`~/.sentinelforge/workflow_invariant_evidence`.

Caller: **passive/unwired**; no router/Foundry/Scan/scheduler/coordinator import.
Authority: bounded local retention only; no new origin, identity, action class,
budget, transport or execution authority. Cleanup: no target residue/teardown/orphan
risk; no cleanup operation claimed. The independent terminal predicate remains a
deterministic outcome evaluator, not observed target-side evidence.

## 7. Focused proof and repository checkpoint

| Layer | Focused test file under `tests/unit/` | Passing cases |
|---|---|---|
| R5E1 | `test_behavior_workflow_invariant_contract.py` | 42 |
| R5E2 | `test_behavior_workflow_invariant_binding.py` | 25 |
| R5E3 | `test_behavior_workflow_invariant_ledger.py` | 22 |
| R5E4 | `test_behavior_workflow_invariant_store.py` | 29 |
| R5E5 | `test_behavior_workflow_invariant_evidence.py` | 29 |
| Total | Every case is included in the unmarked repository invocation | 147 |

Each file was run at its layer's coherent checkpoint. Both aggregate twins and the
held boundary, independent terminal evaluation, ownership/tenant/account/origin
refusal, stale/changed captures, negative/malformed/forged values, operation order,
replay/budget precedence, false-transition tampering, restart/double-application,
filesystem publication/refusal and inert eligibility are covered. R5E5 audits all
five modules' imports and absence of production consumers.

The E4 child-process proofs use fresh interpreter exec and pipe barriers, not
`multiprocessing` spawn from pytest's extension-heavy parent; they remain safe in
the unmarked invocation. This does not introduce a target concurrency oracle.

Python: **3.12.14**. Base collection was **3499** items before edits. The current
base has **27** marked process cases: the historical nine-file master-plan command
omits `tests/unit/test_local_security_check_baseline.py`. The full two-invocation
checkpoint must also include that existing tenth file to cover the full tree.

The final repository gate ran once, after all five layers, on Python **3.12.14**:

```text
.venv/bin/python -m pytest -q -m 'not subprocess_spawn'
```

Result: **3618 passed, 1 skipped, 27 deselected, 3 warnings in 39.78s**.

```text
.venv/bin/python -m pytest -q -m subprocess_spawn \
  tests/integration/test_session_safety.py \
  tests/unit/intel/test_token_store.py \
  tests/unit/test_behavior_capability_consumption_store.py \
  tests/unit/test_behavior_capability_execution_receipt_store.py \
  tests/unit/test_behavior_capability_effect_promotion.py \
  tests/unit/test_behavior_capability_effect_crash_recovery.py \
  tests/unit/test_epistemic_cas.py \
  tests/unit/test_teardown_deadline.py \
  tests/unit/test_verify_r5d10_evidence.py \
  tests/unit/test_local_security_check_baseline.py
```

Result: **27 passed, 115 deselected in 16.64s**. Those 115 unmarked cases already
ran in the first invocation. Union: **3645 passed, 1 skipped, 0 failed**, covering
all **3646** collected items. Delta over the unchanged base test inventory:
**3498 + 147 = 3645 passing cases**, with the same single conditional websocket skip.
The base collection was measured before edits; no second full baseline run is
claimed. All 147 new cases ran in the unmarked command. The first invocation's three
warnings are two existing ldap3/pyasn1 deprecations and one scheduling-sensitive
aiosqlite closed-event-loop worker warning; none is suppressed or attributed to E.

The canonical-ID validator file passed **3** focused cases and is also included in
the full gate. An additive-registry audit verifies all old records/aliases are
unchanged, all six new IDs validate, and the new plan and new master-plan lines
introduce no bare IDs. The inherited master text still contains bare round
references corresponding to OCB-R6, OCB-R7 and OCB-R8 at the base; whole-file source
validation fails there too. That existing
documentation debt is preserved, not hidden by changing registry semantics.

This advances only the bounded passive spine to **Suite-proved**, at code checkpoint
`2fc28add4a5b6bf1e7bbd6c898d0e03953e4fcfc` plus this additive documentation/registry
change. It advances no production-wired, lab, native, live, external or payout claim.

Targeted `ruff check`, `ruff format --check` and Python byte-compilation pass all ten
new Python files. `scripts/local-security-check.sh` ran before every layer commit:
it actually exits **0** at this base, unlike the work order's inherited exit-1
expectation, because reviewed shell/eval/exec/os.system matches are now baselined.
It reports no new/Family-E violation. Repository-wide Ruff debt, example secret
warnings and unavailable Bandit remain reported; a green critical script does not
erase that debt. No matcher, baseline file, dependency or frozen surface was changed.

## 8. Delivery identities

| Layer | Local commit |
|---|---|
| R5E1 | `dcbd0b51ff5c679e2d6693a1cbd086aabac618b6` |
| R5E2 | `23f6abe7bc5715cd0e076938e6403fc8b88a6cd9` |
| R5E3 | `49533d47fd546d17757ca9e3f75f424b219c784e` |
| R5E4 | `b7a58ac72c5311373e7266163401a225944902d1` |
| R5E5 | `2fc28add4a5b6bf1e7bbd6c898d0e03953e4fcfc` |

The documentation-only branch tip follows this code checkpoint; its final SHA is
recorded in the handoff. `git push -u origin ocb/r5e-workflow-invariant-spine` was
rejected before execution with the exact policy error:
`approval required by policy, but AskForApproval is set to Never`.
All commits remain local. Per the work order, publication is left to Jason and no
alternate publication path is attempted. Delivery therefore remains open at the
permitted local-SHA stop. Mediator verification against the real repository and
Jason's separate merge go remain required; no merge is authorized here. Commits
carry no generated or co-author trailer.

## 9. Deferred work and declared E5 stop boundary

No injected/concrete transport, independent running-workflow effect-occurrence oracle,
Foundry/Scan profile, scheduler, production coordinator, canonical finding promotion,
OCB-R7 candidate assembly, receipt/certificate, report/submission material, lab/native
run or acceptance artifact is provided. `OCB-S21` is only registered. Negative-value
or underflow, total-versus-line-item consistency and bounded-effect over-application
are deferred Family-E shapes. No concurrency shape is implemented.

The next program decision is mediator verification of this real branch and Jason's
separate merge go. The master-plan ordinary A–D loop measurement remains open.
A separately authorized Family-E active tail must define the independent observed
effect oracle, bounded transport/admission, cleanup and receipt authority before any
running-workflow or `OCB-S21` claim. No new slice ID is assigned to that deferred work.

## 10. Authority and external-gate statement

Every layer is default-off by absence of a production caller. E1–E3 are pure; E4–E5
perform bounded local filesystem I/O only. There is no external gate for this passive
spine: a lab/native artifact would not make it executable and must not be fabricated.
No external target, report, submission or payout outcome was attempted or claimed.

This work order changes no offensive capability, target traffic or execution
authority: it is a passive, unwired foundation.
