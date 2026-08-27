# OCB-R5D3 Passive Consumption-Ledger Plan

Status: suite-proved as a passive, unwired design slice; the exact pushed delivery
SHA is recorded in the implementation handoff

Base: SentinelForge `main` at `0271c010e38f53b2ef7a4cde16602928e2b6b099`

Canonical stage: OCB-R5 Family D, slice `R5D3`. The registered downstream scenario
is `OCB-S17`; R5D3 does not implement or claim that scenario.

## 1. Bounded outcome and persistence boundary

Durable one-time use has two separate concerns:

1. deterministic transition semantics decide whether an admissible presentation is a
   first consumption, an identical-presentation replay, or a distinct presentation
   after the capability budget is spent; and
2. active persistence must store that transition with exclusive-create or
   cross-process compare-and-swap behavior.

R5D3 implements only the first concern in
`core/behavior/capability_consumption_ledger.py`. The caller supplies an explicit
immutable prior ledger, and the pure evaluator returns a content-addressed decision
plus the exact next ledger. It performs no storage operation. It does not import or
reference `BehavioralReceiptStore`, create a file or database row, read configuration,
or claim survival across process restart.

R5D1 remains the logical validity axis. R5D2 remains the confinement and capture-
freshness evidence axis. R5D3 consumes their already-typed decisions without
reimplementing revocation, expiry, binding, confinement, origin, or capture semantics.
This closes the passive semantic gap in which the same caller-supplied R5D1
`use_index` could otherwise classify as valid repeatedly; the ledger's recorded entry
count, not that caller index, is authoritative for R5D3.

## 2. Immutable content-addressed ledger

The R5D3 public surface retains typed hashes and logical use slots only:

| Type | Public contract |
|---|---|
| `ConsumptionEntry` | Capability ID, R5D2 decision ID as the replay key, exact R5D1 and R5D2 decision references, zero-based filled use slot, and `capability_consumption_entry` ID |
| `CapabilityConsumptionLedger` | Canonically sorted immutable entries and an order-independent `capability_consumption_ledger` ID over their sorted entry IDs |
| `ConsumptionDecision` | Capability, prior-ledger, next-ledger, and R5D2-presentation references, typed outcome and reason, and `capability_consumption_decision` ID |
| `ConsumptionResult` | The decision and the exact next-ledger object returned by the evaluator |

The empty tuple is the valid genesis ledger. `with_entry()` returns a new ledger and
never mutates its receiver. Ledger construction rejects duplicate entry IDs, invalid
entry content addresses, non-canonical direct construction, and every attempt to turn
on durable-persistence, target-I/O, backend-dispatch, receipt, finding, or executable
authority. The ledger mode is fixed to
`behavioral_capability_consumption_ledger_v1`.

Ledger identity is order-independent: construction first validates every entry,
rejects duplicates, and sorts by `entry_id`; the ledger ID is then
`stable_hash("capability_consumption_ledger", {"entry_ids": [...]})`. An eventual
store can persist the serialized entries and this ID, but R5D3 provides no store or
write authority.

Entry and decision construction retains the R5D1/R5D2 decision objects and transition
ledgers only as private `repr=False, compare=False` validation context. That context
does not appear in `to_dict()`, the content-address payloads, or repr output. Every
builder computes its ID after validation, and every frozen dataclass `__post_init__`
revalidates types, typed-reference prefixes, exact private/public bindings, logical
bounds, passive flags, and its recomputed ID. Boolean values are rejected where a
logical integer slot is required.

## 3. Admissibility gate

`evaluate_consumption()` accepts an `IssuedCapabilityContract`, one R5D1
`CapabilityDecision`, one R5D2 `ConfinementDecision`, and a
`CapabilityConsumptionLedger`. Before classifying consumption it reconstructs the two
decision dataclasses and the complete ledger through their own validation paths. A
forged decision or ledger ID therefore fails before any transition is considered.

The three capability references must be identical, the R5D1 outcome must be `VALID`,
and the R5D2 outcome must be `CONFINED_FRESH`. Every other R5D1 or R5D2 outcome and
every cross-capability mixture raises `ConsumptionLedgerDenied` with
`capability_use_is_not_admissible`. An escaped, stale, revoked, expired, misbound, or
already-used logical presentation is malformed input for the consumption question;
R5D3 does not translate it into one of its three outcomes.

## 4. Fixed transition precedence

For admissible inputs, let the replay key be the R5D2 confinement-decision ID and let
`consumed` be the prior-ledger entries for the exact capability. The evaluator applies
this order:

1. `REPLAYED_PRESENTATION` when a consumed entry already has that replay key;
2. `CAPABILITY_ALREADY_CONSUMED` when the presentation is distinct but
   `len(consumed) >= contract.max_uses`; and
3. `FIRST_CONSUMPTION` otherwise, recording one entry at
   `use_slot = len(consumed)`.

The order distinguishes an exact idempotent retry or captured-evidence replay from a
new presentation after budget exhaustion. At a fully consumed budget, an already-
recorded presentation is therefore always `REPLAYED_PRESENTATION`.

Both refusal outcomes retain the exact prior-ledger object and record nothing. A first
consumption must change the ledger ID; a refusal must not. `ConsumptionDecision.build`
independently re-derives the ordered expected outcome and expected next ledger, in
addition to enforcing the changed-ledger-if-and-only-if-first-consumption guard. A
caller cannot construct a differently labeled refusal or attach an unrelated next
ledger while retaining a valid decision.

## 5. Three-axis composition

The complete passive composition is:

```text
consumable in the supplied ledger = R5D1 outcome VALID
                                and R5D2 outcome CONFINED_FRESH
                                and R5D3 outcome FIRST_CONSUMPTION
```

The axes remain orthogonal. A capability can still be logically valid and its current
evidence still confined-fresh after the same use was recorded; R5D3 then refuses the
second attempt as replay or budget exhaustion without changing either upstream
decision. No R5D3 output changes R5D1 or R5D2 state.

## 6. Focused proof

`tests/unit/test_behavior_capability_consumption_ledger.py` collects 42 cases. They
cover:

- deterministic first consumption and reproducible entry, ledger, decision, and
  genesis IDs;
- identical-presentation replay with exact input-ledger object identity;
- single-use cross-presentation exhaustion and multi-use slots `0..N-1`;
- replay-over-exhaustion precedence at a full budget and independent enforcement by
  the decision builder;
- multi-capability ledger isolation and exclusion of caller-supplied R5D1 `use_index`
  from the budget decision;
- all four inadmissible R5D1 outcomes, both inadmissible R5D2 outcomes, and both
  cross-capability mismatch directions;
- forged input and output content addresses, duplicate entries, invalid entry content,
  direct substitution, and boolean/negative/out-of-budget slots;
- immutable passive flags and AST-confirmed absence of `os`, `tempfile`, and receipt-
  store imports;
- private-context and raw capture exclusion from fields, serialization, and repr;
- order-independent ledger identity; and
- explicit three-axis independence after the first consumption.

The R5D3 focused file passes all 42 cases. The canonical-ID registry test file passes
all three cases, including the registered `R5D3` assertion; the combined checkpoint is
45 passing cases. The full repository suite passes
`2884 passed, 1 skipped, 3 warnings in 39.24s` on Python 3.12.12: exactly 42
additional passes over the R5D2 baseline, with the skip and warning counts unchanged.
Targeted Ruff lint passes every changed Python file, and the two new Python files pass
targeted Ruff format checking.

The required `scripts/local-security-check.sh` exits 1 on the documented pre-existing
broad-text matcher results, missing Bandit, and repository-wide Ruff debt. It reports
no R5D3-file violation; that baseline is not a green gate and is not repaired or hidden
inside this slice.

## 7. Passive, unwired authority boundary

No API router, Foundry path, Scan profile, scheduler, UI, coordinator, or production
package imports R5D3. The only consumer is its focused unit test. The evaluator reads
only supplied immutable Python values and returns new immutable Python values.

R5D3 adds no origin, identity, action class, request budget, feature flag, backend,
target traffic, storage write, reservation token, receipt transition, callback,
finding construction, promotion, retry, or execution path. It creates no target or
local-storage residue and therefore makes no cleanup or orphan-risk claim.

Offensive capability, target traffic, and execution authority are unchanged.

## 8. Open active work and stop boundary

R5D3 is the terminal passive Family-D slice. These obligations remain explicitly open:

- durable persistence with exclusive-create or cross-process compare-and-swap;
- expiry enforcement against a running target and clock;
- receipt completion and abort semantics;
- verified cleanup and teardown execution;
- an independent target-effect oracle and finding construction; and
- the full `OCB-S17` vulnerable/secure acceptance matrix.

The planned next Family-D work, if separately authorized, is an active/wired durability
slice that persists the R5D3 transition rules atomically through the existing receipt
boundary. It must not infer traffic, persistence, or execution authority from this
passive ledger. Running-target expiry, receipt lifecycle, cleanup, effect proof, and
`OCB-S17` follow as separately gated obligations.
