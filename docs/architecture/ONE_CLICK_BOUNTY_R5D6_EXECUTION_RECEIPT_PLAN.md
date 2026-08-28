# OCB-R5D6 Real-Clock Execution-Receipt Plan

Status: implemented and suite-proved locally; production-unwired

Base: clean `main` at `dbaf3a7ad5f5757cb50fc188ae80b0e2caab62f9`

Scope choice: SHALLOW. R5D6 owns one real wall-clock read and an ephemeral terminal
execution-receipt decision. It owns no durable receipt store. A later R5D7 slice may
add purpose-built persistence under its own namespace; it must not reuse the live
`BehavioralReceiptStore` namespace.

## 1. Bounded intent

R5D6 adds `core/behavior/capability_execution_receipt.py`. Its single public evaluator
reads one wall-clock instant, asks R5D5 to classify that exact instant, composes the
returned liveness verdict with an already-computed R5D3 consumption verdict, and mints
one immutable `CapabilityExecutionReceipt` terminal value.

The slice composes four previously established axes without reimplementing them:

- R5D1 owns the logical capability verdict;
- R5D2 supplies the confinement/freshness evidence already consumed by R5D3;
- R5D3/R5D4 own consumption classification and any prior local durability; and
- R5D5 alone decides whether the supplied instant is inadmissible, expired, not yet
  live, or admitted live.

R5D6 does not call R5D3 or R5D4 to consume or persist anything. The caller supplies the
existing `ConsumptionDecision`. It does not dispatch an action, contact a target,
provision a callback, observe an effect, create or promote a finding, retry, or clean
up target state. No production caller imports the module.

## 2. One real-clock seam

`evaluate_capability_execution(logical_decision, admission, consumption_decision, *,
clock=time.time)` is the first Family-D function with a real-clock default. It requires
the exact R5D1 `CapabilityDecision`, R5D5 `AdmittedRuntimeContract`, and R5D3
`ConsumptionDecision` dataclass types plus a callable clock before reading time.

The evaluator calls `clock()` exactly once. A raised clock exception, integer, boolean,
NaN, or positive or negative infinity fails closed as `RuntimeExecutionDenied`; only a
finite value whose exact type is `float` proceeds. It then requires the R5D1 decision,
R5D5 admission, and R5D3 consumption verdict to share the same
`issued_capability_contract:<64hex>` reference.

The accepted instant is passed unchanged to
`evaluate_runtime_liveness(logical_decision, admission, now=observed_epoch)`. R5D6
does not compare the instant to admission or expiry itself. R5D5 remains the sole time
decider. A source-AST test proves that `time.time` occurs exactly once in the module,
solely as the `clock` parameter's default, and that `clock()` has exactly one call site.

## 3. Fixed total terminal precedence

The terminal outcome precedence is:

1. `EXECUTION_REFUSED_INADMISSIBLE` when R5D5 returns
   `LOGICALLY_INADMISSIBLE`;
2. `EXECUTION_REFUSED_ALREADY_CONSUMED` when R5D3 returns either
   `REPLAYED_PRESENTATION` or `CAPABILITY_ALREADY_CONSUMED`;
3. `EXECUTION_REFUSED_EXPIRED` when R5D5 returns `EXPIRED_AT_RUNTIME`;
4. `EXECUTION_REFUSED_NOT_LIVE` when R5D5 returns `NOT_YET_LIVE`; and
5. `EXECUTION_COMPLETED` only for the conjunction of R5D5 `ADMITTED_LIVE` and R5D3
   `FIRST_CONSUMPTION`.

The 4-by-3 liveness/consumption matrix is total and directly tested. In particular,
logical inadmissibility beats both an expired clock position and an already-consumed
verdict, and an already-consumed verdict beats an expired or not-yet-live instant.
There is no partial-complete state.

`EXECUTION_COMPLETED` is the name of this terminal composition verdict. It is not
evidence that R5D6 dispatched or completed a target action; this production-unwired
slice has no target action surface.

## 4. Content address and forgery guard

`CapabilityExecutionReceipt` is a frozen dataclass containing:

- `capability_ref` with prefix `issued_capability_contract`;
- `liveness_ref` with prefix `runtime_liveness_decision`;
- `consumption_ref` with prefix `capability_consumption_decision`;
- the finite real-float `observed_epoch`, serialized as exact `repr(float)`;
- the terminal `CapabilityExecutionOutcome`; and
- fixed mode `behavioral_capability_execution_receipt_v1`.

Its `receipt_id` is
`stable_hash("capability_execution_receipt", payload)`. The payload contains the three
typed references, exact epoch encoding, outcome, and mode. The private live
`RuntimeLivenessDecision` and `ConsumptionDecision` contexts are excluded from the
hash, public projection, representation, and equality.

Both `build()` and `__post_init__()` require the exact live context types, revalidate
those frozen values, bind their public IDs and shared capability, bind the exact R5D5
observed instant, recompute the terminal outcome from both live contexts, and rederive
the receipt content address. A caller cannot make a forged semantic outcome valid by
rehashing it. Identical inputs including the instant produce equal receipts; changing
only the instant changes the liveness and receipt IDs. This ephemeral type deliberately
has no `from_dict()`.

## 5. Passive authority and storage boundary

These public flags must each be exactly `False`:

- `target_dispatch_authority`;
- `execution_effect_authority`;
- `finding_promotion_authority`; and
- `target_cleanup_authority`.

The module imports only math, time, dataclass/enum/typing utilities, the exact
R5D1/R5D3/R5D5 types and evaluator, and the existing content-address helpers. Its AST
guard forbids `asyncio`, `socket`, `subprocess`, `httpx`, `requests`, `os`, `pathlib`,
`json`, `capability_consumption_store`, and `receipts`. It has no filesystem,
environment, database, network, target, behavioral-receipt, or durable
capability-execution-receipt namespace.

R5D5's prior source guard was narrowed to recognize exactly this authorized R5D6
consumer. R5D5 remains pure and clock-injected; R5D6 is itself production-unwired, and
R5D6's repository guard proves that no other `core/` module imports it.

If R5D7 adds receipt persistence, it must use a purpose-built
`capability_execution_receipts` namespace and may reuse only the established receipt
filesystem-safety primitives. It must not write to the live production
`behavioral_receipts` namespace.

## 6. Verification

`tests/unit/test_behavior_capability_execution_receipt.py` collects 63 cases. They
cover the complete fixed-precedence matrix, the required cross-axis dominance pairs,
single clock read and exact R5D5 delegation, unmutated R5D3 input, typed content
addresses and exact public projection, private-context exclusion, deterministic and
instant-specific identity, all invalid epoch classes, argument and subclass refusal,
clock exceptions, all cross-capability substitutions, exact-false authority fields,
wrong mode, inconsistent epoch and outcome, forged IDs, hash-consistent semantic and
reference substitutions, private-context substitution, allowed-import shape, the sole
`time.time` default, and production-unwired status.

The exact R5D6 plus canonical-ID checkpoint is:

`.venv/bin/python -m pytest tests/unit/test_behavior_capability_execution_receipt.py tests/unit/test_canonical_id_registry.py -q`

It reports `66 passed`: 63 R5D6 cases and the unchanged three-case canonical-ID file.
The compatibility checkpoint including R5D5 reports `137 passed`: the existing 71
R5D5 cases, 63 R5D6 cases, and three registry cases.

The final Python 3.12.12 full repository suite reports
`3051 passed, 1 skipped, 4 warnings in 39.16s`, exactly 63 new passing cases over the
R5D5 baseline of `2988 passed, 1 skipped`. The skip count is unchanged. The warning
set contains the two existing dependency deprecations and two occurrences of the
documented scheduling-sensitive pre-existing `aiosqlite` closed-event-loop warning;
no warning was suppressed or reclassified.

Targeted `ruff check` and `ruff format --check` pass all four changed Python files,
including the narrowly updated R5D5 compatibility guard. `git diff --check` is clean.
The required `scripts/local-security-check.sh` exits 1 on the documented
repository-wide broad-text matcher results, missing Bandit, and unrelated Ruff debt.
It reports no changed-file Ruff violation. That red baseline is neither hidden nor
repaired in this slice.

## 7. Evidence and authority statement

R5D6 adds a bounded real-clock semantic capability: Sentinel can read one wall-clock
instant and mint an ephemeral decision describing how existing logical, liveness, and
consumption verdicts compose. It does not expand offensive capability, target traffic,
or execution authority. It adds no persistence and cannot dispatch, prove an effect,
promote a finding, or verify cleanup.

A green R5D6 suite is focused-tested and suite-proved local behavior. It is not
lab-attested, live-observed against a target, target-enforced, finding-producing,
payout-proven, or `OCB-S17` acceptance evidence.

## 8. Open work and stop boundary

- [x] R5D6 reads one real clock instant and mints an ephemeral, content-addressed
  terminal execution-receipt decision.
- [ ] R5D7 durably persists terminal capability-execution receipts in a purpose-built
  namespace with cross-process atomicity, restart survival, refusal immutability, and
  tamper-evident reload.
- [ ] Dispatch an independently admitted target action or evaluate an independent
  target effect.
- [ ] Construct or promote a finding from verified target evidence.
- [ ] Verify target-residue cleanup.
- [ ] Run and accept `OCB-S17` for confinement, expiry, one-time use, replay refusal,
  and cleanup.

R5D7 is the planned next slice. It may add only production-unwired durable receipt
persistence; it must not infer dispatch, target scope, traffic, callback, effect,
cleanup, finding, or acceptance authority from R5D6's clock read or terminal value. No
later slice identifier is assigned here.
