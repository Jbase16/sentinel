# OCB-R5D5 Admitted-Runtime Expiry Plan

Status: suite-proved as a passive, production-unwired semantics slice; the exact
unpushed local delivery SHA is recorded in the implementation handoff

Base: SentinelForge `main` at `9128aa44afc47c9165e5625003b080cec7035bbc`

Canonical stage: OCB-R5 Family D, slice `R5D5`. The registered downstream scenario
is `OCB-S17`; R5D5 does not implement or claim that scenario.

## 1. Bounded outcome and passive boundary

R5D5 adds `core/behavior/capability_runtime_expiry.py`, which defines an explicit
content-addressed `AdmittedRuntimeContract` and a pure
`evaluate_runtime_liveness()` function. The contract says that one named runtime has
admitted one exact R5D1 issued capability for the absolute wall-clock interval
`[admitted_at_epoch, expires_at_epoch)`. The evaluator composes that admission with an
already-computed R5D1 `CapabilityDecision` at one caller-injected finite epoch.

A capability is runtime-live iff R5D1 classifies its presentation `VALID` and the
admitting runtime's wall-clock window contains the observed instant. R5D5 adds only
the second conjunct; it never re-decides the first. The clock is an injected argument,
so the module is a pure function of `(logical_decision, admission, now)` and reads no
real time.

The module performs no filesystem, database, environment, network, target, or clock
I/O. It does not import R5D4's consumption store and owns no persistence, backend
dispatch, callback provisioning, execution-receipt transition, effect evaluation,
finding construction, promotion, retry, or cleanup. No API router, Foundry path, Scan
profile, scheduler, coordinator, package export, UI, or other `core/` module imports
it. Its only importer is its focused unit test.

## 2. Admitted runtime contract and content address

`AdmittedRuntimeContract` binds:

- the exact `issued_capability_contract:<64hex>` reference from its privately retained
  R5D1 `IssuedCapabilityContract` context;
- one `admitted_runtime:<64hex>` identity;
- finite, real-float `admitted_at_epoch` and `expires_at_epoch` values with the strict
  invariant `expires_at_epoch > admitted_at_epoch`; and
- mode `behavioral_capability_runtime_expiry_v1`.

Its `admission_id` is the house `stable_hash()` content address with prefix
`admitted_runtime_capability`. The identity payload includes the typed capability and
runtime references, mode, and both epochs serialized through exact `repr(float)`
strings. It excludes the private live contract context and the declared passive
authority flags. `target_dispatch_authority`, `execution_receipt_authority`, and
`real_clock_read_authority` must each be exactly `False`.

`build()` and `__post_init__()` independently require the typed references, exact
R5D1 capability binding, finite float epochs, ordered window, fixed mode, passive
flags, and re-derived content address. Integers and booleans are not accepted as
epochs; NaN and positive or negative infinity are denied.

`to_dict()` emits both epochs as exact strings. `from_dict()` requires the caller to
re-supply the real R5D1 contract context, requires the exact schema field set and
passive flags, accepts only the canonical `repr(float)` encoding, and re-verifies the
complete content address. Serialized bytes cannot reconstruct or infer capability
authority. Values such as `1.1` and `1900000000.5` round-trip equal and re-hash to the
same IDs.

## 3. Pure evaluator and fixed precedence

`evaluate_runtime_liveness(logical_decision, admission, *, now)` first requires the
two exact dataclass types, then denies any non-float or non-finite `now` as
`runtime_clock_reading_is_invalid`. It denies a cross-capability pair as
`runtime_admission_capability_mismatch` before classifying time.

For valid inputs, its total precedence is:

1. `LOGICALLY_INADMISSIBLE` when R5D1's outcome is anything other than `VALID`;
2. `EXPIRED_AT_RUNTIME` when `now >= expires_at_epoch`;
3. `NOT_YET_LIVE` when `now < admitted_at_epoch`; and
4. `ADMITTED_LIVE` otherwise.

Logical inadmissibility dominates every wall-clock position. The runtime axis does not
replace an R5D1 revocation, logical-index expiry, wrong binding, or used-capability
refusal, and it does not reveal which time outcome would otherwise have applied. The
window is exactly left-closed and right-open: equality at admission is live, while
equality at expiry is expired.

The returned `RuntimeLivenessDecision` binds the admission ID, unchanged R5D1 decision
ID, shared capability reference, exact observed epoch, outcome, and fixed mode into a
`runtime_liveness_decision:<64hex>` content address. Its private decision and admission
contexts prevent construction of a semantically inconsistent outcome. Identical
inputs, including `now`, return equal decisions; changing only `now` changes the
decision ID.

## 4. Integrity and authority limits

Malformed reference prefixes, cross-capability substitutions, invalid floats,
degenerate or backward windows, non-canonical serialized floats, missing or additional
fields, mutated content, forged IDs, wrong modes, and enabled authority flags all fail
closed. The hash is an integrity identity, not a signature or a source of admission
authority.

R5D5 defines absolute epoch semantics because those values can be compared across
processes and restarts. It deliberately does not choose, read, trust, or correct a
machine clock. A later boundary must own the actual clock reading and the consequences
of clock behavior; the pure evaluator proves only how an injected value is classified.

The source guard parses the module AST and excludes imports of `time`, `asyncio`,
`socket`, `httpx`, `requests`, `subprocess`, and
`capability_consumption_store`. A repository scan separately proves that no other
`core/` Python file references the new module.

## 5. Focused and repository proof

`tests/unit/test_behavior_capability_runtime_expiry.py` collects 71 passing cases.
They cover exact-float admission round trips, reference and private-context binding,
all invalid epoch classes, equal/backward windows, mode and passive-authority refusal,
strict deserialization and tamper refusal, the five-point valid window matrix, every
non-`VALID` R5D1 outcome across five wall-clock positions, cross-capability refusal,
bad clock readings, argument types, instant-specific identity, forged decision and
semantic outcomes, and the AST/source passivity proof.

The exact focused checkpoint is:

`.venv/bin/python -m pytest tests/unit/test_behavior_capability_runtime_expiry.py tests/unit/test_canonical_id_registry.py -q`

It reports `74 passed in 0.18s`: 71 runtime-expiry cases and the unchanged three-case
canonical-ID registry file. The Python 3.12.12 `.venv` full repository suite reports
`2988 passed, 1 skipped, 3 warnings in 38.51s`, exactly 71 new passing cases over the
R5D4 baseline of `2917 passed, 1 skipped`. The skip count is unchanged. The warning
count is one lower than the final R5D4 run because the documented scheduling-sensitive
pre-existing `aiosqlite` closed-event-loop warning occurred once rather than twice;
the two dependency deprecations are unchanged. No warning was suppressed or
reclassified.

Targeted `ruff check` and `ruff format --check` pass all three changed Python files,
and `git diff --check` is clean. The required `scripts/local-security-check.sh` exits
1 on the documented repository-wide broad-text matchers, missing Bandit, and unrelated
Ruff debt. None of its reported locations is an R5D5 changed file. That baseline is
not a green gate and is neither hidden nor repaired in this slice.

## 6. Capability and execution-authority statement

R5D5 adds a passive semantic capability: Sentinel can deterministically describe how
an already-admitted capability's logical verdict and an injected absolute epoch
compose. It does not expand offensive capability, target traffic, or execution
authority. It reads no real clock and cannot dispatch or record completion of an
action.

A green R5D5 test is focused-tested and suite-proved local semantics. It is not
lab-attested, live-observed, target-enforced, finding-producing, payout-proven, or
evidence that expiry works against a running target.

## 7. Open work and stop boundary

- [x] R5D5 pure wall-clock expiry semantics under a separately admitted runtime
  contract, using only a caller-injected epoch.
- [ ] Read a real clock at a boundary.
- [ ] Complete or abort an execution receipt for an executed action.
- [ ] Dispatch to a target or evaluate an independent target effect, finding, or
  promotion.
- [ ] Verify target-residue cleanup.
- [ ] Run and accept the full `OCB-S17` matrix for confinement, expiry, one-time use,
  replay refusal, and cleanup.

The planned next Family-D slice, if separately authorized, is wiring a real clock
reading plus an execution-receipt transition at a boundary (`R5D6`). That slice must
not infer dispatch, target-scope, traffic, callback, effect, cleanup, finding, or
acceptance authority from R5D5's pure evaluator.
