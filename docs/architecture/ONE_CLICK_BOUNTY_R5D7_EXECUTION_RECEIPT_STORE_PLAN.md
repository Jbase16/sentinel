# OCB-R5D7 Durable Capability-Execution Receipt Store Plan

Status: implemented and suite-proved locally; production-unwired

Base: clean R5D6 tip at `4d384b36a0e96adb27a070ae2f66fca2e0d17e46`

Decision: Horn B. R5D6 source remains frozen. R5D7 persists R5D6's public receipt
projection and reloads it as a distinct inert `StoredExecutionReceipt`; it does not
add `from_dict()` or any reloaded subtype to `CapabilityExecutionReceipt`.

## 1. Bounded intent

R5D7 adds `core/behavior/capability_execution_receipt_store.py`, a purpose-built
append-only local store for already-minted R5D6 `CapabilityExecutionReceipt` values.
The caller still owns minting through R5D6. The R5D7 API validates the live receipt,
persists its exact public `to_dict()` projection as canonical JSON, and reloads that
projection with its content address reverified.

The store does not read a clock or combine minting with persistence. It does not
dispatch an action, contact a target, provision a callback, evaluate a target effect,
construct or promote a finding, verify target cleanup, or wire itself into a production
caller. It performs local filesystem I/O only.

## 2. Horn B reload contract

`StoredExecutionReceipt` is a frozen public-only value containing the R5D6 receipt ID,
capability, liveness, and consumption references, parsed finite epoch, exact
`CapabilityExecutionOutcome`, R5D6 mode, four exact-false authority flags, and
`reloaded=True`. It has no live `RuntimeLivenessDecision` or `ConsumptionDecision`
field and therefore cannot be passed off as a live R5D6 receipt.

Construction and reload require:

- `capability_execution_receipt`, `issued_capability_contract`,
  `runtime_liveness_decision`, and `capability_consumption_decision` typed references;
- exact R5D6 mode `behavioral_capability_execution_receipt_v1`;
- all four target-dispatch, execution-effect, finding-promotion, and target-cleanup
  authority flags to be exactly `False`; and
- `reloaded` to be exactly `True`.

`DurableExecutionReceiptResult` returns this inert record plus `durable_written`, which
is `True` only when that call created the final content-addressed file.

## 3. Content-address integrity

The file contains exactly `CapabilityExecutionReceipt.to_dict()` in canonical JSON;
there is no private mint-time context and no store wrapper mixed into the R5D6 receipt
hash. `CAPABILITY_EXECUTION_RECEIPT_STORE_MODE` names the store contract without
changing the persisted receipt projection.

On reload, R5D7 reconstructs the exact six-field R5D6 public hash payload: capability,
liveness, and consumption references; the canonical observed-epoch string; outcome;
and R5D6 mode. `request_fingerprint()` supplies the same canonical SHA-256 digest used
inside `stable_hash()`, and R5D7 restores the
`capability_execution_receipt:<64hex>` type prefix. Focused tests compare this result
directly with freshly minted R5D6 receipt IDs.

R5D7 imports R5D6's `_canonical_epoch` rule rather than forking float encoding. Reload
accepts the stored epoch only when parsing it to a finite exact `float` and applying
that rule yields the byte-identical string. Hash-consistent alternatives such as
`"150"` and `"150.00"` fail closed.

## 4. Namespace, path, and audited primitives

Root selection is, in order:

1. the explicit `root` argument;
2. `$SENTINELFORGE_CAPABILITY_EXECUTION_RECEIPTS`;
3. `$SENTINEL_DATA_DIR/capability_execution_receipts`; or
4. `~/.sentinelforge/capability_execution_receipts`.

This namespace is distinct from both live `behavioral_receipts` and R5D4
`capability_consumptions`. The per-capability grouping key is
`request_fingerprint({"schema_version":1,"capability_ref":...})`. Each final path is:

`execution-<capability-store-key>-<capability_execution_receipt:64hex>.json`

Load binds the per-capability prefix, the filename receipt ID, the public projection's
receipt ID, and the recomputed receipt content address. Any mismatch fails closed.

R5D7 reuses `BehavioralReceiptStore._prepare_root`, `_validate_file_info`,
`_link_exclusive`, and `_fsync_directory`, plus `ReceiptStoreError`,
`_MAX_RECEIPT_BYTES`, `re_full_sha256`, and `request_fingerprint`. It reimplements no
filesystem publication or validation primitive. The reused boundary provides a
non-symlink, euid-owned `0700` root; `O_RDONLY|O_CLOEXEC|O_NOFOLLOW` reads of regular,
euid-owned `0600` files; a one-MiB cap; fully written and file-fsynced temporary
residue; exclusive hard-link publication; and directory fsync.

## 5. Persistence and honest atomicity

`CapabilityExecutionReceiptStore.persist(receipt)` requires the exact R5D6 receipt
type and calls `dataclasses.replace(receipt)` before any store write. That reruns
R5D6's mint-time `__post_init__` and rejects an in-memory object whose public outcome,
content address, or private decisions were forged after construction.

The first publisher creates one immutable canonical file and directory-fsyncs it.
When the final path already exists, the loser opens it through the same safe-read
boundary, revalidates its public projection and filename binding, and requires exact
byte equality with the intended payload. An equal record returns
`durable_written=False`; a mismatch fails closed. Re-persist never replaces or touches
the existing file, so its bytes and `st_mtime_ns` remain unchanged.

This is idempotent convergence, not a first-execution race. Two processes persisting
the identical precomputed receipt converge on one file with exactly one `True` and one
`False` result. Receipts minted at different instants have different content addresses
and both persist. R5D7 does not adjudicate which execution occurred.

## 6. Reload, refusal immutability, and tamper handling

`load(capability_ref)` returns a deterministic tuple of inert records for that
capability. A missing root returns an empty tuple without creating storage. All five
R5D6 terminal outcomes use the same path: the completed outcome and all four refusal
outcomes are durable evidence.

Every load rechecks canonical JSON bytes, schema and exact field set, canonical epoch,
typed references, R5D6 mode, exact-false authority flags, the R5D6 content address, and
the filename/content/hash three-way binding. Outcome, reference, epoch, receipt-ID,
authority, schema, or mode edits; forged filenames; extra live-context fields;
noncanonical JSON; unsafe permissions or ownership; oversized files; and symlinked
roots or final paths all fail closed as `CapabilityExecutionReceiptStoreError`.

## 7. Production boundary and R5D6 freeze

No `core/` module imports the new store. It is not exported from an `__init__`, router,
Foundry path, Scan path, or backend. The module imports only JSON, OS, dataclass,
path, and typing utilities plus R5D6 and receipt-store contracts; an AST test rejects
clock, network, subprocess, and asynchronous transport modules.

R5D6 source `core/behavior/capability_execution_receipt.py` is byte-unchanged from
`4d384b3`. The sole R5D6-file touch narrows its test guard from no consumers to the
exact one authorized importer,
`core/behavior/capability_execution_receipt_store.py`; exact-list equality still
rejects every additional core consumer.

## 8. Verification inventory

`tests/unit/test_behavior_capability_execution_receipt_store.py` collects 55 cases.
They cover all five outcomes; canonical owner-only residue; R5D6 ID/public-field
round-trip; restart and multi-record survival; missing-root behavior; unchanged bytes
and mtime on idempotent re-persist; capability isolation; genuine `spawn` plus
`Barrier(2)` identical-write convergence and distinct-instant publication; namespace
selection; inert public-only fields; exact-false authority; exact input types and
replace revalidation; content, name, hash, schema, mode, epoch, and encoding tamper;
collision mismatch; root/file permissions and ownership; size caps; `O_NOFOLLOW`;
audited primitive reuse; import restrictions; exports; and production-unwired status.

The store-only checkpoint is `55 passed`. The exact R5D6, R5D7, and canonical-ID
compatibility checkpoint is `121 passed`: the unchanged 63 R5D6 cases, 55 R5D7 cases,
and unchanged three-case registry file.

The final `.venv` Python 3.12.12 repository suite is
`3106 passed, 1 skipped, 4 warnings in 41.14s`, exactly 55 new passing cases over the
R5D6 baseline. The skip is unchanged. The warning count and categories are also
unchanged from R5D6: two dependency deprecations and two occurrences of the documented
scheduling-sensitive pre-existing `aiosqlite` closed-event-loop thread warning. No
warning is emitted by R5D7 or attributed to this slice.

Targeted `ruff check` and `ruff format --check` pass all four changed Python files, and
`git diff --check` is clean. The required `scripts/local-security-check.sh` exits 1 on
the documented repository-wide broad-text matcher, missing-Bandit, and unrelated Ruff
debt. It reports no changed-R5D7-file Ruff violation; that pre-existing red baseline is
not reclassified or repaired in this slice.

## 9. Evidence and authority statement

R5D7 adds durable local receipt evidence: after R5D6 mints a terminal decision, an
explicit caller can persist and later reload its public projection with content-address
and filesystem-safety verification. This durability is focused-tested and, after the
full checkpoint recorded above, suite-proved local behavior.

It is not lab-attested, live-observed, target-enforced, finding-producing,
payout-proven, or `OCB-S17` evidence. A stored `EXECUTION_COMPLETED` value still means
only that R5D6 composed its already-supplied logical, liveness, and consumption inputs;
neither R5D6 nor R5D7 proves that a target action ran or had an effect.

R5D7 expands local durability only. It does not expand offensive capability, target
traffic, or execution authority.

## 10. Open work and stop boundary

- [x] R5D7 durably persists and reloads public R5D6 receipt projections in a
  purpose-built local namespace.
- [ ] Dispatch an independently admitted target action or evaluate an independent
  target effect.
- [ ] Construct or promote a finding from verified target evidence.
- [ ] Verify target-residue cleanup.
- [ ] Run and accept `OCB-S17` for confinement, expiry, one-time use, replay refusal,
  and cleanup.

The planned next Family-D work is separately authorized target-effect proof and
verified cleanup, followed by `OCB-S17`; no slice identifier beyond R5D7 is assigned.
