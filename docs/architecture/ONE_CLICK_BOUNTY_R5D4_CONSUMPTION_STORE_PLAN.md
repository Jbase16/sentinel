# OCB-R5D4 Durable Capability-Consumption Store Plan

Status: suite-proved as an active local-storage, production-unwired slice; the exact
pushed delivery SHA is recorded in the implementation handoff

Base: SentinelForge `main` at `2194909cd4f3f76d820e1a92de3b3f9d9c773f7d`

Canonical stage: OCB-R5 Family D, slice `R5D4`. The registered downstream scenario
is `OCB-S17`; R5D4 does not implement or claim that scenario.

## 1. Bounded outcome and active boundary

R5D4 implements the durable half of the two-part consumption contract separated by
R5D3. It adds `core/behavior/capability_consumption_store.py`, which loads persisted
consumption state for one issued capability, calls R5D3's existing
`evaluate_consumption()`, and publishes R5D3's next ledger only when that evaluator
returns `FIRST_CONSUMPTION`.

This is the first active Family-D slice because it performs real local filesystem I/O.
The state survives process restart, and an exclusive-create boundary prevents two
processes from consuming the same use slot. The store is nevertheless production-
unwired: no API router, Foundry path, Scan profile, scheduler, coordinator, package
export, or UI imports it. It performs no target traffic, target-clock comparison,
backend dispatch, callback provisioning, execution-receipt transition, effect
evaluation, finding construction, promotion, or retry of a target action.

## 2. Durable representation and audited storage reuse

The store uses an append-only compare-and-swap log. Each accepted use writes one
canonical JSON file containing the full R5D3 next-ledger snapshot for that capability.
The filename binds a SHA-256 capability store key, the zero-based use slot, and a
SHA-256 state key derived from the exact capability reference plus that slot. Raw
bearer, capture, object, token, and target-response material never enters the filename
or payload.

Each snapshot uses `schema_version: 1`, mode
`behavioral_capability_consumption_store_v1`, the exact capability reference and use
slot, the state key, and `CapabilityConsumptionLedger.to_dict()`. JSON is serialized
with sorted keys and compact separators. Loading requires a contiguous sequence of
use slots; every later snapshot must retain the exact entry IDs from all earlier
slots. Existing state files are immutable and never replaced.

R5D4 composes the already-audited `BehavioralReceiptStore` filesystem primitives
directly. Root preparation rejects symlinks, requires effective-user ownership, and
sets mode `0700`. Snapshot publication uses the receipt store's fully written
exclusive hard-link primitive: an `O_EXCL` temporary file is mode `0600`, flushed and
`fsync`ed, then hard-linked exclusively to the final path before the directory is
`fsync`ed. Reads use `O_NOFOLLOW`, validate regular-file type, effective-user
ownership, exact `0600` mode, and the receipt store's one-MiB size cap. The default
root is `~/.sentinelforge/capability_consumptions`; `SENTINEL_DATA_DIR` and
`SENTINELFORGE_CAPABILITY_CONSUMPTIONS` provide the same bounded override pattern as
the receipt store. Tests always supply an isolated temporary root.

## 3. Reload-safe R5D3 projection

R5D4 adds only the serialization bridge needed to reload R5D3's public ledger bytes.
`ConsumptionEntry.from_dict()` and `CapabilityConsumptionLedger.from_dict()` require
exact schema fields, re-derive every typed entry content address and the ledger content
address, require canonical entry ordering, and keep all passive authority flags false.
`to_dict()` remains the existing public projection.

A reloaded entry is an internal inert `ConsumptionEntry` subtype with
`reloaded == True`. Its live contract, capability-decision, and confinement-decision
contexts are all `None`; those values are not reconstructed or persisted. It can
participate in R5D3's replay-key and consumed-count scans, but `with_entry()` rejects
it as a purported new spend. When R5D3 allows a genuine next use, R5D3 still calls the
unchanged `ConsumptionEntry.build()` with the current live contract and decisions.

No pre-existing R5D3 dataclass field, builder, `__post_init__` validation branch,
outcome, precedence rule, or content-address payload changed. Fixed identity tests
bind the pre-R5D4 genesis, entry, ledger, and decision IDs, and all 42 original R5D3
cases remain unchanged and passing. `from_dict(to_dict(ledger)) == ledger`, while the
reloaded entries carry no private construction authority.

## 4. Atomic record algorithm

`record_consumption()` applies this bounded sequence:

1. Run R5D3 against the in-memory genesis ledger before resolving or touching a store
   root. Every non-`VALID` R5D1 outcome, non-`CONFINED_FRESH` R5D2 outcome, and
   cross-capability mismatch therefore raises `ConsumptionLedgerDenied` before I/O.
2. Load and verify the current append-only snapshots for the exact capability, then
   pass the resulting real `CapabilityConsumptionLedger` to
   `evaluate_consumption()`.
3. Return `REPLAYED_PRESENTATION` or `CAPABILITY_ALREADY_CONSUMED` without publishing,
   modifying, or deleting state. The existing bytes and mtimes remain unchanged.
4. On `FIRST_CONSUMPTION`, publish the exact R5D3 next ledger at the next use-slot path
   through the exclusive hard-link boundary.
5. If another process won that slot, reload and call R5D3 again. The bounded retry may
   now produce replay, exhaustion, or another first consumption at the next available
   slot for a multi-use capability. R5D4 never re-implements that choice.

The replay key remains the R5D2 confinement-decision ID. The number of persisted R5D3
entries, not R5D1's caller-supplied `use_index`, remains the authoritative budget
count. Replay continues to precede exhaustion at a full budget because the only
outcome definition is R5D3's evaluator.

## 5. Integrity, atomicity, and residue limits

Every load rechecks the canonical JSON encoding, envelope identity, filename-derived
state key, exact capability, slot sequence, snapshot chain, entry IDs, ledger ID,
passive flags, file type, owner, mode, and size. Mutated references, injected replay
keys or entries, forged entry or ledger IDs, non-canonical JSON, unsafe modes, and
symlink roots fail closed with typed store or ledger errors.

One successful consumption intentionally leaves one local `0600` snapshot file. A
multi-use capability leaves one immutable snapshot per successful use. A replay or
exhaustion leaves the complete existing file set byte-for-byte and mtime-identical.
No target-side residue is created, so R5D4 owns no target cleanup claim.

The content addresses detect inconsistent or hand-edited state; they are not a secret
MAC or a defense against an already-compromised process running as the same effective
user and deliberately deleting or consistently recomputing the whole store. This is
the same local ownership boundary as the reused receipt storage discipline.

## 6. Focused proof

`tests/unit/test_behavior_capability_consumption_store.py` collects 24 cases. They
cover deterministic durable publication, canonical redaction, restart replay and
single-use exhaustion, three-use persistence across repeated store instances,
replay-before-exhaustion, refusal byte/mtime immutability, independent capability
state, root and file permissions, symlink refusal, simulated wrong ownership,
environment-root isolation, malformed and hand-edited state, all R5D1/R5D2
inadmissible outcomes, both cross-capability mismatch directions, and AST/source
proof that the module has no target/network/clock import or production consumer.

The concurrency proof uses two spawned processes and a barrier immediately before the
real receipt-store hard-link publication boundary. For the same single-use capability
and presentation, exactly one process returns `FIRST_CONSUMPTION` and one returns
`REPLAYED_PRESENTATION`; exactly one durable snapshot remains.

The R5D3 focused file now collects 51 cases: the original 42 cases pass unchanged and
9 additive serialization cases prove round-trip equality, fixed fresh content
addresses, inert reloaded entries, live-built next spends, and public-payload tamper
refusal. The combined R5D3/R5D4 focused checkpoint is `75 passed`; the canonical-ID
registry remains `3 passed`. The full repository suite passes
`2917 passed, 1 skipped, 4 warnings in 38.87s`, exactly 33 new passing cases over the
R5D3 baseline with the skip count unchanged. The final run has one additional
occurrence of the documented scheduling-sensitive pre-existing `aiosqlite` closed-
event-loop warning; a preliminary R5D4 full run reported the R5D3-baseline warning
count of 3. Targeted Ruff passes every changed Python file.

The required `scripts/local-security-check.sh` exits 1 on the documented repository-
wide broad-text matcher results, missing Bandit, and unrelated Ruff debt. It reports no
changed-R5D4-file violation. That baseline is not a green gate and is neither hidden
nor repaired inside R5D4; targeted Ruff passes every changed Python file.

## 7. Active but production-unwired authority boundary

R5D4 expands local durable persistence capability only. It does not expand offensive
capability, target traffic, or execution authority. The R5D3 ledger's
`durable_persistence_authority` flag remains false because the passive ledger itself
does not perform I/O; R5D4's separate store owns the bounded write.

No runtime can reach this store through ordinary Scan or one-click execution. Its only
consumer is its focused unit test. A green R5D4 test proves local persistence,
cross-process atomicity, and reload integrity only; it is not lab-attested,
live-observed, target-enforced, finding-producing, or payout-proven evidence.

## 8. Open work and stop boundary

- [x] R5D4 durable local consumption and cross-presentation replay-refusal state with
  exclusive-create cross-process atomicity.
- [ ] Expiry enforcement against a running target and target-relevant clock.
- [ ] Receipt completion/abort for an actually executed one-click capability action.
- [ ] Independent target-effect evaluation, finding construction, and promotion.
- [ ] Verified target-residue cleanup and teardown.
- [ ] The full `OCB-S17` vulnerable/secure acceptance matrix for confinement, expiry,
  one-time use, replay refusal, and cleanup.

The planned next Family-D slice, if separately authorized, is running-target expiry
enforcement under a separately admitted runtime contract. No identifier is assigned
here. That later slice must not infer dispatch, target scope, traffic, callback,
receipt, effect, cleanup, finding, or acceptance authority from R5D4's local store.
