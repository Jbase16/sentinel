# OCB-R5D1 Issued-Capability Contract Plan

Status: suite-proved as a passive, unwired design slice; commit and push remain
required before closeout

Base: SentinelForge `main` at `dfccecc567bfe25fd837b91a18b05e528394c383`

Canonical stage: OCB-R5 Family D, slice R5D1. The registered downstream scenario is
`OCB-S17`; R5D1 does not implement or claim that scenario.

## 1. Entry gate and bounded outcome

The R5D1 work-order handoff records the R5C9 current-SHA acceptance renewal as passed
and mediator-verified on 2026-08-26 against the unchanged verifier, with Sentinel bound
to `dfccecc`. This SentinelForge slice accepts that gate record without inspecting or
changing the separate acceptance-lab repository.

R5D1 adds one transport-free module,
`core/behavior/capability_contract.py`. It defines:

1. an immutable issued-capability contract;
2. a controlled single-owned-account fixture;
3. an immutable presentation description;
4. a deterministic five-outcome decision; and
5. a pure classifier that creates that decision without dispatch or state mutation.

The module is intentionally passive and unwired. No API router, Foundry path, Scan
profile, scheduler, or production coordinator imports it. It creates no target traffic,
does not reserve budget or write a receipt, provisions no callback receiver, evaluates
no target effect, and cannot promote a finding.

## 2. Issued-capability contract

`IssuedCapabilityContract` models links, tokens, invitations, exports, and callback
references as one capability type. Its authority tuple is explicit and immutable:

| Binding or bound | R5D1 representation |
|---|---|
| Subject/account | `subject_ref` |
| Object/resource | `resource_ref` |
| Operation | `operation_ref` |
| Intended holder/audience | `audience_ref` |
| Issuer | `issuer_ref` |
| Owned tenant | `tenant_ref` plus `tenant_ownership_ref` |
| Operator-supplied provenance | `source_evidence_ref` |
| Bearer material | `secret_digest`; raw material is never accepted as public evidence |
| Lifetime | inclusive `issued_at_index`, exclusive `expires_at_index` |
| Use allowance | `max_uses`, interpreted with a zero-based presentation `use_index` |
| Revocation | `CapabilityRevocationState.ACTIVE` or `.REVOKED` |
| Optional callback | `callback_ref` plus mandatory `callback_scope_ref` |

All reference fields use the existing typed-hash shape
`^[a-z][a-z0-9_]*:[0-9a-f]{64}$`. Tenant, ownership, bearer-digest, and generated ID
fields additionally require their specific type prefixes. Logical bounds are integers,
not wall-clock timestamps; booleans, negative indices, an empty use budget, and a
non-increasing expiry window fail closed.

The public payload contains the mode, every reference, and every logical bound. The
capability identity is exactly:

```text
stable_hash("issued_capability_contract", public_payload_without_id_or_schema_version)
```

The controlled owned-world and optional callback-world objects are retained only as
private validation context. They are excluded from public serialization and from the
capability identity because the public subject, audience, tenant, callback, and scope
references are the canonical authority bindings. Keeping the validated objects private
allows frozen-dataclass substitution to be rechecked without exposing a transport or
secret-bearing object.

## 3. Controlled single-owned-account fixture

`CapabilityOwnedFixture` requires the R4 SDK's exact
`ProofTopology.SINGLE_OWNED_ACCOUNT` shape: an `actor` world of kind
`ExperimentWorldKind.OWNED_ACCOUNT` with persona and ownership references and without
role or lifecycle qualification. The contract subject and audience must both equal the
owned persona, and the tenant plus tenant-ownership references must equal the declared
owned-world tenant context. A non-owned, role-qualified, cross-account, or cross-tenant
substitution fails closed.

The fixture is content-addressed over the complete public contract, the exact world
references, and its passive invariants. It declares zero target requests, no reserved
budget, no backend dispatch authority, no finding authority, and `executable = false`.

No setup mutation occurs. The fixture is disposable and reversible by construction,
creates no residue, and therefore requires no teardown. Its honest orphan-risk value is
false; R5D1 does not claim a cleanup operation that never ran.

## 4. Optional callback reference

Callback-dependent effects remain deferred. R5D1 permits a callback reference only
when all of the following are supplied together:

- a typed `callback_ref`;
- a typed `callback_scope_ref`; and
- an already-valid `ExperimentWorldBinding` whose kind is
  `ExperimentWorldKind.CALLBACK_RECEIVER` and whose callback reference is exact.

The world object is validation context only. The contract does not create a listener,
open a socket, select `ProofTopology.CALLBACK_RECEIVER`, dispatch a callback, or infer
effect authority from the reference.

## 5. Pure classifier and precedence

`classify_presentation()` is total for valid typed contracts and presentations. It
checks in this exact order:

1. `REVOKED` when the immutable contract state is revoked;
2. `EXPIRED` when `at_index < issued_at_index` or
   `at_index >= expires_at_index`;
3. `WRONG_BINDING` when resource, account/subject, audience, or operation differs;
4. `ALREADY_USED` when `use_index >= max_uses`; and
5. `VALID` otherwise.

The order is load-bearing. Revocation is an unconditional authority withdrawal and
therefore dominates every otherwise valid or invalid presentation. The logical issue
window is evaluated next because the capability has no authority outside that window,
irrespective of its requested object or holder. Binding checks precede use exhaustion
so an out-of-scope presentation is never described as merely replayed. The same fixed
binding-field order also makes a multi-mismatch machine reason reproducible.

`use_index` is zero-based: for `max_uses == 1`, index `0` is the first possible use and
index `1` is classified as `ALREADY_USED`. The classifier does not increment or persist
that index. A caller must not interpret this pure classification as durable consumption
or replay enforcement.

Every decision contains the capability ID, presentation ID, outcome, typed machine
reason reference, and its own content address. The classifier does not consult the
target. In R5D1 it is the deterministic outcome evaluator, not independent evidence of
an observed target-side effect.

## 6. Focused proof

`tests/unit/test_behavior_capability_contract.py` covers:

- deterministic construction and one `VALID` presentation;
- each wrong resource, account, audience, and operation binding;
- before-issuance and at-or-after-expiry bounds;
- revocation and single-use exhaustion;
- revoked-over-expired and expired-over-wrong-binding precedence, plus
  wrong-binding-over-use-exhaustion;
- malformed public references, raw bearer strings, non-owned and cross-tenant worlds,
  invalid logical bounds, and forged content addresses;
- exact owned-account fixture binding and passive authority flags;
- callback reference/scope/world all-or-nothing validation; and
- absence of raw bearer material from the contract and fixture serializations.

The focused test file passes all 50 collected cases. Targeted Ruff and Python
byte-compilation also pass. The full Python suite passes with
`2795 passed, 1 skipped, 3 warnings`: exactly 50 more passing cases than the
recorded 2,745-test baseline, with the skip and warning counts unchanged. The required
repository security script was run and exits 1 on its documented pre-existing broad
text matchers and repository-wide Ruff debt; it reports no R5D1-file violation, and
targeted Ruff passes both new Python files. The caller audit, final diff check, commit,
and push remain delivery gates until recorded in the R5D1 handoff.

## 7. Deferred work and stop boundary

R5D1 does not provide a capability backend, transport, durable use ledger, atomic
consumption claim, callback receiver, effect oracle, cleanup executor, receipt
transition, canonical finding, or Scan/UI integration. It does not prove confinement,
expiry, one-time use, replay refusal, or cleanup against a running target. Those remain
unchecked requirements for later separately scoped Family-D slices and `OCB-S17`.

Membership creation, role assignment, invitation consumption, and authority resulting
from invitation consumption remain open Family-C shapes. They are not absorbed into
this capability contract.

The next planned Family-D work is the separately scoped enforcement chain named in the
master plan: confinement and freshness, durable one-time/replay and expiry handling,
cleanup, then the `OCB-S17` exit gate. No new R5D slice identifier is assigned here.

## 8. Authority and external-gate statement

R5D1 is default-off because it has no caller. It adds no origin, identity, action class,
budget, capability backend, target traffic, or execution authority. Offensive
capability, target traffic, and execution authority are unchanged.

There is no external gate for this passive slice and no lab artifact is produced. A
lab or native run would not make this unwired contract more executable and must not be
manufactured as R5D1 evidence.
