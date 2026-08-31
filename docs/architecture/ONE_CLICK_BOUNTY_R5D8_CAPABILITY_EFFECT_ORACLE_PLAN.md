# R5D8 Capability-Execution Effect Oracle Plan

Status: implemented and suite-proved locally on
`ocb/r5d8-capability-effect-oracle`, based on R5D7
`841606278f4ccde1e459d0b3aa8fbec040dc231a`

## 1. Bounded intent

R5D8 adds a default-off, production-unwired capability-effect experiment. One exact,
self-validating R5D6 `EXECUTION_COMPLETED` receipt admits a fixed five-observation
sequence through an injected async transport. The sequence proves whether the
authorized capability effect occurred exactly once while no-capability, replayed,
expired, and inadmissible presentations produced no protected effect. A separately
verified cleanup result is mandatory before any terminal result can be returned.

The slice is the first Family-D component permitted to orchestrate dispatch. That
authority exists only at the injected `CapabilityEffectTransport` seam. The module
contains no concrete HTTP client, reads no clock, has no production caller, and does
not promote a finding. Unit tests use in-process secure and leaking twins; later lab
evidence, if authorized, must inject the operator client and bind its result to exact
Sentinel and verifier SHAs.

## 2. Public contract and default-off authority

`core/behavior/capability_effect_evaluation.py` exports exactly:

- `CAPABILITY_EFFECT_EXECUTION_ENV` and
  `CAPABILITY_EFFECT_EXECUTION_MODE`;
- `CapabilityEffectExecutionConfig`, inert by default and enabled only by an explicit
  `1`, `true`, `yes`, or `on` environment value;
- `CapabilityCleanupResult` and `CapabilityEffectExecutionDenied`;
- `CapabilityEffectObservation`, `CapabilityEffectOracleVerdict`, and
  `CapabilityEffectOracleEvaluation`;
- `CapabilityEffectTransport`, `CapabilityEffectExperimentExecutor`, and
  `CapabilityEffectExecutionResult`.

The executor is single-use under an `asyncio.Lock`. Disabled execution and a second
execution attempt fail before dispatch. The R5D8-local `execution_effect_authority`
is true only for the exact confirmed verdict under enabled configuration and verified
cleanup. It is false for every refuted result and does not alter R5D6's four
always-false authority fields.

## 3. R5D6 gate and owned-world composition

The constructor requires `type(receipt) is CapabilityExecutionReceipt`. Immediately
before the first dispatch, the executor calls `dataclasses.replace(receipt)`, rerunning
R5D6's complete `__post_init__` validation. An in-memory receipt whose outcome,
content address, or private decision context was forged therefore fails before target
traffic. The witness gate must have `EXECUTION_COMPLETED`.

R5D8 follows the validated R5D6 live context to the existing R5D1
`IssuedCapabilityContract` and its exact `experiment_sdk.ExperimentWorldBinding`.
That binding must revalidate as `OWNED_ACCOUNT`; it becomes the observation binding
for every request and oracle input. R5D8 does not create a new world model.

Each injected response carries an exact R5D6 terminal receipt. R5D8 revalidates that
receipt, requires the same capability, and binds the five phases as follows:

| Observation | Required R5D6 outcome | Required clean behavior |
|---|---|---|
| `no_capability_baseline` | `EXECUTION_REFUSED_NOT_LIVE` | denied, no effect |
| `valid_capability_effect_witness` | `EXECUTION_COMPLETED` | allowed 2xx, one effect |
| `replayed_capability_probe` | `EXECUTION_REFUSED_ALREADY_CONSUMED` | denied, no effect |
| `expired_capability_probe` | `EXECUTION_REFUSED_EXPIRED` | denied, no effect |
| `inadmissible_capability_probe` | `EXECUTION_REFUSED_INADMISSIBLE` | denied, no effect |

The valid phase must return the exact constructor receipt ID. The four refusal phases
must return distinct refusal receipts. R5D8 consumes those R5D6 decisions; it never
calls R5D6's evaluator or reconstructs receipt logic.

## 4. Injected transport and evidence boundary

`CapabilityEffectTransport` is a typing protocol with async `dispatch(request)` and
`cleanup(request)` methods. The dispatch request contains only the mode, observation
kind, expected receipt outcome, and typed capability, witness-receipt, owned-world,
persona, ownership, and observation-binding references. Target location, native
session handling, and ephemeral bearer presentation remain responsibilities of the
injected implementation.

The transport response supplies an R5D6 receipt, access decision, target-projection
status, and ephemeral effect value. R5D8 hashes the effect immediately as a
`capability_protected_effect:*` reference and hashes a redacted response summary. Raw
effect content is not retained in observations, results, representations, or public
serialization.

The module imports no `httpx`, `requests`, `socket`, `subprocess`, or `time` module.
No `core/` initializer, router, Foundry path, Scan path, or backend imports it.

## 5. Independent oracle

`CapabilityEffectOracleEvaluation.build(...)` is pure and accepts only the exact
ordered five observations under one owned-world binding. Observations are frozen,
content-addressed, bound to their revalidated R5D6 receipts, and internally reject an
effect unless access was allowed, the response was 2xx, and the target projection was
observed.

The verdict is:

- `CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT` only when the valid witness has one protected
  effect and all four refusal phases are explicit denials with no effect;
- `REFUTED` when an unauthorized phase produces an effect, the effect is duplicated,
  unauthorized access is allowed, or the authorized effect is explicitly absent;
- `INCONCLUSIVE` when a required target projection, access decision, or witness is
  unavailable.

The evaluation ID is
`stable_hash("capability_effect_oracle_evaluation", payload)`. A confirmed evaluation
may carry a content-addressed finding candidate, but
`promotion_authority=False`, `finding_authority=False`, and
`adversarial_triage_required=True` are immutable. An inconclusive evaluation causes a
terminal denial after cleanup.

## 6. Verified cleanup and failure terminalization

After any dispatch attempt, including transport failure or cancellation, the executor
invokes the injected cleanup method. `CapabilityCleanupResult` permits only
`verified`, `uncertain`, or `unattempted`, and records known target requests, possible
unknown target dispatch, and orphaned-owned-state risk. A verified result requires no
request uncertainty and no possible orphan. A cleanup exception becomes `uncertain`
with `orphaned_owned_state_possible=True`.

Only verified cleanup permits a conclusive `CapabilityEffectExecutionResult`.
Anything else raises `capability_effect_cleanup_unverified` with the cleanup snapshot
and any complete oracle attached. Gate/configuration refusals occur before any target
attempt and carry an explicit `unattempted` cleanup value. An attached denial terminal
receipt is accepted only if it is a revalidated R5D6 refusal outcome.

## 7. Reuse inventory

R5D8 imports and composes R5D6 `CapabilityExecutionReceipt` and
`CapabilityExecutionOutcome`, `experiment_sdk` owned-world bindings, R5D1's existing
typed-reference validator, and `normalize.stable_hash`. R5D6 and R5D7 implementation
sources remain byte-unchanged.

The observation/oracle/single-use/cleanup shape follows the accepted Family-C
`role_effect_evaluation.py` pattern. Its role-specific cleanup type is not imported:
it carries membership revocation counts and role observation references, and its
status vocabulary does not match R5D8's required `unattempted` state. R5D8 therefore
uses the narrower four-field capability cleanup contract required by this slice.

The Family-B `state_transition_proof` effect discipline is reused as a contract rule:
compare canonical content-addressed effects and retain references, never raw values.
No primitive is imported from that module because its available functions also own a
concrete policy executor, HTTP lifecycle, and form-specific target semantics that do
not belong in the independent capability oracle.

## 8. Verification record

`tests/unit/test_behavior_capability_effect_evaluation.py` contains 44 cases. They
cover the complete five-phase matrix on both a secure twin and leaking twins; every
R5D6 completion/refusal binding; duplicated, leaked, and absent effects; incomplete
projection evidence; default-off and single-use behavior; concurrent reuse; forged
receipt revalidation; exact witness identity; transport and cancellation-safe failure
terminalization; verified, uncertain, skipped, and exception cleanup paths; raw-effect
redaction; content-address tamper rejection; protocol/import guards; exact exports;
and production-unwired status.

The exact R5D6, R5D8, and canonical-ID checkpoint is
`110 passed in 0.61s`: 63 unchanged R5D6 cases, 44 R5D8 cases, and three registry
cases. The final `.venv` Python 3.12.12 repository suite is
`3150 passed, 1 skipped, 2 warnings in 35.85s`, exactly 44 new passing cases over the
R5D7 baseline. The skip remains the conditional missing `/ws/terminal` case. The
two warnings are the unchanged dependency deprecations. The count is two below R5D7
because the known scheduling-sensitive `aiosqlite` closed-event-loop thread warnings
did not occur in this final run; no warning is emitted by or attributed to R5D8.

Targeted `ruff check` passed all four changed Python files. `ruff format` reformatted
the two new files and left the two narrow existing-file changes unchanged; the final
format check and diff check are part of the commit checkpoint.

`scripts/local-security-check.sh` still exits 1 on its documented repository-wide
broad-text matcher, missing Bandit, and unrelated Ruff debt. Python syntax passed,
and its output identified no R5D8-file violation. This pre-existing red baseline is
not repaired or reclassified by R5D8.

## 9. Evidence, authority, and stop boundary

R5D8 is focused-tested and suite-proved local behavior. It shows that one injected
transport can drive the fixed matrix and that the same independent oracle confirms a
secure twin while refuting effect leakage. That is not lab-attested, live-observed,
payout-proven, or accepted `OCB-S17` evidence.

- [x] Add default-off injected dispatch for the fixed five-observation matrix.
- [x] Bind every observation to an exact R5D6 terminal outcome and one owned world.
- [x] Prove one authorized effect, refusal-phase absence, and fail-closed cleanup on
  in-process twins.
- [ ] Wire a Family-D backend or Scan route into production.
- [ ] Promote an R5D8 candidate into a canonical finding.
- [ ] Run an operator-attested, exact-SHA lab matrix.
- [ ] Accept `OCB-S17` for confinement, expiry, one-time use, replay refusal, and
  cleanup.

No slice identifier beyond R5D8 is assigned. The next separately authorized work is
finding-promotion/durable-claim and production-wiring design, followed by exact-SHA
lab execution and `OCB-S17` acceptance.
