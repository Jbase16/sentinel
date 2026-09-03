# R5D9 Capability-Effect Operator Wiring Plan

Status: implemented locally on `ocb/r5d9-capability-effect-wiring`, based on the
suite-proved R5D8 tip
`852138cdd35a330d9204f957f38cee55e2e052f8`

## 1. Bounded intent

R5D9 supplies the concrete operator-side seam that R5D8 deliberately omitted. A
`PolicyExecutorCapabilityEffectTransport` sends the fixed R5D8 capability-effect
matrix through the existing `PolicyExecutor`, and a
`CapabilityEffectOneClickDispatcher` composes that transport with Foundry authority,
an owned persona, genuine R5D5/R5D6 decisions, and the frozen R5D8 executor. The
`POST /behavioral-authorization` API can select this exact profile under an explicit
request field.

This is a narrow production-wiring crossing, not a live-target claim. The existing
`SENTINELFORGE_BEHAVIOR_CAPABILITY_EFFECT_EXECUTION` gate remains off by default, the
ordinary primary behavioral gate must also be enabled, and the route reserves its
existing root execution receipt before constructing the concrete dispatcher. Tests
exercise only controlled in-memory target twins through the real policy seam. No
external target was contacted, no lab run occurred, and no finding was promoted.

## 2. Route, authority, and profile isolation

Both `/behavioral-authorization` request models accept an optional exact
`capability_effect` mapping with `schema_version`, `run_id`, `target_url`, and
`cleanup_url`. The two URLs must be distinct, have no embedded credentials or
fragment, and remain within the already-authorized canonical target origin. Public
specification output contains only typed request, endpoint, run, and specification
references.

A capability-effect request is mutually exclusive with the role-monotonicity profile.
It also suppresses ambient interaction, continuation, fresh-boundary, generalized,
and graph-bound execution settings so unrelated process configuration cannot add
prerequisites or authority. Enabled execution requires all of the following:

- `SENTINELFORGE_BEHAVIOR_PRIMARY=1`;
- `SENTINELFORGE_BEHAVIOR_CAPABILITY_EFFECT_EXECUTION=1` (or another existing true
  spelling accepted by the frozen R5D8 config);
- the ordinary Foundry controlled-workflow authority and an exact signed
  `behavioral_capability_effect` workflow for the same target origin;
- an available owned source persona; and
- a successfully reserved root behavioral receipt for the exact gate/specification
  fingerprint.

With the capability-effect gate off, the selected profile returns
`selected_execution_disabled`, names the existing disabled gate, creates no concrete
transport, and sends no target request. The from-URL form returns that disabled result
before browser capture once the pre-existing primary route gate and request context
have admitted the call. An identical enabled request is deduplicated by the root
receipt and cannot send the matrix again.

## 3. Concrete transport and fixed request envelope

`PolicyExecutorCapabilityEffectTransport` implements R5D8's two-method async
`CapabilityEffectTransport` protocol. Its target endpoint receives exactly five
ordered POST requests:

| Observation | R5D6 terminal outcome | Controlled-target expectation |
|---|---|---|
| `no_capability_baseline` | `EXECUTION_REFUSED_NOT_LIVE` | denied, no effect |
| `valid_capability_effect_witness` | `EXECUTION_COMPLETED` | allowed 2xx, one effect |
| `replayed_capability_probe` | `EXECUTION_REFUSED_ALREADY_CONSUMED` | denied, no effect |
| `expired_capability_probe` | `EXECUTION_REFUSED_EXPIRED` | denied, no effect |
| `inadmissible_capability_probe` | `EXECUTION_REFUSED_INADMISSIBLE` | denied, no effect |

The baseline and witness are sent during preparation because R5D8 requires the real
witness receipt at construction time. Their redacted observations are then consumed
once when the frozen executor begins its ordered matrix; they are not sent again. The
remaining three phases are sent on demand. Dispatch validates every R5D8 request
field against the exact capability and owned-world binding before returning the
matching observation.

All five target actions use `PolicyExecutor.send_action`. The authorized witness is
the only exception in form: it first obtains the executor's existing
`ProposalExecutionClaim(max_requests=1)` and consumes it through
`send_claimed_action`. The dedicated capability-effect policy permits at most six
requests total, at most five to one endpoint, no cross-object reads, no privilege
mutation or creation, no delete, and no real-user-data access. The sixth request is
reserved for cleanup.

## 4. Genuine terminal receipts and the frozen R5D8 boundary

The concrete dispatcher builds the existing R5D1 capability, R5D2 confinement,
R5D3 consumption, and R5D5 admitted-runtime values for one owned world. Each target
phase is sent first; only after the real policy dispatch returns does the transport
call the existing R5D6 evaluator at that phase's actual admitted, live, or expired
instant. The resulting self-validating `CapabilityExecutionReceipt` must have the
phase-exact outcome above. The witness observation returns the exact receipt supplied
to the R5D8 executor.

No outcome is assigned by constructing or mutating a receipt. R5D6 owns receipt
classification and content addressing; R5D5 owns the half-open runtime semantics.
The direct R5D5 and R5D6 consumer guards are therefore widened by exactly this new
module. Their implementation files remain unchanged.

`core/behavior/capability_effect_evaluation.py` remains byte-identical to the R5D8
tip. Its consumer guard now permits exactly
`core/behavior/capability_effect_one_click.py`, and the new module's guard permits
exactly `core/server/routers/foundry.py`. R5D8 still owns exact receipt-type
revalidation, the completed-receipt gate, the owned-account check, the single-use
lock, the independent oracle, and terminal cleanup adjudication.

## 5. Effect redaction and candidate boundary

The policy response is parsed only as a bounded response projection. Raw protected
effect content is immediately content-addressed before the prepared observation can
enter transport object state. The frozen R5D8 executor then applies its own protected
effect content-addressing to the ephemeral transport value. Neither raw effect,
resource, session, bearer, authorization envelope, nor target response body appears
in a run, candidate, representation, receipt, route response, or durable outcome.

The same R5D8 oracle confirms the secure controlled twin and refutes a twin that leaks
an effect on replay. A confirmed oracle creates only a redacted, adversarial-triage
candidate. The route returns `finding=None`, `finding_confirmed=False`,
`promotion_authority=False`, and `finding_authority=False`. The existing root receipt
stores a generic `no_executable_candidate` projection solely for replay prevention;
it does not persist the R5D9 execution, candidate, or finding claim.

## 6. Real cleanup and failure terminalization

After the matrix—or after any preparation/dispatch failure—the transport attempts one
same-origin compensating POST through the same policy executor. Cleanup is `verified`
only when the request itself is valid, the response is 2xx, the target explicitly
confirms cleanup and observed projection, and it explicitly reports no possible
orphan. A denial, malformed response, negative target result, transport exception,
invalid request, repeated cleanup call, or unreliable request counter yields
`uncertain` with `orphaned_owned_state_possible=True`.

The frozen R5D8 executor rejects even a confirmed oracle when cleanup is not verified.
Known request counts come from `PolicyExecutor.restraint_summary()` and include the
cleanup request; uncertain transport delivery remains separately visible through
`target_request_may_have_been_sent`.

## 7. Verification record

`tests/unit/test_behavior_capability_effect_one_click.py` proves the exact specification
shape, default-off behavior, signed authority, genuine evaluator ordering, five-phase
secure and leaking twins, proposal-claim consumption, typed-hash redaction, cleanup
success/failure/exception behavior, content-address revalidation, no new HTTP client,
the exact production consumer, and the unchanged lab import boundary. Foundry route
tests prove disabled no-traffic behavior, one enabled six-request run with root-receipt
deduplication, pre-traffic workflow refusal, and from-URL no-capture behavior.

The final scope is 12 files rather than the work order's approximate 9-10. The two
additional existing files are the R5D5 and R5D6 exact-consumer guard tests: direct,
truthful composition of `AdmittedRuntimeContract` and `evaluate_capability_execution`
necessarily makes the new operator module a consumer of both. Only those expected
sets change; the R5D1-R5D8 implementation sources remain byte-frozen. The slice is
committed locally only; pushing remains the operator's decision.

The exact new-module, R5D8 consumer-guard, and canonical-ID checkpoint is
`64 passed in 0.91s`. The broader transport/oracle/R5D5/R5D6/Foundry/registry checkpoint
is `274 passed in 2.53s`. The final Python 3.12.12 repository suite is
`3171 passed, 1 skipped, 5 warnings in 36.73s`, exactly 21 passing cases over R5D8.
The skip remains the conditional missing `/ws/terminal` case. Two warnings are the
unchanged dependency deprecations; the other three are occurrences of the documented
scheduling-sensitive `aiosqlite` closed-event-loop thread warning. No warning is
emitted by or attributed to R5D9.

`scripts/local-security-check.sh` exits 1 on the documented repository-wide broad-text
shell/dynamic-execution matchers, potential-secret examples, missing Bandit, and
unrelated Ruff debt. Its Python syntax check passes, none of its reported broad-text
locations is an R5D9 changed file, and targeted Ruff passes the changed Python files.
R5D9 does not relabel or repair that red baseline. Diff and frozen-source checks are
part of the same commit checkpoint.

`ruff check` passes all eight changed Python files. `ruff format --check` passes the
six new or narrowly changed Family-D/registry files. The two pre-existing legacy files
that R5D9 must edit, `foundry.py` and `test_foundry_router.py`, fail whole-file format
checking both at the exact `852138c` parent and after the scoped R5D9 changes. They are
left on that inherited formatting baseline rather than introducing unrelated
whole-file churn; this is the one expected-work-order formatting checkpoint that is
not green. `git diff --check` remains clean.

## 8. Evidence, repository, and next boundary

R5D9 is production-wired, focused-tested, and controlled-target suite-proved only.
The concrete adapter is operator-side Sentinel code. The observe-only visual
acceptance lab neither imports nor administers it; only a separately attested Sentinel
SHA may cross that boundary. No live external request, native run, lab attestation,
public-target result, accepted report, or payout evidence belongs to this slice.

- [x] Add the concrete PolicyExecutor capability-effect transport.
- [x] Wire the exact profile to Foundry behind the existing default-off gate and root
  receipt.
- [x] Prove the secure/refuted five-phase matrix and real fail-closed cleanup on
  controlled targets.
- [x] Preserve typed-hash-only public evidence and triage-only authority.
- [ ] Run an operator-attested, exact-SHA lab matrix and accept `OCB-S17`.
- [ ] Add any finding-promotion or durable-claim path in a later, separately authorized
  slice.

The planned next work is the separately authorized exact-SHA `OCB-S17` operator run.
Finding promotion remains later work. No slice identifier beyond R5D9 is assigned.
