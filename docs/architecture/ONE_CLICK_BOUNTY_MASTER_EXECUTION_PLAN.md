# Sentinel One-Click Bounty Master Execution Plan

Status: authoritative program index, current-state ledger, and forward execution order

Repository snapshot: `ocb/r5c5-role-membership-lifecycle` at `0de4e1a`, based on
`main` at `fc1e997`

Last verified: 2026-08-24

## 1. Purpose

This document answers three questions in one place:

1. What is Sentinel ultimately trying to deliver?
2. Which parts are actually implemented, integrated, and externally evidenced now?
3. What is the single forward order from the current repository to the product finish
   line?

It does not replace the detailed contracts in the source plans. It is the program map
above them. When a source plan's old "current" statement conflicts with this ledger,
use current code and tests first, this verified ledger second, and the old statement as
historical context only.

This is a documentation and sequencing contract. It grants no execution authority,
adds no target traffic, and weakens no safety gate.

## 2. Product finish line

From one ordinary bug-bounty scan, Sentinel should be able to:

1. accept an explicitly authorized target and optional operator-provided personas;
2. reconstruct the target's relevant resources, actions, identities, and constraints;
3. rank payout-relevant security goals and choose the smallest supported proof topology;
4. safely acquire or manufacture only the owned prerequisites needed for that proof;
5. execute bounded counterexamples through the existing policy, scope, ownership,
   provenance, budget, and receipt gates;
6. learn from denials and observations without silently increasing authority;
7. independently confirm a security-property violation;
8. promote only completed, positively stored proof into a canonical finding;
9. produce one deterministic, receipt-bound, sanitized `SubmissionCandidate`; and
10. present the result to the operator for review and external submission.

The operator remains the final external actor. The finish line does not include
automatic submission, permission inference, CAPTCHA bypass, public-target mutation,
or a promise that every target produces a finding.

In plain language: one click should carry an authorized assessment from discovery to a
reviewable bounty draft when Sentinel can prove a real issue safely. Today, Sentinel can
do that for a narrow controlled authorization path and can produce a receipt-bound
finding candidate for narrow graph-bound prerequisite omission and reordering paths.
Family C now has suite-proved role/membership contracts, exact runtime binding, an
atomic execution claim, and a default-off owned setup/revocation lifecycle, but it has
not run the protected-effect comparison or reached ordinary-click or external
acceptance.
The external `OCB-S15` gates pass against vulnerable and secure loopback twins,
including capture freshness, durable denial replay, ordinary-Scan persistence, and an
exact adjacent-order counterfactual. Sentinel cannot yet search and prove the full
planned family set or honestly certify that all valuable paths were exhausted.

## 3. Document authority and ownership

| Source | Role now | What it owns | What it must not be used for |
|---|---|---|---|
| This master plan | Program authority | Current status, cross-plan mapping, critical path, exit gates | Detailed implementation design |
| [`ONE_CLICK_BOUNTY_RECONCILIATION_PLAN.md`](ONE_CLICK_BOUNTY_RECONCILIATION_PLAN.md) | Detailed product contract and backlog | OCB-R0 through OCB-R9 requirements, safety invariants, proof families, acceptance definitions | Its stale baseline or unchecked summary as current truth |
| [`behavioral-counterexample-engine.md`](behavioral-counterexample-engine.md) | Implementation record | Why the behavioral components and gates were introduced | Forward priority or current suite status |
| [`ONE_CLICK_BOUNTY_ROADMAP.md`](ONE_CLICK_BOUNTY_ROADMAP.md) | Historical roadmap | Original milestones, phases, and product intent | Its old "immediate next slice" as the current next task |
| [`SENTINEL_VISUAL_ACCEPTANCE_LAB_PLAN.md`](SENTINEL_VISUAL_ACCEPTANCE_LAB_PLAN.md) | Lab design and safety contract | Twin design, evidence layers, native journey, acceptance criteria | Proof that a Sentinel integration run occurred |
| [`CANONICAL_ID_REGISTRY.json`](CANONICAL_ID_REGISTRY.json) | ID authority | Stable `LAB-*`, `OCB-*`, and `DB-*` identifiers | Implementation or pass status |
| `sentinel-visual-acceptance-lab` repository | Executable external verifier | Scenario implementations, run manifests, attestations, and artifacts | Sentinel implementation truth |
| Current production callers and tests | Implementation truth | What can run, under which gates, at the recorded SHA | Product, native, or payout acceptance by themselves |

### Update rule

Every completed work order must update the relevant detailed plan and this ledger in the
same change or in an immediately following documentation-only change. A stage is never
advanced from a commit message alone.

Every OCB slice must also produce at least one focused commit and push it to the shared
remote. Record the pushed commit SHA in the slice handoff before calling the slice
complete. Multiple commits are allowed when the slice has independently reviewable
units, but unrelated OCB slices must not be collapsed into one commit. If a push is
blocked, report the blocker and leave the slice explicitly incomplete.

### Living checklist convention

The forward workstreams and dashboard are also the program's visual to-do list:

- `[x]` means the named bounded item is implemented and its cited checkpoint exists;
- `[ ]` means required work or evidence remains, including partially implemented items;
- a checked implementation slice does not check off its parent stage, external gate, or
  higher evidence label;
- each completed slice adds its pushed commit and concise proof note beneath the owning
  workstream before the next slice begins; and
- dependencies discovered from current code may be added as indented sub-items, but
  closed items are not silently renamed or rewritten to make the sequence look cleaner.

At each slice closeout, update the repository snapshot, relevant ledger row, owning
workstream checklist, immediate-next decision, dashboard, and any changed gate result.
Keep unresolved security, native, live, and external evidence visibly unchecked.

Start every OCB slice from the current synchronized `main` on one dedicated short-lived
`ocb/<slice-slug>` branch. A slice branch contains only that slice and its required tests,
evidence, and documentation. Push the branch early for remote visibility, but do not
merge it until the slice gates pass and the handoff is reviewed. After merge, resync
`main` before creating the next slice branch. Direct slice development on `main` is not
allowed.

## 4. Evidence vocabulary

These labels are intentionally cumulative:

| Label | Meaning |
|---|---|
| Designed | A reviewed contract exists; no implementation claim. |
| Implemented | Production code exists and focused tests exercise it. |
| Production-wired | A real API, scheduler, scan, or UI caller can reach it under its gates. |
| Suite-proved | The complete repository suite passes at the stated SHA. |
| Lab-attested | The external lab recorded the operator journey and supporting evidence. |
| Live-observed | An external driver exercised a running Sentinel build and bound the artifact to its SHA. |
| Payout-proven | A real authorized program accepted the finding or paid it. |

No lower label implies a higher one. In particular, a green test suite is not a
live-observed result, and a live loopback result is not payout proof.

## 5. Verified baseline

### Sentinel repository

- Slice branch: `ocb/r5c5-role-membership-lifecycle`, pushed and aligned with its
  remote at code checkpoint `0de4e1a`.
- Base: `main` and `origin/main` at `fc1e997` when the Family-C branch chain was
  created.
- Python: declared 3.12 environment; the verification run used Python 3.12.12.
- Full suite on 2026-08-24:
  `2713 passed, 1 skipped, 4 warnings in 35.55s`.
- The former 17-skip backlog has been reduced to one remaining conditional skip:
  `tests/verification/test_websocket_terminal_bidirectional.py` skips because
  `/ws/terminal` is absent.
- The full run is logic-green, but not warning-clean. It emitted closed-event-loop
  `aiosqlite` thread cleanup warnings plus two upstream `ldap3`/`pyasn1`
  deprecations.
- `scripts/local-security-check.sh` remains red on repository-wide matcher and Ruff
  debt outside the Family-C diff. Targeted Ruff and prohibited-pattern checks passed
  for the R5C5 files.
- The ordinary Xcode build is blocked on this machine by the missing Apple Metal
  Toolchain. A bounded build excluding only the two Metal shader sources compiled the
  Swift application successfully; this is not the complete native gate.

### External visual acceptance lab

This evidence was last inspected on 2026-08-22. No Family-C external run was added or
reverified at the current Sentinel SHA.

- Lab snapshot inspected: branch `db-r1-s15-twin` at `529ec4e`.
- LAB-S01 through LAB-S10 each have at least one passing `operator_attested` artifact. These are lab-side
  scenario/operator results, not ten current-Sentinel native integrations.
- The inspected LAB-S10 artifact has a clean-seed streak of one; it does not satisfy the
  plan's three-consecutive-run native criterion.
- DB-S15 has a live external `pass` artifact bound to Sentinel `375137f`. It proves
  persona continuity, stale-credential refusal, canonical finding production, Verify
  binding, and zero cleanup residue for that exact run.
- DB-S15 is valid historical live evidence, but it is not a current-`0de4e1a` artifact.
- No inspected artifact establishes a real public bug-bounty acceptance or payout.

## 6. Where the program is now

### Canonical OCB-R0 through OCB-R9 ledger

| Stage | Current state | What is real now | What remains before stage closure |
|---|---|---|---|
| OCB-R0 Safety and evidence kernel | Complete and suite-proved | Canonical scope, egress, proof mode, owned-lab activation, receipts, evidence identity, exact principal resolution, typed admission, and fail-closed policy paths | Preserve as an invariant; new families must not bypass it |
| OCB-R1 Payout goal and topology model | Implemented and consumed passively | `PayoutGoalTopologyPlanner` selects bounded zero-, one-, paired-, role-, lifecycle-, and callback-world requirements; DB-R1 makes the payout plan drive frontier selection | Expand impact/program semantics only as required by a proof family; `OCB-S11` remains an acceptance reservation |
| OCB-R2 Semantic reconstruction | Implemented, bounded, passive | Unified REST, GraphQL, DOM/form, JavaScript, source-map, OpenAPI, lifecycle, and browser-transition catalog with evidence-strength separation | Broaden source coverage only against named sink deficits; `OCB-S12` is not a lab implementation |
| OCB-R3 Constraint learning and replanning | Implemented, passive | Typed constraint ledger and deterministic replanning influence the selected frontier without granting authority | Feed real execution outcomes from additional proof families; retain `OCB-S13` denial/replan evidence |
| OCB-R4 Generalized experiment kernel | Substantially implemented; topology-general wiring incomplete | Sealed SDK, atomic admission, authorization and omission backends, owned lifecycle manifest compiler, runtime substitution, one-use claims, budgets, provenance, and cleanup | Unify provisioning, proof, oracle, cleanup, and receipt completion under one production coordinator for every supported topology |
| OCB-R5 family A: authorization monotonicity | Complete for the bounded controlled-read slice and production-wired | Path, query, JSON, form, and persisted-GraphQL ownership locators; paired owned reads; independent oracle; ordinary one-click selection and gated dispatch | Treat this as one closed proof slice, not completion of all authorization testing; keep current lab evidence SHA-qualified |
| OCB-R5 family B: state-machine safety | Closed for the bounded omission and reordering scope | Exact-terminal payout selection, three fresh owned worlds, sealed baseline/treatment/control dispatch, canonical effect comparison, omission cross-world rejection, exact adjacent-order swap evidence, verified cleanup, receipt completion/replay refusal, ordinary-click coordination, receipt-bound finding construction, durable denial evidence, and prior/current capture freshness. Omission passed at Sentinel `23709f4` / lab `f9e8a76`; reordering passed at Sentinel `6a1895d` / lab `1e51d53`. | Preserve regressions; defer broader replay and stale-state capability/effect contracts until their positive effect semantics are defined |
| OCB-R5 family C: role and membership safety | Implemented and suite-proved through owned membership lifecycle; not ordinary-click wired | Typed role/membership fixture, monotonicity proof and admission, exact runtime request binding, atomic receipt/budget claim, exact-session native replay, target-side active/revoked observations, verified cleanup, redacted terminal evidence, and replay refusal | Execute and independently evaluate the protected-effect probes, add an ordinary Scan caller, promote only completed positive proof, and prove `OCB-S16` on vulnerable and secure twins |
| OCB-R5 family D: capability safety | Designed | Topology vocabulary recognizes callback/capability worlds | Implement token/link/capability confinement, freshness, replay, expiry, cleanup, and `OCB-S17` |
| OCB-R5 family E: workflow and business-logic safety | Planned later | Some passive state/transition evidence is reusable | Add only after the ordinary A-D pipeline is operational and measured |
| OCB-R5 family F: concurrency safety | Planned later | Existing budgets and receipts are prerequisites, not a concurrency oracle | Add bounded race scheduling, deterministic adjudication, and cleanup after OCB-R8 |
| OCB-R6 Coverage-guided search and stopping | Partial and narrow | Ranked obligations, payout-guided frontier choice, continuation receipts, and deterministic replanning exist | Build the high-value sink ledger, marginal-value scheduler, family-aware coverage, and honest stop certificate; prove `OCB-S18` |
| OCB-R7 Submission-grade candidate assembly | Partial but production-wired for completed proofs | Completed positive receipt to canonical finding, Verify workbench, deterministic receipt-bound `SubmissionCandidate`, and candidate-only report routes | Generalize minimization/replay, impact binding, sanitized reproduction, invalidation behavior, and end-to-end `OCB-S19` across supported families |
| OCB-R8 Operational one-click completion | Partial for OCB-R5 family A and the narrow family-B omission path | The ordinary Scan UI and API carry the behavioral profile; exact payout-selected family-A and narrow graph-bound omission proofs can dispatch under separate gates and promote only receipt-bound completed proof | Coordinate the remaining OCB-R5 families, acquisition, replanning, stop status, restart/deduplication, and report handoff as one bounded run; prove `OCB-S20` |
| OCB-R9 Real-target validation and payout acceptance | Evidence in progress | Full local suite is green; LAB-S01 through LAB-S10 have operator-attested passes; DB-S15 is live-observed on loopback at Sentinel `375137f` | Re-run release gates at the release SHA, then conduct separately authorized real-program validation; only an accepted or paid finding earns payout-proven status |

### What DB-R1 actually changed in this map

DB-R1 was not a new proof-family stage. It reconciled identity, evidence, admission,
finding, reporting, and graph ownership across the existing stages:

- WO01-WO07 established canonical assessment identity and evidence persistence.
- WO08-WO10 bound promotion and frontier selection to receipts and payout plans.
- WO11-WO19 moved proposals, Ghost, Verify, reports, graphs, and policy onto canonical
  typed contracts and removed the superseded CAL runtime.
- WO21-WO22 enforced exact principal identity across Verify and Wraith.
- WO-A closed the completed behavioral proof to canonical finding seam.
- WO-B through WO-M repaired genuine regressions, aligned stale contracts, declared the
  Python environment, and removed test-order/environment ambiguity.

That work hardened the horizontal platform beneath OCB-R4 through OCB-R8. It did not,
by itself, complete OCB-R5 families B-F, generalized OCB-R6 stopping, full OCB-R8
orchestration, or OCB-R9 payout proof.

## 7. Translation from the older plans

| Older roadmap or plan concept | Canonical home now | Current interpretation |
|---|---|---|
| Roadmap M1 / Phase 1 unified click | OCB-R8 | UI/API entry exists, but only the narrow supported proof path is end to end |
| Roadmap Phase 2 acquisition controller | OCB-R2, OCB-R3, and OCB-R8 | Bounded safe-read acquisition and obligation-directed replanning exist; broad authenticated/navigation acquisition remains demand-driven |
| Roadmap Phase 3 semantic reconstruction | OCB-R2 | Implemented as a bounded passive catalog |
| Roadmap Phase 4 experiment/oracle SDK | OCB-R4 | Core SDK/admission/backends exist; topology-general production coordination remains |
| Roadmap Phase 5 proof families | OCB-R5 families A-F | A is closed narrowly, B is closed for its bounded scope, C is active through its owned membership lifecycle, and D-F remain forward work |
| Roadmap Phase 6 adaptive search | OCB-R3 and OCB-R6 | Replanning exists; coverage economics and stopping do not |
| Roadmap Phase 7 promotion/report | OCB-R7 | Canonical promotion/candidate/report seams exist; generalized assembly remains |
| Roadmap Phase 8 operational UI | OCB-R8 | Profile and status are present; full family coordinator is not |
| Roadmap Phase 9 real validation | OCB-R9 | Loopback evidence exists; real-program acceptance does not |
| Behavioral Gate A | OCB-R2 and OCB-R3 | Passive evidence and ranking are implemented |
| Behavioral Gate B | OCB-R4 and OCB-R5 | Proposals/admission are typed and fail closed |
| Behavioral Gate C | OCB-R5 | Active controlled execution is real for OCB-R5 family A and explicit owned runtime components, not all families |
| Lab Phases 0-4 | External lab | Harness, scenarios, instrumentation, and operator-attested runs exist |
| Lab Phases 5-6 | OCB-R8 and OCB-R9 evidence | Sentinel integration is partial; release and real-program evidence remain |

This mapping retires the need to choose between "roadmap phases," "behavioral gates,"
"OCB-R stages," and "DB work orders." OCB-R0 through OCB-R9 is the only forward product
sequence. Gates, phases, and work orders describe implementation or evidence inside
those stages.

## 8. Forward critical path

### Workstream 0 — Keep the baseline honest

Purpose: prevent another planning snapshot from drifting away from the repository.

Exit gates:

- this master ledger is updated with each completed slice;
- the one remaining `/ws/terminal` skip is adjudicated as a separate test-maintenance
  task rather than counted as resolved;
- the `aiosqlite` closed-loop warnings are either fixed or explicitly accepted with an
  owner and rationale; and
- release evidence always records the exact Sentinel and lab SHAs.

This workstream changes no target traffic or authority.

### Workstream 1 — Completed OCB-R5 family B

The bounded omission and adjacent-reordering implementations and their separate
external acceptance gates are closed.

Required flow:

1. ordinary-click topology selection identifies a lifecycle prerequisite;
2. current evidence compiles one minimal lineage-ready recipe;
3. graph-bound claim admission atomically revalidates authority, capture freshness,
   plan identity, provenance, ownership, and whole-sequence budget;
4. the runtime creates only an owned disposable object and registers its returned ID;
5. the target operation receives only runtime-bound values;
6. an independent state-machine oracle adjudicates the result;
7. cleanup runs on success, denial, transport failure, and oracle failure;
8. the durable receipt records completed, denied, cleanup-failed, or orphan-risk state;
9. only a completed positive receipt can enter the existing OCB-R7 promotion seam; and
10. `OCB-S15` proves vulnerable and secure twins, replay denial, temporal stale-capture
    refusal, cleanup, zero residue, and the ordinary Scan persistence seam; and
11. the reordering component proves that one exact adjacent swap preserves the reference
    effect only on the vulnerable twin and is independently refused by the secure twin.

Items 1-9 are production-wired for one unambiguous graph-bound omission plan and are
suite-proved at `9167d9a` (`2645 passed`, `1 skipped`, `3 warnings`). Item 10 passed in
external run `s15-live-r5b3b2c-20260822`, bound to the running Sentinel `23709f4` and
lab verifier `f9e8a76` (artifact SHA-256
`924bd88dd3a677976668a11916ffd5872ed2add14c9e14ee5b042916bbbf3618`). The vulnerable
and secure twins each sent `14` graph requests, completed `3/3` cleanup and `3/3`
cleanup verification, and left zero active residue. Fresh captures rotated owned IDs
and tokens; changed response structure and inconsistent prerequisite lineage each
returned HTTP `409` with zero graph traffic. Runtime schema drift exposed a durable,
strictly redacted denial and truthful cleanup/orphan-risk evidence, then replayed with
zero duplicate traffic. A normal `behavioral_phase_only` Scan completed and persisted
one canonical finding.

The reordering component passed in external run
`s15-reordering-r5b3b2c-final-20260822`, bound to Sentinel `6a1895d` and lab verifier
`1e51d53` (artifact SHA-256
`7b23822e97cf7d1b9fc9a818f3e244e64d5874d2a86912d422f54f3666c2eac4`). The
vulnerable twin was confirmed and the secure twin refuted; each sent `18` graph
requests, completed `3/3` cleanup and verification, left zero active objects, and
returned its completed receipt on duplicate input without target or bridge traffic.
The gate also exposed and closed an origin-hash ordering bug: independent prerequisite
planning now preserves the captured sequence instead of sorting by an origin-derived
operation identifier. The full suite passed `2647` tests with `1` skip and `2` warnings
at that implementation checkpoint.

Non-technical result: Sentinel can now create three disposable owned lab objects for one
clearly selected prerequisite test, compare the normal behavior with either one omitted
prerequisite or one reversed adjacent pair, verify the independent control and cleanup,
and emit only a review-only receipt-bound candidate when the target reproduces the
security-relevant effect. Both bounded paths are externally accepted. Sentinel still
cannot create arbitrary state, infer permission on a public target, claim a payout, or
submit a report.

Traffic/authority: the graph experiment adds bounded owned-lab traffic only behind the
signed graph workflow and three separate default-off claim, provisioning, and execution
gates, plus the existing scope, policy, budget, ownership, and cleanup gates. Disabling
graph execution does not disable the separately authorized URL-capture traffic. The
experiment cannot broaden origins, identities, action classes, or budgets.

### Workstream 2 — Implement OCB-R5 family C role and membership monotonicity

Build the smallest role lattice and reversible owned membership fixture needed to test
whether authority improperly increases or survives revocation. Reuse OCB-R4 admission
and the completed OCB-R5 family B lifecycle path; do not create a second provisioning system.

Checklist status records bounded implementation checkpoints, not Family-C stage
closure:

- [x] **R5C1 — typed role and membership fixture.** Commit `c28ce43` defines the
  content-addressed lattice, owned-world persona references, reversible membership
  fixture, and cleanup contract without target traffic.
- [x] **R5C2 — monotonicity proof, oracle contract, and admission.** Commit `8081a4a`
  binds the active/revoked experiment and signed authority while remaining
  transport-free.
- [x] **R5C3 — exact runtime request binding.** Commit `db570b3` binds sessions,
  generations, request material, policy, ownership, cleanup, and receipt lineage
  without dispatch.
- [x] **R5C4 — atomic single-use execution claim.** Commit `7813316` reserves the
  durable receipt and complete ordered request budget as one rollback-safe,
  transport-free lifecycle.
- [x] **R5C5 — owned membership setup, revocation, and verification.** Commit
  `0de4e1a` consumes one claim behind separate default-off gates, sends only the three
  already-bound membership requests through exact-session native replay, observes
  target-side active/revoked generations, always attempts cleanup, and terminates with
  redacted evidence because protected effects were not evaluated.
    - [x] Refuse a changed retained session before native `fetch` and recheck the echoed
      session attestation in Python.
    - [x] Skip all five protected-effect probe/witness units without transport.
    - [x] Preserve cleanup failure, uncertain dispatch, and orphan-risk truth in the
      durable terminal receipt.
    - [ ] Restore the ordinary Metal-enabled Xcode gate on this machine.
    - [ ] Resolve or explicitly baseline the repository-wide local security-check debt.
- [ ] **R5C6 — protected-effect execution and independent evaluation.** Revalidate the
  exact work order against current callers, then use a fresh single-use lifecycle to
  execute the already-bound baseline, active-role, and revoked-role probe/witness
  units without broadening origin, identity, method, redirect, or budget authority.
    - [ ] Adjudicate the comparison through the bound independent oracle rather than a
      target label, model score, or HTTP status alone.
    - [ ] Complete or abort the receipt truthfully on positive, negative, denial,
      cancellation, transport, oracle, and cleanup paths.
    - [ ] Expose no finding or promotion authority unless completed positive proof is
      stored under the existing canonical gates.
- [ ] Add the bounded Family-C coordinator to the ordinary Scan production path under
  explicit default-off gates, restart/deduplication behavior, and truthful status.
- [ ] Prove `OCB-S16` against vulnerable and secure twins, including negative
  pre-traffic denial, cross-session refusal, revocation freshness, deterministic
  receipts, cleanup, and zero residue.
- [ ] Record current-SHA native and external acceptance evidence before applying
  `lab-attested` or `live-observed` labels.

R5C5's Python checkpoint is `2713 passed, 1 skipped, 4 warnings` at `0de4e1a`.
The open native and repository-security items above prevent treating that checkpoint as
complete release evidence, and no Family-C external acceptance claim is made.

Exit gate: `OCB-S16` proves vulnerable and secure twins, negative pre-traffic denial,
revocation freshness, cleanup, and deterministic receipts.

### Workstream 3 — Implement OCB-R5 family D capability confinement and freshness

Model issued links, tokens, invitations, exports, and callbacks as explicit capabilities
with subject, resource, operation, audience, lifetime, use count, and revocation state.

Exit gate: `OCB-S17` proves confinement, expiry, one-time use, replay refusal, and
cleanup without treating bearer material as ambient authority.

### Workstream 4 — Complete OCB-R6 search and honest stopping

Add a `HighValueSinkLedger` over OCB-R1 goals and OCB-R2 operations. The scheduler chooses only
among already-authorized candidates using payout relevance, reachability gain,
information gain, proof cost, remaining budget, and cleanup risk. It cannot add an
identity, origin, action class, or budget.

Exit gate: `OCB-S18` proves deterministic ordering, failure-driven replanning, bounded
coverage, and a stop certificate that says exactly what was proved, blocked, exhausted,
or never explored.

### Workstream 5 — Close generalized OCB-R7 candidate assembly

Use the existing canonical finding and `SubmissionCandidate` path. Add only the missing
family-neutral proof minimization, replay binding, impact derivation, sanitized
reproduction, invalidation, and duplicate handling.

Exit gate: `OCB-S19` proves that one and only one active receipt lineage renders the
same candidate across Verify, Cortex, AI report, restart, and deduplication, while
negative, stale, cross-session, or invalidated proof cannot render a claim.

### Workstream 6 — Complete OCB-R8 ordinary-click orchestration

Make the existing Scan entry point coordinate OCB-R2 acquisition, OCB-R1 topology
choice, OCB-R5 families A-D, OCB-R3 replanning, OCB-R6 stopping, and OCB-R7 candidate
handoff. Expose only bounded status: observing, acquiring, blocked, proving, cleaning,
confirmed, exhausted, or incomplete.

Exit gate: `OCB-S20` proves the full vulnerable and secure journey, restart behavior,
receipt reuse, deduplication, cleanup, and a truthful no-finding stop result.

OCB-R8 introduces no new traffic class. It coordinates only classes already admitted
and proved in OCB-R2 through OCB-R6; the UI cannot manufacture authority.

### Workstream 7 — Add OCB-R5 families E and F only after the ordinary A-D loop is measured

Workflow/business-logic and concurrency families have larger state, oracle, cleanup,
and reproducibility costs. Add them one bounded family at a time after OCB-R8 demonstrates
that the common coordinator, receipts, stopping, and candidate path work in practice.

### Workstream 8 — Earn OCB-R9 rather than declaring it

At a release candidate SHA:

1. run the complete Python and Xcode gates;
2. run the required lab twin matrix and three clean native journeys;
3. repeat the external driver against that exact Sentinel SHA;
4. preserve manifests, identities, receipts, cleanup proof, logs, screenshots, and
   hashes;
5. start real-target validation only under explicit program scope and operator-provided
   authority; and
6. label the result payout-proven only when the external program accepts or pays it.

## 9. Cross-cutting gates for every work order

Every implementation work order must state and prove:

- **Contract:** the exact invariant and canonical stage/scenario ID.
- **Caller:** the production entry point, or an explicit statement that the slice is
  passive/unwired.
- **Authority:** origins, identities, action classes, budgets, proof mode, and feature
  flags; no implicit expansion.
- **Evidence:** immutable provenance, receipt transitions, identity binding, and
  independent oracle source.
- **Cleanup:** required teardown, residue check, and honest orphan-risk state.
- **Negative proof:** disabled flag, missing authority, stale evidence, replay,
  cross-session identity, and policy denial fail before unauthorized traffic.
- **Focused proof:** narrow positive and negative tests for the changed contract.
- **Repository gate:** full suite at the work-order checkpoint.
- **External gate:** a real-wire lab scenario when observable behavior changes.
- **Documentation:** detailed plan plus this master ledger updated to the exact SHA.
- **Branch:** one current-main-based `ocb/<slice-slug>` branch containing only this slice.
- **Delivery:** at least one focused slice commit pushed to the shared remote, with the
  pushed SHA recorded in the handoff.

## 10. Explicit non-goals and stop conditions

Stop the slice rather than weakening a gate when completion appears to require:

- accepting display names, cookies, or labels as canonical identity;
- dispatching outside explicit scope or following an unadmitted redirect;
- converting passive evidence into active proof without an admitted receipt;
- creating non-owned or non-disposable state;
- hiding cleanup failure, orphan risk, missing coverage, or unavailable evidence;
- increasing traffic, identities, action classes, or budgets during replanning;
- letting a report or model invent claims beyond the canonical candidate;
- treating a mock-only test, lab-side run, or old-SHA artifact as current live proof; or
- automatically submitting a finding to an external program.

## 11. Immediate next decision

Family B remains closed for the bounded omission and adjacent-reordering scope. Family C
is active through the R5C5 owned membership lifecycle. The next implementation work
order is **R5C6 protected-effect execution and independent evaluation**, with its exact
boundary revalidated against current production callers before editing. It should
consume the already-bound Family-C actions in one fresh receipt/claim/cleanup lifecycle;
it must not bolt effect probes onto the already terminated R5C5 receipt, broaden
acquisition, or start Family D.

The Metal Toolchain gap, repository security-check baseline, remaining skip, and warning
debt stay as explicit maintenance/evidence items. They must not be hidden inside R5C6 or
used to advance the Family-C stage label.

## 12. Program dashboard

The checkbox marks closure of the bounded row as named; unchecked rows may still contain
implemented sub-slices.

| Done | Workstream | State | Next evidence |
|---|---|---|---|
| [ ] | Baseline governance | Active | Track the current skip, four warnings, security baseline, and native-toolchain gap separately; keep this ledger current |
| [x] | OCB-R5 family A controlled authorization read | Closed narrow slice | Preserve regression and exact-SHA live evidence |
| [x] | OCB-R5 family B lifecycle/state manufacture | Closed bounded scope | Preserve omission and reordering regressions |
| [ ] | OCB-R5 family C roles/membership | Active through R5C5 | R5C6 effect evaluation, ordinary Scan wiring, then `OCB-S16` |
| [ ] | OCB-R5 family D capabilities | Queued | `OCB-S17` |
| [ ] | OCB-R6 search/stopping | Queued after OCB-R5 families A-D | `OCB-S18` |
| [ ] | OCB-R7 generalized candidate | Partial | `OCB-S19` |
| [ ] | OCB-R8 full ordinary click | Partial | `OCB-S20` |
| [ ] | OCB-R5 families E and F expansion | Deferred | New registered scenarios after OCB-R8 |
| [ ] | OCB-R9 release/payout evidence | Evidence in progress | Current-SHA native streak, then separately authorized real-program result |
