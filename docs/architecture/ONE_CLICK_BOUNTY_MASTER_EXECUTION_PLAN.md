# Sentinel One-Click Bounty Master Execution Plan

Status: authoritative program index, current-state ledger, and forward execution order

Reset baseline: clean `main` at `85b0755`. The accepted merged implementation
checkpoint remains Sentinel-only R5C8 at `87057b8`. The later R5C9 candidate-build
records at `580080a` and `85b0755` are historical producer notes, not an acceptance
prerequisite or R5C9 completion credit; the unmerged runtime-handoff sidecar is
abandoned. No renewed R5C9 lab, native, or live-evidence claim has been earned.
The accepted native evidence remains separately bound to `ocb/s16-native-journey` at
Sentinel `5f03c35`.

Last verified: 2026-08-25

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
atomic execution claim, and a default-off owned setup/revocation/protected-effect
lifecycle with an independent oracle. Its bounded coordinator is production-wired to
the ordinary Scan path. `OCB-S16` now has exact-SHA external and actual
Swift/WKWebView loopback evidence covering both twins, exact retained native sessions,
receipt reuse across real app restarts, cleanup, ordinary Scan persistence, and three
fresh-state cycles. The accepted revocation-survival scenario is native-proven;
production also admits an active-role escalation verdict that is suite-proved but not
covered by that native artifact. R5C7 now seals the server-side role profile against
mixed modes and ambient backend composition. The valid Sentinel portion of R5C8
restores generated-project parity. The attempted lab-side verifier extension is not
accepted evidence and does not close a provenance or acceptance gate. Broader Family-C
shapes, current-SHA acceptance, and payout evidence remain open.
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

Repository boundaries are part of the evidence contract. A SentinelForge task may cite
an already accepted immutable lab artifact recorded here, but it must not inspect,
modify, test, commit, push, merge, delete, or otherwise administer the sibling visual
acceptance repository. In a separately scoped native run, the operator starts the
complete real SentinelForge app and its own loopback backend; the observe-only lab
starts its website, reads the authenticated public API plus target ledger, and attests
the Sentinel SHA. No app, ZIP, backend package, sidecar, or source import crosses the
repository boundary. Cross-repository work produced outside that boundary is
quarantined, cannot satisfy a checkbox, and must be recorded as such rather than
normalized into the plan after the fact.

Start every OCB slice from the current synchronized `main` on one dedicated short-lived
`ocb/<slice-slug>` branch. A slice branch contains only that slice and its required tests,
evidence, and documentation. Push the branch early for remote visibility, but do not
merge it until the slice gates pass and the handoff is reviewed. After merge, resync
`main` before creating the next slice branch. Direct slice development on `main` is not
allowed.

Keep SentinelForge tasks in `workspace-write`. When protected `.git` metadata blocks an
otherwise authorized branch, commit, fetch, or push, approve only that exact Git
command outside the sandbox; never remove the repository fence to solve Git
writability.

## 4. Evidence vocabulary

These labels are intentionally non-substitutable. The implementation labels are
progressive. `Lab-attested`, `Native-proven`, and `Live-observed` are acceptance
dimensions that may overlap; neither native nor live evidence implies the other.

| Label | Meaning |
|---|---|
| Designed | A reviewed contract exists; no implementation claim. |
| Implemented | Production code exists and focused tests exercise it. |
| Production-wired | A real API, scheduler, scan, or UI caller can reach it under its gates. |
| Suite-proved | The complete repository suite passes at the stated SHA. |
| Lab-attested | The external lab recorded the operator journey and supporting evidence. |
| Native-proven | The external verifier exercised the actual product UI/runtime path and bound the result to the stated build; loopback evidence is permitted and remains loopback-only. |
| Live-observed | An external driver exercised a running Sentinel build and bound the artifact to its SHA. |
| Payout-proven | A real authorized program accepted the finding or paid it. |

No label silently substitutes for another. In particular, a green test suite is not a
live-observed result, a protocol-driver run is not automatically native, and a native
or live loopback result is not public-target or payout proof.

## 5. Verified baseline

### Sentinel repository

- Reset source baseline: clean `main` at `85b0755`; Sentinel-only R5C8 implementation
  remains merged at `87057b8`.
- Commits `580080a` and `85b0755` retain the historical fact that a producer built and
  documented an app candidate. That package is not required by the acceptance topology,
  satisfies no R5C9 checkbox, and is not the basis for forward work. The unmerged
  `ocb/r5c9-runtime-handoff` sidecar branch is abandoned and nothing from it lands.
- Accepted native evidence remains bound to `ocb/s16-native-journey` at Sentinel
  `5f03c35`; the native-journey implementation began at `fd57721` and its original
  Family-C branch chain was created from `main` at `fc1e997`.
- Python: declared 3.12 environment; the verification run used Python 3.12.12.
- Full suite at R5C8 on 2026-08-24:
  `2745 passed, 1 skipped, 3 warnings in 36.01s`.
- The former 17-skip backlog has been reduced to one remaining conditional skip:
  `tests/verification/test_websocket_terminal_bidirectional.py` skips because
  `/ws/terminal` is absent.
- The full run is logic-green, but not warning-clean: two dependency deprecations and
  one pre-existing `aiosqlite` closed-event-loop thread warning were reported.
- `scripts/local-security-check.sh` remains red on repository-wide matcher and Ruff
  debt outside the Family-C diff. Targeted Ruff and diff checks passed for the R5C8
  Sentinel files.
- Sentinel commit `8329be8` adds the required interaction and Family-C role gates to
  `ui/project.yml`, regenerates the committed schemes, and makes
  `tests/unit/test_acceptance_scheme.py` require exact project-spec/scheme environment
  parity while preserving a behavior-gate-free standard scheme.
- The exact `5f03c35` SentinelForge-Acceptance Debug build succeeded on 2026-08-24.
  Its executable SHA-256 is
  `186b243a6ec8e19c76dd9421381264f7f1996b414c617883cae27ecc31bea518`.

### External visual acceptance lab

Family-C external and native evidence was generated and inspected on 2026-08-24. The
accepted lab baseline remains the last accepted checkpoint described below; no later
verifier change is accepted by this plan.

- Native verifier code checkpoint: `3511bf6ec450f184a8ba300bfa251be70116be59`;
  corrected evidence commit `25a81e0` on pushed branch
  `ocb/s16-native-acceptance`. The correction expands the verifier commit to its
  actual full SHA; the journey payload is unchanged.
- Artifact `val-s16-native-family-c-20260824-r5` passed against Sentinel
  `5f03c35789e555a22e284806b05771d6b070d4e5`. SHA-256
  `ec758a046f8fe911148413d7baa2ffee67f8ad0ffaf59c9920bc58134c5c224b`
  binds three pair-level fresh-state vulnerable/secure cycles, 12 native Scans, six
  real app restart retries, 48 exact governed role actions, zero additional governed
  role actions on retry, exact session order, verified cleanup, and zero residue.
- The artifact records `native_app_exercised: true`, `loopback_only: true`, no open
  obligations, and the bounded evidence label `native_proven`. It does not establish
  public-target acceptance or payout.
- The 48-action and retry-delta counters cover the governed role-action ledger, not all
  HTTP routes served by the loopback target. Login, app-shell, control, and cleanup
  traffic is not included in those two counters.
- The reconciled SUT, verifier, and executable hashes match the retained checkouts and
  binary. The verifier accepted those identities as operator inputs; it did not itself
  prove clean checkouts, source-to-build provenance, or PID-to-executable identity.
- Quarantined boundary violation: R5C8 lab residue was produced from a Sentinel-scoped
  task and therefore supplies no Sentinel verifier, provenance, build, native, or live
  evidence and satisfies no R5C8 or R5C9 checkbox. Its legitimacy and disposition
  belong to a separate lab-side task. SentinelForge does not cite the residue's lab SHAs
  as its own work or grant authority to inspect or administer it here.

- Prior protocol-bridge Family-C checkpoint: pushed branch `ocb/s16-live-acceptance` at
  `fb142925afc5304fab39940dec69f261826b0e59`.
- External artifact `val-s16-live-family-c-20260824` passed against Sentinel
  `ff799a7eee735836a8ec1acfcc1cc61d992c2318` and is content-bound by SHA-256
  `838108e8d2b317c6755409c1911c7c09c2919808b258d0eae4e1da652c3c5f53`.
- The artifact is `live_observed` external-loopback evidence and explicitly records
  `native_app_exercised: false`; it is not native or payout proof.
- Older lab snapshot inspected for historical native evidence: branch
  `db-r1-s15-twin` at `529ec4e`.
- LAB-S01 through LAB-S10 each have at least one passing `operator_attested` artifact. These are lab-side
  scenario/operator results, not ten current-Sentinel native integrations.
- The inspected LAB-S10 artifact has a clean-seed streak of one; it does not satisfy the
  plan's three-consecutive-run native criterion.
- DB-S15 has a live external `pass` artifact bound to Sentinel `375137f`. It proves
  persona continuity, stale-credential refusal, canonical finding production, Verify
  binding, and zero cleanup residue for that exact run.
- DB-S15 is valid historical live evidence, but it is not a current-`ff799a7` artifact.
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
| OCB-R5 family C: role and membership safety | Accepted revocation-survival scenario is prior-SHA native-proven; R5C7 profile isolation and R5C8 Sentinel scheme parity are suite-proved; current-SHA acceptance remains open, while broader membership-creation, role-assignment, and administrative-boundary shapes are open and deferred | Typed role/membership fixture, monotonicity proof and admission, exact runtime/effect binding, atomic receipt/budget claim, eight-unit exact-session native replay, target-side active/revoked observations, independent protected-effect evaluation, verified cleanup, strict completed/aborted receipts, two-level retry deduplication, truthful default-off status, canonical routing of completed positive proof, mutually exclusive role-profile selection, generated Acceptance parity, and three prior pair-level fresh vulnerable/secure Swift/WKWebView cycles | Renew the current-SHA negative protocol gate and native vulnerable/secure matrix against the unchanged verifier baseline through the operator-driven observe-only topology before Family D; the broader Family-C shapes remain open and deferred and are not part of R5C9 |
| OCB-R5 family D: capability safety | Designed | The planner recognizes the capability-confinement property and callback-receiver topology; no executable capability backend exists | After the R5C9 acceptance gate, implement the transport-free issued-capability contract, then confinement, freshness, replay, expiry, cleanup, and `OCB-S17` |
| OCB-R5 family E: workflow and business-logic safety | Planned later | Some passive state/transition evidence is reusable | Add only after the ordinary A-D pipeline is operational and measured |
| OCB-R5 family F: concurrency safety | Planned later | Existing budgets and receipts are prerequisites, not a concurrency oracle | Add bounded race scheduling, deterministic adjudication, and cleanup after OCB-R8 |
| OCB-R6 Coverage-guided search and stopping | Partial and narrow | Ranked obligations, payout-guided frontier choice, continuation receipts, and deterministic replanning exist | Build the high-value sink ledger, marginal-value scheduler, family-aware coverage, and honest stop certificate; prove `OCB-S18` |
| OCB-R7 Submission-grade candidate assembly | Partial but production-wired for completed proofs | Completed positive receipt to canonical finding, Verify workbench, deterministic receipt-bound `SubmissionCandidate`, and candidate-only report routes | Generalize minimization/replay, impact binding, sanitized reproduction, invalidation behavior, and end-to-end `OCB-S19` across supported families |
| OCB-R8 Operational one-click completion | Partial for OCB-R5 families A-C | The ordinary Scan UI and API carry the behavioral profile; exact payout-selected family-A, narrow graph-bound family-B, and bounded Family-C role proofs can dispatch under separate gates and route only receipt-bound completed positive proof | Coordinate the remaining OCB-R5 families, acquisition, replanning, stop status, and report handoff as one bounded run; prove `OCB-S20` |
| OCB-R9 Real-target validation and payout acceptance | Evidence in progress | Full local suite is green; Family-C has a three-cycle current-SHA native loopback artifact; LAB-S01 through LAB-S10 have operator-attested passes; DB-S15 is live-observed on loopback at Sentinel `375137f` | Resolve or baseline the remaining release-gate debt at a release SHA, then conduct separately authorized real-program validation; only an accepted or paid finding earns payout-proven status |

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
    - [x] Restore the ordinary Metal-enabled Xcode gate on this machine. The standard
      Debug build succeeded on 2026-08-24 with both Metal sources enabled.
    - [ ] Resolve or explicitly baseline the repository-wide local security-check debt.
    - [ ] Reconcile or explicitly baseline the six generated web-schema drift snapshots.
- [x] **R5C6 — protected-effect execution and independent evaluation.** Commit
  `fdd7d1c` uses a fresh single-use lifecycle to execute the already-bound baseline,
  active-role, and revoked-role probe/witness units without broadening origin,
  identity, method, redirect, or budget authority.
    - [x] Adjudicate the comparison through the bound independent oracle rather than a
      target label, model score, or HTTP status alone.
    - [x] Complete or abort the receipt truthfully on positive, negative, denial,
      cancellation, transport, oracle, and cleanup paths.
    - [x] Expose no finding or promotion authority unless completed positive proof is
      stored under the existing canonical gates.
    - [x] Preserve exact higher, active-lower, and revoked-lower session selection for
      all eight bound actions, with manual redirects and the original request budget.
    - [x] Persist only redacted, content-addressed observations and a non-promoting
      candidate reference; raw protected-effect values remain private.
- [x] Add the bounded Family-C coordinator to the ordinary Scan production path under
  explicit default-off gates, restart/deduplication behavior, and truthful status.
    - [x] Require an exact operator-supplied role specification for typed role order,
      retained sessions, membership generations, in-origin actions, and response
      pointers; ordinary capture does not infer or broaden any of them.
    - [x] Advertise the role backend only with two explicit role worlds, require the
      signed role workflow and four independent default-off Family-C gates, and retain
      the exact eight-request, two-privilege-mutation native-session policy.
    - [x] Bind both capture orchestration and protected-effect execution to durable
      fingerprints/claims so identical outer and inner retries reuse receipts without
      repeating role traffic; persist truthful disabled, completed, and denial status.
    - [x] Reconstruct and route a role finding through `CompletedBehavioralProof` and
      `TaskRouter` only when the completed outer receipt exactly matches positive R5C6
      evidence; refuted proof remains a no-finding result.
- [x] Prove `OCB-S16` against vulnerable and secure twins, including negative
  pre-traffic denial, cross-session refusal, revocation freshness, deterministic
  receipts, cleanup, and zero residue.
- [x] Record then-current exact-SHA external acceptance evidence and apply
  `live-observed` only to that bounded protocol-bridge run. It remains bound to
  Sentinel `ff799a7`; the negative contracts are suite-proved, but were not rerun as
  live evidence at accepted native SUT `5f03c35`.
- [x] Record current-SHA native Swift/WKWebView acceptance before applying
  `native-proven` or closing the Family-C stage row.
    - [x] Bind the exact Sentinel checkout `5f03c35`, verifier checkout `3511bf6`,
      acceptance executable SHA-256, scenario seed, and artifact SHA-256.
    - [x] Complete three fresh-state vulnerable/secure pairs through the actual
      SwiftUI and WKWebView path, with 12 native Scans and six process-changing
      restart retries.
    - [x] Preserve exact eight-action and generation order, three distinct retained
      native sessions per case, vulnerable-only canonical findings, zero additional
      governed role actions on retry, verified cleanup, and zero residue.
- [x] **Family-C closure review checkpoint.** The 2026-08-24 review walked the
  implementation ancestry and production path, recomputed final artifact and binary
  hashes, re-derived the native journey metrics, classified the ignored failed-run
  diagnostics, and reran the known security and schema-drift baselines.
    - [x] Preserve the accepted native claim: the artifact proves the
      `confirmed_revocation_survival` scenario on owned loopback; it does not prove the
      separately implemented `confirmed_active_escalation` positive branch.
    - [x] Keep the four ignored failed-run JSON files local and non-promotable. Three
      contain a raw diagnostic UUID and none carries an evidence label.
    - [x] **R5C7 — seal the server-side Family-C profile.** Commit `f91f5cb` requires
      `role_monotonicity` to carry the exact role specification and
      `behavioral_phase_only`, reject a role specification under other modes, and keep
      ambient graph or generalized backends from influencing a role-profile request.
      Focused positive and negative API/Foundry tests pass without adding traffic or
      authority; the full suite is `2745 passed, 1 skipped, 4 warnings`.
    - [x] **R5C8 — restore reproducible Acceptance configuration in Sentinel
      (corrected scope).** Sentinel `8329be8` restores exact
      `ui/project.yml`/generated-scheme environment parity, preserves a
      behavior-gate-free standard scheme, and is covered by focused tests plus the
      `2745 passed, 1 skipped, 3 warnings` Sentinel suite. Wrong-actor lab residue is
      quarantined, satisfies no checkbox, and is not cited as SentinelForge work. R5C8
      introduces no lab-source or verifier-change requirement.
    - [ ] **R5C9 — renew current-SHA acceptance.** Re-earn the negative protocol gate
      and native vulnerable/secure matrix at the current SHA against the **unchanged**
      accepted verifier baseline, in a **separately scoped lab task**. The operator runs
      the complete real SentinelForge app and its own `:8766` backend; the observe-only
      lab runs its website, observes the authenticated public API plus target ledger,
      and attests the observed Sentinel SHA. No app, ZIP, backend package, sidecar, or
      source import crosses the boundary, and no native pass exists without a real
      attestation file. R5C9 must not change verifier or lab source; if the unchanged
      verifier cannot run against the current app, **stop and report the blocker**
      rather than modifying the lab. The accepted native proof predates R5C7
      (`f91f5cb`), which changed the server role profile, so R5C9 re-proves the native
      matrix against the code as it now stands. Broader membership-creation,
      role-assignment, and administrative-boundary shapes stay **open and deferred**;
      invitation-token/link confinement remains Family D. None is part of R5C9.

The accepted native SUT was `2743 passed, 1 skipped, 2 warnings` when reverified at
checkout `5f03c35`. The exact acceptance Debug build succeeds and its executable
remains content-stable across the native matrix. The later R5C8 Sentinel checkpoint at
`8329be8` is `2745 passed, 1 skipped, 3 warnings`; its project/generated-scheme parity
is suite proof, not a source-bound build or replacement native artifact.
External run `val-s16-live-family-c-20260824` passed against Sentinel
`ff799a7eee735836a8ec1acfcc1cc61d992c2318` using verifier
`fb142925afc5304fab39940dec69f261826b0e59`; its artifact SHA-256 is
`838108e8d2b317c6755409c1911c7c09c2919808b258d0eae4e1da652c3c5f53`.
The earlier external artifact records malformed-specification refusal with zero target
requests, one cross-session bridge refusal with durable aborted-receipt reuse, exact
eight-action vulnerable and secure direct runs, vulnerable-only ordinary-Scan finding
persistence, traffic-free completed-receipt replay, and zero lab residue. It also
records `native_app_exercised: false`.

Native run `val-s16-native-family-c-20260824-r5` passed against Sentinel
`5f03c35789e555a22e284806b05771d6b070d4e5` using verifier
`3511bf6ec450f184a8ba300bfa251be70116be59`; its artifact SHA-256 is
`ec758a046f8fe911148413d7baa2ffee67f8ad0ffaf59c9920bc58134c5c224b`.
It records the actual SwiftUI/WKWebView journey, three pair-level clean state roots, three
vulnerable findings and three secure no-finding results, six receipt-reusing app
restart retries with zero additional governed role actions, exact governed target
ledgers and native-session references, verified cleanup, and zero residue. The open
current-SHA acceptance, repository-security, and generated
web-schema drift baselines still prevent treating this as complete release evidence.

Exit gate: the accepted `OCB-S16` revocation-survival scenario remains native-proven at
its cited SUT. R5C7 sealed the server profile and R5C8 repaired only Sentinel's
Acceptance project/scheme parity. It did not upgrade the accepted verifier or repair
its documented operator-supplied provenance limitations. The gate to Family D remains
open until R5C9 re-earns the negative protocol gate and native vulnerable/secure matrix
at the current SHA against the unchanged accepted verifier baseline, with the observed
Sentinel SHA operator-attested by the separately scoped observe-only lab. The broader
Family-C shapes remain open and deferred rather than becoming part of R5C9. The
existing artifacts remain exact-SHA evidence and are not public-target or payout proof.

### Workstream 3 — Implement OCB-R5 family D capability confinement and freshness

Model issued links, tokens, invitations, exports, and callbacks as explicit capabilities
with subject, resource, operation, audience, lifetime, use count, and revocation state.

The Family boundary is explicit: invitation-token or invitation-link confinement and
freshness belong to Family D; membership creation, role assignment, and the authority
resulting from consuming an invitation remain open Family-C shapes.

First bounded slice after the Family-C repair gate: **R5D1 — transport-free typed
issued-capability contract and controlled single-owned-account fixture.** Bind subject,
resource, operation, audience, issuer, lifetime/expiry, use count, revocation state, and
source evidence while retaining only typed hashes publicly. Define valid,
wrong-resource/account, expired, revoked, and already-used outcomes without dispatch,
callback provisioning, finding promotion, or new execution authority.

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

Family B remains closed for the bounded omission and adjacent-reordering scope. The
2026-08-24 **Family-C closure review checkpoint and R5C7 server-profile repair are
complete**. R5C7 preserves the accepted `5f03c35` native revocation-survival proof while
requiring an exact phase-only role mode, rejecting mixed profiles, and excluding
unrelated behavioral backends from role-profile selection at commit `f91f5cb`.

The corrected R5C8 checkpoint is merged at Sentinel `87057b8`: the committed Acceptance
scheme and `ui/project.yml` carry the same bounded behavior-gate environment, while the
standard scheme grants none. Wrong-actor lab residue remains quarantined and supplies no
accepted evidence or completion credit; its disposition is a separate lab-side task.

The 2026-08-25 reset voids the R5C9 candidate-package and runtime-handoff premises. The
planned next slice is **R5C9 current-SHA acceptance renewal**. The accepted native proof
predates R5C7 (`f91f5cb`), which changed the server role profile, so the operator next
runs the complete real SentinelForge app and its own `:8766` backend while the
separately scoped, unchanged observe-only lab runs its website, observes the
authenticated public API plus target ledger, and attests the observed Sentinel SHA.
The run is neither packaged nor automated, and no native pass exists without a real
attestation. Broader membership-creation, role-assignment, and administrative-boundary
shapes remain open and deferred; invitation-token/link confinement remains Family D,
and none is part of R5C9. Only after the R5C9 acceptance renewal passes and is verified
should R5D1 begin.

The repository security-check baseline, six generated web-schema drift snapshots,
remaining skip, and warning debt stay as explicit maintenance/evidence items. They must
not be hidden inside the coordinator slice or used to advance the Family-C stage label.

## 12. Program dashboard

The checkbox marks closure of the bounded row as named; unchecked rows may still contain
implemented sub-slices.

| Done | Workstream | State | Next evidence |
|---|---|---|---|
| [ ] | Baseline governance | Active | Track the current skip, current warning set, security baseline, and six web-schema drift snapshots separately; preserve the exact native build |
| [x] | OCB-R5 family A controlled authorization read | Closed narrow slice | Preserve regression and exact-SHA live evidence |
| [x] | OCB-R5 family B lifecycle/state manufacture | Closed bounded scope | Preserve omission and reordering regressions |
| [x] | OCB-R5 family C roles/membership | Accepted revocation-survival scenario is prior-SHA native-proven; R5C7 profile isolation and R5C8 Sentinel scheme parity are suite-proved; current-SHA acceptance remains open, while broader Family-C shapes are open and deferred | Renew current-SHA acceptance against the unchanged verifier baseline through the operator-driven observe-only topology; the broader shapes are not part of R5C9 |
| [ ] | OCB-R5 family D capabilities | Blocked on the R5C9 acceptance gate | R5D1 transport-free issued-capability contract, then `OCB-S17` |
| [ ] | OCB-R6 search/stopping | Queued after OCB-R5 families A-D | `OCB-S18` |
| [ ] | OCB-R7 generalized candidate | Partial | `OCB-S19` |
| [ ] | OCB-R8 full ordinary click | Partial | `OCB-S20` |
| [ ] | OCB-R5 families E and F expansion | Deferred | New registered scenarios after OCB-R8 |
| [ ] | OCB-R9 release/payout evidence | Evidence in progress | Resolve or baseline remaining release gates, then separately authorized real-program evidence |
