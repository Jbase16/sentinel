# Sentinel One-Click Bounty Reconciliation Plan

Status: detailed capability contract and staged backlog; current program status and
execution order are authoritative in
[`ONE_CLICK_BOUNTY_MASTER_EXECUTION_PLAN.md`](ONE_CLICK_BOUNTY_MASTER_EXECUTION_PLAN.md)

Baseline: `f9d3607950885953ab620b973723044d342e7925`

Last reconciled: 2026-08-09

## Purpose

This plan reconciles Sentinel's original Boundary Counterexample Compiler and
Backward-Chaining Exploit Compiler ideas with the code that now exists. It has three
jobs:

1. preserve the original capability promises so unfinished work cannot disappear;
2. distinguish implemented foundations from narrow implementations and missing
   universal behavior; and
3. define one dependency-ordered backlog from the current repository to an honest
   click-to-bounty-candidate workflow.

This document is the forward-planning source of truth. The following documents remain
valuable, but serve different purposes:

- [`behavioral-counterexample-engine.md`](behavioral-counterexample-engine.md) is the
  detailed implementation record for completed behavioral slices.
- [`ONE_CLICK_BOUNTY_ROADMAP.md`](ONE_CLICK_BOUNTY_ROADMAP.md) is the historical roadmap
  beginning at the first ordinary-scan bridge.
- [`SENTINEL_VISUAL_ACCEPTANCE_LAB_PLAN.md`](SENTINEL_VISUAL_ACCEPTANCE_LAB_PLAN.md) is
  the design and safety contract for the external visual acceptance lab.

## Finish-line contract

The finish line is not a claim that every URL contains a vulnerability or that every
valid report will be paid. It is this engineering contract:

> Given an authorized target and any unavoidable operator-supplied authentication,
> Sentinel discovers payout-relevant operations, chooses the minimum sufficient proof
> topology, constructs the controlled prerequisite state it can safely manufacture,
> learns explicit constraints from failed attempts, replans within signed authority,
> independently confirms any counterexample, and produces a reproducible
> submission-grade candidate from one ordinary scan action.

External report submission remains an explicit operator action. Sentinel must never
expand scope, identities, workflows, action classes, or traffic merely because a plan
would otherwise be blocked.

## Architectural reconciliation

The earlier names describe different layers, not competing replacements:

```text
Authorized URL and optional owned identities
                  |
                  v
Target semantic reconstruction and capability graph
                  |
                  v
Payout-goal and proof-topology planner
                  |
                  v
Backward prerequisite compiler and constraint replanner
                  |
                  v
Policy-gated experiment manifest and isolated worlds
                  |
                  v
Independent property oracle and counterexample minimizer
                  |
                  v
Evidence, closure accounting, triage, and bounty candidate
```

- **Boundary Counterexample Compiler** is the umbrella black-box search architecture.
- **Payout-goal and proof-topology planner** decides what valuable property to test and
  whether it needs zero, one, two, or another controlled world arrangement.
- **Backward-Chaining Exploit Compiler** determines what prerequisite state and
  sequence must be constructed for the chosen goal.
- **Proof backends** execute one property family, such as authorization or lifecycle
  prerequisite enforcement.
- **Policy, receipts, provenance, and reporting** remain invariant safety and evidence
  boundaries around all of them.

The paired-persona engine is therefore one proof backend. It is not the universal
planner, and a URL without meaningful accounts must not be forced into that topology.

## Status vocabulary

- **Implemented** — production caller exists and focused tests cover the contract.
- **Narrow** — production behavior exists, but only for explicitly bounded shapes.
- **Passive only** — useful analysis exists but cannot create target traffic or grant
  execution.
- **Missing** — the original capability has no complete implementation.
- **Validated** — the relevant native or wire acceptance path has produced evidence;
  validation does not imply universal target coverage.

## Current capability ledger

| Original capability | Status | Current implementation | Remaining obligation |
|---|---|---|---|
| Deterministic observation and state fingerprints | Implemented | `normalize.py`, `models.py`, and `graph.py` produce redacted action, state, transition, and world identities. | Preserve these identities across every new semantic source. |
| Passive action/resource/capability graph | Implemented, bounded and unified | `TargetSemanticCatalog` joins observed REST, GraphQL, DOM/form, server-identifier, lifecycle, browser-transition, JavaScript, source-map, and OpenAPI evidence without merging evidence strength. | Preserve the catalog through R4-R8 and expand only through bounded source adapters. |
| Typed `requires -> produces` operations | Implemented with resource provenance | `SemanticOperation`, `SemanticSlot`, `SemanticResource`, and `SemanticRelation` type downstream inputs, server-issued IDs, parent, owner, tenant, role, and lifecycle context. | Turn the typed graph and R3 learned facts into generalized controlled state in R4. |
| Backward prerequisite search | Implemented, analysis only | `ConstraintReplanner` now connects payout witness goals and evidence-backed constraints to the deterministic bounded `BackwardExploitCompiler`. | Connect replanned sequences to generalized R4 manifests and experiment admission. |
| Exact value lineage and variable binding | Implemented, narrow | `ValueLineageLedger` and `PlanRehydrator` bind captured values across path, query, JSON, form, and GraphQL locations in one world. | Support additional typed values and safely proven cross-world handoffs where a proof topology requires them. |
| Owned lifecycle manufacturing and cleanup | Narrow | Captured create/read/cleanup lifecycles can become admitted controlled sequences. | Generalize beyond direct path-bound identifiers and the current lifecycle shapes. |
| Latent capability-directed discovery | Passive and cataloged | Capability-linked JavaScript, source-map, and OpenAPI routes become published or specified semantic operations; unmatched and ambiguous routes remain coverage deficits. | Feed every source through ordinary acquisition and actively confirm only through separately admitted R4-R8 workflows. |
| Security-obligation graph and closure | Implemented for the observed frontier | Open, blocked, finding, upheld, and conditionally closed questions are content-addressed and bounded. | Add high-value sink reachability and prevent current-frontier closure from being presented as broad target exhaustion. |
| Paired-persona authorization oracle | Implemented, narrow | Controlled cross-object reads use owned identities and independent proof before finding promotion. | Generalize object location, role relationships, operations, and proof matrices. |
| State-machine prerequisite oracles | Production-wired and externally passed for bounded omission and adjacent reordering | Exact same-world lineage preserves a content-addressed DAG; one payout-selected terminal can execute sealed baseline, treatment, and independent control across three fresh owned worlds, compare canonical effects, verify family-specific evidence, clean up, persist redacted denial/completion state, and revalidate current capture before rebuilding the admitted plan. Omission passed at Sentinel `23709f4` / lab `f9e8a76`; reordering passed at Sentinel `6a1895d` / lab `1e51d53`. | Define replay and stale-state capability/freshness semantics before adding those counterfactuals. |
| Bounded adaptive safe-read exploration | Implemented, narrow | Receipt-chained same-origin GET transitions can expose and hand off one newly actionable obligation. | Add topology-aware acquisition without creating a free-form browser agent. |
| Ordinary one-click behavioral bridge | Implemented for family A and bounded family-B omission/reordering paths; external Scan seam passed | The native Scan UI can send paired-persona or anonymous-passive profiles; the backend can consume the exact payout-selected graph plan under separate signed workflow and execution gates, with no fallback to a broader executor. External `behavioral_phase_only` acceptance persisted one canonical omission finding; the separate reordering twin proved direct ordinary-click selection. | Coordinate the remaining permitted property families without manufacturing authority. |
| Proof topology selector | Implemented and bounded for the closed Family-B scope | `PayoutGoalTopologyPlanner` binds the graph backend to the exact compiled terminal; ordinary click selects one unique omission or, when omission is not uniquely selectable, one unique adjacent reordering. Graph-absent v1 identities remain stable. | Add only separately admitted executable topologies. |
| Payout-grade goal language | Implemented as an initial passive ontology | `PayoutSink`, `SecurityWitnessGoal`, `SecurityProperty`, `WorldRequirement`, and `GoalBlocker` describe ranked goals without granting authority or claiming a finding. | Add program-specific impact, cleanup, and broader proof requirements in R4-R6; R3 constraints already bind to these goals. |
| Failure-derived constraint learning | Implemented, passive and evidence-gated | `StructuredConstraintExtractor` recognizes bounded machine-readable prerequisite failures; `ConstraintLedger` keeps structured or independently controlled facts separate from untrusted-text hypotheses. | Add source adapters only when their structured semantics can be validated without promoting prose to fact. |
| Deterministic replanning | Implemented, passive | `ConstraintReplanner` preserves payout-goal evidence, compiler policy and bounds, records disproved assumptions, and refuses fact regression, repetition, contradiction, cycles, and limit exhaustion. | R4 may execute only separately admitted replanned experiments under the original signed authority. |
| Generalized counterexample/oracle SDK | Authorization and bounded graph-bound omission/reordering are production-wired and externally passed | The sealed SDK and atomic admission still govern family A. R5B3b2c adds an exact-terminal graph claim, three fresh owned worlds, baseline/treatment/control execution, family-specific positive evidence, cleanup verification, durable completion/replay refusal, and receipt-derived candidate promotion. | Additional world topologies and broader mutation semantics remain open. |
| Coverage-guided payout scheduler | Narrow | One highest-ranked supported obligation can be dispatched at a time. | Schedule by payout-relevant sink, reachability gain, information gain, proof cost, and remaining authority. |
| Defensible stopping certificate | Narrow | Closure is honest about the current discovered frontier. | State exactly which high-value sinks were found, reached, proven, refuted, blocked, or never sufficiently observed. |
| Submission-grade candidate assembly | Planned, not complete for the adaptive chain | Existing finding, provenance, triage, report, and operator submission components are available. | Assemble minimized behavioral proof lineage and impact into the existing report workflow automatically. |

## Backward compiler kernel checklist

This list preserves the ten original requirements verbatim in meaning and assigns each
one to the forward backlog.

- [x] Typed operation graph describing what an action consumes and produces.
- [x] Initial rich goal language for payout-grade security witnesses. **R1**;
  refine impact, cleanup, and evidence requirements in **R2-R6**.
- [x] Bounded backward prerequisite solver.
- [x] Exact variable binding for supported captured locations.
- [ ] General multi-step execution beyond the current owned lifecycle shapes. **R4**
- [x] Constraint learning from trustworthy failure evidence. **R3**
- [x] Deterministic replanning after an assumed path fails. **R3**
- [ ] General safe creation and cleanup of controlled state. **R4-R5**
- [ ] General proof-oracle contract and additional property families. **R4-R5**
- [ ] High-value sink coverage ledger with defensible blocked/exhausted states. **R6**

## Original Boundary Counterexample sequence

| Original step | Status now | Forward owner |
|---|---|---|
| 1. Reproducible baseline and regression harness | Implemented; S01-S10 provide the current real-shaped catalog. | Permanent gate |
| 2. Observation normalization and deterministic state fingerprinting | Implemented. | Preserve in R2-R6 |
| 3. Passive action/resource/capability graph | Implemented, bounded and unified through R2. | Preserve in R3-R8 |
| 4. Coverage ledger with no active traffic | Implemented for known evidence. | Extend in R6 |
| 5. Isolated world manager | Partial through persona worlds and browser ownership; R1 now represents the required topology without creating worlds. | Generalize runtime world construction in R4 |
| 6. Authorization hyperproperty oracle | Implemented, narrow. | Generalize in R5A |
| 7. Policy-constrained experiment executor | Implemented for admitted shapes. | Generalize in R4 |
| 8. Old-versus-new differential validation | Partial through shadow promotion and vulnerable/secure controls. | Preserve per R5 family |
| 9. Counterexample minimization and repeated replay | Partial for omission and receipt-backed proofs. | Generalize in R4 and R7 |
| 10. Translation into findings and reports | Implemented for existing finding paths; adaptive candidate assembly remains. | Complete in R7 |
| 11. Coverage-guided scheduler | Partial obligation ranking only. | Complete in R6 |
| 12. Additional property families | Authorization and prerequisite omission started. | Continue in R5 |

## Authoritative implementation backlog

### R0 — Reconcile the plan and freeze the baseline

Status: complete when this document is merged.

#### Technical explanation

Record current capabilities, explicit gaps, implementation dependencies, and permanent
acceptance gates at one repository identity. Preserve the prior roadmaps as historical
records and point them here instead of rewriting their implementation history.

#### Non-technical explanation

Sentinel now has one accurate map showing what is real, what works only in a narrow
case, and what still has to be built. An old idea cannot disappear merely because a
newer feature was implemented nearby.

#### Target traffic and execution authority

No target traffic. No execution-authority change.

#### Exit gate

- [x] Every original compiler-kernel requirement has a status and forward owner.
- [x] Every original counterexample-engine phase has a status and forward owner.
- [x] Historical roadmaps point to this plan.
- [x] Baseline identity is recorded above and focused documentation checks pass.

### R1 — Universal payout goals and proof topology

Status: **implemented and focused-tested**.

#### Technical explanation

Define immutable, redacted contracts for `PayoutSink`, `SecurityWitnessGoal`,
`SecurityProperty`, `ProofTopology`, `WorldRequirement`, and `GoalBlocker`. Build a
passive selector that consumes the current operation/capability graph, security
obligations, available proof backends, signed envelope, and available owned identities.
It must rank goals and choose the minimum sufficient admissible topology without
calling a transport.

Initial sink classes must include:

- export and download;
- payment, credit, balance, refund, and payout;
- invitation and membership;
- API keys, tokens, and integrations;
- role and permission changes;
- password, email, and recovery changes;
- file and private-message access;
- administrative and bulk operations; and
- account deletion, ownership, and transfer.

Initial topology classes must include:

- zero-persona anonymous;
- fresh anonymous browser state;
- one owned account;
- two owned accounts;
- owned role differential;
- controlled lifecycle state; and
- callback receiver required but unavailable or available.

The selector may recommend only a topology authorized by the existing envelope. A
missing identity, workflow, callback service, or action class becomes an explicit
blocker rather than an excuse to broaden authority.

#### Non-technical explanation

Sentinel will decide what kind of test a valuable operation actually needs. A public
download may need no account, a private document may need Alice and Bob, and an account
recovery package may need one account plus a fresh browser. This slice chooses and
explains the setup; it does not yet perform a new exploit.

#### Target traffic and execution authority

No target traffic. No new execution authority.

#### Exit gate

- [x] The same evidence produces the same ranked goals and topology on repeated runs.
- [x] Zero-, one-, and two-persona fixtures select different correct topologies.
- [x] Unsupported callback or role requirements remain visible blockers.
- [x] No selector code imports or invokes a target transport.
- [x] No raw identity, token, URL query value, or response body enters public output.
- [x] Existing authorization and omission planners remain behaviorally unchanged.

### R2 — Complete target semantic reconstruction

Status: **implemented as a bounded passive catalog and focused-tested**.

#### Technical explanation

Unify typed operation discovery from captured REST requests, GraphQL documents and
persisted operations, bounded JavaScript and source maps, OpenAPI documents, HTML
forms, safe browser transitions, client validation metadata, server-issued identifiers,
and observed lifecycle transitions. Add explicit resource provenance and parent-child,
ownership, tenant, role, and lifecycle-state relationships. Every inferred operation
must retain redacted source references and an epistemic status: observed, specified,
published, inferred, or unconfirmed.

R1 intentionally exposes an important input deficit rather than weakening redaction:
current REST normalization can replace semantic path segments with placeholders, and
captured GraphQL exchanges can collapse distinct operation labels after normalization.
R2 must reconstruct stable redacted semantics before the payout selector can claim
complete sink recognition from ordinary captured traffic.

#### Non-technical explanation

Sentinel will build a more complete map of the doors, keys, rooms, and required order
of operations exposed by the site. A route found in JavaScript will be labeled as a
published lead, while a request that actually succeeded will be labeled as observed;
the two will never be treated as equally proven.

#### Target traffic and execution authority

Passive compilation adds no traffic. Any new artifact acquisition must be a separate
same-origin safe-read admission using the existing policy, budget, and provenance
boundaries. No mutation authority is added.

#### Exit gate

- [x] One bounded catalog represents every supported source with source provenance.
- [x] Equivalent operations deduplicate without merging distinct worlds or tenants.
- [x] Resource IDs, parent IDs, lifecycle state, and downstream input slots are typed.
- [x] Truncation, ambiguity, conflicting specifications, and dropped evidence are
  explicit coverage deficits.
- [x] Deterministic lab-shaped contract fixtures prove REST, GraphQL, form,
  JavaScript, source-map, and OpenAPI paths without adding a UI or traffic surface.

### R3 — Constraint learning and deterministic replanning

**Status: complete as a passive kernel.** `constraints.py` creates a bounded,
content-addressed ledger from already-acquired structured responses and independent
controls. `replanning.py` applies facts to the existing operation contracts and
recompiles the same `SecurityWitnessGoal` without changing policy or authority. Raw
free text is never retained as a prerequisite fact, and neither module imports a
transport.

#### Technical explanation

Introduce a content-addressed `ConstraintLedger` for response-backed prerequisite
facts such as missing fields, parent resources, membership, role, lifecycle state,
CSRF/session context, and server-issued capabilities. Begin with deterministic
structured evidence; free-form error text may generate a hypothesis but never a fact
without an independently successful control. Recompile the same goal after new
constraints, preserving the original evidence, plan lineage, policy digest, bounds,
and every disproved assumption.

Stopping must be state-based rather than time-based. One goal ends only as:

- confirmed counterexample;
- independently upheld control;
- blocked by signed authority;
- blocked by safety or cleanup requirements;
- unreachable in the current proven operation graph;
- incomplete because semantic evidence was truncated or ambiguous; or
- bounded search exhausted with the exact bound recorded.

#### Non-technical explanation

If the site says an order needs an address, Sentinel records that requirement, finds a
safe way to create an address if one is known and authorized, and rebuilds the plan.
It does not keep blindly retrying, and it does not pretend an unexplained failure means
the operation is secure.

#### Target traffic and execution authority

The ledger and compiler are passive. Replanning grants no authority. Executing a
replanned step may use target traffic only through the separately admitted R4
experiment boundary and the original signed envelope.

#### Exit gate

- [x] Structured missing-prerequisite responses create deterministic typed constraints.
- [x] Untrusted free text cannot directly authorize or satisfy a prerequisite.
- [x] Replanning never repeats a disproved identical plan.
- [x] Cycles, contradictory constraints, and search bounds produce honest blockers.
- [x] A lab-shaped offline flow demonstrates `fail -> learn -> replan -> controlled prerequisite path`; R4 remains responsible for admitted target execution.

### R4 — Generalized experiment, world, and oracle SDK

#### Technical explanation

Define a common proof-carrying manifest for goals, topology, prerequisite sequence,
world bindings, controls, mutation expectations, cleanup, budgets, provenance, and
oracle verdicts. Generalize world provisioning across zero-, one-, two-, role-,
lifecycle-, and callback-based topologies while preserving exact browser/persona
ownership. An oracle must compare an experiment with the minimum independent control
and may emit only confirmed, refuted, or inconclusive—not a finding directly.

#### Non-technical explanation

Sentinel will gain one safe test bench where different broken-lock experiments can be
plugged in without giving the planner free control of the target. Every experiment
must arrive with its permission slip, controlled identities, cleanup plan, comparison,
and proof budget already sealed.

#### Implementation status

- [x] **R4A — Passive sealed experiment SDK.** A content-addressed manifest now binds
  the selected payout goal and R3 replan to one exact zero-, one-, two-, role-,
  lifecycle-, or callback-world shape; partitions control actions by their real
  worlds; requires one-to-one mutation cleanup and verification; claims the entire
  action budget; preserves backend-specific guard requirements; and limits oracle
  output to `confirmed`, `refuted`, or `inconclusive` with no finding authority.
- [x] **R4B — Atomic experiment admission.** `GeneralizedExperimentAdmission` now
  strictly revalidates the current envelope signature, target origin, backend workflow
  grants, manifest authority context, bounty-safe execution policy, provenance seam,
  Persona Vault ownership, special-world attestations, structural action class, exact
  actor and endpoint, and redacted request identity. It durably reserves the admission
  identity before atomically reserving the complete ordered `ProofBudget` sequence;
  denial rolls back every budget slot. The resulting claim is single-use, default-off,
  explicit-only, non-executable, and has no backend-dispatch or finding authority.
- [x] **R4C1 — Admitted object-authorization execution and receipt.** The separately
  default-off `AdmittedAuthorizationExperimentExecutor` atomically assigns one exact
  R4B claim to a single unpersisted runtime-owner token, then revalidates the current
  manifest, signed authority context, vault-backed worlds,
  policy digest, ownership proof, capture-derived requests, and runtime binding IDs,
  then delegates the legacy peer/source/counterfactual oracle through the existing
  `PolicyExecutor`. A fourth owner read supplies the independently budgeted witness.
  Missing traffic, policy denial, provenance drift, or witness failure becomes
  `inconclusive`; even `confirmed` yields only a content-addressed candidate reference
  and an `ExperimentOracleEvaluation` requiring adversarial triage, never a finding.
  Unused reservation slots are released and every executed terminal state is stored in
  the original redacted receipt.
  Current ownership admission is limited to objects whose researcher-created identity
  can be proven from the request URL; body, query, form, and GraphQL object bindings
  remain R5A rather than being accepted on caller assertion.
- [x] **R4C2 — Admitted omission execution and cleanup receipt.** The separately
  default-off `AdmittedOmissionExperimentExecutor` revalidates one lifecycle-bound
  owned world, the exact baseline/treatment/witness topology, all runtime action
  binding IDs, and the original R4B reservation before delegating to the existing
  fresh-state confirmation backend. The admitted backend preserves the valid
  baseline, removes exactly one query-capability binding, runs the independent
  wrong-object control, cleans every fresh object, and then repeats a safe read for
  each object to prove archival, removal, or terminal absence. An uncertain create,
  policy denial, cleanup response, or cleanup read stops promotion, releases unused
  slots, records an orphan warning, and produces only an inconclusive generalized
  evaluation. Even a confirmed fail-open yields a content-addressed candidate
  reference with mandatory adversarial triage and no finding authority.

R4A and R4B send no target traffic and provision no browser, persona, or callback.
R4B does reserve mutable policy budget and creates narrowly scoped eligibility for a
single-use backend adapter, but it grants no ambient or direct dispatch authority. Owned
worlds are checked against the Persona Vault; role, lifecycle, anonymous, and callback
worlds additionally fail closed without a backend-supplied attestation validator.
R4's backend-adapter kernel is complete at this explicit-only boundary. It is not yet
ordinary one-click behavior: later slices must expand proof families, schedule them,
and connect admitted experiments to the normal URL-scan workflow.

#### Target traffic and execution authority

R4C1 introduces up to four reads when both admission and authorization execution are
explicitly enabled. R4C2 separately permits one exact admitted omission sequence of up
to 52 requests under the existing plan-step ceiling (13 for the current three-step
recipe): three researcher-owned creates at most, the bounded baseline/omission/control
reads, three archival or deactivation mutations, and three cleanup-verification reads.
Every action consumes the pre-reserved sequence through `PolicyExecutor`; no delete,
real-user-data authority, ambient dispatch, finding promotion, or automatic ordinary-
scan activation is introduced.

#### Exit gate

- [x] Existing authorization and omission backends conform without weaker checks.
  URL-addressed authorization conforms through R4C1 and lifecycle-bound omission
  execution through R4C2; generalized ownership locators remain R5A.
- [x] Zero-, one-, and two-world manifests cannot be interchanged or forged.
- [x] Controls and experiments reserve their complete budgets atomically.
- [x] Uncertain mutation or cleanup stops the sequence and remains visible.
- [x] Oracle results cannot bypass adversarial triage or finding promotion.

### R5 — Expand payout-relevant proof families

Each family is an independent subproject. No family inherits traffic or authority merely
because another family passed its gate.

#### R5A — Generalized object authorization

- [x] Path, query, JSON, form, and GraphQL object locations for controlled reads.
- [ ] Alice/Alice, Bob/Bob, Bob/Alice, anonymous/Alice, and low-role/high-role controls
  where the selected topology and envelope permit them.
- [ ] Read, mutation, follow-up owner read, and server-produced field semantics.

##### Implementation status

- [x] **R5A1 — Passive generalized ownership-locator evidence.**
  `GeneralizedOwnershipLocatorCompiler` now derives a content-addressed ownership
  evidence index from existing capture records. It accepts only an exact, non-sensitive,
  same-world lineage from a successful safe owned-create response into a later successful
  request. It classifies URL paths, query parameters, JSON fields, form fields, and
  GraphQL variables while retaining the exact structural pointer and request-template
  digest. GraphQL classification requires protocol evidence rather than a caller label or
  a field named `variables`. Cross-world matches, ambiguous producers, failed uses,
  consequential creates, token-like capabilities, and caller ownership assertions fail
  closed. Public output contains no raw URL, identifier, body, persona, or token.
- [x] **R5A2 — Proof-manifest and admission binding.**
  `GeneralizedOwnershipExperimentCompiler` now seals a matched actor/target-owner
  ownership pair into one content-addressed proof over the existing R4 manifest. Each
  side binds its capture digest, exact R5A1 evidence and use IDs, lineage binding, world,
  operation, endpoint, capability, value hash, protocol, and structural locator. The
  proof additionally binds the manifest's distinct legitimate controls, actor treatment,
  owner witness, oracle, backend conformance, source contract, goal, and authority
  context. `GeneralizedOwnershipExperimentAdmission` deep-copies and reconstructs both
  current captures, rejects same-object or non-equivalent pairs, rechecks every capture
  origin, the current envelope signature, authorized workflow, target identity, and
  authority context, then emits only a non-executable admission contract. It neither
  creates an R4B lease nor exposes a runtime claim.
- [x] **R5A3a — Locator-aware policy ownership guard.**
  `LocatorOwnershipProof` is now issued only by the session's `OwnershipRegistry` after
  the registry extracts the object value at one exact path, query occurrence, JSON
  pointer, form occurrence, or GraphQL-variable pointer and resolves it to exactly one
  object created by the stated controlled owner. The proof HMAC-seals the registry,
  R5A2 proof and role references, distinct actor and owner, complete method/URL/body
  fingerprint, object, collection, locator, and pointer. Public serialization exposes
  only opaque references and the structural locator. `ExecutionPolicy` can separately
  verify this proof with scope and cross-object semantics, but the result explicitly
  carries no execution authority and does not affect `evaluate_action`.
- [x] **R5A3b — Generalized authorization execution.**
  `GeneralizedAuthorizationExecutionPlanner` revalidates the current R5A2 admission,
  rehydrates the exact actor and owner requests, performs one structural substitution,
  and asks the current `OwnershipRegistry` to seal the resulting R5A3a treatment.
  `GeneralizedExperimentAdmission` can reserve that treatment only when the locator
  proof verifies. The separately default-off executor then consumes one R4B claim and
  one claim-owned `LocatorRuntimePermit` bound to the R4 action identity, reservation,
  R5A2 admission, R5A3a proof, complete prepared plan, and sanitized transport-header
  context. It executes the owner control, actor control, actor/owner treatment, and
  independent owner witness through `PolicyExecutor`, and persists a non-promoting
  generalized authorization receipt whose treatment provenance carries the complete
  opaque authority chain.
- [x] **R5A4 — Ordinary one-click selection and dispatch.**
  `GeneralizedAuthorizationOneClickDispatcher` now compiles both ordinary persona
  captures into R5A1 indexes, intersects only exact equivalent ownership uses with the
  payout-ranked operation plan, and deterministically selects one bounded candidate.
  It constructs and revalidates the R4 manifest and R5A2 admission without traffic.
  When both existing R4 admission and R5A3b execution gates are enabled, it imports the
  exact admitted owner value into the session registry with proof/role/capture binding,
  obtains one R4 claim, and dispatches R5A3b instead of the legacy replay. Ordinary
  scans therefore need no caller-side planner wiring and cannot double-dispatch both
  backends. Disabled gates leave the registry and request budget untouched.

##### R5A1 technical explanation

R5A1 is an analysis-only compiler over `ValueLineageLedger`. It reuses exact producer-to-
consumer value hashes, capture-bound request digests, safe-create classification, and
content-addressed evidence contracts. It does not write to `OwnershipRegistry`, reserve a
`ProofBudget`, build runtime `CandidateAction` authority, call `PolicyExecutor`, or emit a
finding. Its current limitation is deliberate: it proves captured ownership semantics but
does not yet authorize a counterfactual request using those semantics.

##### R5A1 non-technical explanation

Sentinel can now recognize Alice's server-created document when its ID later appears in a
URL, a query box, a JSON or form submission, or a GraphQL variable. For example, it can
prove that `documentId` in a captured GraphQL request came from Alice's earlier successful
document creation instead of trusting someone to label it "Alice's." It still cannot use
that new proof to test Bob-versus-Alice automatically; R5A2 and R5A3 add that safely.

##### R5A1 target traffic and execution authority

R5A1 sends no target traffic and grants no execution authority. It analyzes only records
already captured through existing authorized workflows. It creates no accounts or objects,
does not mutate or clean up target state, and cannot promote evidence into a finding.

##### R5A2 technical explanation

R5A2 composes `GeneralizedOwnershipIndex`, `ProofExperimentManifest`, the signed
`AuthorizationEnvelope`, and the existing R4 control/oracle contracts without importing
`PolicyExecutor`, `OwnershipRegistry`, or `ProofBudget`. It requires distinct controlled
values with identical capability, create operation, consumer operation, normalized
endpoint, locator kind and pointer, and protocol. The manifest must contain exactly two
owned worlds, two independently bound legitimate controls, one actor-side cross-object
treatment, and one target-owner witness. Admission recompiles the proof from copied
captures and returns no lease, claim token, dispatch authority, or finding authority.

##### R5A2 non-technical explanation

Sentinel now seals both halves of the intended test: Bob's legitimate document request
and Alice's equivalent document request. It proves they use the same kind of operation
and the same exact ID location, then locks those facts to the planned Bob/Alice test and
Alice verification read. If the account, object, field, request, website, permission
envelope, control, or witness changes, admission refuses the blueprint. Sentinel still
does not send that blueprint to the target; R5A3 is the execution pass.

##### R5A2 target traffic and execution authority

R5A2 sends no target traffic and grants no execution authority. It performs no ownership-
registry writes, budget reservations, world provisioning, target mutations, cleanup,
backend dispatch, or finding promotion. Its admission artifact explicitly has no single-
use runtime claim; an R5A3 adapter must be separately designed, gated, and verified.

##### R5A3a technical explanation

R5A3a introduces `OwnedRequestLocatorKind`, `LocatorOwnershipProof`, and
`LocatorOwnershipVerification` in the safety layer. The registry—not a caller—extracts
the located raw value and requires one unambiguous `(origin, collection, object ID)`
entry for the stated target-owner persona. A session-random secret produces opaque actor,
owner, request, object, and collection references and authenticates the complete proof.
Verification repeats structural extraction, current registry resolution, request
fingerprinting, and constant-time seal comparison. `ExecutionPolicy.verify_locator_ownership`
also requires scope, a classified `CROSS_OBJECT_READ`, explicit controlled ownership
intent, and distinct actor/owner identities. It does not call or modify
`evaluate_action`, `ProofBudget`, provenance, or transport. The current fingerprint is
the exact method, normalized URL, and body material; R5A3b is responsible for
binding the admitted runtime/session context and transport-owned headers.

##### R5A3a non-technical explanation

Sentinel's safety lock can now open the sealed blueprint and check the actual proposed
request without sending it. If Alice's document ID is supposed to be the second query
parameter, a nested JSON field, a form value, or a GraphQL variable, the lock extracts
that exact location and confirms the value belongs to Alice in Sentinel's live controlled
registry. Changing the method, URL, any body material, account, owner, ID, collection,
field, occurrence, or registry makes the proof fail. A successful check still leaves the
request stopped at the gate; R5A3b is the separately controlled mechanism that can
use this evidence to run the four-part experiment.

##### R5A3a target traffic and execution authority

R5A3a sends no target traffic and grants no execution authority. Proof issuance and
verification consume no request budget, write no new ownership, record no provenance,
create no runtime lease or claim, and cannot reach `PolicyExecutor.raw_send`.
`CandidateAction` deliberately has no generalized proof field, and ordinary policy
evaluation continues to deny non-URL cross-object ownership even after the passive guard
has verified it. That connection exists only in the separately gated R5A3b adapter.

##### R5A3b technical explanation

R5A3b composes the current `OwnershipExperimentAdmissionContract`, exact R5A2 proof,
R4 manifest and claim, `OwnershipRegistry`, `ExecutionPolicy`, `ProofBudget`, persona
vault, shared `ProvenanceSink`, and the existing marker-differential authorization
oracle. Preparation recompiles both captures, retains only read-proven GET/HEAD or
captured GraphQL query operations, substitutes only the admitted structural locator,
sanitizes replay headers, and produces no traffic or budget authority. R4 admission
now accepts a generalized cross-object action only through a verified locator proof;
ordinary `evaluate_action` remains unchanged. At execution, the claim issues one
stateful permit whose opaque identity binds the treatment action, R4 reservation,
R5A2 admission, R5A3a proof, prepared action/header plan, and live runtime claim. The
permit is consumed atomically before the treatment can reach transport. All four reads
cross `PolicyExecutor`; the treatment conduct block and durable receipt bind the same
authority chain. The result remains a triage-required candidate with no finding or
promotion authority. Current limitations are paired owned accounts, non-mutating reads,
already captured equivalent requests, and explicit R4/R5 execution gates. R5A4 supplies
the ordinary-scan selection, proof-bound registry import, and admission wiring.

##### R5A3b non-technical explanation

Sentinel can now safely run the full Bob-versus-Alice test even when the document ID is
hidden in a query field, JSON body, form field, or GraphQL variable instead of the URL
path. It first proves Alice owns the exact object, proves Bob and Alice captured the same
read operation, and locks the whole four-step plan. It then reads Alice's object as
Alice, Bob's object as Bob, tries Alice's object once as Bob, and reads Alice's object
again as Alice to independently verify any leaked private marker. A one-use key ties
that attempt to this exact plan, object, accounts, safety budget, and request headers;
changing any one of them stops the request. R5A4 can now discover and launch this exact
sequence from a normal paired-persona URL scan. Sentinel still does not test real users,
try mutations, cover anonymous or role-based topologies, or turn the result directly
into a finding.

##### R5A3b target traffic and execution authority

Preparation sends no traffic, consumes no budget, and grants no execution authority.
Execution introduces at most four in-scope target reads only when the existing R4
admission gate and the separate
`SENTINELFORGE_BEHAVIOR_GENERALIZED_AUTHORIZATION_EXECUTION` gate are both enabled and
one active R4 claim owns the full reservation. Exactly one request may be a cross-object
read, and its target must resolve in the live registry to the stated controlled owner.
The permit is single-use and claim-owned; it is not stored on `CandidateAction` and does
not change ordinary policy evaluation. This slice grants no create, update, mutation,
delete, cleanup, real-user-data, ambient dispatch, finding, promotion, or one-click
authority.

##### R5A4 technical explanation

R5A4 adds a bounded selector/dispatcher at the existing Foundry URL-scan seam. It uses
the ordinary source and peer capture records, the current semantic operation catalog,
and the payout-goal ordering to consider at most 64 equivalent R5A ownership pairs. A
candidate must survive exact structural read validation and complete R4-manifest/R5A2
reconstruction. Selection itself is passive. Dispatch occurs only when both
`SENTINELFORGE_BEHAVIOR_PROOF_EXPERIMENT_ADMISSION` and
`SENTINELFORGE_BEHAVIOR_GENERALIZED_AUTHORIZATION_EXECUTION` are enabled. The registry
accepts the captured owner value only through a dedicated admission path bound to the
R5A2 proof, owner role, and capture digest. The dispatcher then claims the existing R4
reservation and invokes R5A3b through an isolated policy, four-request budget, ownership
registry, and provenance sink that cannot change legacy fallback behavior. An executed
R5A4 plan replaces, rather than supplements, the legacy authorization replay for that
scan. Results remain non-promoting and receipt feedback deliberately treats them as
triage evidence until a later promotion slice.

##### R5A4 non-technical explanation

Sentinel no longer needs a developer to manually connect the Bob/Alice blueprint after a
normal URL scan. If Bob and Alice each created and then read the same kind of controlled
object, Sentinel can recognize the highest-value matching operation, lock the exact two
objects and request field, and—when the two safety switches are enabled—run the four-read
proof once. For example, opaque document IDs in `/documents/{id}` now work even when they
do not resemble a UUID. Sentinel still needs those controlled captures to contain a
successful create-to-read lineage, and a confirmed result remains a candidate requiring
adversarial triage rather than an automatically submitted finding.

##### R5A4 target traffic and execution authority

With either execution gate disabled, R5A4 sends no traffic, writes no ownership registry
entry, reserves no budget, and leaves the pre-existing one-click backend unchanged. With
both gates enabled and one candidate fully admitted, it grants only the same single-use
R5A3b authority: at most four in-scope controlled reads, exactly one possible cross-object
read, no mutation, no create, no delete, no real-user data, no finding promotion, and no
second legacy authorization dispatch. The opaque-ID endpoint normalization added for
this seam groups more concrete paths into one budget bucket; it can only tighten the
per-endpoint traffic ceiling.

#### R5B — Generalized lifecycle prerequisite enforcement

- [x] **R5B1:** Passive multiple-prerequisite and non-linear lifecycle topology
  from exact same-world value lineage.
- [x] **R5B2:** Graph-bound experiment compilation with an explicit supported-
  topology matrix and fresh controlled baseline requirements.
- [x] **R5B3a:** Signed-context graph-bound manifest and fail-closed static admission.
- [x] **R5B3b1:** Concrete request, action-policy, and endpoint-budget binding with
  non-consuming reservation preview.
- [x] **R5B3b2a:** Default-off, single-use graph-bound claim admission with a
  durable non-renewable receipt and atomic ordered budget reservation.
- [x] **R5B3b2b:** Claim-consuming fresh-world provisioning and exact runtime
  lineage substitution without experiment dispatch.
- [x] **R5B3b2c:** Separately admitted omission and reordering dispatch, effect
  comparison, cleanup terminalization, and replay evidence.
  - [x] Production implementation checkpoint for one unambiguous graph-bound
    omission plan at Sentinel `88e893c`.
  - [x] External vulnerable/secure twin, completed-receipt replay, primary cleanup,
    and zero-residue components at Sentinel `9967de6` and lab `fda7b0c`.
  - [x] Response-schema drift refused with HTTP `409` before terminal traffic; the
    independently measured target cleaned its one known object and retained zero state.
  - [x] Production `behavioral_phase_only` ordinary-Scan completion surface at
    Sentinel `2cca4f0`; it preserves canonical promotion and persistence while
    suppressing all post-behavior reasoning, tools, dispatch, and verification.
  - [x] Durable, strictly redacted denied-path graph and cleanup evidence at Sentinel
    `0eb7a76`, including traffic-free direct and URL-capture duplicate replay.
  - [x] Explicit prior-artifact versus current-capture structural and graph-selection
    freshness binding at Sentinel `9167d9a`; the executable plan is rebuilt only from
    current records, while changed structure or lineage fails before experiment traffic.
  - [x] Full `OCB-S15`: external fresh/stale capture, ordinary-Scan persistence, and
    durable-denial acceptance passed at Sentinel `23709f4` and lab `f9e8a76`.
  - [x] Production reordering selection and a positive reordering effect oracle,
    externally passed at Sentinel `6a1895d` and lab `1e51d53`.
- [ ] Replay and stale-state specifications after their capability-freshness and
  post-cleanup effect oracles are defined.
- [ ] Zero-persona and one-persona workflows in addition to paired accounts.

##### R5B1 technical explanation

R5B1 adds `ObservedPrerequisiteRelation` and `ObservedPrerequisiteGraph`. Each relation
binds one compiler capability and exact `LineageBinding` to the producing and consuming
operation, capture source, and normalized observed state. The graph validates one
same-world acyclic dependency topology, requires every retained prerequisite to reach
the high-value terminal operation, and derives roots, direct terminal prerequisites,
branches, joins, and maximum dependency depth. `StateMachineLegalityCandidate` v2 now
content-addresses this graph instead of exposing only a flat topological order. The
ordinary passive orchestrator carries the graph into its state-machine artifact and
security-obligation evidence, while the existing omission compiler must reconstruct the
same graph before accepting its already-supported narrow experiment. The ordinary miner
retains its existing 16-step plan ceiling, permits at most 32 exact relations per graph,
and retains at most 64 state-machine candidates per run.
This pass still requires one unambiguous successful captured observation per operation;
repeated same-operation instances and alternative producer paths remain unresolved.

##### R5B1 non-technical explanation

Sentinel no longer remembers a workflow merely as “do A, then B, then C.” It can now
preserve that A produced one piece needed by both B and C, while B produced a second
piece also needed by C. For example, it can distinguish “create an order and create an
address, then use both to export an invoice” from a simple three-step line. Every arrow
comes from an exact value that Sentinel watched move between controlled requests; route
names and error prose cannot invent an arrow. This is the blueprint needed for smarter
workflow tests, but it is not yet proof that skipping, reordering, replaying, or using a
stale step succeeds, and it is not itself a vulnerability finding.

##### R5B1 target traffic and execution authority

R5B1 sends no target traffic and grants no execution, mutation, admission, budget,
finding, or promotion authority. It analyzes records already present in the scan. Every
relation explicitly records `necessity_proven=false`, `enforcement_proven=false`,
`finding_authority=false`, and `executable=false`. Existing default-off omission
execution remains limited by its unchanged lifecycle, policy, ownership, budget, and
admission gates; the new graph is an additional reconstruction invariant, not a new
permission path.

##### R5B2 technical explanation

R5B2 adds a bounded `GraphBoundPrerequisiteExperimentCompiler` to the ordinary passive
orchestrator. Its complete 4-by-4 support matrix makes each combination of linear,
joining, branching, or branch-join topology and omission, reordering, replay, or stale-
state family explicitly supported or deferred. The compiler currently supports one
direct isolated-producer omission for a query, JSON, or form binding on linear, joining,
and branch-join graphs, plus one adjacent independent-operation reordering when both
operations feed a common downstream consumer on a joining or branch-join graph. Each
specification content-addresses the R5B1 candidate, graph, topology rule, exact delta,
three-instance fresh-state requirement, captured successful non-truncated reference
state, owned lifecycle cleanup bindings, independent control/effect oracle requirements,
and all unresolved safety/admission blockers. It reconstructs the compiler plan, recipe,
lineage bindings, source states, success observations, and graph before emitting a spec.
The result retains at most 64 specifications; truncation remains an explicit incomplete-
work diagnostic. Replay and stale-state rows are deliberately deferred because their
capability-freshness and post-cleanup effect semantics are not interchangeable with
prerequisite enforcement.

##### R5B2 non-technical explanation

Sentinel can now turn the workflow blueprint into a sealed test design. If “approve the
workflow” produces the one token consumed by “export,” it can describe an exact test
that removes only that approval step and token. If two independent preparation steps
both feed the final export, it can separately describe reversing just those two steps.
Every design says that Sentinel must first prove the normal sequence works on one fresh
controlled object, try the one changed sequence on a second, run an independent control
on a third, and clean up and verify all three. It refuses unsafe path deletion and does
not pretend that repeating an expiring token or using an archived object is the same
kind of test. These are complete blueprints, not executed vulnerability findings.

##### R5B2 target traffic and execution authority

R5B2 sends no target traffic and grants no world provisioning, request mutation, budget,
admission, execution, finding, promotion, or reporting authority. Every specification is
`admission_ready=false`, `finding_authority=false`, and `executable=false`, and always
retains blockers requiring a graph-bound manifest, fresh controlled state, an independent
effect oracle, and separate experiment admission. The current default-off narrow omission
backend is unchanged and remains the only lifecycle execution path; R5B2 specifications
cannot reach it or any transport.

##### R5B3a technical explanation

R5B3a adds `GraphBoundManifestAdmissionPlanner` as an analysis-only boundary in the
ordinary behavioral orchestrator. For each R5B2 specification without unresolved safety
or cleanup blockers, it validates the current `AuthorizationEnvelope` signature, expiry,
disclosure attestation, target origin, and explicit
`behavioral_graph_bound_prerequisite_experiment` workflow. It then content-addresses the
authorization context without serializing the envelope id or signature, binds the exact
target, actor/world, R5B2 compilation and lifecycle capture, policy digest, graph, delta,
fresh-state requirement, cleanup requirement, and effect oracle, and creates three
planned fresh-world slots. Every slot requires a later ownership proof and freshness
attestation and carries the exact lifecycle and cleanup-lineage bindings. The manifest
also calculates separate baseline, treatment, independent-control, and cleanup request
units. Its total must fit both the current policy's total-request limit and a fixed
96-request manifest ceiling. Expected omission or reordering backend gaps transfer into
the manifest as explicit pending blockers; any unknown R5B2 blocker prevents manifest
compilation. Static admission returns deterministic `not_requested`, source-blocked,
authority-denied, no-admissible-specification, or ready-for-explicit-boundary results.

##### R5B3a non-technical explanation

Sentinel can now turn each experiment blueprint into a tamper-evident permission packet.
The packet proves which approved target and researcher identity it belongs to, which
workflow and one-change test it describes, which three fresh controlled test worlds must
exist, how ownership and cleanup must be proved, and the maximum number of requests the
complete experiment would need. A copied packet cannot silently be pointed at another
site, person, graph, policy, or experiment. An unsigned, changed, expired, wrong-target,
wrong-workflow, unsafe, incomplete-cleanup, or over-budget packet is refused. “Ready” at
this stage means only that the packet is complete enough to present to the future
execution gate. Sentinel still cannot create the fresh objects, construct the concrete
requests, reserve the budget, run the experiment, or claim a vulnerability from it.

##### R5B3a target traffic and execution authority

R5B3a sends no target traffic and grants no provisioning, mutation, budget reservation,
backend dispatch, execution, finding, promotion, or reporting authority. It never calls
the policy scope callback, `PolicyExecutor`, receipt store, budget reservation API, or a
transport. Every manifest retains blockers for endpoint/action policy preflight, atomic
budget reservation, a single-use receipt, fresh-state provisioning, independent-oracle
execution, cleanup verification, and the family-specific backend. Its world slots remain
`provisioned=false`, its budget remains `reserved=false`, and the manifest and result
remain `dispatch_authority=false`, `finding_authority=false`, `target_requests_sent=0`,
and `executable=false`. R5B3b must introduce a separate default-off active boundary.

##### R5B3b1 technical explanation

R5B3b1 adds `GraphBoundRequestBinder` between static admission and any active backend.
It independently re-mines and requires exact equality for the current lifecycle and
state-machine artifacts, recompiles R5B2, reconstructs the exact `BackwardPlan` and
`RehydrationRecipe`, and rehydrates baseline request templates and owned cleanup
templates in memory. It emits three explicit sequences per manifest: the
captured valid baseline, the graph-bound treatment, and an independent control, with
conditional cleanup immediately following each world. Omission treatments remove only
the exact query, JSON, or form locator and lineage binding sealed by the delta;
reordering treatments preserve the same requests and bindings while applying only the
sealed independent-operation order. Each request is bound to its source and template
digest, operation, fresh-world slot, input lineage bindings, method, classified action,
expected effect, hashed endpoint key, and current policy decision. Raw URLs, headers,
bodies, values, and endpoint keys remain ephemeral and never enter `to_dict()`.

The complete ordered endpoint/action sequence must match the R5B3a baseline, treatment,
control, cleanup, and total request-unit counts. A new `ProofBudget.preview_reservation`
uses the same locked cumulative total, per-endpoint, cross-object, privilege, and create
calculation as `try_reserve`, but allocates no reservation. Unknown reconstruction,
origin, safety, policy, action-class, phase-count, locator, capture, per-endpoint, or
budget mismatches fail closed. Successfully bound plans resolve only the manifest's
endpoint-binding and action-policy-preflight blockers; receipt, reservation, fresh-state,
oracle, cleanup-verification, active-boundary, and backend blockers remain.

##### R5B3b1 non-technical explanation

Sentinel can now fill the permission packet with the exact captured request templates it
would use. It lays out the normal run, the one-change test, the independent comparison,
and cleanup for all three controlled worlds. It checks that an omission really removes
only the approved field, or that a reordering really changes only the approved order.
It then asks the safety policy about every request and simulates reserving the entire
request allowance, including repeated calls to the same endpoint. The simulation cannot
consume or hold that allowance. Secret tokens, request bodies, account data, and concrete
endpoint keys stay in memory and the public artifact contains only typed hashes.

This does not yet mean the three fresh worlds exist. Their newly created IDs and tokens
must still be substituted during active execution, under the sealed lineage bindings.
Sentinel has a fully inspected request plan, but it has not acquired the one-time right
to run it, reserved the real budget, sent anything, observed an effect, cleaned up live
state, or proved a vulnerability.

##### R5B3b1 target traffic and execution authority

R5B3b1 sends no target traffic and grants no provisioning, reservation, receipt, backend
dispatch, execution, finding, promotion, or reporting authority. It may call the local
scope and policy evaluators, but never calls `PolicyExecutor`, `raw_send`, a receipt
store, `try_reserve`, or transport. `preview_reservation` is read-only. Every plan remains
`budget_reserved=false`, `single_use_claim_acquired=false`,
`dispatch_authority=false`, `finding_authority=false`, `target_requests_sent=0`, and
`executable=false`. R5B3b2a introduces the separate default-off, single-use claim
boundary that validates these bindings again; later R5B3b2 passes must still allocate
fresh state and connect a backend before any request may be sent.

##### R5B3b2a technical explanation

R5B3b2a adds `GraphBoundExecutionClaimAdmission` as an explicit, default-off boundary.
It re-runs `GraphBoundManifestAdmissionPlanner` against a fresh copy of the signed
authorization and current policy, then re-runs `GraphBoundRequestBinder` against the
current capture, lifecycle, state-machine, compilation, and static manifest. Both fresh
public artifacts must exactly equal the caller-supplied artifacts. The boundary selects
one explicit prepared plan and uses only the fresh binder's private request material to
reconstruct its complete ordered action/endpoint sequence. It previews the sequence
again immediately before any write.

Admission content-addresses the selected plan, authority, policy, action bindings,
budget bindings, and request count without persisting URLs, endpoint keys, headers,
bodies, tokens, or reservation secrets. `BehavioralReceiptStore.reserve` first acquires
one durable non-renewable receipt; `ProofBudget.try_reserve` then atomically holds the
entire ordered sequence. A budget race aborts the new receipt, and contract-construction
failure releases the budget and aborts the receipt. The returned thread-safe lease can
move from `active` to `claimed` once, or either the unclaimed lease or claimed handle can
abort and release the unused budget. A durable abort remains terminal, so the same
fingerprint cannot be retried. If durable abort fails, the budget is still released and
the in-memory lease is closed while the receipt remains fail-closed in `reserved` state.

Focused tests cover the default-off gate, deterministic side-effect-free revalidation,
exact reservation identity, public redaction, one-use claiming, terminal replay denial,
capture and authority revalidation, a post-receipt budget race, abort-store failure, and
content-addressed contract tamper rejection. The lease still has no way to provision a
world, substitute returned runtime values, dispatch a request, compare an effect,
terminalize successful execution, or create a finding.

##### R5B3b2a non-technical explanation

Sentinel can now turn one inspected experiment plan into a sealed, one-use ticket. Before
issuing it, Sentinel checks the signed permission, the latest recorded workflow, every
request, and the full request allowance again. It then stamps the ticket into a durable
ledger and holds the complete allowance at once, so another task cannot spend half of it
while this experiment is waiting. For example, an approved invoice-export omission plan
can reserve exactly its normal run, one-change run, independent comparison, and cleanup
calls as one indivisible packet. Claiming that ticket twice is impossible, and aborting
it frees the unused request allowance but does not create a second ticket.

This still does not create the three fresh controlled accounts or objects, fill newly
returned IDs into later requests, send the experiment, decide whether behavior differs,
clean up live data, or prove a bounty. It secures the one-use permission and capacity
needed before those active steps can be connected.

##### R5B3b2a target traffic and execution authority

R5B3b2a sends zero target requests. It grants only local claim authority: when
`SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM` is explicitly enabled and the
boundary is explicitly invoked, Sentinel may write one redacted durable receipt, reserve
the exact ordered `ProofBudget` sequence, and transition the returned lease to `claimed`
once. Raw receipt tokens and budget reservation IDs never enter public artifacts. The
claim exposes no transport call, runtime world manager, provisioning method, policy
execution method, effect oracle, cleanup sender, findings store, promotion path, or
backend-dispatch authority; it remains `target_requests_sent=0` and `executable=false`.

##### R5B3b2b technical explanation

R5B3b2b adds `GraphBoundFreshWorldProvisioner` behind the separate default-off
`SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING` gate. The request binder
now orders one sealed plan as a provisioning prefix for all three world slots, exactly
three terminal baseline/treatment/control actions, and a conditional cleanup suffix.
Filtering by phase still yields the exact compiled baseline, treatment, and control
operation order. Each private request retains its exact input and output
`LineageBinding` objects while the public artifact retains only their content-addressed
identities.

The claim admission boundary carries only the freshly reconstructed private plan into
its in-memory claim resources. A claimed handle can transition once through
`claimed -> provisioning -> provisioned -> aborted`. The provisioner rechecks every
request-template, endpoint-budget identity, and policy digest plus the signature,
expiry, scope, and workflow of the retained authorization, then sends only non-terminal
prerequisite actions. It extracts create IDs and prerequisite values from the declared response JSON
locators, rejects a create ID equal to the captured ID or reused across world slots,
registers exact ownership, substitutes values at the declared path/query/JSON/form
locators, and rechecks endpoint-budget stability. Before cleanup it materializes all
three terminal requests in memory to prove their remaining inputs are available, but it
never passes those requests to `PolicyExecutor`.

Success and failure both skip every reserved terminal slot, clean each successfully
created world with the sealed cleanup request, remove the corresponding in-memory
ownership grant after a successful cleanup, abort the non-renewable receipt, and release
the unused reservation. It verifies the resulting conduct chain and returns only an
opaque provenance reference. A successful R5B3b2b call therefore returns only a redacted
provisioning-and-cleanup result; it never returns a live-world lease. Captured-ID reuse,
policy refusal, transport failure, response-lineage failure, ambiguous ownership, and
cleanup uncertainty fail closed and report possible orphaned state where applicable.

R5B3b2b deliberately does not execute the baseline, treatment, or independent-control
terminal action. It does not compare effects, independently verify cleanup at the
target, complete a proof receipt, create a finding, or promote a submission candidate.
Those blockers remain assigned to R5B3b2c.

##### R5B3b2b non-technical explanation

Sentinel can now rehearse the safe setup for a workflow test using three disposable lab
objects. It creates each object, uses the new server-returned ID and tokens instead of
the old recorded values, proves it could build each final test request, and then removes
the objects without sending any final security-test request. If setup fails, Sentinel
skips the final requests and cleans up whatever it safely can. This proves the lifecycle
machinery, not a vulnerability: no workflow result is compared and no finding is made.

##### R5B3b2b target traffic and execution authority

R5B3b2b adds bounded owned-state traffic only when both the existing graph-bound claim
gate and the new provisioning gate are explicitly enabled and invoked. Its authority is
limited to the already reserved in-scope prerequisite prefix and conditional cleanup
suffix. It cannot dispatch any terminal baseline, treatment, or control action; cannot
increase the reserved action sequence; and cannot access a finding, promotion, report,
or submission surface. With the provisioning gate disabled it sends zero requests and
leaves the claimed ticket available for explicit abort. Every completed provisioning
probe ends with a terminally aborted receipt, zero reserved units, and no retained live
lease because no experiment was completed.

##### R5B3b2c implementation-complete technical explanation

At Sentinel `88e893c`, `PayoutGoalTopologyPlanner` makes the
`graph_bound_prerequisite` backend available only for a terminal operation that exactly
matches a compiled graph-bound omission candidate. Candidate admissibility and dispatch
additionally require the signed graph workflow.
`GraphBoundPrerequisiteOneClickDispatcher` revalidates the payout context, graph digest,
authorization reference, exact terminal, static admission, private request binding, and
one unambiguous omission plan before consuming the existing single-use claim. There is
no generalized or legacy fallback after this graph plan is selected.

At Sentinel `6a1895d`, the same dispatcher selects one unique adjacent-reordering plan
when the terminal has no uniquely selectable omission plan. The positive reordering
oracle requires all three fresh-world terminal observations to reproduce the captured
reference effect and binds that evidence to the exact sealed swap, plan, and terminal
evidence references. A target-side order rejection is refuted and cannot create a
candidate. A positive result carries a typed reordering witness and no omission-only
runtime-value inequality. Passive planning also preserves observed prerequisite order;
it no longer lets an origin-derived action hash decide whether an otherwise identical
capture is considered ambiguous.

`GraphBoundPrerequisiteExperimentExecutor` then uses the claimed whole-sequence budget
to create exactly three fresh owned worlds and dispatch the sealed baseline, treatment,
and independent-control terminal requests. It compares canonical status and response
body effects, requires a distinct cross-world capability-rejection witness and a
runtime-value inequality attestation for a positive omission result, and runs and
verifies every sealed cleanup. Cleanup uncertainty remains terminal and reports possible
orphaned state. Cancellation aborts the claimed graph receipt and direct receipt, while
the URL wrapper independently aborts its outer receipt before propagating.

At Sentinel `0eb7a76`, a graph execution denial terminalizes the claimed graph receipt
with a strictly validated redacted evidence record: semantic reason/category, typed
claim and plan identities, proof family, cleanup counters and evidence references,
truthful orphan-risk state, and explicit false finding, promotion, and retry authority.
Raw responses, URLs, runtime values, tokens, and runtime workflow identifiers are not
admitted. The direct endpoint copies that evidence into its root receipt, and the URL
capture wrapper copies only the revalidated evidence into its own root receipt. Both
render HTTP `409` from durable state; an identical request replays the same denial before
capture or execution. Persistence or validation failure returns `503` instead of
claiming a durable denial.

At Sentinel `9167d9a`, enabled graph execution additionally requires an explicit prior
source/peer capture pair. `GraphBoundCaptureFreshnessBinding` hashes but never exposes
the private artifacts, compares ordered redacted action/state snapshots for both worlds,
and then binds a value-independent payout selection and graph-plan shape. Owned object
IDs and capability tokens may rotate between captures. A changed response structure or
changed prerequisite lineage returns HTTP `409`; missing prior evidence stops before
window access, and stale evidence stops after the one current capture but before graph
experiment traffic. The graph dispatcher then compiles and admits only the current
capture's plan. The final freshness reference is content-addressed into the one-use
claim, completed outcome, denial evidence, durable receipt, and finding lineage.

Only a completed, positively stored graph outcome with verified cleanup can construct
`GraphBoundPrerequisiteFindingCandidate`. The selection bundle binds the payout plan,
candidate, goal, exact terminal, specification, prepared plan, graph target, and graph
digest. The Scan promotion seam reloads the durable receipt, requires exact target,
envelope, source-persona, and peer-persona context equality, requires result/receipt kind
equality, reconstructs the exact finding from the stored outcome, and refuses any
tampered or spliced candidate before writing canonical evidence. The candidate requires
adversarial triage and grants neither report-promotion nor submission authority.

The full Python 3.12 repository suite passed `2645` tests with `1` skip and `3` warnings
at Sentinel `9167d9a`. The complete external run `s15-live-r5b3b2c-20260822` then passed
against the running Sentinel `23709f4` with lab verifier `f9e8a76`; its artifact SHA-256
is `924bd88dd3a677976668a11916ffd5872ed2add14c9e14ee5b042916bbbf3618`.

The vulnerable and secure twins each sent `14` graph requests, completed and
independently verified cleanup for all three fresh worlds, left zero active objects,
and reused the completed receipt with zero target or bridge traffic. Prior and current
captures rotated owned IDs and tokens while retaining the admissible structure. Changed
response structure and inconsistent prerequisite lineage each returned HTTP `409` with
zero graph traffic. Runtime response-schema drift returned a durable, redacted aborted
receipt with truthful cleanup/orphan-risk evidence, then replayed the same denial with
zero duplicate traffic. Finally, an ordinary `behavioral_phase_only` Scan completed and
persisted exactly one canonical finding. This closes full `OCB-S15` for the narrow
omission slice.

The separate external run `s15-reordering-r5b3b2c-final-20260822` passed against
Sentinel `6a1895d` with lab verifier `1e51d53`; its artifact SHA-256 is
`7b23822e97cf7d1b9fc9a818f3e244e64d5874d2a86912d422f54f3666c2eac4`. The vulnerable
twin was confirmed and the secure twin refuted. Each sent `18` graph requests,
completed and verified cleanup for all three fresh worlds, left zero active objects,
and replayed its completed receipt with zero target or bridge traffic. The full
repository suite passed `2647` tests with `1` skip and `2` warnings. This closes the
bounded Family-B omission and reordering scope. Broader replay and stale-state
specifications remain deferred until their capability-freshness and post-cleanup effect
contracts are defined.

##### R5B3b2c implementation-complete non-technical explanation

Sentinel can now take one clearly identified workflow test, create three disposable
objects that it owns, run the normal final action on one, omit exactly one prerequisite
on another, use the third as an independent control, compare what the target actually
did, verify that a capability from a different object is rejected, and remove all three.
If the result and cleanup meet every requirement, Sentinel can create a review-only
finding candidate tied to the durable proof receipt. The external lab has now observed
that narrow behavior for both a vulnerable and enforcing secure target, including
three-world cleanup, zero-traffic duplicate handling, and canonical Scan persistence.

When that narrow execution is denied, Sentinel can now retain a safe explanation of the
reason and cleanup state without storing the target's raw response, URL, runtime token,
or runtime identifier. Repeating the same denied request returns the stored answer
without rerunning the experiment. The external lab has verified this behavior and zero
duplicate traffic.

Sentinel can also take the earlier paired observation that motivated the test, capture
both owned personas again immediately before execution, and check that the same workflow
and prerequisite question still exist. New object IDs and tokens are expected and do
not fail the check; a changed response shape or changed prerequisite relationship does.
Only the newly captured version is allowed to supply the executable plan. The separate
acceptance lab has observed both the permitted rotation case and the two fail-closed
stale cases.

Sentinel can also test one exact order claim: on three owned disposable objects it runs
the normal prerequisite order, reverses one adjacent pair on the treatment object, and
runs the normal order again on the control. If the reversed order preserves the same
target effect, it can create a review-only reordering candidate; if the target rejects
the swap, it records a refutation and creates no finding. The external lab observed both
outcomes and zero residue.

For example, in an owned lab workflow where an approval token is supposed to be
required before export, Sentinel can prove that the normal approved export works, test
the same export without the approved prerequisite on a fresh object, reject a token from
a different fresh object, and clean up each object. The narrow omission path is
externally accepted and full omission `OCB-S15` is closed. The adjacent-reordering
component is also externally accepted. Sentinel still cannot infer permission on a
public target, promise a payout, promote a report automatically, or submit anything
externally.

##### R5B3b2c implementation-complete target traffic and execution authority

The graph experiment sends target traffic only when the signed
`behavioral_graph_bound_prerequisite_experiment` workflow and all three separate
default-off graph claim, fresh-world provisioning, and prerequisite-execution gates are
enabled. Its dedicated policy permits at most 96 total requests, 24 per endpoint, and
exactly three creates; it permits no cross-object reads, privilege mutation, delete, or
real-user data access. Every request must remain within the signed origin, sealed action
sequence, ownership registry, and pre-reserved budget. The continuation workflow and
graph workflow are mutually exclusive before graph dispatch.

The `0eb7a76` denial-evidence change grants no new traffic or execution authority. The
first run uses the same admitted graph budget; a duplicate denied URL-capture request
now stops earlier and therefore reduces traffic. Stored denial evidence cannot create a
finding, promote a report, authorize retry, or bypass any gate.

The `9167d9a` freshness change adds no target request or action class. Missing prior
evidence stops before window access. A stale artifact requires only the already-admitted
current paired capture, then stops before graph experiment traffic; its identical retry
stops before another capture. A matching artifact rebuilds the graph plan from current
records under the unchanged signed workflow, three default-off gates, ownership policy,
and pre-reserved budget. The freshness binding itself grants no dispatch, finding,
promotion, or retry authority.

Disabling any graph gate prevents graph experiment traffic, but it does not disable the
already-authorized ordinary-click URL capture that precedes direct graph selection. That
capture retains its existing scope and authority contract. This checkpoint adds no new
public-target permission and no background, automatic, reporting, payout, or submission
authority.

The reordering path uses the same signed workflow, three default-off gates, exact
origin, ownership registry, and pre-reserved `96`-request ceiling. Its accepted external
manifest used `18` requests per twin because all three worlds execute both prerequisites,
one terminal action, cleanup, and cleanup verification. It adds no method, endpoint,
identity, origin, redirect, real-user-data, promotion, payout, or submission authority.

#### R5C — Authority monotonicity and role enforcement

- [ ] Invitation, membership, role assignment, and administrative boundaries.
- [ ] Lower authority must not gain an effect available only to higher authority.
- [ ] All role changes use owned tenants and reversible cleanup.

#### R5D — Capability confinement, freshness, and replay

- [ ] Object-bound, account-bound, tenant-bound, single-use, and expiry properties.
- [ ] Tokens and keys remain ephemeral; public evidence contains only typed hashes.
- [ ] Callback-dependent effects require an owned callback receiver and explicit scope.

#### R5E — Owned-data integrity relations

- [ ] Controlled field write versus authoritative follow-up read.
- [ ] Server-produced, client-writable, ignored, and role-sensitive field classes.
- [ ] Mass-assignment claims require demonstrated protected effect, not response echo.

#### R5F — Parser, cache, and trust-boundary disagreement

- [ ] Method, path, encoding, header, host, cache-key, and proxy/router interpretations.
- [ ] Only safe counterfactual pairs with explicit target authorization.
- [ ] Independent effect oracle; response difference alone is not a vulnerability.

#### Technical explanation

Implement each property as a topology-aware experiment compiler plus an independent
oracle under the R4 SDK. Add one family at a time, starting with the highest expected
bounty yield and lowest safe proof cost: R5A, R5B, R5C, then R5D. R5E and R5F remain
separately gated because they require broader mutation or protocol-boundary reasoning.

#### Non-technical explanation

Sentinel will learn additional categories of broken locks one by one. It will first
generalize the account and workflow flaws it already understands, then add roles,
one-time capabilities, protected data changes, and finally disagreements between
layers such as caches and application routers.

#### Target traffic and execution authority

Every family changes target traffic when its experiments are enabled. Authority is
never shared across families. Each family must define its exact action classes,
maximum requests, owned-data requirements, and cleanup behavior before integration.

#### Exit gate for every family

- [ ] Vulnerable and secure twins produce confirmed and upheld outcomes respectively.
- [ ] Ambiguous evidence is inconclusive, never promoted.
- [ ] Counterexamples reproduce from a fresh controlled state.
- [ ] Cleanup success or failure is durable and report-visible.
- [ ] Native and wire acceptance show zero out-of-scope requests.

### R6 — Coverage-guided payout search and defensible stopping

#### Technical explanation

Add a `HighValueSinkLedger` and scheduler over ranked security goals. Record each sink
as discovered, insufficiently observed, reachable, planned, executing, confirmed,
upheld, blocked, or bounded-exhausted. Rank the next experiment by estimated impact,
new state/relation coverage, information gain, proof strength, execution cost, cleanup
risk, and available authority. A stop certificate must describe only the explored
frontier and must preserve every blocker and coverage deficit.

#### Non-technical explanation

Sentinel will keep choosing the most valuable unanswered question instead of walking a
generic checklist. It stops because every valuable door it knows about was either
tested, proven secure for the tested property, found broken, or shown to require
missing permission or evidence—not because a timer ran out or it became bored.

#### Target traffic and execution authority

Scheduling itself is passive. Dispatch uses only existing R4/R5 experiment authority.
The scheduler cannot increase budgets, add identities, change origins, or reinterpret a
blocked goal as permission to try something else.

#### Exit gate

- [ ] Scheduler order is deterministic for identical evidence and authority.
- [ ] New information can change priority without erasing prior decisions.
- [ ] Repeated zero-progress work is not reissued under a new identifier.
- [ ] Stop certificates distinguish target coverage from current-frontier coverage.
- [ ] Dropped or bounded evidence prevents an exhaustive claim.

### R7 — Submission-grade candidate assembly

#### Technical explanation

Accept only independently confirmed counterexamples with valid receipts, provenance,
scope, topology, cleanup, and graph dispositions. Reconstruct a sanitized deterministic
reproduction, impact argument, affected operation, restraint summary, correlation
identifiers, and evidence references. Route the result through the existing finding
adversary, deduplication, severity rationale, FindingsStore, report composer, and draft
workflow. Preserve explicit operator confirmation for external submission.

#### Non-technical explanation

After Sentinel proves a broken lock, it prepares the complete bounty case file without
making the operator rebuild the story by hand. The operator still reviews and submits
it, and Sentinel still cannot promise eligibility, uniqueness, severity, acceptance,
or payment.

#### Target traffic and execution authority

No target traffic. No new execution authority. External submission remains a separate
operator-authorized irreversible action.

#### Exit gate

- [ ] Fresh replay reproduces the candidate from sanitized instructions.
- [ ] Report claims are mechanically traceable to receipts and provenance.
- [ ] Raw credentials, private markers, tokens, and unrelated response data are absent.
- [ ] Refuted, inconclusive, duplicate, or cleanup-uncertain results cannot surface.
- [ ] Native UI exposes the complete draft and its remaining operator decisions.

### R8 — Operational one-click completion

#### Technical explanation

Replace manual proof-mode configuration with an evidence-driven recommended topology,
while requiring the operator to supply or approve any missing envelope, identity,
workflow, or callback authority. Surface acquisition, planning, execution, proof,
cleanup, coverage, and report status as one durable scan state. Restart must resume or
honestly terminate receipts without duplicating target effects.

#### Non-technical explanation

The operator supplies the URL and the permission Sentinel cannot invent. Sentinel then
chooses the safe test setup, runs the supported search, explains what is blocked, and
returns either a proven candidate or an honest coverage report from the same Scan
button.

#### Target traffic and execution authority

No new classes of traffic beyond R2-R6. The UI cannot create authority; it passes only
operator-selected existing authorization to the backend.

#### Exit gate

- [ ] Zero-account targets do not demand two personas.
- [ ] Account targets request only the minimum missing owned identities or roles.
- [ ] Restart and duplicate-click behavior is receipt-safe.
- [ ] The UI never labels passive visibility as an adaptive proof.
- [ ] One scan exports both confirmed candidates and explicit coverage limitations.

### R9 — Real-target validation and payout acceptance

#### Technical explanation

Advance through deterministic twins, unknown-to-the-runner seeded staging targets,
authorized public-program canaries, independent human evidence review, and explicit
operator submission. Track confirmed findings, duplicates, informative and rejected
reports, payouts, severity, requests per finding, cleanup failures, out-of-scope I/O,
human interventions, open/blocked goals, and yield beyond established scanners.

#### Non-technical explanation

The software claim is not earned by code volume or a lab pass. It is earned when the
same one-click system safely finds reproducible issues on targets it was not built
around and at least one real program accepts and pays for the result.

#### Target traffic and execution authority

This phase uses real target traffic only under reviewed program scope, conservative
budgets, owned accounts, and explicit operator authorization. Submission remains
operator-confirmed.

#### Exit gate

- [ ] Supported automated and native release gates pass from clean state.
- [ ] Calibration records zero out-of-scope requests.
- [ ] No unresolved cleanup failure is hidden.
- [ ] Findings reproduce independently.
- [ ] At least one Sentinel-originated finding is accepted and paid.
- [ ] Repeated results demonstrate generalization beyond one target or proof family.

## Dependency-ordered to-do list

This is the execution order unless a newly discovered safety dependency requires an
explicit plan revision:

1. [x] **R1** — payout-goal contracts and passive proof-topology selector.
2. [x] **R2** — unified semantic reconstruction and resource provenance.
3. [x] **R3** — constraint ledger and deterministic replanning.
4. [ ] **R4** — generalized experiment, world, and oracle SDK.
5. [ ] **R5A-R5D** — highest-yield proof families.
6. [ ] **R6** — coverage-guided scheduling and stop certificates.
7. [ ] **R7** — submission-grade candidate assembly.
8. [ ] **R8** — operational one-click completion.
9. [ ] **R5E-R5F** — separately gated integrity and boundary-disagreement families.
10. [ ] **R9** — continuous real-target validation and payout acceptance.

R1-R3 establish the passive decision, semantic, constraint-learning, and replanning
substrate of the universal planner center. R4 supplies executable-world construction.
R5-R8 turn that center into broader finding yield and an operator-ready
workflow. R9 is how the product claim is earned.

## Acceptance strategy from this point

The existing S01-S10 catalog remains a regression foundation, not a detour and not a
permanent proof of future behavior. Each new slice adds the smallest scenario needed to
falsify its new claim. Proposed future coverage is:

| Scenario | Purpose |
|---|---|
| S11 | Zero-persona, one-persona, and paired-persona topology selection |
| S12 | High-value sink discovery across REST, GraphQL, forms, JavaScript, source maps, and OpenAPI |
| S13 | Structured failure constraint learning and successful replanning |
| S14 | Missing authority blocks replanning before target traffic |
| S15 | Generalized multi-step state manufacture with verified cleanup |
| S16 | Role and membership monotonicity, vulnerable and secure twins |
| S17 | Capability confinement, freshness, and replay |
| S18 | Coverage-guided ordering and honest stop certificate |
| S19 | Submission-grade candidate assembly and sanitized reproduction |
| S20 | Full ordinary-click run across acquisition, proof, report, restart, and deduplication |

Scenario numbers are reservations, not implementations. A scenario is added only with
the corresponding slice; the plan must not create a second speculative lab backlog
detached from production code. R1's S11 purpose is currently covered by deterministic
zero-, one-, and two-persona contract fixtures. The visual system scenario remains
reserved until R8 exposes topology selection through the ordinary scan workflow; R1
deliberately adds no UI or execution surface. R2's S12 source matrix is likewise
covered at the passive contract boundary; an operator-visible end-to-end presentation
remains reserved for R8 rather than introducing a temporary diagnostic UI.

## Permanent verification rules

For every slice:

1. Inspect and preserve current architecture before editing.
2. Add deterministic unit tests for every new contract and denial path.
3. Run the narrowest focused check after the coherent edit.
4. At the slice checkpoint, run the relevant behavioral, router, persistence, and UI
   gates once.
5. Add or update one real-wire lab scenario when the slice changes observable behavior.
6. Require native acceptance when the slice changes the macOS operator journey.
7. Review the final diff for secrets, raw target data, debug artifacts, unbounded
   collections, accidental authority, and stale documentation.
8. Never describe a focused test pass as payout readiness.

## Plan-change control

This plan may change when implementation evidence invalidates an assumption, but no
original capability may be silently removed. A revision must:

- state what changed and why;
- move, replace, or explicitly reject the affected item;
- identify the preserving or superseding contract;
- update dependencies and acceptance gates; and
- retain the historical decision in version control.

An item may be marked complete only when its production caller, safety boundary,
focused tests, and required acceptance evidence all exist. A design document, unused
class, mocked-only path, or one successful manual run is not completion.
