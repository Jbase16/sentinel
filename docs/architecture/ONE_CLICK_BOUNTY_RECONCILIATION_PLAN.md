# Sentinel One-Click Bounty Reconciliation Plan

Status: authoritative forward implementation plan

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
| State-machine prerequisite omission oracle | Implemented, narrow | Exact capability-linked lifecycle omissions can be recreated, compared, and independently confirmed. | Generalize prerequisite types, lifecycle shapes, and non-account state machines. |
| Bounded adaptive safe-read exploration | Implemented, narrow | Receipt-chained same-origin GET transitions can expose and hand off one newly actionable obligation. | Add topology-aware acquisition without creating a free-form browser agent. |
| Ordinary one-click behavioral bridge | Implemented | The native Scan UI can send paired-persona or anonymous-passive profiles to the backend. | Replace manual proof-topology choice with an evidence-driven recommendation and permitted automatic selection. |
| Proof topology selector | Implemented, passive and bounded | `PayoutGoalTopologyPlanner` now consumes R2 semantic projections and selects the minimum supported zero-, one-, two-, role-, lifecycle-, or callback-world topology from evidence, proof-backend availability, owned worlds, and envelope authority. | Generalize executable worlds in R4 and let the ordinary-click coordinator consume the decision in R8. |
| Payout-grade goal language | Implemented as an initial passive ontology | `PayoutSink`, `SecurityWitnessGoal`, `SecurityProperty`, `WorldRequirement`, and `GoalBlocker` describe ranked goals without granting authority or claiming a finding. | Add program-specific impact, cleanup, and broader proof requirements in R4-R6; R3 constraints already bind to these goals. |
| Failure-derived constraint learning | Implemented, passive and evidence-gated | `StructuredConstraintExtractor` recognizes bounded machine-readable prerequisite failures; `ConstraintLedger` keeps structured or independently controlled facts separate from untrusted-text hypotheses. | Add source adapters only when their structured semantics can be validated without promoting prose to fact. |
| Deterministic replanning | Implemented, passive | `ConstraintReplanner` preserves payout-goal evidence, compiler policy and bounds, records disproved assumptions, and refuses fact regression, repetition, contradiction, cycles, and limit exhaustion. | R4 may execute only separately admitted replanned experiments under the original signed authority. |
| Generalized counterexample/oracle SDK | Authorization and prerequisite-omission adapters implemented; passive generalized ownership binding and admission implemented | `ProofExperimentManifest` seals the passive proof plan; `GeneralizedExperimentAdmission` revalidates its authority and atomically reserves the complete budget; the default-off R4C adapters consume that exact claim through the existing authorization or omission oracle. R5A now proves exact same-world owned-create response identifiers across path, query, JSON, form, and GraphQL-variable locations, binds an actor/target-owner pair to one manifest, and reconstructs both captures under the current signed authority without granting a runtime claim. | R5A must still consume the passive ownership admission through a separately gated executor; ordinary one-click selection and dispatch remain later integration work. |
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

- [ ] Path, query, JSON, form, and GraphQL object locations.
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
- [ ] **R5A3 — Generalized authorization execution.** Extend the separately gated R4C1
  backend so policy can prove a selected object inside the admitted path, query, JSON,
  form, or GraphQL-variable location, then execute only the sealed controls and witness.

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

#### R5B — Generalized lifecycle prerequisite enforcement

- [ ] Multiple prerequisites and non-linear lifecycle states.
- [ ] Omission, reordering, replay, and stale-state experiments.
- [ ] Zero-persona and one-persona workflows in addition to paired accounts.

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
