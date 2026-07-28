# Sentinel One-Click Bounty Roadmap

Status: forward implementation plan
Starting point: `4d2d6cd` (`feat(scans): bridge behavioral one-click execution`)

## Purpose

This document defines the implementation path from Sentinel's current behavioral
engine to an honest "click -> bounty candidate" workflow.

The finish line is not a promise that every URL contains a vulnerability or that a
program will pay every valid report. It is an engineering contract:

> After the operator supplies scope, authorization, and any unavoidable account
> authentication, one ordinary scan action autonomously acquires meaningful target
> behavior, derives target-specific security obligations, safely executes the
> strongest admissible experiments, adapts to their results, and produces a
> reproducible submission-ready report for every independently confirmed finding.

Report submission remains an explicit operator decision because it is an external,
irreversible action. A valid finding also remains subject to program eligibility,
duplication, severity, and triage judgment.

## Current position

Sentinel already has substantial pieces of this system:

- Strict target scope and execution-policy boundaries.
- Durable execution receipts and duplicate suppression.
- Isolated Persona Vault identities and authenticated browser windows.
- One-click paired URL capture through Foundry.
- Direct navigation capture for ordinary pages and API URLs.
- Paired-world read exploration.
- Passive behavioral normalization and state coverage.
- A backward-chaining prerequisite graph.
- Target-derived security obligations and closure accounting.
- Obligation-ranked proof dispatch.
- Fresh researcher-owned object construction and cleanup.
- Independently confirmed cross-principal authorization proofs.
- Exact state-machine prerequisite-omission confirmation.
- Receipt-to-graph feedback and report-facing findings.
- An optional `behavioral_one_click` profile on ordinary bounty scan requests.
- A passive, page-bound `InteractionIntent` catalog for visible browser controls.
- Existing finding storage, verification sessions, sanitized reproduction rendering,
  bounty reports, and an operator-confirmed HackerOne submission client.

The important current limitations are:

- The macOS ordinary Scan screen does not yet send the explicit behavioral profile.
- A single URL load exposes only behavior naturally produced by that navigation.
- The obligation frontier can execute two receipt-chained sealed safe-read intents,
  but the mechanism is not yet generalized into the bounded adaptive loop.
- Acquisition and proof continuation do not form one adaptive multi-round loop.
- Fresh-owned execution supports narrow captured lifecycle shapes.
- Omission confirmation supports one exact capability-linked lifecycle shape.
- Most open security-relation types lack independent active proof oracles.
- The engine can acquire one obligation-directed response, but cannot yet repeat that
  process as a bounded adaptive chain.
- Closure accounts for the current evidence frontier; it does not establish broad
  target coverage.
- Behavioral findings are not yet connected directly to the submission-grade report
  and draft workflow.

## Non-negotiable architecture rules

Every phase below must preserve these rules:

1. Passive analysis sends no target traffic.
2. Every active request crosses `PolicyExecutor`, scope enforcement, a proof budget,
   and provenance recording.
3. The reasoning model never receives raw transport authority.
4. A hypothesis is not a finding. Every relation needs an independent proof oracle.
5. The operator's signed envelope controls origins, personas, workflows, and action
   classes. Sentinel never guesses or broadens authority.
6. Real-user objects are excluded. Active proofs use anonymous state or
   researcher-owned personas and objects.
7. State-changing setup must have a proven bounded cleanup path before execution.
8. Cleanup uncertainty is terminal and visible; it cannot be hidden by a finding.
9. Receipts are durable, content-addressed, redacted, and non-renewable through
   retries or restarts.
10. Search continuation requires evidence-backed progress, not elapsed time or a
    model's unsupported confidence.
11. A closure certificate describes only the bounded evidence frontier that produced
    it. It never means "the target has no vulnerabilities."
12. External report submission requires explicit operator confirmation.
13. The validated Gemma asset and its prompts are not changed as part of this
    roadmap unless separately approved.
14. The shelved `core.web` orchestrator is not revived wholesale. Useful live
    contracts may be reused, but the behavioral engine remains the control plane.

## Milestone map

Milestone labels describe product capability, not implementation chronology. In
particular, M1's final UI wiring is deliberately deferred until the acquisition loop
behind it is materially stronger.

| Milestone | Human-visible result |
| --- | --- |
| M1 — Unified click | The ordinary Scan action can explicitly invoke today's behavioral proofs. |
| M2 — Autonomous acquisition | Sentinel can safely discover meaningful workflows beyond the initial URL load. |
| M3 — Generalized proof library | Sentinel can confirm several high-value target-derived security relations. |
| M4 — Adaptive search | Real experiment results generate and prioritize the next materially different question. |
| M5 — Submission-ready output | Every confirmed result automatically becomes a complete, sanitized bounty draft. |
| M6 — Real-world validation | The workflow demonstrates accepted and paid findings on authorized public programs. |

## Phase 1 — Complete the unified ordinary-scan click (deferred integration)

### Technical implementation

1. Add an explicit behavioral execution profile to the macOS scan configuration:
   approved envelope, source persona, and peer persona.
2. Filter envelopes by target origin and required workflow before presenting them.
3. Show only open, vault-backed persona windows; require two distinct identities
   when the selected proof topology needs two worlds.
4. Send the existing `behavioral_one_click` request object through
   `SentinelAPIClient.startScan`.
5. Decode behavioral phase state and finding references in ordinary scan status.
6. Surface preflight denial, missing windows, cleanup uncertainty, cached execution,
   and confirmed finding as distinct UI states.
7. Preserve the existing scan path byte-for-byte when no behavioral profile is
   selected.

### Non-technical result

The operator selects the permission slip and researcher accounts once, enters a URL,
and presses the normal Start Scan button. Sentinel runs today's behavioral machinery
without requiring a separate BOLA Lab action.

### Target traffic and authority

This phase adds no proof type or request budget. It only passes explicit authority to
the already implemented ordinary-scan bridge. Missing or ambiguous configuration adds
zero behavioral traffic.

### Exit gate

- One UI integration test proves the exact request body.
- One backend-to-UI test covers each terminal state.
- With the profile omitted, ordinary scan behavior and traffic remain unchanged.
- With invalid authority, no capture navigation or ordinary scanner tool runs.

## Phase 2 — Build the behavioral acquisition controller

This is the first major discovery multiplier.

### 2A. Safe interaction vocabulary

#### Technical implementation

- Normalize browser-observed controls into structural intents such as navigate,
  reveal, select, filter, paginate, open detail, submit known-safe form, and return.
- Classify every intent as passive, read-like interaction, reversible owned mutation,
  externally consequential, destructive, or unknown.
- Admit only passive and explicitly authorized safe interactions initially.
- Bind each intent to its DOM locator, page-state fingerprint, world, origin, action
  class, and expected side effect.
- Reject file uploads, purchases, messages, invitations, password changes, external
  communication, destructive actions, and unknown forms by default.

#### Non-technical result

Sentinel learns the difference between opening a menu and sending money. It can touch
safe controls without treating every button as permission to act.

#### Traffic and authority

This introduces browser interaction authority but not arbitrary form submission.
Every resulting request remains within the existing scope and policy boundaries.

### 2B. Bounded browser-state explorer

#### Technical implementation

- Add a content-addressed browser state using origin, route template, DOM structure,
  visible control structure, and redacted network coverage.
- Execute one safe intent at a time and record the state transition and newly exposed
  network operations.
- Use novelty and obligation relevance, not DOM order, to prioritize the frontier.
- Enforce hard bounds for states, transitions, depth, interaction count, response
  bytes, wall-clock liveness, and per-endpoint requests.
- Persist acquisition receipts so a restart cannot renew the same exploration budget.
- Backtrack through browser history or a proven reversible navigation path.

#### Non-technical result

Sentinel can walk through the authorized building, remember the rooms it has already
seen, and prefer doors likely to answer an important security question.

#### Traffic and authority

This adds bounded navigation and safe UI-generated target traffic. It does not yet
authorize writes used as vulnerability tests.

### 2C. World-aware acquisition

#### Technical implementation

- Support explicit world topologies:
  - anonymous;
  - one authenticated persona;
  - two authenticated personas;
  - one persona before and after a state transition;
  - two personas with fresh owned objects;
  - separately authorized role-differentiated personas.
- Synchronize comparable navigation across worlds without requiring identical DOMs.
- Detect world-specific controls, operations, response structures, capabilities, and
  reachable states.
- Prevent cookies, headers, tokens, object identifiers, and browser storage from
  crossing world boundaries.

#### Non-technical result

Sentinel can compare an anonymous visitor, Alice, Bob, and—when explicitly
configured—a higher-role test account. Targets that do not need two people can use a
one-world or before/after topology instead.

#### Traffic and authority

Traffic increases according to the selected world topology. No topology is inferred
as authorized merely because credentials exist.

### 2D. Obligation-directed acquisition

#### Technical implementation

- Give the ranked obligation frontier an acquisition resolver distinct from proof
  execution.
- Convert blockers such as missing peer lifecycle, unresolved operation semantics,
  unknown cleanup, or unseen capability producer into exact evidence-acquisition
  goals.
- Admit acquisition only when it can produce a named missing evidence type.
- Feed new captures back into the graph and require graph-digest or blocker progress
  before another acquisition round.

#### Non-technical result

Sentinel stops wandering. If it suspects a hidden elevator but lacks the call button,
it searches specifically for evidence that could reveal or rule out that button.

#### Exit gate for Phase 2

- Controlled labs demonstrate discovery of important workflows not emitted by the
  initial page load.
- Every action is scope-checked and receipt-backed.
- Unsafe controls remain blocked.
- No world state leaks into another.
- Every additional acquisition round removes a blocker, adds a new operation/state,
  or terminates.
- Crash and duplicate tests prove budgets cannot be renewed.

## Phase 3 — Complete target semantic reconstruction

### Technical implementation

1. Unify captured browser traffic, direct navigations, bounded JavaScript artifacts,
   source maps when authorized, HTML forms, GraphQL documents, REST structures, and
   observed client state into one redacted operation catalog.
2. Infer operation roles: create, read, update, archive, delete, approve, publish,
   export, invite, share, transition, token issue, token consume, and role change.
3. Track producer-consumer lineage for server-issued identifiers, capabilities,
   nonces, CSRF tokens, workflow tokens, pagination cursors, and state versions.
4. Infer state transitions and prerequisites from repeated owned-world observations.
5. Represent ambiguity explicitly; competing interpretations remain separate rather
   than being collapsed by a model guess.
6. Add artifact provenance and confidence based on independent observations, not
   model certainty.
7. Detect client/server contract disagreement: operations or required fields present
   in artifacts but absent from observed UI, and vice versa.

### Non-technical result

Sentinel builds blueprints from what the target actually reveals. It learns which
actions create keys, which doors consume them, and which rooms are advertised only in
the building plans.

### Target traffic and authority

Semantic inference itself is passive. Artifact fetching and confirmation traffic use
separate, bounded acquisition authority.

### Exit gate

- Multiple framework-neutral labs produce the same semantic graph from REST,
  GraphQL, form, and direct API variants.
- Secret values never appear in graph snapshots.
- Every inferred prerequisite cites at least one concrete observation.
- Ambiguous semantics cannot become executable without independent confirmation.

## Phase 4 — Create the generalized experiment and oracle SDK

This phase prevents each new vulnerability family from becoming bespoke route code.

### Technical implementation

1. Define a versioned `SecurityRelation` contract:
   subject, object, worlds, intended invariant, required evidence, counterfactual,
   admissible action classes, cleanup contract, and independent verdict oracle.
2. Define a versioned `ExperimentManifest` that compiles a relation into:
   baseline legs, counterfactual legs, negative controls, cleanup, exact policy
   budget, redaction schema, and receipt schema.
3. Separate four roles mechanically:
   hypothesis generator, manifest compiler, policy admission, and verdict oracle.
4. Require oracle-specific evidence sufficiency before finding promotion.
5. Add differential minimization to remove unnecessary actions while preserving the
   confirmed result.
6. Generate a deterministic replay recipe from the minimized manifest.
7. Provide a conformance suite that every new relation family must pass before it can
   enter the primary resolver.

### Non-technical result

Sentinel gets a standard laboratory bench. A new lock idea is not trusted until it
comes with a controlled test, a comparison case, cleanup instructions, and a judge
that does not depend on the idea's inventor.

### Target traffic and authority

The SDK itself sends no traffic. Individual manifests receive only the exact authority
their relation and envelope allow.

### Exit gate

- Existing BOLA, fresh-owned BOLA, and omission confirmation run through the common
  contract without weakening their current invariants.
- A malformed or over-budget manifest fails before transport.
- A hypothesis generator cannot declare its own hypothesis confirmed.

## Phase 5 — Expand high-value proof families

Each family is implemented separately in shadow, lab, controlled canary, and primary
stages. A family is not "supported" merely because Sentinel can generate a mutation.

### 5A. Generalized object authorization

- Path, query, JSON, form, header, GraphQL variable, persisted GraphQL, and nested
  identifier bindings.
- Read, download, export, metadata, and bounded integrity variants.
- Anonymous-to-owned, peer-to-owned, and explicitly authorized role comparisons.
- Independent self baselines and negative controls.

Plain-language result: Sentinel can test many kinds of "Bob can access Alice's
thing," not only one captured request shape.

### 5B. Generalized state-machine prerequisite enforcement

- Multi-step workflows rather than the current exact short lifecycle.
- Missing, reordered, duplicated, stale, and cross-object prerequisite variants.
- Known-valid controls proving that the prerequisite is meaningful.
- Reversible owned setup and cleanup only.

Plain-language result: Sentinel can test whether the server enforces the required
order of operations instead of trusting the client to follow the UI.

### 5C. Authority monotonicity and role enforcement

- Compare the same safe operation across explicitly configured roles.
- Detect lower-role success where a higher role is required.
- Confirm role binding through allowed and denied controls.
- Exclude self-assigned or fabricated administrator status.

Plain-language result: Sentinel can prove that a low-privilege test account has an
ability reserved for a higher-role test account.

### 5D. Capability confinement, freshness, and replay

- Object binding, persona binding, tenant binding, expiry, one-time use, and
  workflow-state binding.
- Known-valid same-object control, wrong-object control, and bounded replay.
- Tokens remain inside the execution boundary and never enter graphs or reports.

Plain-language result: Sentinel can determine whether a real server-issued key works
outside the exact place or moment where it should work.

### 5E. Owned-data integrity relations

- Unauthorized modification of fresh researcher-owned objects.
- Lost prerequisite or stale-version enforcement.
- Cross-persona writes only when the program and envelope explicitly allow them.
- Exact before/after state verification and cleanup.

Plain-language result: Sentinel can prove that Bob can alter Alice's disposable test
object without touching anyone else's data.

### 5F. Parser, cache, and trust-boundary disagreement

- Compare independently parsed or cached representations of one bounded request.
- Detect authorization-relevant disagreement without smuggling, denial-of-service,
  poisoning third-party users, or shared-cache harm.
- Require target-specific safe controls and an oracle that demonstrates security
  impact, not merely different responses.

Plain-language result: Sentinel can find cases where two guards interpret the same
safe request differently, but only when that disagreement produces controlled,
reproducible impact.

### Traffic and authority for Phase 5

Every family changes traffic only through its own signed workflow and exact budget.
Higher-risk families remain unavailable when the program policy does not explicitly
permit them. Race testing, request smuggling, denial-of-service, destructive actions,
and real-user access are not silently introduced by this roadmap.

### Exit gate for each family

- Framework-neutral lab fixtures.
- False-positive adversarial fixtures.
- Independent oracle and minimized replay.
- Exact scope, budget, ownership, and cleanup tests.
- Redaction and crash-recovery tests.
- Shadow comparison against existing logic where applicable.
- At least one authorized real-target canary producing either a valid rejection or a
  confirmed result without scope or cleanup failure.

## Phase 6 — Adaptive hypothesis search and defensible stopping

### Technical implementation

1. Replace the fixed two-round continuation ceiling with a bounded search session
   whose authority is allocated by relation, world, endpoint, and total conduct
   budget.
2. Treat every terminal receipt as graph evidence:
   violated, upheld, blocked, inconclusive, cleanup-uncertain, or environment-blocked.
3. Generate follow-up hypotheses only from concrete residuals:
   unexplained world differences, newly revealed operations, unsatisfied
   prerequisites, parser disagreement, unexpected controls, or graph blockers.
4. Measure hypothesis novelty structurally so reordered or cosmetically changed tests
   cannot renew authority.
5. Use expected information gain and bounty-relevant impact to rank admissible work,
   while safety and evidence sufficiency remain hard gates.
6. Allow acquisition and proof rounds to alternate:
   obligation -> missing evidence -> acquisition -> recompile -> proof -> receipt ->
   disposition -> next obligation.
7. Persist the entire search session so restart, UI retry, or model retry cannot
   reset budgets or forgotten failures.
8. Produce one of four honest terminal states:
   - `finding`;
   - `conditionally_closed`;
   - `blocked_with_required_operator_action`;
   - `budget_or_policy_exhausted_with_open_frontier`.

### Non-technical result

Sentinel behaves less like a checklist and more like a persistent investigator. A
failed theory teaches it what to try next, but it cannot repeat the same idea in a
different costume or keep spending requests without measurable progress.

### Target traffic and authority

This expands the number of possible rounds, not the kinds of authority available.
The envelope and global conduct budget remain absolute ceilings. Additional rounds
require prior receipt-backed progress.

### Exit gate

- No repeated experiment identities or equivalent mutations.
- Every round changes the graph or terminates.
- Search survives process restart without budget renewal.
- Blocked operator actions are specific and resumable.
- Stable fully accounted graphs can close the bounded frontier.
- New evidence invalidates closure and correctly reopens search.

## Phase 7 — Evidence, impact, and submission-grade promotion

### Technical implementation

1. Promote every confirmed behavioral proof into the canonical finding and evidence
   pipeline.
2. Bind minimized replay, world attribution, exact scope decision, conduct
   provenance, cleanup proof, and receipt identities into a versioned evidence
   package.
3. Generate target-specific impact from demonstrated capability, not vulnerability
   labels or speculative worst cases.
4. Render clear reproduction instructions with separate persona steps and sanitized
   placeholders.
5. Add duplicate/deconfliction fingerprints based on root cause, endpoint template,
   relation, and proof identity.
6. Connect behavioral findings to the existing bounty report and
   `SubmissionRender` path.
7. Produce an operator-reviewable draft; never call the submission client
   automatically.
8. Preserve enough local private evidence for triage follow-up while keeping secrets
   out of shareable reports.

### Non-technical result

When Sentinel finds a broken lock, it automatically prepares the photographs,
timeline, exact reproduction steps, impact explanation, cleanup proof, and draft
report a bounty triager needs.

### Target traffic and authority

Report generation is passive. Optional replay validation uses the already admitted
proof manifest. Submission remains a separate explicit external action.

### Exit gate

- A confirmed finding produces a complete report without manual transcript editing.
- Reproduction works from a clean owned test state.
- Reports contain no raw secrets or unrelated user data.
- Demonstrated impact and severity survive adversarial reviewer inspection.
- Duplicate execution returns the same report identity without target traffic.

## Phase 8 — Operational one-click experience

### Technical implementation

1. Create one scan progress model spanning acquisition, graph construction,
   experiment compilation, proof execution, cleanup, closure, and reporting.
2. Persist resumable blockers such as login, CAPTCHA, email verification, missing
   role, or required program attestation.
3. Let the operator satisfy a blocker and resume the same receipt-bound session
   without restarting the search.
4. Show traffic budgets, action classes, worlds, open obligations, cleanup state, and
   why Sentinel stopped.
5. Provide three operator actions:
   - start/resume authorized research;
   - inspect evidence and report;
   - explicitly approve external submission.
6. Remove the need to visit diagnostic BOLA/Foundry screens during ordinary use while
   keeping them available for debugging.

### Non-technical result

The normal experience becomes: configure the program once, authenticate any required
research accounts, paste a URL, and click Start. Sentinel asks for help only when a
human-only wall appears, then resumes from exactly where it stopped.

### Target traffic and authority

The UI does not create authority. It displays and passes existing signed authority.
Resume cannot renew budgets or bypass an earlier denial.

### Exit gate

- A non-technical operator can complete a lab run without diagnostic screens.
- Human-only blockers resume rather than restart.
- Every stop state explains what happened and what remains unknown.
- No UI retry duplicates target traffic.

## Phase 9 — Real-target validation and payout acceptance

Engineering completion is not enough. Sentinel's actual product claim must be earned
empirically.

### Validation ladder

1. **Deterministic labs**
   - Known vulnerable and fixed versions.
   - Multiple frameworks and API styles.
   - False-positive and cleanup-failure cases.

2. **Owned staging targets**
   - Unknown-to-the-runner seeded vulnerabilities.
   - Full click-to-report workflow.
   - Scope, crash, restart, and duplicate testing.

3. **Authorized public-program canaries**
   - Conservative traffic budgets.
   - Operator-reviewed scope and accounts.
   - Valid rejection evidence is counted as useful calibration.

4. **Submission-quality validation**
   - Independent human review of evidence, novelty, impact, and program eligibility.
   - Explicit operator submission.

5. **Payout proof**
   - At least one accepted paid finding demonstrates that click-to-bounty is real.
   - Repeated accepted findings across different targets or relation families
     demonstrate that it is a capability rather than one lucky result.

### Required metrics

- Confirmed findings per authorized target.
- Accepted, duplicate, informative, and rejected report rates.
- Payout and severity distribution.
- Requests and browser actions per confirmed finding.
- False-positive rate after independent reproduction.
- Cleanup success and orphaned-state rate.
- Scope-denial and out-of-scope-I/O count.
- Human interventions per scan and intervention category.
- Open, blocked, and conditionally closed obligation counts.
- Novel experiment yield compared with established scanner output.

### Release gate

Sentinel should not be described as achieving click-to-bounty until:

- the ordinary workflow is end-to-end;
- the full supported test suite is a clean release gate;
- zero out-of-scope target requests are observed in calibration;
- no unresolved cleanup failure is hidden;
- confirmed findings reproduce independently;
- at least one real program accepts and pays a Sentinel-originated finding;
- repeated results show that discovery and proof generalize beyond one lab or target.

## Recommended implementation order

The implementation dependency order is:

1. Phase 2A-2B — safe interactions and state explorer.
2. Phase 3 — semantic reconstruction over the new evidence.
3. Phase 2C-2D — multi-world and obligation-directed acquisition.
4. Phase 4 — generalized manifest/oracle contract.
5. Phase 5A-5D — highest-yield proof families first.
6. Phase 6 — adaptive multi-round search.
7. Phase 7 — automatic evidence and report promotion.
8. Phase 1 plus Phase 8 — connect the now-capable loop to the ordinary UI and finish
   the operational experience.
9. Phase 5E-5F — separately gated higher-risk or less universal families.
10. Phase 9 — continuous real-target calibration and payout acceptance.

The order deliberately builds acquisition before adding many proof families. A large
oracle library has little value if Sentinel never sees the target workflows needed to
compile its experiments. It also postpones the final Scan-button integration so that
the button exposes a materially stronger system rather than merely making today's
narrow proof path look finished.

## Planning size

This is not one remaining pass. A realistic planning range is approximately 28-40
small, reviewable implementation passes, depending on how much existing Wraith,
Foundry, reporting, and verification code can be adopted without weakening the newer
behavioral invariants.

The roadmap should be adjusted after each milestone using measured calibration data.
Phases should not be declared complete because their classes exist; completion means
their exit gates pass end-to-end.

## Completed Phase 2A slices

### Passive interaction-intent catalog

The first Phase 2A slice now converts visible controls from each already-loaded owned
browser world into a bounded, redacted, content-addressed, risk-classified catalog.
The catalog is bound to the origin, normalized page path, world, and structural
locator. It is included in behavioral shadow and request identity but remains
non-executable. Browser labels, identifiers, values, destination strings, and form
data are discarded before they cross the driver bridge.

Target traffic and execution authority remain unchanged. The capture path reads local
DOM structure after navigation but performs no interaction and sends no new target
request. Snapshot failure degrades to an empty catalog.

### Obligation-directed interaction admission

The behavioral shadow now compares the exact ranked obligation frontier with the
passive catalog and seals at most one eligible read intent for the authorized actor
world. It ignores obligations that already have proof paths and rejects peer-world,
scripted, ambiguous, disabled, truncated, state-changing, external, destructive, and
unknown controls. The manifest binds the exact catalog, page, locator, world,
unresolved obligation, scope, policy digest, current budget state, and a one-action
limit. Same-origin navigation ranks ahead of native reveal because it can later be
resolved into one exact gated GET without executing page event handlers.

Target traffic and execution authority remain unchanged. The selector has no driver,
transport, receipt, reservation, or execution dependency.

### Controlled interaction read acquisition

The controlled acquisition boundary is now implemented and connected to ordinary
one-click URL scans behind
`SENTINELFORGE_BEHAVIOR_INTERACTION_ACQUISITION=1`.

Technical implementation:

- Add a local-only driver resolver that re-reads the admitted locator without
  activating it and returns one exact current same-origin navigation destination.
- Rebuild the structural snapshot and reject changed page, world, locator, catalog,
  destination class, or admission identity.
- Compile only an authenticated GET candidate; do not click the DOM, submit a form,
  execute page event handlers, follow redirects, or grant general browser control.
- Send that one GET through `PolicyExecutor` and the existing persona-bound transport
  under a pre-reserved one-request budget.
- Persist a redacted receipt and feed the new response record back into behavioral
  analysis. Retry must reuse the terminal receipt without traffic.
- Require the separate signed
  `behavioral_interaction_read_acquisition` workflow and skip acquisition whenever
  the current obligation frontier already has an actionable proof path.

Non-technical result:

- Sentinel rechecks that its chosen door is still the same safe internal doorway,
  then retrieves exactly what is behind that doorway using the correct researcher
  account.
- It still cannot press arbitrary buttons, run forms, make purchases, send messages,
  or wander through multiple links.

Target traffic and execution authority:

- Conditional change: when separately enabled and fully bound, this slice may send
  one same-origin authenticated GET. It grants no click or form authority. Missing,
  stale, changed, out-of-scope, unbudgeted, or cached admission adds zero traffic.

Exit gate:

- Exact freshness and admission binding are checked immediately before transport.
- Every request crosses scope, policy, budget reservation, and provenance gates.
- A retry cannot send the GET twice.
- No DOM event handler or form submission can run.
- The response becomes bounded evidence for the next shadow round.
- With the feature disabled or any binding invalid, target traffic remains zero.

The one-of-a-kind property is a double-sealed evidence-acquisition boundary. Sentinel
chooses the door because of a named unanswered security obligation, binds that choice
to the exact paired-world catalog and safety state, and then re-reads the binding
after durable reservation immediately before a single transport request. It acquires
new evidence without giving a model ambient click authority or trusting the page's
event handlers.

### Content-addressed browser-state transition contract

The first Phase 2B slice now turns the existing one-GET acquisition result into a
redacted, content-addressed before/after state transition.

Technical implementation:

- Define a browser behavior identity from target, owned world, normalized page,
  structural interaction catalog, and bounded normalized operation coverage.
- Bind the complete state identity to the current policy and proof-budget state
  without including raw URLs, identifiers, DOM text, response bodies, or credentials.
- Record the exact admitted intent, named security obligation, acquisition receipt,
  request/response evidence references, newly exposed operation references, blocker
  progress, and before/after states as one deterministic transition.
- Make transition replay strict: the persisted redacted artifact is reconstructed and
  revalidated, and its receipt and acquisition identities must match the acquisition
  summary that contains it.
- Preserve pre-upgrade acquisition receipts as zero-traffic reusable evidence; because
  they lack the new state references, replay marks the transition explicitly
  unavailable instead of corrupting the receipt or inventing state.
- Apply hard bounds of eight states, seven transitions, four levels of depth, 512
  operation references, and 512 obligation references.
- Stop on duplicate behavior, no operation-or-blocker progress, an unobserved control
  surface, no next state-bound admission, or any state/transition/depth limit.
- A next admission is eligible only when it is bound to the exact after-state page,
  catalog, world, policy, budget, and still-open obligation.

Non-technical result:

- Sentinel now writes a tamper-evident map entry saying which room it started in,
  which approved door it inspected, what new kind of target behavior appeared, and
  why it stopped.
- For example, if one safe link exposes a previously unseen `/documents/{id}` read
  operation, Sentinel records that as real progress. Because the current GET did not
  render that destination in the browser, it honestly marks the new room's controls
  as unseen and refuses to choose another door from invented page state.
- It still cannot walk through multiple rooms, click arbitrary controls, submit
  forms, or claim a new page was rendered when only its response was acquired.

Target traffic and execution authority:

- Unchanged in this slice. State and transition evaluation runs only after the
  existing separately authorized acquisition. It cannot call the driver or
  transport and does not permit a second GET.
- At this slice checkpoint, ordinary one-click remained capped at one
  interaction-acquisition GET per scan; the later receipt-chained slice raises the
  current cap to two.

Exit gate:

- Identical redacted inputs produce identical state and transition identities.
- Dynamic identifiers are reduced into normalized operation references.
- A transition cannot be replayed under a different receipt, acquisition, page,
  world, policy, budget, or obligation binding.
- An unrendered destination is always ineligible for another interaction.
- Focused state, acquisition, receipt, orchestrator, and one-click router tests pass.

The one-of-a-kind property is an evidence-bearing exploration halt. Sentinel does not
merely remember that a URL was fetched: it proves which security obligation justified
the door, which sealed acquisition crossed it, which behavior was actually new, and
why another action is or is not presently defensible. The map cannot silently turn a
transport response into imaginary browser authority.

### Receipt-bound inert destination observation

The second Phase 2B slice now turns the exact already-acquired authenticated response
into a truthful destination control catalog without running the downloaded page.

Technical implementation:

- Require the separate
  `SENTINELFORGE_BEHAVIOR_INTERACTION_RENDER=1` feature flag and signed
  `behavioral_interaction_render_observation` workflow in both direct and ordinary
  one-click preflight.
- Recompute and bind the exact acquisition receipt, admission, obligation, actor
  world, request identity, response body hash and shape, normalized operation,
  destination page, target, policy, and budget state.
- Parse at most 2 MiB of the acquired response using `DOMParser` in WebKit's isolated
  client content world; never insert it into a live document, run target scripts,
  navigate, or load subresources.
- Scan at most 4,096 candidate nodes and return at most 256 sanitized structural
  controls. Require the native result to attest zero target requests.
- Rebuild the redacted catalog in Python, rerun destination reasoning with only the
  actor's new controls, and bind a complete observed after-state to that exact
  catalog.
- Present at most one next admission only when it matches the exact destination page,
  catalog, actor world, current policy, remaining budget, and open obligation.
- Persist only content-addressed observation references and counters. Raw response
  bytes and structural controls remain ephemeral.
- Treat truncation, cached acquisition without raw bytes, driver failure, changed
  evidence, or any contract mismatch as an unobserved state that cannot continue.

Non-technical result:

- Sentinel can inspect the blueprint returned from the room it just opened without
  walking into the room or switching on anything inside it.
- If that blueprint exposes a new safe-looking door relevant to an unanswered
  security question, Sentinel can prepare that exact door as its next choice.
- It still cannot open the second door, run JavaScript-built controls, submit forms,
  change data, or assume the prepared control remains live.

Target traffic and execution authority:

- Unchanged by observation itself. It sends zero additional requests beyond the
  acquisition that produced its source response and grants no navigation, click,
  script, form, write, external-origin, or second-transition authority.

Exit gate:

- Changed body, response, page, world, admission, obligation, receipt, or
  authorization bindings fail before the native observer.
- The observer runs in an isolated WebKit world and cannot be replaced by
  target-controlled JavaScript globals.
- Raw HTML and controls cannot enter the durable orchestration receipt.
- A complete destination catalog can become the after-state and can present only an
  exactly state-bound, still non-executable next admission.
- Truncated or unavailable observations cannot authorize continuation.

The one-of-a-kind property is an authenticated browser-state advance without ambient
page authority. Conventional tools either execute untrusted page code to discover
controls or parse HTML without connecting it to the exact authorized persona action,
policy, proof budget, and durable response evidence. Sentinel makes that connection
falsifiable while keeping the next action inert.

### Receipt-chained second safe-read transition

The third Phase 2B slice now executes exactly one second interaction when the first
completed transition sealed an eligible next admission.

Technical implementation:

- Require
  `SENTINELFORGE_BEHAVIOR_INTERACTION_SECOND_TRANSITION=1`, all earlier interaction
  gates, and the separately signed
  `behavioral_interaction_second_read_transition` workflow.
- Accept only the admission ID and intent ID already committed to the first
  transition's `eligible_for_next_transition` decision.
- Revalidate the parent receipt, transition, after-state, observation, page, catalog,
  actor world, policy, remaining budget, obligation, and response body before local
  resolution.
- Re-parse the same authenticated response in WebKit's isolated client world and
  resolve the admitted structural locator twice. Target code is not run and the live
  page is not consulted.
- Require both local resolutions to produce the same exact same-origin HTTP
  destination, then delegate one GET to the existing policy-gated acquisition
  boundary with manual redirects and a 2 MiB response cap.
- Reserve a distinct durable child receipt whose identity includes the parent
  receipt, transition, after-state, observation, admission, policy, depth, and an
  implementation transition ceiling of two.
- Feed the child response through inert observation and a second content-addressed
  state transition. Hard-stop at transition two even when another safe intent could
  be prepared.
- Reject child receipts transplanted onto another parent and prevent retries from
  repeating the second GET.

Non-technical result:

- Sentinel can now open the exact second door it chose from the first authenticated
  blueprint, inspect the returned blueprint safely, and add a second tamper-evident
  map entry.
- For example, an initial account page may expose a safe link to an audit index; the
  audit index may expose a safe link to one audit detail. Sentinel can retrieve both
  in order when each step answers a named security question.
- It still cannot choose an unrelated door, press buttons, submit forms, run target
  JavaScript, make changes, leave scope, or continue to a third door.

Target traffic and execution authority:

- Conditional change: this slice may add one same-origin authenticated GET, raising
  the interaction maximum from one to exactly two.
- It grants no DOM, script, form, write, redirect-following, external-origin, or
  open-ended browsing authority. Disabled, stale, changed, cached-parent, denied, or
  non-progress paths add zero second-transition traffic.

Exit gate:

- The structural destination is resolved twice from the same receipt-bound response
  and must remain byte-for-byte identical before transport.
- The child receipt is distinct, parent-bound, redacted, terminal, and replay-safe.
- Changed resolution after reservation sends nothing and aborts the child receipt.
- The second response becomes bounded evidence and an exact depth-two state
  transition.
- Transition two stops deterministically at the implementation ceiling.

The one-of-a-kind property is parent-provenance-as-execution-authority. The second
request is not authorized because a crawler found another link; it is authorized
only because the exact first receipt, resulting state, security obligation, inert
response evidence, and sealed next admission all still agree immediately before the
request.

## Immediate next slice

The next slice generalizes the fixed two-step controller:

> Turn the proven parent-child mechanism into a bounded adaptive safe-read loop that
> may continue only while each receipt-backed transition produces measurable new
> behavior or resolves a named security blocker.

Technical scope:

- Extract the two-transition orchestration into a reusable controller over the
  existing state, depth, transition, operation, obligation, policy, and proof-budget
  limits.
- Make each child receipt point to its immediate parent so the complete exploration
  chain can be reconstructed and replay-validated.
- Repeat inert observation, shadow derivation, obligation ranking, admission, double
  resolution, acquisition, and transition evaluation without introducing a
  free-form browser loop.
- Stop on duplicate behavior, no catalog/operation/blocker progress, unavailable raw
  response evidence, policy or budget exhaustion, receipt reuse without ephemeral
  evidence, or any hard state/depth/transition limit.
- Keep the initial implementation read-only and same-origin.

Non-technical scope:

- Sentinel will be able to keep opening only the next justified safe door while each
  room reveals genuinely new evidence, then stop for a concrete recorded reason.
- It still will not press buttons, fill forms, make changes, or treat persistence
  alone as permission to continue.

Target traffic and execution authority:

- Conditional change: the controller may authorize more than two same-origin GETs,
  but never beyond the existing hard state, transition, depth, endpoint, and total
  request budgets. No mutation or ambient browser authority is introduced.
