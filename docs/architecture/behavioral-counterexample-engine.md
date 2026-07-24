# Behavioral Counterexample Engine

## Objective

Turn Sentinel's existing observations into a coverage-guided black-box behavioral
model, then use the existing `PolicyExecutor` to search for reproducible violations
of security relations across isolated execution worlds.

The engine is additive. Existing scan, proof, finding, provenance, reporting, and
submission contracts remain authoritative until the new path has demonstrated
behavioral equivalence and better validated-finding yield.

## Compatibility invariants

1. Passive observation cannot send target traffic.
2. Active experiments, when authorized in a later phase, must use
   `core.cortex.execution_policy.PolicyExecutor`; no raw transport is exposed to the
   scheduler.
3. Shadow failures cannot alter capture, replay, scan, or finding behavior.
4. Raw headers, cookies, query values, request values, and response values do not
   enter the behavioral graph. Only names, structural shapes, and SHA-256 hashes are
   retained.
5. Every in-memory collection is bounded against adversarially unique target data.
6. The engine cannot promote a finding. A future counterexample must pass the
   existing verification, provenance, adversarial-triage, and reporting pipeline.
7. Model prompts and fine-tuned model behavior are outside this architecture.

## Phase 1: passive shadow kernel

Implemented under `core.behavior`:

- Deterministic exchange normalization.
- Structural action and response-state fingerprints.
- Per-world transition heads.
- Cross-world structural and content-variant coverage signals.
- Hard limits for contexts, worlds, actions, states, transitions, and concrete
  content variants.
- Opt-in observation of finalized Ghost flows through
  `SENTINELFORGE_BEHAVIOR_SHADOW=1`.

This phase has no executor or network interface.

## Activation gates

### Gate A: passive correctness

- Deterministic snapshots for equivalent observations.
- No raw secret values in snapshots.
- Observer faults never affect existing capture results.
- Bounded behavior under unique-response floods.
- Existing Ghost, BOLA, execution-policy, and provenance tests remain green.

### Gate B: authorization equivalence

Before sending traffic, add an experiment proposal type containing intent but no
transport. Reproduce existing owned two-persona BOLA test cases from the behavioral
model. Compare proposed experiments with the established BOLA engine; disagreements
remain diagnostic.

Implemented in proposal mode:

- Independent identifier-correspondence inference across paired GraphQL, JSON, URL
  path, query, and request-header observations.
- Exact redacted mutation locators and three-leg authorization experiment plans.
- Conservative risk classification; mutations and unknown operations require later
  policy reclassification.
- Static candidate-set comparison with the established BOLA planner. The comparison
  imports no replay transport and never calls `hunt()`.
- Hard bounds on occurrences, correspondences, mutations, and proposals.

### Gate C: policy-constrained execution

Authorize only paired-world read experiments through `PolicyExecutor`. Run the old
and new engines together. The established engine remains authoritative until the new
engine matches its confirmed findings and restraint evidence across controlled labs.

Implemented as a controlled, single-experiment activation gate:

- Requires a signed, unexpired Foundry `AuthorizationEnvelope` that explicitly
  permits the `behavioral_object_authorization` workflow and target origin.
- Requires two distinct accountable `ResearchPersona` identities, a strict scope
  filter, bounty-safe mode, one shared proof budget, and one shared provenance sink.
- Recompiles the proposal from the supplied captures and rejects stale, altered,
  ambiguous, write-class, or legacy-incompatible proposals before transport.
- Rehydrates raw identifiers only inside the execution stack; they never enter the
  passive graph or redacted scheduler summary.
- Attempts at most three ordered legs. Both self baselines must succeed and fit inside
  the bounded response contract before the single counterfactual read is attempted.
  Each attempted leg crosses `PolicyExecutor`.
- Delegates the semantic verdict to `core.wraith.bola_replay`; Gate C does not
  introduce a second finding oracle or promote findings independently.
- A controlled executor is single-use, and the runtime handoff reserves a durable
  execution receipt before target traffic, preventing retries or replay amplification
  across requests, processes, and app restarts.

### Primary activation and obligation dispatch

`BehavioralPrimaryScheduler` supplies the bounded read-eligibility predicate used by
active exploration, but it no longer owns final execution selection. The unified
security-obligation frontier is authoritative at the runtime handoff. Its one-step
resolver binds the highest-ranked outcome-bearing obligation to one exact controlled
proposal and never invokes the legacy multi-operation hunt, so primary activation
cannot duplicate target traffic.

The operator-only `POST /v1/foundry/behavioral-authorization` endpoint is the runtime
handoff. It accepts bounded paired captures, vault persona IDs, and a signed Foundry
authorization envelope. `SENTINELFORGE_BEHAVIOR_PRIMARY` is off by default; while off,
the endpoint returns the redacted plan without creating a replay transport. When on,
it constructs one shared bounty-safe policy/provenance context and routes the selected
experiment through the authenticated SND persona windows. Legacy BOLA remains the
semantic verdict oracle and confirmed findings retain planner, restraint, and conduct
provenance metadata.

BOLA Lab now feeds this handoff directly. Capture hooks are bound to immutable vault
persona IDs, include request method and response status, and are ignored by the backend
unless that exact persona owns the active capture slot. Stopping capture disables the
page hook, and stale events cannot recreate a default repository-local JSONL file. Once
two owned persona captures and an approved behavioral authorization envelope are
available, the UI submits the pair in one action and displays either the default-off
plan or the authoritative legacy verdict.
Capture files are allocated by the authenticated backend under
`~/.sentinelforge/captures` rather than selected through save dialogs or supplied as
client filesystem paths; the directory and JSONL files use owner-only permissions and
remain outside the repository. Capture records are schema-limited, request and response
bodies are truncated explicitly, and each capture stops accepting records at 20,000
events or 16 MiB. The SND WebSocket handshake uses Sentinel's shared origin and API-token
validator, preventing another local or browser-origin client from replacing the trusted
UI execution node when authentication is required.

The capture surface includes native main-frame navigation, not only page-level
`fetch`/XHR hooks. A direct HTTP(S) resource or API URL therefore becomes a bounded GET
observation with its final URL, status, and response text, and can feed the same generic
REST authorization planner without requiring the target to be a client-side web app.

### One-click paired URL orchestration

The operator-only `POST /v1/foundry/behavioral-authorization-from-url` endpoint removes
the remaining manual capture choreography from a ready research context. Its input is
only the target URL, approved envelope ID, and two owned persona IDs. Primary mode must
already be enabled, and the backend validates the URL, both vault identities, the signed
and unexpired envelope, workflow permission, exact origin scope, the SND connection, and
both registered persona windows before navigating either window. The operator must
authenticate those isolated windows first because no target-independent signal can
reliably distinguish a logged-in browser from an anonymous session.

After preflight, the endpoint atomically reserves a durable URL-intent receipt and takes
exclusive ownership of the capture seam. It navigates and captures the source persona,
waits for bounded network quiescence, stops and fsyncs that capture, then repeats the same
sequence for the peer. Every JSONL record is re-opened through a no-follow, owner-only
file check and must match the persona that owned its session. Fetch and XHR starts and
ends are tracked without persisting activity records, so quiet requires zero in-flight
requests. A fresh capture nonce rejects late callbacks from prior sessions, including a
prior run of the same persona. Only then are the two
artifacts handed directly to the primary scheduler and existing three-leg legacy proof
oracle. Raw capture paths and records are never returned by the orchestration response.
During an active capture, the native window also cancels any main-frame redirect or
navigation whose normalized origin differs from the submitted URL; an authorized URL
cannot silently carry the orchestrator onto an out-of-scope site.

An identical completed click returns the redacted intent receipt without re-capturing or
replaying. Concurrent, aborted, or crash-stranded intents fail closed. BOLA Lab exposes
this path as **Capture Both & Run** once two persona windows are open and an approved
envelope is selected; the prior manual capture controls remain available as a diagnostic
fallback. Thus the steady-state operator action is one click after the unavoidable
account-authentication setup, for ordinary pages, API URLs, and non-marketplace targets
alike.

### Closed-loop paired read exploration

When primary mode has no executable proposal after the initial paired capture, Sentinel
now seeks the missing read behavior inside the same durable transaction. This is not a
general crawler: `BehavioralReadExplorer` accepts only HTTP(S) references published
verbatim in an owned response, requires the source and peer worlds to expose the same
structural route template, and fetches each persona's own reference before re-planning.
HTML anchor targets and JSON URL values are supported; static assets, external origins,
credentialed URLs, and paths or query actions associated with state changes are rejected.

Every discovery request crosses the same shared bounty-safe `PolicyExecutor`, request
budget, SND persona transport, and provenance sink as the final proof. Exploration is
bounded to six paired steps and 512 KiB per response. The entire primary transaction is
capped at 40 requests and five requests per endpoint template: two owned discovery reads
leave exactly three slots for peer baseline, source baseline, and the single
counterfactual read. The loop stops immediately after proposal compilation produces an
eligible read candidate. Durable receipts retain only fixed exploration counters and
state, never discovered URLs or response content.

The resulting capability is distinct from route crawling or parameter fuzzing: Sentinel
uses two owned worlds as an online behavioral oracle, advances them as a pair, and spends
traffic only until the already-authoritative proof engine has the minimum evidence it
needs.

### Persisted GraphQL semantics

`PersistedOperationCatalog` recovers GraphQL documents from explicit prior captures
and bounded same-origin JavaScript artifacts. If a request carries a persisted-query
SHA-256, only an exact document hash may resolve it; operation-name fallback is
forbidden. A request without a hash resolves only when one document is unambiguous.
Recovered mutations and subscriptions remain non-read operations and are rejected by
the scheduler and Gate C.

BOLA Lab reads already-loaded script resource URLs from the source persona window
without network I/O. When primary execution is enabled, the backend fetches at most
16 in-scope artifacts through the same `PolicyExecutor`, bounty-safe budget, SND
persona session, and provenance sink used by the proof. Each response is capped at
2 MiB before crossing the browser bridge, while the catalog also enforces aggregate,
document-count, and parser-work bounds. Invalid authorization envelopes are rejected
before the first artifact request. With primary execution disabled, no artifact fetch
is attempted. The three proof responses use the same 2 MiB streaming cap; any truncated
baseline or counterfactual is `AMBIGUOUS` and cannot confirm a finding.

### Durable execution receipts

Primary execution now has a filesystem-backed idempotency boundary under
`~/.sentinelforge/behavioral_receipts` (or `SENTINELFORGE_BEHAVIOR_RECEIPTS`). The
canonical paired-capture request is SHA-256 fingerprinted in memory, then a complete
owner-only receipt is published atomically before GraphQL artifact resolution or proof
traffic. Exactly one concurrent caller receives an unpersisted reservation token; only
that caller can complete or abort the receipt.

Completed duplicates return a redacted cached conduct summary without contacting the
target. Concurrent duplicates and aborted or crash-stranded reservations fail closed.
Receipt files contain only hashed target, envelope, and persona references plus fixed,
bounded counters and verdict state. Captures, request values, response bodies, operation
names, and semantic finding evidence are rejected by the persisted schema. This makes
the active proof budget non-renewable by restarting the UI or backend.

### Backward-chaining exploit compiler: analysis kernel

`BackwardExploitCompiler` introduces a separate prerequisite graph rather than
overloading the passive behavior graph or the post-finding causal graph. Each
`OperationContract` is a redacted typed transformation: it consumes semantic
capabilities, produces semantic capabilities, records whether success was actually
observed, and carries a static safety posture. A `BackwardGoal` names a terminal
operation and any output that operation must produce for the goal to be meaningful.

The compiler plans backward from the terminal operation, selects observed producers for
missing capabilities, and orders the resulting operations forward only when their
prerequisites can actually be satisfied. The bounded best-first search prefers safe,
observed producers; detects dependency cycles that have no bootstrap capability; and
returns explicit missing-capability, step-limit, and search-limit blockers. Plan identity
commits to the complete redacted operation catalog, compiler policy, limits, goal,
initial capabilities, and ordered step IDs.

Already-captured REST and GraphQL exchanges can feed this kernel without another target
request. The adapter retains only normalized paths, operation names, semantic field
names, structural hashes, and status-derived success state. Raw identifiers, tokens,
URLs, request values, and response values are not retained. Non-read captured operations
remain `unknown` safety rather than being guessed safe.

This phase is intentionally incapable of execution. Every result is `analysis_only` and
`executable: false`, including prerequisite-complete plans. Unknown or consequential
operations add blockers, owned writes require a cleanup contract, and the compiler has
no transport or `PolicyExecutor`. The lineage phase below supplies exact capture
bindings, but any active phase must still
prove ownership, validate cleanup, and reserve an execution budget through existing
policy and provenance gates before even one compiled step can run.

The novel distinction is that Sentinel is beginning to represent a remote application
as transformations capable of manufacturing the state required by a valuable sink. It
is not merely ranking endpoints or chaining findings that already exist; it can explain
which observed operations would have to execute, in which order, to make a currently
unavailable security experiment possible.

### Exact value lineage and controlled rehydration

`ValueLineageLedger` adds the missing evidence between a semantic compiler edge and the
captured bytes that support it. It extracts bounded candidate values from REST paths,
query parameters, JSON and form request bodies, and JSON responses. A producer-output to
consumer-input binding exists only when the semantic capability, exact value hash,
isolated world, and temporal order all match. Two personas observing the same value do
not create lineage, repeated producer locations are ambiguous, and duplicate request
templates are never selected arbitrarily.

Public lineage contracts contain only capability names, hashes, world and capture
references, and exact locators. Raw identifiers, tokens, URLs, headers, bodies, and
session material remain inside the session-local ledger. Its capture digest commits to
the complete input records, while its catalog digest uses the same operation contract
as the backward compiler. Short raw path values and authorization headers cannot enter
the serialized snapshot.

`PlanRehydrator` converts a prerequisite-complete `BackwardPlan` into a deterministic
`RehydrationRecipe`. It verifies the plan catalog, requires exactly one same-world
request template for every step, proves each non-initial capability through one exact
lineage binding, and binds the recipe identity to the plan, capture, catalog, world,
steps, bindings, validation errors, and execution blockers. Changed captures, forged
recipes, unsupported locators, missing ownership proof, and secret-bearing capabilities
fail closed.

This remains an analysis slice and adds zero target traffic. A ready recipe is still
`executable: false`; the in-memory rehydrated step has no send method, redacts its
representation, and cannot cross `PolicyExecutor`. The next active slice must replace
captured producer values with fresh runtime outputs, register researcher ownership at
the executor seam, prove cleanup operations, and reserve a non-renewable multi-step
budget before execution authority can be considered.

The one-of-a-kind element is the evidence chain from a backward semantic dependency to
the exact producer field and exact downstream request slot that carried the same value.
Sentinel is no longer merely saying that `CreateInvoice` could enable `ExportInvoice`;
it can prove where its invoice identifier emerged, where that exact identifier was
consumed, in which isolated world, and whether the supporting capture is still current.

### Controlled compiled runtime: fresh owned-state substitution

`ControlledRuntimeSequenceExecutor` is an explicit-import, single-use execution seam
for a deliberately narrow class of lineage-ready recipes. Before any target traffic or
budget reservation, it verifies the signed authorization envelope and workflow, exact
target origin, isolated persona world, bounty-safe policy, scope filter, ownership
registry, provenance sink, operation intents, structural action classification, and an
owned reversible cleanup contract. It supports only same-origin `POST` creation,
same-origin `GET` reads of the newly owned object, and `PATCH` or `PUT` cleanup whose
body is restricted to a small archival/deactivation vocabulary. `DELETE`, external
side effects, payments, messages, unknown writes, non-path ownership, and ambiguous
lineage fail closed.

After preflight, the proof budget atomically reserves the complete ordered sequence.
The runtime executes the create, extracts the fresh identifier from the exact response
locator proven by capture lineage, substitutes it only into the proven downstream path
slot, registers that concrete URL as researcher-owned, and then permits the read through
the existing `PolicyExecutor`. Cleanup is attempted for every successfully registered
create even when a later main step fails. Unused reservation entries are released, all
actual requests remain budgeted and provenance-recorded, and the result contains only
bounded counters, hashes, status, and fixed error codes rather than runtime identifiers
or response data.

This module is not imported by `core.behavior`, registered with Ghost, exposed through
an API, connected to the UI, or selected by a scheduler. Therefore this slice changes
the authority of direct internal callers that deliberately construct every required
contract, but it changes no production target traffic and grants no autonomous runtime
authority to Sentinel's existing workflows. It also does not infer cleanup, create
accounts, follow browser flows, handle query/body-only ownership, or claim that a safe
sequence proves a vulnerability.

The novel element is the transactional bridge from captured causal evidence to fresh,
owned runtime state: the same exact field-to-path lineage that justified the plan
controls substitution, ownership registration, budget reservation, and compensating
cleanup as one fail-closed unit. The compiler is no longer limited to replaying stale
captured identifiers, while the executor still cannot improvise an unsafe step.

### Durable compiled-sequence admission

`ControlledSequenceAdmission` places a default-off, durable admission boundary around
one fully constructed `ControlledRuntimeSequenceExecutor`. The environment gate
`SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION` must be explicitly true. Admission then
runs the runtime's complete traffic-free preflight and fingerprints the sequence,
recipe, plan, capture, catalog, isolated world, target, authorization envelope, actor,
and policy digest before reserving an owner-only receipt. Only the process holding the
unpersisted reservation token can execute and finalize that fingerprint.

Completed, aborted, cleanup-failed, concurrently reserved, and crash-stranded attempts
cannot silently receive another execution budget. A completed duplicate returns only
the cached redacted sequence summary. A failure before runtime completion advances the
receipt to an aborted terminal state; cancellation or a receipt-finalization failure
leaves the exclusive reservation in place, which also blocks replay. Persisted compiled
outcomes accept only the sequence hash, bounded step and policy counters, orphan-state
flag, provenance root, budget snapshot, and a bounded fixed error code. URLs, persona
IDs, envelope IDs, request and response material, captured identifiers, and fresh
runtime values are excluded by schema validation.

The admission module remains an explicit internal import. It is not exported from
`core.behavior`, registered with Ghost, selected by the primary scheduler, exposed by
an API, or connected to the UI. This slice therefore grants execution authority only
to a caller that deliberately enables the new gate and constructs the already-authorized
runtime object. Default production behavior sends no new target traffic. It still does
not choose a goal, compile arbitrary captures, infer intents or cleanup, launch browser
flows, or determine that the resulting behavior is a bounty-valid vulnerability.

In plain language, Sentinel now has a guarded internal start switch that works once for
one exact approved chain. For example, an internal coordinator can start the proven
create-note, read-that-new-note, archive-note chain; a second click, second process, or
restart receives the prior redacted result or a refusal instead of repeating requests.
The switch is not yet connected to ordinary scans or a user-facing one-click action, so
Sentinel cannot independently decide when to press it.

The one-of-a-kind property is that admission identity commits simultaneously to the
backward plan, exact capture lineage, isolated actor world, authorization envelope,
policy configuration, and executable sequence. The execution budget is therefore a
durable property of the evidence-backed experiment itself rather than a resettable
property of one process invocation.

### Execution-manifest compiler

`ExecutionManifestCompiler` removes the hand-written assembly between an exact
`BackwardPlan`/`RehydrationRecipe` pair and the controlled runtime/admission boundary.
Manifest v1 accepts only one observed `POST` operation explicitly classified as an
owned reversible create, one or more observed `GET` operations explicitly marked as
requiring owned state, and one observed `PATCH` or `PUT` cleanup operation outside the
main plan. Every owned read must have exactly one direct response-field-to-request-path
binding from that create. Sensitive, query/body-owned, read-only, multiple-create,
unknown-safety, unobserved, stale, forged, or ambiguous shapes are rejected.

Compilation verifies the backward plan identity, plan/recipe step equality, complete
catalog and capture digests, allowed analysis blockers, exact rehydration recipe
identity, cleanup metadata and capture uniqueness, authorization envelope, actor world,
target origin, bounty-safe policy, ownership registry, provenance sink, and runtime
structural classification. It deterministically derives only three intents:
`OWNED_CREATE`, `SAFE_READ`, and `OWNED_UPDATE_LOW_RISK`. The resulting manifest commits
to redacted target, authorization, and actor references, the policy digest, sequence,
plan, recipe, capture, catalog, terminal operation, and ordered roles. It remains
`executable: false`; execution still requires the separate default-off durable admission
gate.

This compiler performs no target I/O, reserves no budget, writes no receipt, and is not
exported from `core.behavior`, selected by a scheduler, exposed through an API, or wired
to the UI. Consequently this slice changes neither target traffic nor execution
authority. It also does not infer operation safety, invent cleanup, select a goal,
support arbitrary state machines, or decide whether an observed result is a valid
security finding.

In plain language, Sentinel can now package a proven create-note, read-that-new-note,
archive-note chain for its guarded start switch without a developer manually labeling
each runtime step. If the evidence only shows a read, the cleanup is uncertain, or the
identifier travels somewhere other than the proven URL path, Sentinel refuses to build
the package. It prepares the exact approved chain but still does not start it.

The novel property is the deterministic proof-carrying handoff: semantic backward plan,
exact captured value lineage, explicit safety metadata, runtime intent, authorization,
policy, and durable admission all become one content-addressed manifest without raw
target values. This closes the manual translation gap where a correct analysis could
otherwise be assembled into a materially different execution.

### Evidence-backed owned lifecycle mining

`LifecycleContractMiner` removes the remaining manual safety/ownership enrichment for
the manifest-v1 lifecycle. It first builds the conservative observed catalog and exact
lineage ledger from captured exchanges. A candidate exists only when one successful
same-world `POST` response produces a non-sensitive identifier that appears exactly in
the path of a successful `GET` and in the path of one subsequent successful `PATCH` or
`PUT`. The cleanup body must pass the same shared archival/deactivation predicate used
again by the active runtime. The create body must also be structured and free of
privilege, financial, messaging, tenant, recipient, or external-destination fields.
The structural action classifier must independently confirm both writes as
`OWNED_CREATE` and `OWNED_UPDATE_LOW_RISK`.

The miner rejects repeated or ambiguous producer locations, multiple cleanup bindings,
duplicate operation observations, role conflicts, cleanup operations that vary for the
same create contract, cross-world values, query/body-only ownership, sensitive
capabilities, consequential create paths, and unsafe cleanup bodies. Only accepted
operations are copied into a new enriched catalog: the create receives
`owned_reversible_write` plus its exact cleanup operation, reads receive
`requires_owned_state`, and cleanup receives both. Every other operation retains its
original conservative posture. The unchanged captures are then reprocessed against
that exact enriched catalog so lineage and catalog identities remain coherent.

Mining performs no network I/O, policy evaluation, budget reservation, receipt write,
authorization decision, or execution. It is not exported from `core.behavior`, wired to
Ghost, scheduled, exposed through an API, or connected to the UI. This slice therefore
changes neither target traffic nor execution authority. It also does not select which
owned read is security-relevant, infer destructive rollback, support query/body-owned
objects, or claim a vulnerability from a valid lifecycle.

In plain language, Sentinel can now learn from a capture that “this request created our
test note, this request read that exact note, and this request safely archived it.” That
learned lifecycle can pass directly into the backward planner and manifest compiler
without a developer manually labeling the operations. If two cleanup actions look
possible, the identifier crosses personas, or cleanup changes arbitrary content,
Sentinel leaves the operations untrusted and builds nothing. It still prepares rather
than starts the experiment.

The one-of-a-kind property is evidence-derived execution typing: an operation becomes
an owned reversible create or cleanup only because an exact captured value proves the
entire same-world lifecycle and the active runtime shares the identical cleanup safety
predicate. Safety metadata is no longer a hand-authored bridge between observation and
execution, yet it remains deterministic and independently rechecked.

### Owned-experiment factory

`OwnedExperimentFactory` closes the passive assembly gap from captured exchanges to a
bounded inventory of controlled runtime bundles. It mines owned lifecycle candidates,
creates one deterministic `BackwardGoal` per directly bound owned `GET`, compiles each
goal through `BackwardExploitCompiler`, builds its exact-world `RehydrationRecipe`, and
passes the result through `ExecutionManifestCompiler`. The factory rejects other actor
worlds, blocked plans, incomplete recipes, and unsupported manifests; deduplicates by
content-addressed manifest identity; and caps compilation before work begins. A global
authorization, target, policy, provenance, ownership-registry, or runtime-preflight
failure rejects the factory call rather than being hidden as an ordinary candidate
failure.

Every prepared experiment retains the existing authorization-bound runtime and durable
admission object, but the factory supplies `ControlledAdmissionConfig(enabled=False)`
explicitly. Environment configuration therefore cannot silently make factory output
executable. Inventory serialization contains only hashes, contract identifiers,
derived roles, and bounded counters. The factory performs no transport call, reserves
no proof budget, writes no receipt, chooses no candidate for execution, and is not
exported from `core.behavior`, scheduled, exposed through an API, or connected to the
UI. This slice changes neither target traffic nor execution authority. It also does not
decide whether an owned read is security-relevant, discover unobserved endpoints,
generalize beyond direct path-bound identifiers, or claim a vulnerability or payout.

In plain language, if Sentinel has already seen one safe test object being created,
read in two different ways, and safely archived, it can now automatically prepare two
separate guarded experiments—one for each read—without a developer wiring either chain
by hand. It throws away a package if the object belongs to another persona or any proof
step does not line up, and it never presses the start switch. Sentinel still cannot use
this factory to invent missing requests, decide that a result is a bounty-worthy bug,
or execute anything automatically.

The novel property is exhaustive proof-preserving experiment assembly: every admissible
owned read in a capture set becomes a deduplicated, content-addressed package whose
lineage, cleanup, authorization, policy, actor world, and runtime structure have already
survived the same gates used at execution. This removes per-experiment manual driving
without weakening the boundary between passive understanding and controlled action.

### Capability-linked latent affordance mining

`LatentAffordanceMiner` joins two previously disconnected evidence surfaces: semantic
capabilities produced by successful captured JSON responses and parameterized operations
published in already-acquired JavaScript, source maps, or OpenAPI documents. A candidate
exists only when one unambiguous producer in an isolated world emits a canonical
capability such as `job_id` or `download_token`, one same-origin artifact route contains
exactly one compatible path or query parameter, and the method/route shape has not
already been observed. Named parameters require exact semantic agreement. Generic
parameters such as `{id}` additionally require their resource parent to agree with the
produced capability.

The miner rejects cross-origin URLs, credential-bearing URLs, path traversal, partial or
multi-parameter templates, ambiguous producers, ambiguous same-world matches, observed
operations, malformed source maps, unsupported artifact types, and every artifact or
candidate beyond explicit byte/count bounds. Candidate identity is structural and
stable as additional evidence arrives; a separate evidence digest seals exact capture
locators, value hashes, and artifact hashes. Public results retain route templates and
semantic capability names but never raw identifiers, tokens, artifact contents, source
URLs, target origins, or persona names. Sensitive token/key handoffs are marked and
remain confirmation-only.

This module consumes only caller-supplied captures and artifact text. It imports no
transport, performs no target I/O, reserves no proof budget, and grants no execution
authority. It is explicit-only, with no scheduler, API, UI, or runtime wiring. A latent
affordance proves that the target published a plausible producer-to-consumer handoff; it
does not prove that the route exists at runtime, that the current actor may access it,
or that the resulting behavior is vulnerable. Version 1 deliberately excludes
concatenated/computed routes, more than one unresolved parameter, non-JSON producers,
and arbitrary route guessing.

In plain language, if exporting Alice's controlled document returned a `jobId` and an
already-downloaded client file contains an unused request for
`/api/export-jobs/${jobId}`, Sentinel now connects those clues and records a possible
hidden elevator. If that route was already visited, belongs to another site, needs two
unknown keys, or two captured actions could have produced the value, Sentinel records
nothing. It has found evidence of a door in the building plans, but it still does not
touch the door.

The one-of-a-kind property is capability-directed hidden-surface discovery rather than
route keyword scoring: target-produced values become typed keys, artifact operations
become typed locks, and only structurally compatible, previously unseen pairs enter the
security frontier. Additional artifacts strengthen the same stable affordance instead
of manufacturing duplicate leads. This is the first passive input required by the
future security-obligation graph and fixed-point stopping contract.

### Security-obligation graph

`SecurityObligationGraphBuilder` converts the passive behavioral evidence surfaces into
one deterministic dependency graph of security questions. Each proven lifecycle read
produces an `upheld` owned-control node and an `open` ownership-boundary obligation that
depends on that control. Each Alice/Bob authorization proposal becomes an open
counterexample obligation. Each latent affordance becomes an open operation-confirmation
obligation plus an open capability-confinement obligation that cannot be resolved before
the operation itself is confirmed.

Obligation identity commits to target, property, subject, dependencies, risk class, and
whether resolution eventually requires execution. Exact lifecycle, proposal, artifact,
capture-locator, and affordance evidence is sealed separately, so stronger corroboration
does not manufacture a new security question. The graph rejects missing dependencies,
cycles, target mismatches, forged identities, duplicate evidence, and malformed status
or risk contracts. Explicit obligation, dependency, and evidence limits fail closed and
are included in the graph digest; dropped work can therefore never be mistaken for full
coverage.

The builder is pure analysis. It imports no transport, sends no target request, reserves
no proof budget, grants no execution authority, and is not exported from
`core.behavior`, scheduled, exposed through an API, or wired to the UI. An `open` node
is a durable question, not a finding. An `upheld` owned-control node proves only that a
known-good lifecycle was observed; it does not imply that the related ownership boundary
is secure.

In plain language, Sentinel now keeps a living map where every known door has its own
unanswered security question. A normal Alice-owned document proves that Alice's key
works, but it simultaneously creates the unresolved question “can another key open this
door?” A possible hidden elevator creates “does this elevator exist?” first and “does it
keep Alice's key confined?” second. Sentinel cannot silently skip the second question or
pretend an empty map means a safe building. This pass changes neither target traffic nor
execution authority.

The novel property is evidence-derived search accounting: controls, adversarial persona
swaps, and hidden capability handoffs become one dependency-aware frontier instead of
three disconnected feature outputs. The target's own behavior continuously defines the
questions Sentinel must answer, while graph identity makes forgotten or dropped work
detectable.

### Evidence-referenced fixed-point closure

`SecurityClosureEvaluator` applies content-addressed `ObligationDisposition` records to
one security-obligation graph. Every terminal disposition requires redacted,
content-addressed evidence references; an obligation cannot be silently deleted or
assigned two answers. `upheld`, `violated`, and `subsumed` decisions require every
prerequisite to be upheld or validly subsumed. Subsumption must point to a semantically
equivalent question whose coverage chain ends at an upheld obligation, and cycles are
rejected. Disposition count is bounded by graph size and each disposition accepts at
most 64 evidence references. `blocked` and `unreachable` remain explicit non-resolution
states.

The resulting `SecurityClosureCertificate` uses a strict outcome order. Any violated
obligation yields `finding`. Empty or truncated graphs and explicit blocked or
unreachable obligations yield `blocked`. Unanswered obligations yield `open`. A fully
resolved graph remains `open` until the caller supplies a prior derivation graph with an
identical digest at round two or later; only then is it `conditionally_closed`. The
certificate commits to the current and previous graph digests, every disposition,
status counts, unresolved, blocked, and finding identities, and the reason closure was
withheld.

This is evidence-frontier closure, not proof that a target has no vulnerabilities. It
means only that all questions derivable from the current bounded evidence were resolved
and that the supplied prior graph contains no different questions. New captures,
artifacts, relations, or derivation rules invalidate that frontier and require another
closure cycle. The evaluator performs no discovery, target request, proof-budget
reservation, or execution. It is explicit-only and not exported, scheduled, routed, or
connected to the UI. It validates evidence-reference structure and accounting, not the
authenticity or semantic sufficiency of a future proof oracle's evidence, and it cannot
prove that a caller actually scheduled two independent derivation runs. This pass
changes neither target traffic nor execution authority.

In plain language, Sentinel now needs a recorded answer linked to supporting receipts
for every room on its current map. “We could not enter” stays visibly blocked, “the lock
failed” becomes a finding, and “the lock held” closes only that question. Even after
every question has an answer, Sentinel compares the map with a second supplied map; if
a new room appears, the search continues. If the maps are unchanged, Sentinel may close
this version of the map—but it never claims the whole building has no hidden rooms.

The novel property is a proof-accounting stopping contract rather than a timer or
checklist exhaustion. Sentinel closes a bounded search frontier only when its
target-derived obligation graph is fully accounted for and structurally stable, while
every inability to continue remains a machine-verifiable blocker instead of being
laundered into “no finding.”

### Closed-loop behavioral shadow orchestration

`BehavioralShadowOrchestrator` composes the previously separate passive contracts into
one content-addressed control-plane result. One bounded invocation mines the actor's
owned lifecycles, compiles paired-world authorization proposals when a peer capture is
present, mines capability-linked latent affordances from caller-supplied artifacts,
attempts default-off owned-experiment assembly when authorization and policy context is
available, derives the security-obligation graph, evaluates closure, and ranks every
remaining open obligation. The run identity commits to every component digest, the
experiment-stage outcome, closure certificate, ranked frontier, and an explicit count
of open obligations omitted by the ranking bound. Truncating presentation therefore
cannot be mistaken for resolving or deleting search work.

Ranking distinguishes an unanswered question from a question that has a proven safe
resolution seam. An ownership boundary is actionable only when the factory produced a
matching proof-carrying owned experiment. An authorization counterexample is actionable
only when it is classified as a read and its captured REST or GraphQL read semantics are
independently proven. State mutations, unresolved persisted operations,
latent-operation confirmation, unresolved capability confinement, missing
prerequisites, denied factory preflight, and questions with no matching resolver remain
visible but unavailable. Prepared does not mean executable: the run and every component
remain `executable: false`, and all factory admissions are constructed disabled.

The existing Foundry behavioral endpoint now returns this artifact under
`behavioral_shadow` before its optional controlled proof run. It reuses the already
bounded capture records and any client artifact bodies the existing GraphQL resolver
already fetched. Its compiler-only policy executor has a transport function that always
refuses; orchestration cannot create an additional target request, reserve proof budget,
write an execution receipt, or promote its selected obligation into runtime. A shadow
failure is reported explicitly without breaking the established controlled proof path.
This pass therefore changes neither target traffic nor execution authority.

In plain language, Sentinel's maps, unanswered lock questions, and prepared locksmith
jobs now reach one foreman. The foreman puts jobs with a real safe tool at the front and
keeps “we saw a possible hidden elevator but do not yet have a safe way to test it” on
the board instead of pretending it can be run. For example, a proven create/read/archive
note lifecycle can become the selected prepared experiment, while a published export
job route remains an unanswered lead until a controlled confirmation method exists.
Sentinel still does not press the start switch in this pass.

The one-of-a-kind property is obligation-first resolver binding. Sentinel does not rank
a canned test list and then look for justification; target-derived security questions
are the durable control plane, and an existing proof-carrying resolver must bind back to
the exact question before it can be selected as actionable. This makes missing
capabilities, denied authority, and unexplored hidden surfaces first-class search state
instead of silent coverage gaps.

Current limitations are explicit. The coordinator is wired to the Foundry behavioral
route, not yet the general scan runner. Latent affordance mining receives artifact text
only when that text was already acquired; it adds no fetch of its own. Version 1 can
prepare owned experiments only for the existing exact path-bound create/read/cleanup
contract, and it can resolve paired-world authorization proposals only through the
established read-only proof path. Closure remains accounting over the supplied bounded
frontier, not a claim that the target contains no other vulnerabilities.

### Receipt-to-disposition feedback

`ReceiptDispositionAdapter` converts a terminal, strictly redacted behavioral execution
receipt into an evidence-referenced disposition only when the receipt context matches the
current target, authorization envelope, and ordered persona pair, and its selected
proposal binds to exactly one open read-only authorization obligation. The adapter
round-trips every supplied receipt through the persisted receipt validator before using
it. Duplicate receipts, conflicting receipts for one obligation, non-terminal receipts,
context mismatches, unrecognized verdicts, and proposals without an exact open graph
binding fail closed.

The established three-leg BOLA oracle remains authoritative. `BOLA_CONFIRMED` violates
the exact obligation; a completed `DENIED` or `NO_CROSS_READ` result upholds only that
tested boundary; `AMBIGUOUS`, `ERROR`, and aborted executions become blocked. A terminal
receipt with no selected proposal cannot close anything. Compiled create/read/cleanup
receipts are explicitly unsupported as authorization evidence: successfully
manufacturing and cleaning up owned state does not prove that another principal was
unable to access it.

After the Foundry route durably finalizes an execution receipt, it passively adapts the
receipt, reruns the same shadow derivation against the previous graph, and returns the
updated closure plus the content-addressed feedback batch. The second derivation has no
transport and cannot reserve budget. If feedback accounting fails, the original proof
receipt and pre-execution frontier remain intact and the response exposes an explicit
feedback error instead of losing or reinterpreting the completed execution.

In plain language, Sentinel now attaches the test receipt to the exact lock question that
caused the test. If Bob opened Alice's document and the independent oracle found Alice's
private marker, that question becomes a finding. If the completed experiment proved Bob
was denied, only that exact question is closed. If the evidence was ambiguous, Sentinel
marks the question blocked. A receipt saying “we successfully created and cleaned up our
own test document” is never misrepresented as proof that Bob could not read it.

This pass changes neither target traffic nor execution authority. It observes the result
of the already authorized, already bounded proof and updates the passive accounting
frontier afterward. It does not select or execute another obligation.

The one-of-a-kind property is receipt-bound epistemic feedback: runtime success is not
allowed to become a security conclusion merely because an experiment completed. A
content-addressed target-and-persona-scoped receipt must bind to the exact target-derived
question, and only the independent oracle's terminal semantics determine whether that
question was upheld, violated, or blocked. Execution bookkeeping and security proof are
therefore mechanically separated while still forming a deterministic closed evidence
loop.

Current limitations remain deliberate. The adapter recognizes the established captured-
object authorization receipt and the fresh-owned boundary receipt described below.
Aborted receipt-store records that lack an exact graph binding remain unbound. Standalone
compiled owned-experiment receipts remain preparatory because setup completion alone does
not establish an authorization verdict. The route updates one completed receipt into one
derivation round; the feedback adapter itself does not select or execute another
obligation.

### Single-step closed-loop obligation resolver

`SingleStepObligationResolver` makes the unified `BehavioralShadowRun` frontier the
authority for final active selection. It walks the deterministic ranked frontier,
requires an exact content-addressed binding from one open obligation to one proposal in
the same shadow run, and dispatches at most the highest-ranked binding for which an
existing resolver can produce a terminal security verdict. The selected proposal is
still recompiled and validated against the current captures inside
`ControlledAuthorizationExecutor`; every target request still crosses the existing
signed-envelope, origin, persona, bounty-safe policy, shared budget, provenance, and
durable route-receipt gates. The established three-leg BOLA oracle remains the only
component allowed to declare the authorization result.

Proof-carrying owned create/read/cleanup packages are outcome-bearing only when the
fresh-owned boundary coordinator described below can bind the same package to a
symmetric peer lifecycle and the established BOLA oracle. Otherwise the resolver still
defers them: a compiled setup receipt alone proves no cross-principal property. If a
lower-ranked authorization obligation has a real verdict oracle, it may be selected and
the number of higher-ranked preparatory items deferred remains explicit in diagnostics.
Missing or ambiguous bindings fail closed. When active mode is enabled, failure to build
the authoritative obligation frontier aborts the durable receipt and refuses all proof
traffic instead of silently falling back to the older proposal scheduler.

The Foundry route now uses `BehavioralPrimaryScheduler` only as the bounded eligibility
predicate for pre-frontier read exploration. It no longer calls that scheduler's active
execution method. After the frontier is built, exactly one obligation-selected proposal
may enter the existing controlled executor; its terminal receipt is then adapted into a
disposition and the frontier is derived again as before. Resolver plans retain
`selected_proposal_id` for the current receipt and Swift contracts while adding the
selected obligation, shadow-run identity, frontier index, and content-addressed plan
identity. Focused tests verify deterministic redaction, exact binding, deferral of
preparatory-only work, disabled-mode zero traffic, no-candidate zero traffic, route-level
selection, and refusal when the frontier is unavailable.

In plain language, Sentinel's foreman—not a separate checklist—now chooses the next test
that can actually answer a security question. Suppose the board's first job says “we can
safely create and archive our own note,” while the second says “test whether Bob can read
Alice's document.” The first job is useful preparation but cannot answer whether the lock
fails, so Sentinel records that it deferred the setup job and runs the second job once
through the proven lock-testing machine. It then files the receipt against that exact
question and redraws the board. Sentinel still cannot turn a successful setup sequence
into a finding, automatically resolve hidden-route questions, or execute repeatedly
until the whole frontier closes.

This slice changes target traffic and execution authority only inside the already
explicitly enabled `SENTINELFORGE_BEHAVIOR_PRIMARY` path. It does not increase request
budgets, action classes, origins, personas, workflows, or retry authority. Default-off
behavior still sends no resolver traffic. When enabled, the same maximum of one existing
three-leg authorization experiment may run, but the obligation frontier now chooses
that experiment and a missing frontier prevents it entirely.

The one-of-a-kind property is outcome-aware obligation dispatch. Sentinel does not
equate an executable procedure with evidence that answers the security question that
caused it. The control plane can rank preparation, proof, and blocked work together,
while the active seam admits only an exact question-to-oracle binding and preserves the
rest as explicit unresolved state. That mechanically prevents scheduler drift and the
common autonomous-testing failure where “the tool ran successfully” becomes “the
security property was proven.”

### Atomic fresh-owned authorization boundary

`FreshOwnedBoundaryExecutor` turns one exact, symmetric owned lifecycle into terminal
authorization evidence. It accepts only source and peer inventories whose captured
operation roles, endpoint templates, authorization envelope, policy instance, ownership
registry, provenance sink, and runtime contracts agree. Both runtime sequences are
atomically claimed before traffic. The coordinator then reserves one immutable seven-
action package: source create, peer create, source-owned baseline read, peer-owned
baseline read, peer-to-source cross-object read, peer cleanup, and source cleanup.
Server-issued identifiers are extracted through the previously proven response lineage,
registered as observed researcher-owned state, and substituted only into the previously
captured path locators. The existing three-leg BOLA classifier remains the verdict
oracle; the coordinator does not reinterpret an HTTP 200 as a finding.

Every request crosses the shared `ExecutionPolicy` under an exact bounty-safe budget of
seven total requests, five per endpoint template, one cross-object read, zero privilege
mutations, and two creates. DELETE and real-user-data access remain forbidden. Both
`behavioral_object_authorization` and `behavioral_compiled_owned_sequence` must be
present in the signed envelope, and both `SENTINELFORGE_BEHAVIOR_PRIMARY` and
`SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION` must be explicitly enabled. Cleanup runs in
the package's `finally` path. A failed cleanup is persisted as `cleanup_failed` with
possible orphaned state; it cannot be hidden by a confirmed vulnerability. The durable
receipt retains only content-addressed boundary, experiment, lifecycle, obligation, and
provenance references plus bounded counters. Receipt feedback can therefore close only
the exact open ownership obligation selected by the frontier.

In plain language, Sentinel can now manufacture Alice's and Bob's disposable test notes,
verify that each person's own note is readable, ask Bob for Alice's fresh note exactly
once, and archive both notes afterward. If Bob receives Alice's private marker, the old
lock-testing machine—not the planner—confirms the bug and Sentinel files that proof
against the exact question it set out to answer. If the target does not expose a captured,
safe create/read/archive pattern for both accounts, Sentinel does not improvise one and
the item remains unresolved.

This slice changes target traffic and execution authority conditionally. With either
feature flag off, either workflow missing, a non-symmetric peer capture, a changed policy
contract, or an unavailable exact budget, it adds zero target traffic and grants no new
authority. With every gate satisfied and the owned experiment ranked first, it replaces
the previously deferred setup with exactly seven pre-reserved requests. It does not add
crawling, retries, destructive cleanup, arbitrary writes, real-user-object access, or a
second frontier dispatch.

The one-of-a-kind property is proof-carrying ephemeral ownership composition. The same
observed create response that supplies the runtime identifier also becomes the policy's
ownership evidence, the input to two independent baselines, the constrained cross-
principal counterfactual, the cleanup target, the redacted durable receipt, and the graph
disposition. There is no gap where a model can invent an identifier, assert ownership,
skip the control, broaden the endpoint, or call successful setup a vulnerability. This
is a closed, deterministic conversion from captured safe behavior to fresh-state bounty
evidence while preserving the independent security oracle.

Current limitations are intentional. Version 1 supports only an exact two-step
create/read main sequence plus one reversible low-risk update cleanup whose identifier
has direct path lineage. Both personas must expose the same lifecycle shape. The package
does not discover a missing peer lifecycle, infer novel cleanup, exercise mutations as
the vulnerability, retry uncertain responses, or continue to another obligation after
its terminal verdict unless the separately authorized bounded continuation controller
below admits one final round.

### Receipt-gated bounded continuation

`BoundedContinuationController` allows the Foundry route to dispatch at most two total
proof rounds from one captured evidence frontier. It remains transport-free: the
existing `SingleStepObligationResolver`, controlled authorization executor, fresh-owned
boundary executor, execution policies, and BOLA oracle retain their responsibilities.
Before every active round, the route reserves a separate durable fingerprint over the
root request, round index, shadow run, resolver plan, exact obligation, and exact
resolution reference. The terminal round receipt is converted into a disposition and
the shadow graph is derived again with all prior dispositions before another plan can be
considered.

Continuation requires strict monotonic progress. The selected obligation must disappear
from the next unresolved set, the remaining unresolved set must be a strict subset of
the previous set, the graph identity must remain stable, and neither the obligation nor
its resolution reference may repeat. Sentinel stops immediately on a confirmed finding,
cleanup uncertainty, an aborted proof, a blocked or conditionally closed frontier,
missing progress, missing executable work, the second terminal round, or the fixed
fourteen-request proof allowance. A confirmed finding with failed cleanup is reported
as `cleanup_uncertain`, preserving the vulnerability while prioritizing the operational
safety incident. The root receipt stores a strictly redacted, content-addressed transcript
of both independently durable round receipts.

The authority is separately default-off. `SENTINELFORGE_BEHAVIOR_CONTINUATION=1` has no
effect unless primary behavioral execution is also enabled and the signed envelope
explicitly permits `behavioral_bounded_continuation`. The one-click URL route validates
that workflow before opening or navigating either persona window. When enabled, the
captured-object policy permits at most two cross-object reads instead of one so two
distinct three-leg authorization proofs can complete; its existing per-endpoint limit
still prevents repeating the same endpoint template. A fresh-owned round retains its
exact seven-request policy and cannot run twice in the same continuation session.

In plain language, Sentinel may now test a second different lock when the first lock held
and the evidence board proves that a different unanswered lock is next. The first test
gets filed before the second begins. If the first test finds a real break-in, leaves test
state behind, produces uncertain evidence, or fails to remove an item from the board,
Sentinel stops. Even in the cleanest case it gets only two tests—not an open-ended loop.

This slice changes target traffic and execution authority only behind the new flag and
workflow. Disabled behavior is unchanged. Enabled behavior can add one terminal proof
round, raising the session ceiling from one round to two and the captured-object
cross-read ceiling from one to two. It adds no new action classes, origins, personas,
destructive operations, real-user-data access, retries, crawling, or autonomous time-
based persistence. Asset resolution and bounded read exploration remain governed by
their existing independent limits and are not repeated between continuation rounds.

The one-of-a-kind property is receipt-gated monotonic exploitation. Sentinel does not
continue because a model says another idea looks promising, because time remains, or
because a checklist has more entries. The cryptographically identified receipt from the
previous real experiment must alter the exact unresolved security frontier in the
expected direction before another resolver can receive authority. Reasoning progress,
execution identity, traffic budget, and durable evidence therefore form one mechanical
admission condition.

Current limitations are explicit. Version 1 allows one continuation only, uses the same
captured records and client artifacts for both rounds, and does not generate new targets
or hypotheses between them. Two fresh-owned rounds are not supported because each fresh
boundary executor is single-use. A second captured-object proof may still be refused by
the existing shared endpoint or request budget. The controller does not claim global
absence when its bounded frontier remains open.

### Gate D: generalized security relations

Add one independently tested relation at a time: integrity, authority monotonicity,
freshness, parser agreement, interpreter confinement, and state-machine legality.
No relation may surface a finding without an independent proof oracle and minimized
replay.

#### State-machine prerequisite legality

`StateMachineLegalityMiner` is the first generalized relation connected to the unified
shadow frontier. It reuses the existing operation catalog, bounded
`BackwardExploitCompiler`, `ValueLineageLedger`, and `PlanRehydrator`. High-value
terminal operations are selected from redacted REST templates and GraphQL operation
names. The compiler may propose a prerequisite chain, but that semantic plan is not
enough for admission. Every operation must have exactly one successful observation in
one captured world, those observations must occur in plan order, and every required
capability must have one exact producer-to-consumer value-lineage binding. Repeated
steps, cross-world chains, different concrete values with the same field name,
ambiguous producers, missing lineage, and out-of-order observations are rejected.

Accepted relations produce two content-addressed graph nodes. An upheld
`state_machine_control` records the exact observed good path. An open
`state_machine_legality` obligation depends on that control and asks whether the
terminal operation actually enforces the prerequisite path. The legality node is
ranked, but it has no resolution reference and is therefore non-actionable. It cannot
be selected by the active resolver, receive target traffic, or become a finding merely
because the terminal operation looks valuable. A later slice must supply an
independent, minimized proof oracle before the obligation can be resolved.

The miner is bounded to 4,096 records, 64 high-value goals, 64 candidates, 1,024 search
states per goal, 16 plan steps, and 32 exact lineage bindings per candidate. Invalid
records, dropped goals, dropped candidates, catalog-limit failures, and relation-limit
failures enter explicit relation-incompleteness accounting so fixed-point closure cannot
silently claim complete coverage. Public artifacts retain only hashes, semantic risk, redacted source
references, exact lineage-binding references, and content-addressed plan/recipe
identities. Target origins, persona names, identifiers, tokens, request bodies, and
response bodies are excluded.

In plain language, Sentinel can now observe the legitimate route to a valuable result
and turn it into a new security question. If the evidence shows “create recovery
request, complete identity check, download recovery package,” Sentinel records both
that exact working hallway and the unanswered question “does the download door refuse
people who skipped the identity-check hallway?” Merely seeing three similarly named
doors is insufficient: the same exact redacted key must be proven moving from one step
to the next. Sentinel does not test the shortcut yet and does not call it a
vulnerability.

This slice changes neither target traffic nor execution authority. It consumes only
already-captured records, imports no transport, reserves no proof budget, writes no
receipt, and creates no resolver mapping. Existing active executors and continuation
limits are unchanged. It also does not infer business intent, prove that a prerequisite
is mandatory, manufacture unobserved setup steps, support ambiguous or repeated
captures, or establish a payout-valid bypass.

The one-of-a-kind property is proof-derived backward security accounting. A valuable
terminal effect is connected to its observed prerequisite state machine only when
compiler dependencies, chronological observations, exact same-world value lineage, and
rehydration identity all agree. That proof-carrying relation then becomes a durable
unanswered security obligation instead of remaining an interesting standalone plan or
a scanner keyword match.

## Current baseline debt

The broad repository suite is not a clean release gate yet. On the initial Phase 1
baseline, 1,511 tests passed, 17 skipped, and 21 pre-existing tests failed; the
Python 3.14 environment also hit process/fork segmentation faults. Focused Ghost,
BOLA, policy, provenance, and behavioral-kernel tests are the Phase 1 compatibility
gate while the unrelated baseline failures are audited separately.
