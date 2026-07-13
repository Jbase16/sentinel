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

### Primary-planner activation bridge

The behavioral engine can now own proposal selection through
`BehavioralPrimaryScheduler`. Ranking is deterministic and based on proof feasibility:
proven read semantics, usable paired baselines, cross-world response differentiation,
and direct resource locators. The scheduler executes only the highest-ranked proposal
and never invokes the legacy multi-operation hunt, so primary-planner activation
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

### Gate D: generalized security relations

Add one independently tested relation at a time: integrity, authority monotonicity,
freshness, parser agreement, interpreter confinement, and state-machine legality.
No relation may surface a finding without an independent proof oracle and minimized
replay.

## Current baseline debt

The broad repository suite is not a clean release gate yet. On the initial Phase 1
baseline, 1,511 tests passed, 17 skipped, and 21 pre-existing tests failed; the
Python 3.14 environment also hit process/fork segmentation faults. Focused Ghost,
BOLA, policy, provenance, and behavioral-kernel tests are the Phase 1 compatibility
gate while the unrelated baseline failures are audited separately.
