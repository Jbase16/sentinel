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
