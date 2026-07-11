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
- Executes exactly three ordered legs. Both self baselines must succeed before the
  single counterfactual read is attempted. Each leg crosses `PolicyExecutor`.
- Delegates the semantic verdict to `core.wraith.bola_replay`; Gate C does not
  introduce a second finding oracle or promote findings independently.
- A controlled executor is single-use, preventing retries or replay amplification.

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
