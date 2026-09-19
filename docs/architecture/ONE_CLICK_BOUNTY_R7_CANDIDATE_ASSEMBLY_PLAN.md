# OCB-R7 Submission-Grade Candidate Assembly

Status: suite-proved local implementation; push blocked by execution approval policy.
Mediator verification and Jason's separate merge go remain pending.

Base: `493f76f681cbdf3598e09cbe20448bcb46b080c9`.
Branch: `ocb/r7-candidate-assembly`.
Canonical stage: `OCB-R7`. Exit gate: `OCB-S19`.
Contract: revised work order, Rev 2, family-shaped reproduction.

## 1. Bounded outcome and authority

The existing [SubmissionCandidate owner](../../core/reporting/submission_candidate.py)
assembles immutable, content-addressed draft artifacts from one current canonical
finding and exactly one `(receipt_id, provenance_root)` lineage. Multiple cited
observations may belong to that lineage. A finding with multiple independent
receipt roots is refused; the assembler never chooses one arbitrarily or merges
roots. Different sole lineages have different content addresses.

Both shapes are production-wired through the existing Verify candidate/promote,
Cortex report, AI report/section, and scans bounty-report paths. The shared builder
owns shape selection, claims, impact, content addressing, and refusal. No caller flag,
model output, report context, or display label can select a proof shape or add a claim.
No new rendering flag is needed. There is no transport, submission authority,
identity, origin, action class, budget, proof mode, or durable raw capture.

The family producers, receipt schema, canonical admission/persistence, independent
oracles, acceptance targets, and `core/submission/h1_client.py` are unchanged. The Lab
is uninvolved. This is a local deterministic assembly/refusal gate, with no native or
external gate and no renewal of previous native evidence.

## 2. Two reproduction shapes and a necessary source boundary

**Shape R — `replayable_recipe`.** A current canonical finding must actually cite
captured proof observations with retained request commitments. The existing Ghost
producer supplies normalized CAS evidence (including request/response body hashes),
source identity, exact URL identity, and credential identity. The existing persisted
Ghost flow supplies raw request records transiently; assembly never creates one.
Each selected record is checked against that existing normalized CAS observation,
exact URL/persona/source, method/status, and complete capture state before sanitizing.
A copied response paired with a different request body cannot qualify.
Duplicate JSON object keys and repeated form parameter names refuse because the
retained parsed commitment cannot distinguish their raw interpretation. The original
capture position must match the canonical Ghost credential epoch; changed ordering
refuses before dependency analysis.

The builder reprojects the retained capture on every render, including restart. The
owned draft is not a second source of proof. Missing, changed, truncated, ambiguous,
foreign, or response-only sources refuse. Requests are rendered as sanitized request
templates with credential and uncommitted header values supplied by the reviewer.
`replayable` describes the artifact shape; it grants no permission to execute it.

**Shape A — `evidence_attestation`.** An eligible Family-D LOCAL evidence-admission
uses its existing `CapabilityEffectEvidence`, source receipt, and evidence root.
Assembly verifies the existing eligibility predicate, canonical claim material,
identity/session, and CAS content address. The artifact retains all five phase
observations, the oracle summary, and verified cleanup, with no invented HTTP step,
endpoint, or request. Every surface marks it non-replayable and returns an empty
`steps_to_reproduce` list. Its claim remains repeated exposure of the same
protected-effect representation, not independent proof of two backend mutations.

This slice does **not** wire Ghost observations into automatic A-C finding promotion.
Current response-only Verify observations and synthetic completed-proof summaries do
not establish the original request body and are not relabeled as Shape R. They
refuse unless the canonical finding actually has supported captured proof. The
existing canonical admission API can admit receipt-backed captured observations;
OCB-S19 exercises that API with real isolated receipt and capture stores. Automatic
upstream acquisition/promotion/orchestration remains outside this assembly slice.

## 3. Minimization, lineage binding, and deduplication

The existing [value-lineage machinery](../../core/behavior/lineage.py) checks the
selected captures' exact recorded producer/consumer closure. A known prerequisite
outside the selected proof is refused rather than silently omitted. Ambiguous
lineage is refused. Every cited proof observation survives. Only duplicate selection
of the identical capture for the identical proof observation is removable; distinct
requests, observations, and proof roots are never silently collapsed.

Candidate dependency commitments bind the retained producer and consumer capture
commitments, capability, and exact locators. They do not inherit the full transcript
salt, so unrelated capture noise cannot change the minimized candidate's address.
Shape A retains all five observations and cleanup because the existing eligibility
predicate and claim depend on them; unrelated producer/runtime detail is omitted
while remaining committed through the evidence root.

`candidate_receipt_lineage` binds the canonical session, strict completed receipt,
active-proof citations, and canonical observation commitments. The candidate also
binds the canonical finding commitment, minimized reproduction/attestation, sanitized
claims, and impact metadata. Its canonical revision is the minimal finding/lineage
revision, not the session-wide revision: an unrelated session event does not change
this candidate. No timestamp is generated during assembly.

Repeated calls on any of the four surfaces and fresh store/ledger instances produce
the same candidate digest. The Workbench has one deterministic draft
path per finding commitment. Immutable candidate fields use tuples and serialized
JSON strings; returned dictionaries are fresh projections.

## 4. Claim-specific eligibility and invalidation

Every live render route loads the current canonical session read model. Existing
ledger lifecycle filtering removes invalidated/suppressed observations and findings;
assembly does not retain an old route-level canonical snapshot. The builder requires
the committed confirmed finding, complete active citations, one strict completed
receipt lineage, and matching target/envelope/persona/session identity.

Shape R requires fresh recorded credential identity and supported positive receipt
semantics. Negative/inconclusive proof, orphan-risk outcomes, missing captures,
request substitution, and cross-session identity refuse before artifact construction.
The assembler does not invent a time-to-live or a new constraint freshness oracle.

Shape A invokes the existing `evaluate_replay_leak` eligibility check unchanged.
A `refuted` oracle verdict is required for the eligible replay-leak claim: the
one-time-effect invariant was refuted. D's existing LOCAL admission records UNKNOWN
credential freshness, which is not reinterpreted as invalidation. Explicit STALE
identity still refuses. A secure D outcome produces no candidate. No blanket
`verdict == refuted` filter is used across claim types.

Severity is copied from the canonical finding. Impact and effect class come only
from its recorded metadata. Absent/unsupported values are `unknown`; D's existing
`impact_assessment=unassessed` remains unassessed, and its provisional severity is
not upgraded. Neither an AI model nor a caller supplies impact prose.

## 5. Sanitization and disposable state

The extended [promoter sanitizer](../../core/verify/promoter.py) covers request
headers/cookies, persona context, URL values, request bodies, response excerpts,
JSON field names, reflected credentials, and claim prose. It handles literal,
URL-encoded, and JSON-escaped representations. Raw credentials stay in memory;
owned drafts retain only credential length/hash fingerprints for restart redaction.
Unknown header values are placeholders. Redaction collisions and residual known
secrets refuse rather than emit a partially sanitized artifact. Diagnostics on the
four artifact surfaces contain constant messages, never raw exceptions.

[Candidate Workbench](../../core/verify/workbench.py) persists only owned mode-0600
schema-2 draft JSON in its mode-0700 directory. Initial targets retain only the
origin; unvetted path/query material is not persisted before capture sanitization.
The draft is bounded to 2 MiB. Legacy schema-1 drafts refuse and are disposable;
there is no silent trust-preserving migration. Retained raw Ghost files and canonical
CAS/receipt data are read, not rewritten, by assembly.

Owned-draft teardown reports `removed`, `absent`, or `failed`, with explicit
`orphaned_owned_state_possible`. Deleting a draft never deletes a canonical finding,
receipt, or source capture. A failed unlink is reported honestly. A later authorized
render may reconstruct a disposable draft from the retained source.

## 6. Cross-cutting gate record

- **Contract:** `OCB-R7` / `OCB-S19`, Rev 2 taxonomy, one active lineage and claim-specific refusal.
- **Caller:** Verify candidate/promote, Cortex report, AI report/section, scans bounty report.
- **Authority:** none added; render/read and owned-draft disposal only.
- **Evidence:** content-addressed finding, receipt, canonical observations, and minimized source projection; no reprobe.
- **Cleanup:** owned draft only; teardown and orphan-risk failure tested separately from immutable source evidence.
- **Negative proof:** invalidation, stale identity, cross-session proof, secure D, missing/changed captures, altered requests, ambiguous/multiple roots, and secret-bearing diagnostics refuse.
- **Focused proof:** [OCB-S19 scenario](../../tests/unit/test_ocb_s19_candidate_assembly.py), [sanitizer tests](../../tests/unit/test_candidate_sanitization.py), and existing candidate/Verify/lineage/canonical-reader regressions.
- **Repository gate:** Python 3.12.14, complementary unmarked and `subprocess_spawn` invocations; final results recorded in section 8.
- **External gate:** none; assembly sends zero target requests. Existing in-memory proof setup precedes request-denying assembly checks.
- **Documentation:** this slice record and [master ledger](ONE_CLICK_BOUNTY_MASTER_EXECUTION_PLAN.md), with the local delivery identity and push blocker recorded in section 8.
- **Branch:** `ocb/r7-candidate-assembly`, solely this slice, from the exact base above.
- **Delivery:** focused branch handed to mediator; local proof is not acceptance or merge authority.

The inherited repository security-check baseline and six web-schema drift snapshots
remain separate governance debts. This slice neither suppresses them nor changes
their baselines.

## 7. OCB-S19 retained-store examples

These are actual renders from isolated test stores built with the existing receipt,
Ghost capture, canonical admission, and Family-D producer APIs on Python 3.12.14.
The credentials and target identities are synthetic test data. They prove assembly,
not a new live target finding or automatic A-C capture-to-finding orchestration.
Assembly ran with target-request methods denied. Fresh store/read-model instances
reproduced both candidates. The temporary draft was then removed for each shape,
with `orphaned_owned_state_possible=false`; source receipts remained available.

Shape R: one minimized request, `replayable=true`, and identical addresses:

- Verify: `submission_candidate:6df5cbc144ebe27113ebafa56bfed264cce5578c240bcf1a786e07cc222c43b9`.
- Cortex: `submission_candidate:6df5cbc144ebe27113ebafa56bfed264cce5578c240bcf1a786e07cc222c43b9`.
- AI and scans returned the same address, including after restart.
- Receipt: `behavioral-91c89016db092c18a2c029d8134c1c40b138681ddf58221e846fb7a1885e51dd`.
- Lineage: `candidate_receipt_lineage:f76e28afd56181d580078a1cd4bad1eacb24680cccdc2283caf6148a2a76694e`.

Shape A: `submission_candidate:9a1d043054530a901b1632660a0afa2338a340e929feec6a8ba67dae2b1299a7` on all four surfaces and restart.

- Kind: `evidence_attestation`; label: `Receipt-bound evidence attestation (non-replayable)`.
- Receipt: `behavioral-2222222222222222222222222222222222222222222222222222222222222222`.
- Evidence root: `ae0084313f8a9533f611115b498e38d0fad011f060da393d0027aa63e0858341`.
- Oracle verdict: `refuted` (eligible); `replayable=false`; five retained
  observations; zero reproduction steps; no reconstructed endpoint.
- Claim: repeated exposure of the same target-reported protected-effect
  representation after capability consumption. It does not independently prove
  two backend state mutations. Canonical severity remains `medium`; impact is
  unassessed rather than invented.

After the existing ledger invalidated each specimen's cited canonical observation,
Verify, Cortex, and AI refused, and scans returned zero candidates. The Family-D
refuted verdict rendered before that lifecycle invalidation and refused afterward:
oracle refutation and canonical invalidation are separate contracts.

## 8. Verification and delivery

The OCB-S19 scenario contains 34 cases in
[the dedicated scenario module](../../tests/unit/test_ocb_s19_candidate_assembly.py).
The repository gate includes those cases and the shared sanitizer, candidate,
lineage, endpoint, canonical-invalidation, and report-consistency regressions.

The sanitizer mutation control replaced `ArtifactSanitizer.text` with an identity
function only in a separate test interpreter. The captured-token leak regression
`test_capture_secrets_are_removed_from_every_promoted_field_and_raw_capture_survives`
then failed as required: `1 failed in 0.10s`, exit 1. No source was edited for this
control; the normal sanitizer is exercised by the successful repository suite.

The final unmarked invocation on Python 3.12.14:

```text
.venv/bin/python -m pytest -m "not subprocess_spawn" tests/
3451 passed, 1 skipped, 26 deselected, 3 warnings in 36.16s
```

The three warnings were two ldap3/pyasn1 deprecations and one aiosqlite worker
shutdown warning. An initial full run exposed one existing assertion expecting the
previous session-refusal wording; the route's constant safe message now preserves
that requirement and the full unmarked gate was rerun successfully.

The complementary real-process invocation:

```text
.venv/bin/python -m pytest -m subprocess_spawn tests/
26 passed, 3452 deselected, 2 warnings in 16.83s
```

The union is **3477 passed, 1 skipped, 3478 collected**, comprising the base
3422 passing tests plus 55 added tests. The two warnings in the marked run were
the same ldap3/pyasn1 deprecations. The complete 26-test `subprocess_spawn` set ran
in its own interpreter; no selected test was left unrun.

The scenario directly checks candidate addresses on all four surfaces; shared
renderer determinism is additionally covered by the existing candidate tests.
Negative/secure D and stale R refusal are exercised across all four routes. The
R-specific negative, inconclusive, and orphan-risk outcome branches are explicit
builder checks; the scenario does not separately instantiate every such R outcome
through all four routes. Existing canonical-admission tests cover negative and
inconclusive admission refusal.

`scripts/local-security-check.sh` was run before committing and exited 1 on the
inherited baseline. All 10 files matching its prohibited-operation or secret patterns
are byte-identical to base `493f76f`; this slice adds no pattern match. Targeted Ruff
checks passed for all changed production modules and the two new test modules.
`git diff --check` passed. All 25 relative Markdown links in this slice record and
the master ledger resolve, with no URL-escaped paths. The six web-schema drift
snapshots were neither rerun nor changed. No native, lab, external-target, transport, or submission check was required
or performed for this deterministic assembly slice.

Branch delivery: `ocb/r7-candidate-assembly`. Local implementation commit:
`38ba94de532bec187a9576664c7743ffbc3d2fe1`. The exact authorized command
`git push -u origin ocb/r7-candidate-assembly` was rejected before execution:
`approval required by policy, but AskForApproval is set to Never`.
There is **no verified pushed SHA** for this slice. No alternate publication path
was attempted. A following documentation-only commit records this local identity
and delivery blocker; its SHA is included in the operator handoff.

The completed implementation and repository gate are suite proof, not acceptance.
Publication, mediator verification, and Jason's separate explicit merge go remain
outstanding. The work order explicitly permits this local-SHA handoff when execution
approval policy blocks the push.
