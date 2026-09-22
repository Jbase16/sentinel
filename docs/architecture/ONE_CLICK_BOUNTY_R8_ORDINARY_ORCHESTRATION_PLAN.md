# OCB-R8 Ordinary-Click Orchestration (Option B)

Status: mediator-verified PASS and LANDED canonical on `origin/main` (2026-09-22).
Suite-proved, default-off. The implementer's own push was blocked by its execution
approval policy; after independent mediator verification against the real repository
and Jason's separate explicit go, the mediator pushed the branch and fast-forwarded
`main` to it. A live native OCB-S20 journey remains a separate post-merge acceptance.

Base: `0988a4de51ee80e5f9da56f9083a4c02dd143b81`.
Branch: `ocb/r8-ordinary-orchestration`.
Canonical stage: `OCB-R8`. Exit gate: `OCB-S20`.
Gate: `SENTINELFORGE_ORDINARY_CLICK_ORCHESTRATION`, default `False`.
Posture: suite-proved, default-off; no native or `make accept-*` run in this slice.

## 1. Bounded outcome after the three hard stops

This slice implements the ratified Option B boundary. The ordinary Scan entry can,
only when the new gate is enabled, sequence the four existing native one-click
families through the public Foundry URL endpoint. It does not wire, widen, or edit
OCB-R6. It does not export private typed manifests or cleanup authority from an OCB-R5
producer. It does not attempt B/C/D receipt feedback through the existing unsupported
OCB-R3 branches.

The earlier R8 shapes were correctly refused because R6 cannot honestly record the
production generalized Family-A receipt, and Families B/C/D deliberately keep their
typed proof and one-shot teardown authority private. Option B preserves those
boundaries: native family results remain the authority for their own terminal state,
finding, and cleanup outcome. The coordinator observes and aggregates them but does
not reinterpret private evidence, fabricate coverage, or call cleanup a second time.

This slice adds no canonical identifier. The existing `OCB-R8` and `OCB-S20` names are
used as registered; `CANONICAL_ID_REGISTRY.json` is unchanged.

## 2. Production seam and exact sequencing

There are exactly two production-source changes:

1. [ordinary_orchestration.py](../../core/server/ordinary_orchestration.py) is the
   server-layer coordinator. Its location permits it to call the existing Foundry
   router endpoint without introducing a `core.behavior` to `core.server` dependency.
2. [scans.py](../../core/server/routers/scans.py) selects the coordinator only inside
   the existing non-anonymous behavioral phase and only when the gate is enabled.
   When the gate is disabled, the existing request and single endpoint call remain
   the executed branch.

The coordinator receives the existing validated
`RunBehavioralAuthorizationFromURLRequest` and constructs one new instance per
applicable family. Every instance retains the same target, envelope, paired personas,
and private assessment-session binding while carrying exactly one selector shape:

| Family | Applicability | Public request shape |
| --- | --- | --- |
| A | Always | No prior records, role selector, or capability selector |
| B | Both prior-record lists are present | The paired prior-record lists only |
| C | A role-monotonicity selector is present | The role selector only |
| D | A capability-effect selector is present | The capability selector only |

The order is deterministic: A, then each applicable family in B/C/D order. A missing
selector is recorded as `applicable: false` and `attempted: false`; it is never
reported as a failed or exhausted pass. Role and capability selectors never share a
request, and B never receives an unpaired prior-record list. Per-request exclusivity,
native family budgets, public admission, receipt deduplication, and every existing
producer/oracle contract remain the Foundry endpoint's responsibility.

Gate-on therefore issues one always-A pass plus one pass per profile-selected family
among B/C/D. It is a bounded sequence over the same admitted traffic class, not a
blind four-pass fanout and not a traffic grant. Gate-off executes the original one
profile-selected call.

## 3. Bounded states and terminal honesty

The only coordinator-state vocabulary is:

```text
observing, acquiring, blocked, proving, cleaning, confirmed, exhausted, incomplete
```

The trace and final state use only those values. Family summaries expose bounded
native status tokens, native result kind, oracle verdict, applicability, whether a
pass was attempted, cleanup status/orphan risk, and an R7 handoff summary. They never
expose a target endpoint, request body, credential, cookie, reservation token, or raw
native result.

Terminal precedence is honest and deterministic:

- `incomplete` wins when an applicable pass has no recognized native terminal, a
  call fails unexpectedly, candidate handoff fails, or cleanup reports uncertainty
  or possible orphaned owned state;
- otherwise `confirmed` means at least one native result produced a canonical finding
  that the existing R7 resolver accepted;
- otherwise `blocked` means at least one applicable native pass was refused or denied;
- otherwise `exhausted` requires every applicable family to have reached a recognized
  native terminal with no confirmed finding.

`exhausted` is explicitly serialized as `sequence_exhausted`. It is not OCB-R6
coverage exhaustion and carries no coverage, marginal-value, SearchPlan, scheduler,
ledger, or SearchStopCertificate field or implication. R6 remains passive and
unwired.

## 4. Cleanup and candidate handoff

The coordinator reads public cleanup projections already returned by each family.
Nested Family-D cleanup and the flat Family-B/Family-C cleanup fields are normalized
into a bounded report. `status == uncertain`, a cleanup failure, or
`orphaned_owned_state_possible == true` forces `incomplete`, sets
`attention_required`, and prevents later applicable family calls. The coordinator has
no cleanup callback and invokes no teardown path; a family cleanup is never repeated.

Native confirmation alone can enter candidate handling. Families B/C retain the
existing Scan canonical-finding route before the existing R7 resolver is called.
Family D uses only the existing R5D10 promotion's original assessment session and
canonical finding ID. The public R7 resolver and builder determine Shape R versus
Shape A; the coordinator supplies no shape flag and invents no claim.

In particular, an eligible Family-D replay leak has native oracle verdict `refuted`.
The focused scenario evaluates the retained evidence with the real
`evaluate_replay_leak` predicate and routes the promoted canonical finding through R7
as `evidence_attestation`. A refuted but ineligible D specimen remains a no-finding
terminal. The coordinator never uses `verdict == refuted` as a generic failure or a
generic confirmation.

## 5. Cross-cutting gate record

- **Contract:** `OCB-R8` / `OCB-S20`, Option B ordinary-click sequencing with the
  exact eight-state coordinator vocabulary and truthful sequence exhaustion.
- **Caller:** the existing ordinary non-anonymous behavioral phase in
  `core/server/routers/scans.py`; the anonymous-passive path is unchanged.
- **Authority:** no identity, origin, action class, budget, proof mode, durable
  capture, submission power, or traffic class is added. The default-off coordinator
  gate sequences existing public family calls but grants none of them authority.
- **Evidence:** only public immutable family result/receipt projections and existing
  canonical findings are observed. The coordinator persists no evidence and retains
  no raw native response in its public result.
- **Cleanup:** native cleanup is observed once and reported; uncertain/orphan risk is
  explicit and terminal. No coordinator-owned cleanup or second teardown exists.
- **Negative proof:** gate-off makes one unchanged native call; non-applicable families
  are not attempted; public refusal maps to `blocked`; unknown native state, handoff
  failure, and cleanup/orphan risk map to `incomplete`; ineligible D produces no
  candidate; sequence exhaustion makes no R6 claim.
- **Focused proof:** [OCB-S20 scenario](../../tests/unit/test_ocb_s20_ordinary_orchestration.py)
  plus the existing [ordinary Scan regressions](../../tests/unit/test_scan_behavioral_one_click.py).
- **Repository gate:** Python 3.12.14 with the required complementary unmarked and
  `subprocess_spawn` invocations. Results are recorded in section 7 after completion.
- **External gate:** none in this slice. A real-wire vulnerable/secure native OCB-S20
  journey is a separate post-merge acceptance requiring separate authorization.
- **Documentation:** this slice record. The canonical-ID registry is frozen.
- **Branch:** `ocb/r8-ordinary-orchestration`, solely this slice, from the exact base
  above.
- **Delivery:** the repository gate is green. The implementer's own authorized push
  was rejected before execution by its local approval policy; after independent
  mediator verification against the real repository and Jason's separate explicit go
  (2026-09-22), the mediator pushed `ocb/r8-ordinary-orchestration` to origin and
  fast-forwarded `main` to it. Recorded SHAs are in section 7.

The inherited repository security-check baseline and six web-schema drift snapshots
remain separate governance debts. This slice neither suppresses nor changes them.

## 6. OCB-S20 suite scenario

The focused suite uses in-process fakes and existing controlled in-memory Family-D
fixtures only. It sends zero live-target traffic. It proves:

- exact A+B+C and A+D request selection with isolated selectors;
- an honest `exhausted` result only after every applicable pass is terminal, with no
  coverage or marginal-value claim;
- a non-applicable family remains visibly non-applicable and unattempted;
- a 409 native refusal becomes `blocked` without a finding;
- an unknown terminal and uncertain/orphan-risk cleanup become `incomplete`, and no
  later family is called after cleanup attention is required;
- gate-off ordinary Scan uses the original single call and returns its original native
  result;
- gate-on ordinary Scan runs A plus the selected native family;
- an eligible Family-D `refuted` result reaches the real R7 builder as Shape A while
  target-request methods are denied; and
- a real refuted-but-ineligible evidence specimen produces no handoff or candidate.

These are suite-level coordination proofs. They are not native acceptance, external
target evidence, or payout proof.

## 7. Verification and delivery

Focused proof on Python 3.12.14:

```text
.venv/bin/python -m pytest tests/unit/test_ocb_s20_ordinary_orchestration.py -q
10 passed in 0.80s
```

The final unmarked invocation on Python 3.12.14:

```text
.venv/bin/python -m pytest -m "not subprocess_spawn" tests/
3461 passed, 1 skipped, 26 deselected, 3 warnings in 37.71s
```

The complementary real-process invocation:

```text
.venv/bin/python -m pytest -m subprocess_spawn tests/
26 passed, 3462 deselected, 2 warnings in 17.07s
```

The union is **3487 passed, 1 skipped, 3488 collected**: the base union of
3477 passing tests plus 10 OCB-S20 cases. The marked and unmarked selections are
complementary. The warnings were the two established ldap3/pyasn1 deprecations and,
in the unmarked run, the existing aiosqlite worker-shutdown warning.

Targeted Ruff checks passed for both changed production modules and the new scenario
module. `scripts/local-security-check.sh` was run before commit and exited 1 on the
inherited repository baseline: its literal greps match explanatory/identifier text in
unchanged `core/` files, and its optional repository-wide Ruff run reports existing
unrelated findings. Neither changed production module matches the prohibited
`shell=True`, `eval(`, `exec(`, or `os.system(` patterns or the script's hardcoded-
secret pattern; targeted Ruff is clean. `git diff --check` and all relative links in
this record pass, with no URL-escaped paths. Commit identities and remote push status
are recorded below. No native journey or `make accept-*` command is authorized or run
for this slice.

Branch delivery: `ocb/r8-ordinary-orchestration`. Implementation commit
`b827fdbca438e999e53973d7ab3541689c4674f6`; suite-proof documentation commit
`e1d7fdf2786ec3849e7c3c95f9d3d70487729064`. When the implementer built this slice, its
own authorized `git push -u origin ocb/r8-ordinary-orchestration` was rejected before
execution (`approval required by policy, but AskForApproval is set to Never`), so at
build time there was no pushed SHA. After independent mediator verification against the
real repository — four-file footprint, zero-byte diff across the frozen surfaces, a
self-reproduced two-invocation gate of 3487 passed / 1 skipped / 3488 collected on
Python 3.12.14, and an inherited-only `local-security-check` baseline — and Jason's
separate explicit go on 2026-09-22, the mediator pushed the branch to origin and
fast-forwarded `main` (`0988a4d..e1d7fdf`). This documentation-only closeout commit,
which records the landing, is the new `main` tip; its SHA and the resulting
`origin/main` advance are reported in the operator handoff.
