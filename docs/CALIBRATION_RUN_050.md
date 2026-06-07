# Calibration Run #50 — full end-to-end pipeline against Juice Shop

The integration test we'd been deliberately deferring. 1121 unit
tests prove each layer in isolation; this run was the first time
*everything we built across Phases 3, 4, and 5 was wired together
end-to-end against a real target*.

**Verdict:** ✅ Pipeline executes end-to-end and produces a
submission-quality bounty report markdown. Two real bugs surfaced
during the first attempt (FindingsStore async race; missing persona
attribution in repro). Both fixed inline. Second run produces the
artifact reviewed below.

---

## What ran

```python
# scripts/calibration_50_end_to_end.py
# 8-step pipeline, every step is a real call into the actual stack
#  (no mocks, no scaffolding — Juice Shop is on the wire):

[1] run_verify_phase(...)        # Phase 3: confirmed findings
[2] pick cross-principal IDOR    # the most interesting finding
[3] FindingsStore.add_finding    # promote to the global store
[4] create_session_from_finding  # Phase 5-VC1: hydrate verify session
[5] bind admin persona           # Phase 5-VC1: persona route
[6] send_exchange × 3            # Phase 5-VC2: structured + scope-gated
     - GET /rest/basket/1 as admin
     - GET https://evil.example/x (must be REJECTED before I/O)
     - rebind to jim
     - GET /rest/basket/1 as jim (cross-principal IDOR confirmation)
[7] promote_to_repro             # Phase 5-VC3: render + sanitize
[8] build_report + swap steps    # core.reporting → final markdown
```

Safety belt: `signal.alarm(120)` + `os._exit(rc)` at the end —
inherits the deadman from Phase 4-G3's ScanSession teardown work
(Calibration Run #37).

## Results

| stage | metric | value |
|---|---|---|
| Phase 3 verify_phase | confirmed findings | **8** (SQLi × 2, single-IDOR × 4, cross-principal IDOR × 2) |
| Phase 3 verify_phase | wallclock | 9.8s |
| Multi-principal pass | cross-principal IDORs caught | 2 (basket/1, users/1) |
| Multi-principal pass | confidence on chosen finding | 0.90 (identical-json signal) |
| Phase 5-VC1 | session hydration latency | < 1ms after the FindingsStore fix |
| Phase 5-VC2 | scope violation handling | structurally blocked BEFORE I/O ✓ |
| Phase 5-VC3 | repro rendered with sanitization | `$TOKEN` placeholder, legend at top |
| Final artifact | bounty report MD bytes | ~3.4 KB |
| Final artifact | CVSS auto-score | 8.1 HIGH |
| Pipeline total | wallclock | ~12s |

## Bugs surfaced — both fixed inline

### Bug #1 — FindingsStore sync-then-async race

**Symptom (commit before fix):** Step 3 in the harness called
`store.add_finding(picked)` then immediately `store.get(finding_id)`
inside `asyncio.run()`. The lookup returned None and the calibration
crashed with `ValueError: finding 'verified-cross-idor-63122' not
found`.

**Root cause:** `FindingsStore.add_finding()` had two branches:
1. *No event loop* — synchronous in-memory append + sync persistence
2. *Inside an event loop* — schedules `add_finding_async()` as a
   background task. **No sync append.** The in-memory list wouldn't
   reflect the new finding until the scheduled task ran on the
   next loop tick.

So *any caller* inside asyncio.run that did `add_finding(x);
get(x['id'])` would race itself. We had 1117 unit tests, none of
which exercised this exact ordering. The integration test found it
in one line.

**Fix (`core/data/findings_store.py`):**
The async branch now does the basic-annotated sync append FIRST
(so `get()` works immediately), then schedules a new
`_reannotate_async()` helper to do the heavy work (dedup analysis,
sequence allocation, DB persistence) on the already-in-list dict
via in-place mutation. The behavior contract is now uniform across
both branches: after `add_finding()` returns, `get(id)` finds the
finding in memory; the async re-annotation is incremental.

**Regression test (`tests/unit/test_findings_store_sync_get.py`):**
4 new tests pinning the sync-then-async contract. The critical one
is `test_sync_add_get_inside_event_loop()` — pre-fix, this returns
None and fails the assert with a message that points at this exact
calibration as the regression source.

### Bug #2 — Repro steps for cross-principal IDOR were narratively identical

**Symptom (first run after fix #1):** The rendered bounty report's
"Steps to Reproduce" had:

```
1. Send `GET /rest/basket/1` … HTTP 200
   curl -X GET -H 'authorization: Bearer $TOKEN' http://…/rest/basket/1
   Response: { … admin's basket data … }

2. Send `GET /rest/basket/1` … HTTP 200
   curl -X GET -H 'authorization: Bearer $TOKEN' http://…/rest/basket/1
   Response: { … same admin's basket data … }
```

Two identical curl commands. A triager reading this would think
"why two steps?" and miss that the WHOLE POINT is "these were
sent as DIFFERENT IDENTITIES and got the SAME RESPONSE." The
$TOKEN placeholder also had no inline legend — they'd see `Bearer
$TOKEN` and guess.

**Root cause #2a:** `FlowStep` didn't carry persona attribution at
capture time. The session knows its *current* persona, but if the
operator rebinds mid-transcript (which is exactly what cross-
principal IDOR verification REQUIRES), the per-step context is
lost.

**Fix #2a (`core/ghost/flow.py`, `core/server/routers/verify.py`):**
Added `FlowStep.persona_at_capture: Optional[str]`, populated by
VC2's `send_exchange` from `session.persona_name` at the moment of
capture. Round-tripped through `to_dict()` / `from_dict()` so it
survives serialization. Same design principle as the existing
`cookies_after_step` field — bind per-step context to the per-step
atom.

**Fix #2b (`core/verify/promoter.py`):** Prose builder now prepends
"As user `<name>`," when the captured step has a persona. And the
combined placeholder legend is injected into the first repro
entry's prose as a top block ("Before running, substitute these
placeholders…") so the triager sees the substitution table before
the first curl.

## The artifact (final markdown)

After both fixes:

```markdown
### Steps to Reproduce

1. _Before running, substitute these placeholders with real values:_
   - `$TOKEN` — the value of the `authorization` header (a token)

   As user `admin`, send `GET /rest/basket/1` to reproduce the
   IDOR confirmation (payload: `admin↔jim`) — the server returns
   **HTTP 200**.

   ```bash
   curl -X GET \
     -H 'authorization: Bearer $TOKEN' \
     http://127.0.0.1:3000/rest/basket/1
   ```

   **Response (HTTP 200):**
   ```
   {"status":"success","data":{"id":1,"coupon":null,"UserId":1,…}}
   ```

2. As user `jim`, send `GET /rest/basket/1` — the server returns
   **HTTP 200**.

   ```bash
   curl -X GET \
     -H 'authorization: Bearer $TOKEN' \
     http://127.0.0.1:3000/rest/basket/1
   ```

   **Response (HTTP 200):**
   ```
   {"status":"success","data":{"id":1,"coupon":null,"UserId":1,…}}
   ```
```

The narrative is now correct: *as admin, do X; as jim (a different
user), do the same X and observe the same response.* That's the
cross-principal IDOR demonstration in three sentences.

## Things this run validated

1. ✅ **End-to-end composability.** Five layers we built across
   four phases ARE actually composable. The integration shape we
   designed for (FlowStep as the shared atom, persona as the
   per-step context, scope as the structural gate) holds up in
   practice.

2. ✅ **Constraint-inversion scope gate works.** When the harness
   tried to send `GET https://evil.example/x`, VC2 logged
   `[verify] BLOCKED out-of-scope request` and raised 403
   BEFORE any network I/O. The harness's "did anything reach the
   wire?" check confirmed nothing leaked.

3. ✅ **Token sanitization works.** The bounty report contains
   `Bearer $TOKEN`, not the actual JWT. The operator's transcript
   contains the actual JWT. Two-audience model holds.

4. ✅ **Persona attribution survives serialization.** The
   `persona_at_capture` field is in `to_dict()` / `from_dict()`
   so it works across the FastAPI boundary + flow-store persistence.

5. ✅ **Deadman switch held.** When the calibration script's
   `os._exit` path completed cleanly, the teardown deadline never
   needed to fire. When the FIRST RUN crashed mid-pipeline (Bug
   #1), the deadline fired at 10s as designed and the process
   exited cleanly. No 3-hour ghost.

## Things this run did NOT validate

* **Bounty platform-specific markdown variants** (Intigriti vs
  HackerOne vs Bugcrowd format differences). The pipeline currently
  always renders the HackerOne-flavored template.
* **Multi-host scope additions in practice.** The scope gate was
  exercised but the operator only ever had one origin in their
  allowlist. Calibration of "add origin → retry the original
  request" is a future test.
* **Persona-bind-then-rebind in a longer transcript.** This run
  did two binds (admin → jim). A run with three or more would
  exercise the same code path but expose any state bleed.
* **Mobile / desktop UI** of VC4 — backend pipeline tested; the
  SwiftUI view is correctness-by-construction (mirror of the
  backend DTOs) but not exercised here.

## Phase status after Run #50

All five Phases shipped + end-to-end validated against a real
target. The full pipeline works:

```
recon → Phase 3 active verification → cross-principal IDOR detection
      → Phase 5 verification session
      → VC2 fail-closed scope gate
      → VC3 sanitized repro promoter
      → BountyReport with CVSS scoring
      → submission-quality markdown
```

Total: **1121 Python unit tests green**, **two real integration
bugs caught and fixed**, **one bounty-report markdown saved at
`/tmp/calibration_50/bounty_report.md`** for human review.

---

**Closing observation.** This calibration run is exactly why
integration tests matter. 1117 unit tests pre-Run-#50 said the
pipeline was correct. Running it for real surfaced two bugs neither
suite would have caught — one a real correctness issue
(FindingsStore race), one a real product-quality issue (persona
attribution in repro). Both got fixed in under 30 minutes. The
"complete not minimum progress" directive that drove this whole
arc means we shouldn't stop until we've proven the loop closes.
Run #50 is the proof.
