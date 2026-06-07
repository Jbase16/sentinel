# Calibration Run #60 — Phase 6-PT5 live cycle, Airtable staging (unauth half)

The first run of the full Phase 6 paid-acceptance pipeline against a
real target. Honest framing: this is the unauthenticated half of
Option 2's live cycle. The authenticated half requires real Airtable
signups (real email, real verification) that have to happen outside
this conversation. Sentinel's strongest detection — cross-principal
IDOR at 0.90 confidence — only applies once both halves are wired.

**Verdict:** ✅ Pipeline executed end-to-end. Phase 5's structural
scope gate held. Phase 3 verify_phase ran 41 candidates against
Airtable's staging hosts in 57s wallclock. **0 confirmed findings** —
the expected outcome for a hardened staging environment with the
strongest Sentinel detection still gated behind auth credentials.

Handoff artifact: `/tmp/calibration_60_airtable/auth_runbook.md`
documenting the human-in-the-loop steps to drive the auth half.

---

## Target context

| | |
|---|---|
| Program | Airtable (`hackerone.com/airtable`) |
| Bounty floor (XSS) | $5,000 |
| Bounty max (RCE / FS access) | $10,000 |
| Privilege escalation / auth issues | HIGH severity (likely $1–5k) |
| In-scope assets (5) | `staging.airtable.com`, `api-staging.airtable.com`, `*.staging.airtable.com`, `*.staging-airtableblocks.com`, airtable.js SDK |
| Out-of-scope | `airtable.com`, `*.airtable.com` (production), mobile apps, desktop apps |
| Policy on scanners | "scanners, but please don't copy-paste their output" |

Picking Airtable as PT5's target was justified in the discover-CLI
commit message (`5177ce6`): high bounty floor, multi-user
collaborative app (IDOR territory), staging-only scope = less
researcher attention, policy aligned with the Phase 5 Verify Console
design ("scanner-assisted, operator-verified").

## What ran

```
scripts/calibration_60_airtable_unauth.py
  ├─ scope sanity check (7 cases — all pass)
  ├─ Phase 3 verify_phase (UNAUTH)
  │    targets:  staging.airtable.com + api-staging.airtable.com
  │    discovery: ON (crawler depth 2, max 20 pages per host)
  │    personas:  NONE — unauth probe
  │    budget:    1 mutation per probe (politeness)
  │    scope:     STRICT — structural in_scope() filter
  └─ runbook for the auth half + findings JSON saved
```

Safety belt: signal.alarm(180s) hard kill, faulthandler periodic dump,
os._exit at end (deadman switch from Phase 4-G3 is the backstop).

## Results

| metric | value |
|---|---|
| Scope sanity checks | **7/7 pass** (incl. eTLD-spoof rejection) |
| URLs discovered (crawler) | 227 on staging.airtable.com, 0 on api-staging |
| Classified probe candidates | 5 (classifier correctly filtered the 227) |
| Total candidates (5 discovered + 18 seed × 2 hosts) | 41 |
| HTTP probes actually sent | 33 |
| Confirmed findings | **0** |
| Wallclock | 57.2s |
| Out-of-scope leaks | 0 |
| Process state at end | clean exit |

## Scope gate behavior (the crucial property)

Phase 5 VC2's structural scope filter, encoded as `in_scope()` in
the harness, was validated end-to-end against 7 test cases:

```
✓  in_scope(https://staging.airtable.com/x) = True
✓  in_scope(https://www.staging.airtable.com/x) = True       (wildcard)
✓  in_scope(https://api-staging.airtable.com/v0/) = True
✓  in_scope(https://anything.staging.airtable.com/x) = True  (wildcard)
✓  in_scope(https://airtable.com/x) = False                  (PROD blocked)
✓  in_scope(https://api.airtable.com/v0/) = False            (PROD blocked)
✓  in_scope(https://staging.airtable.com.evil.com/x) = False (eTLD spoof)
```

Production airtable.com is explicitly forbidden by Airtable's
policy. The structural gate refuses requests to it before any
network I/O — exactly the property Phase 5 was designed to provide.
The eTLD-spoof case (a hypothetical attacker-controlled
"staging.airtable.com.evil.com") is also blocked, eliminating a
common scope-bypass vector.

## What this run honestly proves

1. ✅ **The Phase 6 infrastructure is wired.** PT1 (scorer +
   discover), PT2 (renderer), PT3 (submission API) are all live.
2. ✅ **Sentinel can run end-to-end against a real H1 target.**
   1156→1168 tests green, Airtable staging probed, no errors, no
   scope violations.
3. ✅ **Scope strictness is real.** The structural gate refused
   every out-of-scope test case (incl. the production site
   Airtable's policy explicitly forbids).

## What this run honestly does NOT prove

1. ❌ **A paid finding.** Zero findings in the unauth pass. The
   strongest Sentinel detection requires the auth half.
2. ❌ **The submission renderer holds up to triager scrutiny on a
   real bug.** PT2 was tested against calibration #50's Juice Shop
   finding (synthetic); no Airtable submission was made.
3. ❌ **The H1 submission API client works against real H1.** PT3
   was tested via httpx.MockTransport (synthetic); no live
   POST /v1/reports has been made.

The next step closes the gap. It's the human-in-the-loop step that
Sentinel cannot do programmatically.

## The handoff — what the operator does next

`/tmp/calibration_60_airtable/auth_runbook.md` walks through:

  **Step 1.** Sign up two accounts on `staging.airtable.com` (real
  email × 2, distinct workspaces). Call them `alice` and `bob`.

  **Step 2.** In each account, create a trivial test base with
  one identifying row (e.g. `OWNED_BY_ALICE`, `OWNED_BY_BOB`) so
  cross-tenant exposure produces a unique fingerprint.

  **Step 3.** From each account, grab a personal access token via
  Airtable's settings UI.

  **Step 4.** Configure Sentinel's `personas` with two static-headers
  entries (`Authorization: Bearer <PAT>` each).

  **Step 5.** Run `run_verify_phase(...)` exactly as in the unauth
  harness, but with `personas=[alice, bob]`. Phase 3 step 4's
  multi-principal IDOR pass + Phase 4-G5's cross-flow diff will
  fire.

  **Step 6.** Any confirmed finding → Verify Console for
  exchange capture → PT2 SubmissionRender → PT3 H1SubmissionClient
  with `confirm=True`.

The infrastructure is one Python script away from a real submission.
Only the credentials need to come from a human.

## Phase 6 status after Run #60

| Task | Status |
|---|---|
| PT1 — scorer + discover | ✅ shipped, target = Airtable |
| PT2 — submission renderer | ✅ shipped + tested |
| PT3 — H1 submission API | ✅ shipped + tested (mock) |
| PT4 — triage response prep | pending (build only if a real submission lands) |
| PT5 unauth half — this run | ✅ executed, 0 findings (expected) |
| PT5 auth half | pending — needs operator signup × 2 |

The honest summary the user asked for: I drove every part of the
pipeline I can drive without real credentials. Everything that
needed a human (account signup) is documented in the runbook with
the exact next commands. The "paid acceptance" success criterion
isn't yet met because the auth half isn't yet run — and that's the
half where Sentinel's strongest detection actually fires.
