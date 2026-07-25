# Calibration Run #38 — Phase 3 step 4: cross-principal IDOR

Closes the last step of Phase 3 (active exploitation). The single-
principal IDOR heuristic from Run #26 / commit `d008a75` finds
"horizontal IDOR within an identity" — Alice fetches `/baskets/1` and
`/baskets/2`. This run adds **cross-principal IDOR**: two distinct
authenticated identities (Alice + Jim) probing the **same** URL to
detect "Jim can read Alice's resource using Alice's URL."

**Verdict:** ✅ Live-confirmed against Juice Shop. Both canonical
cross-principal IDORs (`/rest/basket/1`, `/api/users/1`) caught at
0.90 confidence. Total wallclock 9.9s clean exit. 957 unit tests green.

---

## What ran

```
python3 -u <harness> \
    --target http://127.0.0.1:3000 \
    --personas admin@juice-sh.op,jim@juice-sh.op \
    --per_probe_budget 2 \
    --max_hosts 1
```

The harness exercises `core.wraith.verify_phase.run_verify_phase` with
two authenticated personas. The new `_run_multi_principal_idor` pass
runs AFTER the single-principal loop completes, takes the IDOR-shaped
candidates (numeric/UUID terminal path segments), fetches each one as
each persona, and compares responses across identity pairs.

## What was caught

**8 findings total:**

| # | type                                    | URL                                | confidence | persona attribution |
|---|-----------------------------------------|------------------------------------|------------|---------------------|
| 1 | SQLi (active verification)              | `/rest/products/search?q=...`      | 0.92       | admin               |
| 2 | IDOR (active verification, horizontal)  | `/rest/basket/1`                   | 0.60       | admin (probe → /2)  |
| 3 | IDOR (active verification, horizontal)  | `/api/users/1`                     | 0.85       | admin (probe → /2)  |
| 4 | SQLi (active verification)              | `/rest/products/search?q=...`      | 0.92       | jim                 |
| 5 | IDOR (active verification, horizontal)  | `/rest/basket/1`                   | 0.60       | jim   (probe → /2)  |
| 6 | IDOR (active verification, horizontal)  | `/api/users/1`                     | 0.85       | jim   (probe → /2)  |
| 7 | **Cross-Principal IDOR**                | **`/rest/basket/1`**               | **0.90**   | **admin ↔ jim**     |
| 8 | **Cross-Principal IDOR**                | **`/api/users/1`**                 | **0.90**   | **admin ↔ jim**     |

Findings 7-8 are the new class. They're emitted because:
  * Both admin and jim received **byte-identical JSON** for the same URL.
  * Identical JSON across two distinct authenticated identities is the
    canonical cross-principal IDOR signal — both got the same row.

## Proof quality (findings 7-8)

```
★ http://127.0.0.1:3000/api/users/1
  signal='identical-json'  conf=0.90
  attacker='admin'  victim='jim'

  as 'admin' (301B):
    {"status":"success","data":{"id":1,"username":"","email":"admin@juice-sh.op",
     "role":"admin","deluxeToken":"…","lastLoginIp":"…","profileImage":"…",…}}

  as 'jim'   (301B):
    {"status":"success","data":{"id":1,"username":"","email":"admin@juice-sh.op",
     "role":"admin","deluxeToken":"…","lastLoginIp":"…","profileImage":"…",…}}
```

That's a bounty-quality artifact: as Jim, you can read admin's email,
role, deluxeToken, and profile metadata. Same byte-for-byte, no
ambiguity.

## The signal taxonomy

Three confidence tiers calibrated empirically during this run:

| signal               | when                                                | confidence |
|----------------------|-----------------------------------------------------|------------|
| `identical-json`     | both auth'd identities → same JSON, same URL        | 0.90       |
| `distinct-json+size` | both → distinct JSON, similar size (per-id data)    | 0.85       |
| `distinct-body`      | both → distinct non-JSON 200 OK                     | 0.60       |
| (skipped)            | identical non-JSON body across identities (SPA shell)| —         |

The **identical-JSON-is-IDOR / identical-HTML-is-shell** split was
the key insight calibrated against Juice Shop. The first version of
the heuristic treated all identical bodies as shells and missed the
Juice Shop case entirely — fixed inline before commit.

## What changed in code

  * `core/wraith/verify_phase.py`:
    - Added `_run_multi_principal_idor(candidates, identity_contexts, scope_filter)`.
    - Added `_is_idor_shape(url)` helper (mirrors classifier + verifier).
    - Wired the multi-principal pass into `run_verify_phase` after the
      single-principal loop. Runs ONLY when 2+ authenticated identities
      are present.
    - Findings tagged with `cross_principal_idor`, both attacker/victim
      personas in tags + metadata, full leak-pair list in metadata for
      multi-victim cases.

  * `tests/unit/test_verify_phase.py`: +6 new tests in
    `TestMultiPrincipalIDOR`. Tests pin:
    - Skipped with <2 auth identities.
    - Identical JSON → flagged (the Juice Shop case).
    - Identical HTML → NOT flagged (SPA shell).
    - Distinct JSON same shape → flagged.
    - Non-IDOR URL shape (no terminal numeric segment) → no probes.
    - All findings carry attacker/victim attribution.

## What was NOT changed

  * `core/web/MultiPrincipalDiffEngine` (the orphaned WebOrchestrator
    sub-pipeline) — was NOT wired. Reason: full WebOrchestrator wiring
    requires MutatingTransport, BaselineHandle, ExecutionPolicy per
    principal, EventBus, etc. — a much bigger refactor than the
    in-place comparison logic this commit added. The `core/web/` code
    is still available for future direct use; today's verify_phase has
    its own simpler comparison engine.

## Phase 3 status — complete

| step | what                                          | status |
|------|-----------------------------------------------|--------|
| 1    | verifier fixes + active-verification hook     | ✅ shipped |
| 2    | persona-aware identity contexts               | ✅ shipped |
| 3    | crawler-driven candidate discovery            | ✅ shipped + Run #36 |
| 4    | multi-principal IDOR                          | ✅ shipped + Run #38 |

The full Phase 3 pipeline now does end-to-end:
  recon → discover URLs → classify → probe (per identity) → confirm →
  cross-principal compare → emit findings with attribution.

All 4 steps live-verified against OWASP Juice Shop. Run #36 confirms
the crawler-discovery layer works against a real H1 target
(gitlab.com). The pipeline is production-ready for the bug_bounty mode
overlay on real targets.

---

**Final stats this session:**
* 957 unit tests passing (started at 947 before Phase 3 step 4).
* 6 commits to main: d008a75, 0fb99dc, 57a2eff, e77c003, 6c38c18, 27f5498, plus this one.
* 4 task entries closed (#34, #35, #36, #37, #38).
* 0 ghost processes.
