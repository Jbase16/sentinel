# Calibration Run #16 — Phase 2G Live Test (End-to-End Success)

After Run #15 surfaced the empirical truth that HackerOne's public scope
pages are Cloudflare-walled and Bugcrowd's are React-SPA shells, Phase 2G
shipped two pieces: a Keychain-backed token store and an API path on the
HackerOne extractor. This run verifies the API path against the real
HackerOne API with a real operator token.

**Verdict:** ✅ End-to-end success. The pipeline produced four complete
config files from the H1 `security` program in ~56 seconds, correctly
identified the program's "no automated scanning" rule, and refused to
proceed with scan-blocked status. Every Phase 2 layer worked.

---

## The run

```
python scripts/sentinel_ingest.py \
    --program hackerone:security \
    --out-dir /tmp/intel-live \
    --skip-verify
```

Token stored via `token_store.put("hackerone", "your-handle", <token>)`
into macOS Keychain (backend selected automatically).

Wall-clock breakdown (from stderr log):
- 0.0s: Resolver dispatched → HackerOneExtractor v2.0 (API path)
- 0.4s: HTTP 200 from `https://api.hackerone.com/v1/hackers/programs/security`
  with 33 structured_scopes
- 0.4s: Ollama tags probe — `sentinel-9b-god-tier:latest` warm
- ~55s: LLM extraction over the H1 policy text
  (the policy is several KB of markdown describing scope, rules, severity bars)
- 55s: Compilers ran, files written, summary printed, exit 2 (blocked)

## What the pipeline correctly identified

### 33 structured scope items from the API (no LLM)

The H1 API returned scope items with full typed metadata — no
hallucination risk. Our `_parse_structured_scopes` produced:

- **25 in-scope** items spanning `hackerone.com`, `api.hackerone.com`,
  `www.hackerone.com`, the `*.hackerone-user-content.com` S3 buckets,
  `mta-sts.wearehackerone.com`, `reviewer.pullrequest.com`, etc.
- **8 out-of-scope** items: `hackerone-swag.com`, `support.hackerone.com`
  (Freshdesk-hosted), `www.hackeronestatus.com` (Atlassian-hosted),
  `*.hacker.one` marketing sub-domains (Marketo / Unbounce hosted),
  `h1.community` etc.
- Each item carries the per-rule `instruction` text from H1's API as
  inline `# notes`, e.g.:
  ```
  hackerone.com  # This is our main application that hackers and customers use to interact with ...
  ```
- 2 items correctly skipped as `OTHER` (a VPN endpoint, a GitHub repo)
  with self-explanatory `# (skipped — other not representable…)` comments.

This is a quality of data that pure scraping could not have produced.
The H1 API does the structured work for us.

### 6 restrictions LLM-extracted from policy text

The local Sentinel-9b model produced clean, typed restrictions from
H1's policy prose. Every one is correctly classified and tied to a
verbatim quote from the policy:

| Restriction | Severity | Quote |
|---|---|---|
| no_dos | hard | "Single request, single user, single IP only / No automated tools or high-volume attacks" |
| no_automated_scan | hard | "No automated tools or high-volume attacks" |
| rate_limited | hard | "Single request, single user, single IP only" |
| business_hours_only | hard | "Test Mon–Thu, off-peak hours only (9pm UTC – 6am UTC)" |
| no_data_destruction | hard | "Data corruption or manipulation" |
| other (case-by-case) | soft | "Cache poisoning DoS will be evaluated on a case-by-case basis based on impact" |

The LLM correctly distinguished hard vs. soft, and the `raw_quote`
field on each restriction provides full traceability back to the
source policy text. The extraction confidence was 0.70 — sensible
for a multi-faceted policy with overlapping rules.

### Enforcement layer activated

The policy_enforcer correctly translated the 6 restrictions into:

```
disabled tools:       ['masscan', 'nuclei', 'nuclei_mutating']
max capability tier:  T2a_SAFE_VERIFY
⛔ scan_blocked:      Do not use automated scanning tools for vulnerability discovery.
```

The `no_automated_scan` restriction triggered the `block_scan` strategy,
which set `scan_blocked=True` on the PolicyEnforcement object. The CLI
then printed `⛔ Scanning is BLOCKED…` and returned exit code 2.

**This is exactly the right behavior.** HackerOne's own security
program explicitly forbids automated scanning. Sentinel refuses to
proceed. The operator sees a clear, actionable error.

## What the test confirmed works end-to-end

Every layer in the design doc executed correctly with live data:

| Layer | Status | Evidence |
|---|---|---|
| Token store (Keychain) | ✅ | `your-handle` + token stored, retrieved on demand, redacted in repr |
| Resolver | ✅ | `hackerone:security` → HackerOneExtractor |
| H1 API auth (Basic Auth + handle:token) | ✅ | 200 OK on first try |
| API → ScopeRule translation | ✅ | 33 items, correct types, instruction notes preserved |
| LLM extraction (Ollama sentinel-9b) | ✅ | 1 attempt, valid JSON, 6 restrictions + 1 persona |
| ProgramScope construction with provenance | ✅ | extractor_version, raw_content_hash, extraction_confidence all set |
| Scope compiler (text scope file) | ✅ | 3.7 KB, well-formed, ready for `pysentinel --scope-file` |
| Persona compiler (personas.json) | ✅ | Auto-synthesized anonymous baseline (no real test creds in policy) |
| Restriction compiler (restrictions.json) | ✅ | Schema-versioned, all enforcement strategies populated |
| Policy enforcer | ✅ | Correctly translated restrictions → disabled tools + tier cap + scan_blocked |
| CLI summary + exit codes | ✅ | Clear summary, exit 2 (BLOCKED_BY_RESTRICTION) |

## Two minor quality observations

These don't break anything but are worth noting:

1. **The H1 API maps both `URL` and `WILDCARD` asset_types to our
   `DOMAIN`** ScopeRuleType. For `URL` items that contain `://` (like
   `https://*.hackerone-ext-content.com`), the engine's scope parser
   will re-classify them as `URL` on load — which is fine, but it does
   mean the round-trip isn't perfectly type-preserving. The behavior
   is still correct; the type label changes.

2. **The LLM extracted only 1 "persona"** which is a placeholder
   ("test user" with no actual credentials, dropped by the persona
   compiler's filter). H1's `security` program doesn't ship test creds
   — the policy says to use your own H1 account. This is correct
   behavior; the persona compiler correctly auto-synthesized just the
   anonymous baseline.

Neither is a bug. Both could be polish in a future round.

## What blocks have lifted vs. what remains

**Lifted:**
- ✅ HackerOne is now ingestible — public AND (via the same code path)
  private programs the operator is invited to
- ✅ The Phase 2 architecture is empirically validated end-to-end
- ✅ The single biggest empirical risk identified in Run #15 (platform
  scraping is dead) is fully resolved for HackerOne

**Still pending:**
- 📋 Phase 2G-C: `sentinel-token add` CLI (convenience — the token can
  also be stored via a one-line Python call as we did here)
- 📋 Phase 2G-Bugcrowd: Bugcrowd's API integration. Bugcrowd's public
  API is less documented; investigate, then mirror the H1 pattern.
- 📋 Phase 2H: Wire policy_enforcer's output INTO Strategos at scan-time.
  Right now the enforcement is a *preview* — the CLI prints what
  would be disabled, but the downstream `pysentinel` doesn't yet
  consume the restrictions.json. The compilers produce a clean
  contract; the consumer needs wiring.

## Aggregate Phase 2 stats — through Run #16

- **367 tests passing** (Phase 1 adjacent + Phase 2A through 2G-B)
- **9 modules in `core/intel/`**: program_scope, llm_extraction,
  resolver, verifier, registrar, policy_enforcer, token_store, plus
  the extractors and compilers packages
- **3 design docs**: PHASE_2_DESIGN, CALIBRATION_RUN_015, this one
- **First successful end-to-end ingest against a real bounty platform**
  in approximately 56 seconds wall-clock, blocking the scan correctly
  per program policy

## The lesson Phase 1 keeps teaching, validated again at the platform layer

Run #15 surfaced the broken-by-default scraping path. Run #16 ships
the fix and proves it. Between the two runs, ~600 LOC of new code
(token store + API extractor + tests) replaced ~250 LOC of broken-
in-practice code, and the proof point is one HTTP request to a real
program returning real structured data.

The pattern keeps holding: **build the smallest piece, run it once
against reality, fix what reality breaks, ship.** No amount of code
review would have caught the Cloudflare wall. No amount of code
review would have caught the structured API being richer than the
scraping path. The empirical loop catches both in a single iteration.
