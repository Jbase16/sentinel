# Calibration Run #15 — Phase 2 Live Test (Reality Check)

Phase 2 closed with 338 tests passing across the full intel pipeline.
Before building Phase 2G (token storage) on top, we ran the first
empirical test against real bug bounty platforms to verify the
foundations actually work in the wild.

**Verdict:** ⚠ Critical finding — platform-specific scraping is
non-functional against HackerOne and Bugcrowd in their current form.
Phase 2G (official API integration) is no longer optional; it's the
only path to making HackerOne and Bugcrowd ingestion work at all.
Generic-URL scraping for self-hosted programs (security.txt, custom
VRP pages) works as designed.

---

## The test

```
mkdir -p /tmp/intel-test
python scripts/sentinel_ingest.py --program bugcrowd:tesla \
    --out-dir /tmp/intel-test --skip-verify -v
```

Plus probes against:

  - `https://hackerone.com/security/policy`
  - `https://bugcrowd.com/tesla`
  - `https://gitlab.com/.well-known/security.txt`

Ollama running locally, `sentinel-9b-god-tier:latest` available — so
LLM extraction was available end-to-end if it had been reached.

## Empirical findings

### Finding 1: HackerOne — Cloudflare wall

`https://hackerone.com/<handle>/policy` redirects to `/users/sign_in`,
and Cloudflare serves a "Just a moment..." bot challenge page in
front. Final HTTP status: **403**. The response body is the
Cloudflare interstitial, not HackerOne content.

```
curl -sL https://hackerone.com/security/policy
# → 403, body is <title>Just a moment...</title> challenge page
```

**Implication:** No amount of clever scraping fixes this. Cloudflare
explicitly blocks anything that isn't a real browser executing JS
challenges. We can't bypass it ethically.

### Finding 2: Bugcrowd — React SPA, empty initial HTML

`https://bugcrowd.com/<handle>` returns a 200 OK with 110KB of HTML.
**But the initial HTML is a JavaScript-only shell.** The `<main>`
element exists in the response — it just has zero text content. The
real policy data is fetched async via the React app after page load.

```
$ python -c "from bs4 import BeautifulSoup; \
             s = BeautifulSoup(open('/tmp/bc-tesla.html').read(), 'html.parser'); \
             print(len(s.find('main').get_text(strip=True)))"
0
```

There's also no embedded `window.__INITIAL_STATE__` or
`<script type=application/json>` hydration blob — the page is purely a
shell. And `https://bugcrowd.com/engagements/tesla.json` returns 406
Not Acceptable (no public JSON variant).

**The CLI hit exactly the failure mode my generic extractor was
designed to handle:**

```
[intel.generic_url] sanitized text empty for https://bugcrowd.com/tesla
❌ Extraction failed (network error, LLM unavailable, or empty page).
```

The soft-fail path worked correctly — clean error, exit code 1, no
crash. But the underlying capability is non-functional.

### Finding 3: Self-hosted (security.txt) — works as designed

`https://gitlab.com/.well-known/security.txt` returns 200 OK with 1.4KB
of real plaintext content. The generic extractor's full pipeline would
process this correctly:

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256
# Preferred disclosure is via HackerOne
Contact: https://hackerone.com/gitlab/
...
```

Generic-URL scraping for the long tail of self-hosted policy pages
remains a real capability.

## What this means for Phase 2

The architecture is **not wrong** — the data model, compilers, verifier,
registrar, policy_enforcer, and CLI are all sound and reusable. What's
wrong is the *fetch step* of the platform-specific extractors. They
were designed assuming raw HTTP GET would return the policy content;
the live test proves that assumption false for both major platforms.

**Three options to fix the platform path:**

| Option | Cost | Stability | Coverage |
|---|---|---|---|
| **A: Use platform official APIs** (HackerOne API, Bugcrowd API) | Medium — Phase 2G work, code already exists in `core/bounty/h1_client.py` | High — APIs are stable contracts | HackerOne: yes (requires token). Bugcrowd: partial (their API is less documented). |
| B: Headless browser (Playwright/Selenium) | High — heavy dependency, fragile to bot detection | Low — Cloudflare specifically detects headless browsers | Both platforms, but ToS-grey |
| C: Manual paste — operator copies policy text into a file, runs `sentinel-ingest --policy-file` | Trivial | Operator-burden | Both platforms via human in the loop |

**Recommended path: A primarily, C as a fallback.** The HackerOne API
client already exists in this repo (`core/bounty/h1_client.py`). It
fetches via HTTPS Basic Auth and returns structured DTOs. Phase 2G
should:

1. Refactor `HackerOneExtractor` to delegate to the existing h1_client
   when a token is configured
2. Add the keychain-backed token store (already in the Phase 2 design)
3. Fall back to the no-op error path when no token is available
   (the current behavior — operator gets a clear "no token; can't
   access HackerOne" message)

For Bugcrowd: investigate their API auth, similar pattern.

For self-hosted: nothing to do — already works.

## What the live test confirmed works

Despite the platform-scraping failure, several things were *empirically
verified* by the run:

- ✅ Ollama integration: `sentinel-9b-god-tier:latest` is reachable,
  model is loaded, ready to accept extraction prompts (we just never
  got that far on this run because of finding 2)
- ✅ Resolver dispatch: `bugcrowd:tesla` correctly routed to
  `BugcrowdExtractor`
- ✅ URL resolution: handle correctly mapped to canonical URL
  `https://bugcrowd.com/tesla`
- ✅ HTTP fetch: redirect chain followed correctly
  (`bugcrowd.com/tesla` → `bugcrowd.com/engagements/tesla` → 200)
- ✅ Sanitizer: correctly identified that the response had no useful
  text (empty `<main>`, all scripts stripped, no fallback signal)
- ✅ Soft-fail path: returned None → CLI returned exit 1 with a clean
  operator-visible error message; no crash, no silent bad data
- ✅ CLI hygiene: clean exit code, output files not created (correct
  — there was nothing to compile)

This is the *Phase 1 calibration philosophy* working as intended. The
ingest pipeline detected its own failure and refused to produce garbage
output, instead of silently writing a `tesla-personas.json` that
contained nothing.

## Path forward — revised priorities

Before this run, Phase 2G (token storage) was framed as "Phase 2G:
secure token storage — unlocks private programs which is most of the
high-payout bounty work" — implying token-gated programs were a
nice-to-have layered on top of working public scraping.

After this run, the framing is:

> **Phase 2G is the only working path to ingesting HackerOne and
> Bugcrowd programs at all.** Public scraping is non-functional. The
> token store + API integration is critical-path.

Revised Phase 2 sequencing:

1. **Phase 2G-A** — Refactor `HackerOneExtractor` to delegate to
   `core/bounty/h1_client.py` when a token is configured. The h1_client
   already exists; the work is wiring + error handling. ~150 LOC.

2. **Phase 2G-B** — Token store: macOS Keychain primary, file fallback.
   Independent of 2G-A. ~120 LOC.

3. **Phase 2G-C** — Bugcrowd API client. Investigate Bugcrowd's API
   auth, build a similar client. ~250 LOC.

4. **Phase 2G-D** — Fall-back UX: when no token is available, CLI
   surfaces a clear instruction:
   `"hackerone:gitlab" requires an API token. Generate one at
   https://hackerone.com/settings/api_token/edit and store with
   `sentinel-token add hackerone <token>`.`

5. **Live re-test** — Re-run today's test with token configured;
   confirm the official-API path produces clean output.

## How the user can actually use this today

For now, until Phase 2G ships:

- ✅ **Self-hosted programs** (security.txt, in-house VRP pages):
  `sentinel-ingest --program https://example.com/security.txt` works.
- ⚠ **HackerOne programs**: blocked until 2G ships. The pipeline
  will reject with a clear error.
- ⚠ **Bugcrowd programs**: blocked until 2G ships.
- ✅ The compilers (scope, personas, restrictions) and policy_enforcer
  all work on any `ProgramScope` object — including ones operators
  hand-construct in Python or via a future `--policy-file` flag.

## Aggregate Phase 2 stats — at the live-test gate

- 338 tests passing (245 intel + 93 Phase 1 adjacent)
- 7 new modules in `core/intel/` (program_scope, llm_extraction,
  resolver, verifier, registrar, policy_enforcer, plus compilers and
  extractors packages)
- 1 CLI script (`scripts/sentinel_ingest.py`)
- 1 design doc (`docs/PHASE_2_DESIGN.md`)
- 1 live test that surfaced a critical empirical truth that 245 unit
  tests couldn't have caught

Zero regressions in Phase 1 code throughout.

The exact thing Phase 1 calibration was designed to surface — "the
bugs that surface in real scans are not the bugs you'd guess from
reading the code" — applies just as cleanly to Phase 2 architecture
verification.
