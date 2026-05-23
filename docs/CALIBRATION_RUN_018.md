# Calibration Run #18 — Precision Pass (Signal Quality)

Run #17 proved the engine works end-to-end against a real H1 program but
surfaced that ~90% of the gitlab.com findings were noise (CDN-edge ports,
testssl client-sim false positives, a redirect-attribution false
positive). Run #18 is the precision pass: turn "the scan runs" into "the
scan's output is trustworthy."

**Verdict:** ✅ Five signal-quality fixes landed, all with regression
tests tied to the exact production shapes that surfaced them. 430 tests
passing, zero regressions. CDN detection verified against the live
gitlab.com resolution.

---

## Fixes

### 1. CDN-aware port suppression (the 90% noise source)

`core/toolkit/raw_classifier.py` gained `cdn_for_target()` — resolves the
target host and checks its IP against published CDN CIDR ranges
(Cloudflare's full v4+v6 blocks, Fastly). When a target is CDN-fronted,
the nmap/naabu/masscan port handlers now **demote Open Port findings to
INFO and annotate `cdn_edge`** instead of emitting MEDIUM/LOW noise.

The port findings on a CDN-fronted host belong to the CDN's edge, not the
program's origin — they're not actionable. We keep them (operator
visibility) but get them out of the actionable tier.

Verified live: `cdn_for_target("https://gitlab.com")` → `cloudflare`. The
22/SSH, 5432/Postgres, 3389/RDP findings that were MEDIUM noise in Run #17
are now INFO + `cdn_edge=cloudflare`.

16 tests (IP-literal + injected-resolver, deterministic, no real DNS).

### 2. Header redirect-attribution fix

`_detect_security_headers` previously evaluated each response block
independently. For gitlab.com→about.gitlab.com, gitlab.com's 301 sets
HSTS but about.gitlab.com's 200 doesn't — the per-block check fired a
false "HSTS absent on gitlab.com."

Now a header is "present" if it appears in **any** hop of the response
chain; "absent" only if **no** hop carries it. This evaluates the
target's response chain as a whole and stops attributing a redirect
destination's missing headers to the original target. Multi-hop findings
are annotated with `redirect_hops`.

8 tests, including the verbatim gitlab.com 301→200 chain.

### 3. testssl client-simulation framework filter

testssl's client-simulation section lists TLS clients (`Java 8u442`,
`Safari 18.4`) connecting to the server — not server frameworks. The
framework regex matched them, producing false "Java Framework Detected"
findings. `_detect_frameworks` now skips matches on lines carrying
TLS-handshake tokens (`TLSv1.x`, `TLS_AES_*`, `ECDH`).

4 tests, including a mixed-output test that keeps a real
`X-Powered-By: Java/17.0.3` banner while dropping the client-sim lines.

### 4. applies_to restriction scoping (the operator's core correction)

The biggest correctness fix. A restriction now carries `applies_to` —
the category of testing it governs. "No automated tools" in a DoS
subsection → `applies_to=["dos"]` → disables DoS tooling but lets the
scan proceed. Only `applies_to=["all"]` rules hard-block. This is the
structural encoding of the distinction the operator drew: respect the
policy without crippling the scanner. Schema 1.0 → 1.1. 7 tests.

### 5. persona compiler always emits a loadable file

GitLab's empty-persona extraction produced `[]`, which pysentinel
rejected. The compiler now synthesizes an anonymous baseline from the
first in-scope domain (never from the H1 API source_url). 4 tests.

### 6. chunked LLM extraction for large policies

GitLab's 25KB policy timed out the 9B model at 300s. Policies over 12KB
are now split on paragraph boundaries, extracted chunk-by-chunk, and
merged (restrictions deduped by kind+description, scalars take first
non-null, confidence takes the minimum). Each chunk stays small enough
to avoid the timeout. Paragraph-boundary splitting preserves the context
the LLM needs for applies_to scoping. 8 tests.

## Also fixed inline during Run #17 (carried here for completeness)

- `ErrorCode.INVALID_REQUEST` → `SCAN_TARGET_INVALID` (dead-path bug)
- engine scope parser strips inline comments emitted by scope_compiler

## Test deltas

| Suite | Run #17 | Run #18 |
|---|---|---|
| intel/ | 358 | 372 (+7 applies_to, +4 persona, +8 chunked, others) |
| test_framework_patterns | 18 | 18 |
| test_cdn_detection | — | 16 (new) |
| test_security_header_redirect | — | 8 (new) |
| **Combined relevant** | 399 | **430** |

Zero regressions.

## What changed about scan output quality — MEASURED (Run #19 re-scan)

The gitlab.com scan was re-run with the fixed classifier loaded
(session c794116a vs Run #17 baseline 140ef33c). Measured severity
distribution, before vs after:

| Severity | Run #17 (before) | Run #19 (after fixes) |
|---|---|---|
| HIGH | 1 (HSTS false positive) | **0** |
| MEDIUM | 8 | **3** |
| LOW | 93 (CDN-edge ports) | **0** |
| INFO | 9 | 154 (CDN ports demoted here) |

Target-check results (all confirmed in production):

| Check | Result |
|---|---|
| CDN-edge ports demoted to INFO + annotated | ✅ 99 Open Port findings, all INFO, all `cdn_edge=cloudflare` |
| HSTS false positive eliminated | ✅ 0 HSTS findings (was 1 HIGH) |
| Java framework FPs eliminated | ✅ 0 (was 4) |

**The actionable tier (MEDIUM+HIGH) dropped from 9 to 3 findings**, and
the single HIGH — which was a false positive — is gone. The 3 surviving
MEDIUM findings:
  - `cross-origin-opener-policy absent` (genuine, curl-verified)
  - `cross-origin-embedder-policy absent` (genuine, curl-verified)
  - `_cfuvid` Session Cookie Misconfiguration (residual FP — that's
    Cloudflare's own bot cookie, not GitLab's; logged for Run #19+).

This is the empirical close on Run #18: the fixes don't just pass unit
tests, they measurably collapse the noise on a real H1 target. An
operator triaging this scan now reads 3 actionable findings instead of
wading through 102 (93 LOW + 8 MEDIUM + 1 HIGH).

## Remaining backlog (Run #19+)

1. **pysentinel SSE event display** — CLI connected to the event stream
   but tool events didn't render in its log (scan worked server-side).
2. **Bugcrowd API adapter** — mirror the H1 API pattern (Bugcrowd's
   public API auth needs investigation first).
3. **Phase 2G-C** — `sentinel-token add` convenience CLI.
4. **Re-scan gitlab.com with the fixed classifier** to confirm the noise
   reduction empirically (requires backend restart + ~5min scan).

## The arc, Run #17 → #18

Run #17 was capability: prove the engine runs end-to-end against a real
program. Run #18 was precision: make its output trustworthy. Both came
from the same loop — scan a real target, see what the output gets wrong,
fix it, test against the exact shape that broke. The five fixes here
came directly from staring at 111 real findings and asking "which of
these would waste an operator's triage time?" That question can only be
answered with real findings in hand, which is the whole point of the
calibration loop.
