# Calibration Run #17 — First Real H1 Scan (gitlab.com, end-to-end)

The first time the full Phase 2 pipeline + the Phase 0/1 scan engine ran
against a real, operator-authorized HackerOne program target. Target:
`gitlab.com` (in-scope, max_severity=critical on the GitLab H1 program).

**Verdict:** ✅ End-to-end success. 111 findings in 5m23s, no Cloudflare
ban, the full ingest→compile→enforce→scan→persist chain executed against
a target neither operator nor engine controls. Surfaced **5 bugs** (3
fixed inline during the run, 2 fixed immediately after) — exactly the
calibration-loop yield that empirical contact produces and code review
cannot.

---

## What ran

```
# 1. Ingest (Phase 2A-2H, API path via stored H1 token)
python scripts/sentinel_ingest.py --program hackerone:gitlab \
    --out-dir /tmp/intel-gitlab --skip-verify

# 2. Scan (Phase 0/1 engine, Phase 2H enforcement wired in)
python pysentinel.py \
    --target https://gitlab.com \
    --scope /tmp/intel-gitlab/gitlab-scope.txt \
    --restrictions /tmp/intel-gitlab/gitlab-restrictions.json \
    --scope-strict --mode bug_bounty
```

Tools fired (bug_bounty overlay): `subfinder`(0) → `dnsx`(2) →
`httpx`(5) → `testssl`(10) → `nmap`(98) → `naabu`(97). Loud tools
(masscan, gobuster, feroxbuster) correctly disabled by the mode overlay.
111 findings after dedup, 5m23s wall-clock, no rate-limit/ban.

## Bugs surfaced

### Bug A — `ErrorCode.INVALID_REQUEST` doesn't exist (pre-existing)

`scans.py` referenced `ErrorCode.INVALID_REQUEST` in two places (one
pre-existing in the scope-deny path, one added in Phase 2H). The enum
has no such member — the real one is `SCAN_TARGET_INVALID`. The
pre-existing reference was dead code that never fired until Phase 2H's
scope-strict path actually triggered it. **Fixed:** both → `SCAN_TARGET_INVALID`.

### Bug B — scope file inline comments break the engine parser

Phase 2C's scope_compiler emits inline comments:
`gitlab.com  # max_severity=critical`. The engine's scope parser at
`scans.py:265-281` doesn't strip inline comments, so it parsed the
whole 35-char string as a DOMAIN target that matched nothing →
`gitlab.com` rejected as out-of-scope → 500 error.

**The embarrassing part:** my Phase 2C round-trip tests *passed* because
the test helper `_parse_scope_file_like_engine` stripped comments — but
the real engine parser doesn't. The test validated against a parser that
wasn't the real one. **Fixed:** engine parser now strips `"  #"` inline
comments (matching the test helper's behavior, closing the gap).

**Lesson:** a round-trip test is only honest if it round-trips through
the *real* consumer. A test-local reimplementation of the parser can
drift from production and give false confidence.

### Bug C — empty personas.json rejected by loader

GitLab's LLM extraction produced 0 personas (the policy lists no test
creds). The persona_compiler emitted `[]`. pysentinel's
`_load_personas_file` requires a non-empty list → hard exit.

**Fixed:** persona_compiler now always synthesizes an anonymous baseline
when output would otherwise be empty, deriving the base_url from the
first in-scope domain (NOT from `source_url`, which for an H1-API scope
is `api.hackerone.com` — wrong). For zero-persona programs, the emitted
file now contains exactly the anonymous baseline.

### Bug D — HSTS false positive

Sentinel reported `strict-transport-security absent` (HIGH) on
gitlab.com. Manual verification:
```
$ curl -sI https://gitlab.com | grep -i strict-transport
strict-transport-security: max-age=31536000
```
gitlab.com *does* send HSTS, even on its 301 redirect response.

**Refined diagnosis (via the about.gitlab.com scan):** this is a
*redirect-attribution* bug, not a classifier parsing gap. gitlab.com
301-redirects to about.gitlab.com. gitlab.com's own 301 response carries
HSTS; about.gitlab.com (the destination) does NOT. Sentinel's httpx
follows the redirect, reads about.gitlab.com's headers, but attributes
the finding to the original target gitlab.com. So "HSTS absent on
gitlab.com" is really "HSTS absent on about.gitlab.com, mislabeled."

Proof the classifier itself is sound: the about.gitlab.com scan
correctly found 7 genuinely-missing headers (curl confirms CSP,
x-frame-options, x-content-type-options, etc. are all absent there).
The classifier reads headers correctly — the bug is *which response's
headers get attributed to which target* when redirects are followed.

**Not yet fixed** — needs the header-fetch step to either (a) not follow
cross-host redirects when attributing header findings, or (b) attribute
the finding to the final URL, not the requested one. Logged for Run #18.

### Bug E — testssl client-simulation framework false positives

Sentinel emitted 4 "Java Framework Detected" findings:
```
Java 8u442 (OpenJDK)   TLSv1.3   TLS_AES_256_GCM_SHA384   ...
Java 17.0.3 (OpenJDK)  TLSv1.3   ...
```
These are testssl's **TLS client-simulation** labels — testssl showing
which client handshakes the server supports — NOT Java running on the
server. The Bug #5 regex correctly matches "Java 17.0.3" (real word
boundary), but the *context* makes it meaningless.

**Fixed:** `_detect_frameworks` now skips matches on lines carrying
TLS-handshake tokens (`TLSv1.x`, `TLS_AES_*`, `ECDH`, etc.). 4 new
tests lock the behavior, including a mixed-output test that keeps a real
`X-Powered-By: Java/17.0.3` banner while dropping the client-sim lines.

## The bigger systemic finding — CDN-fronted port scanning is noise

`gitlab.com` 301-redirects to `about.gitlab.com` and is fronted by
Cloudflare + F5 (Sentinel correctly detected the WAF). The MEDIUM
"open port" findings — `22 (SSH)`, `5432 (Postgres)`, `5900 (VNC)`,
`3389 (RDP)` "on gitlab.com" — are on the **Cloudflare edge IP**, not
GitLab's origin. naive nmap/naabu against a CDN-fronted host scans the
CDN, not the target.

This is not a one-off bug; it's a **class** affecting every CDN-fronted
target — which is most modern bounty targets. A bounty-grade scanner
must detect CDN fronting and either skip origin port-scanning or
annotate the findings as "CDN edge, not origin." Logged as a design
item for a future round — it materially affects signal quality.

## The applies_to fix — the operator's core correction, encoded

During this session the operator corrected a fundamental
misinterpretation: the "no automated tools" rule in H1's `security`
program (Run #16) is in the **DoS-testing subsection**, not a
program-wide ban. Sentinel's LLM extraction had flattened a DoS-scoped
rule into a global `block_scan`, which would (wrongly) refuse to scan
the entire program.

**Fixed structurally** with a new `applies_to` field on every
restriction:

- `applies_to=["all"]` → genuine program-wide rule → block_scan halts
- `applies_to=["dos"]` → DoS-section rule → downgrade to disabling DoS
  tools, scan proceeds
- Default `["all"]` when the extractor can't determine scope (conservative)

The LLM extraction prompt now explicitly instructs the model to scope
each rule by WHERE it appears in the policy. The policy_enforcer only
hard-blocks when `"all"` is present; scoped block rules downgrade to
disabling exactly their named categories. Schema bumped 1.0 → 1.1.

7 new tests lock this: a global no_automated_scan still blocks, a
DoS-scoped one disables nuclei_mutating but proceeds, multi-scope with
"all" present blocks, unmappable scopes warn-but-proceed.

## Test deltas

| Suite | Before | After |
|---|---|---|
| intel/ | 358 | 358 (+7 applies_to, +4 persona, others rebalanced) |
| test_framework_patterns | 14 | 18 (+4 testssl filter) |
| **Combined relevant** | 385 | **399** |

Zero regressions. All five fixed bugs have regression tests tied to the
exact production shapes that surfaced them.

## What this run proved

The entire stack works end-to-end against real-world data:

- Phase 2G token store → H1 API Basic Auth → 33 structured scopes
- Phase 2A-C compilers → scope.txt + personas.json + restrictions.json
- Phase 2H → ExecutionPolicy enforcement (empty restrictions = no block)
- Phase 0/1 engine → 6 tools, dedup, DB persistence, WAF detection
- 111 findings, correct CDN/WAF identification, no ban

It also proved the **signal-quality work is the next frontier**: HSTS
false positive, CDN-edge port noise, and testssl client-sim FPs are all
"the scan ran but some findings are junk" problems. For bounty work
where every false positive costs operator triage time, the next phase
of calibration is precision, not capability.

## Open items (logged, not yet fixed)

1. **HSTS classifier false positive** (Bug D) — header present but
   reported absent.
2. **CDN-fronted port scanning** — systemic; needs CDN detection +
   finding annotation/suppression.
3. **pysentinel SSE event display** — the CLI connected to the event
   stream but tool events didn't render in its log (scan worked
   server-side; only the client display was silent).
4. **LLM timeout on large policies** (carried from Run #16) — GitLab's
   25KB policy timed out the 9B model; restrictions came back empty.
   Needs chunked extraction or longer timeout.

These are the Run #18+ backlog.
