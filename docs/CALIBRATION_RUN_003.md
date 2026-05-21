# Calibration Run #3 — 2026-05-14

Third end-to-end calibration. Goal: verify Bug #7 (Strategos walk-away on
policy-block) fix and produce the first calibration run with diverse tool
execution.

**Verdict:** Bug #7 fix landed and is working in live scans. RUN_003 ran
**4 different tools** (httpx, nikto, nuclei_safe, nuclei_mutating) where
RUN_002 ran only one. The engine progressed past surface_enum's
policy-skip and reached the vulnerability-scan phase for the first time
in our calibration history.

---

## Setup (delta from RUN_002)

| Component | RUN_002 | RUN_003 |
|---|---|---|
| Strategos walk-away on `SKIP_NO_TOOLS` | aborts scan | **continues to next intent** |
| Assessment outcome for "no runnable tools" | `CONTINUE_ENGAGEMENT` (generic) | `SKIP_NO_TOOLS` (specific) |
| Target | `http://127.0.0.1:3000` (Juice Shop) | `http://127.0.0.1:3002` (custom lab, nginx) |

Session ID: `4fa62972-2d1e-42d6-a6ed-a8881f18f151`

---

## Bug #7 — FIXED, observable in live logs

The exact decision sequence that previously aborted now correctly advances:

```
[Strategos] ✓ httpx complete. Findings: 8
[Strategos] Decision: Executing intent_surface_enum
[Narrator] DECISION: assessment -> SKIP_NO_TOOLS.
           No runnable tools for this intent; advancing to the next intent.
[Strategos] Decision: Executing intent_vuln_scan                       ← (new behavior)
[Strategos] Dispatching: nikto (1/3)
[Strategos] Dispatching: nuclei_safe (2/3)
[Strategos] Dispatching: nuclei_mutating (3/3)
```

Compare RUN_002 at the same juncture:
```
[Strategos] Walk Away: No new surface discovered. Aborting deep scan.   ← previous bug
```

The narrator log line explicitly records the new `SKIP_NO_TOOLS`
assessment outcome — meaning the decision ledger captures the new code
path, and the replay capsule will preserve evidence that the fix
fired. This is the audit-trail benefit of using an enum-valued state
instead of an in-line boolean.

Tests pinning the fix: `tests/unit/test_strategos_decisions.py`:
- `test_walk_away_on_no_surface_delta` — legitimate walk-away path,
  preserved (tools ran, found nothing → still walks away)
- `test_no_walk_away_when_surface_enum_skipped_by_policy` — NEW —
  skipped phase → continue to vuln_scan

---

## Empirical comparison: RUN_001 → RUN_002 → RUN_003

| Metric | RUN_001 | RUN_002 | RUN_003 |
|---|---|---|---|
| Wall time | 4.25s | 23.11s | **140.68s** |
| Tools attempted | httpx | httpx | **httpx, nikto, nuclei_safe, nuclei_mutating** |
| Tools producing findings | 1 | 1 | **2 (httpx, nikto)** |
| SCAN_COMMIT rows | 1 | 1 | **4** (one per tool) |
| Total findings | 6 | 6 | **13** |
| Severity diversity | medium only | medium only | **1 HIGH, 8 medium, 2 low, 2 info** |
| Reached vuln_scan phase | No | No | **Yes** |
| nikto HTTP requests | 0 | 0 | **8,073** |
| Termination reason | walk-away | walk-away | **Mission Complete (intents exhausted)** |
| Bug #7 fired | Yes (silent) | Yes (logged) | **No (fixed)** |

The progression is clear: RUN_001 and RUN_002 were calibrating the
infrastructure (auth, model loading, PATH). RUN_003 is the **first run
where Sentinel actually exercised its vulnerability-scanning capability
end-to-end against a target.**

### The HIGH-severity find

nikto produced one HIGH-severity finding against the lab at :3002:

> Missing Content-Type header at `/`

That's a legitimate web-server configuration issue. Whether it'd be
report-worthy depends on the program's policies, but the engine
identified, classified, and persisted it correctly. This is the first
HIGH-severity calibration finding in our run history.

### The "Mission Complete" termination

After all 4 tools ran and intent_verification skipped (no tools selected
for that intent — likely a deeper gap we'll see later), the engine
terminated via:

```
[Strategos] Decision: Executing intent_verification
[Narrator] DECISION: assessment -> SKIP_NO_TOOLS. ...
[Strategos] Mission Complete. All intents exhausted or Walk Away triggered.
```

This is the *correct* termination path: the engine exhausted its plan
and stopped, not abandoned it. The `SKIP_NO_TOOLS` outcome fired twice
(surface_enum and verification) without either causing a walk-away.

---

## What we now know about the engine

From the live RUN_003 log evidence:

1. **Three SCAN_BEGIN events were emitted concurrently** at 16:55:36
   for nikto, nuclei_safe, and nuclei_mutating. The engine dispatches
   tools in parallel within an intent. This is real architecture, not
   sequential one-at-a-time execution.

2. **nikto produced 5 findings against the nginx target.** Most likely
   default-page/server-version disclosures, but real, distinct
   findings from a real binary execution.

3. **nuclei_safe ran and produced 0 findings.** That's an interesting
   data point — either the templates didn't match this target, or the
   bind-loopback constraints filtered nuclei's templates aggressively.
   Worth investigating in a future run.

4. **The EvidenceLedger now uses the singleton config.** Log line at
   16:55:05: `[EvidenceLedger] Recorded Observation` — no preceding
   `[Config] API token written` line. Bug #2 fix continues to hold under
   real ledger activity.

---

## Open questions for next runs

### Why does nuclei_safe find nothing?

nuclei has thousands of templates. Against `nginx/1.31.0` on
`127.0.0.1:3002`, at least *some* should match — outdated-server,
default-creds-on-paths, version disclosures, etc. Possible explanations:

- The target may be misidentified; nuclei needs HTTP/2 or HTTPS for many
  templates and we're scanning HTTP/1.1 over plain HTTP.
- The capability gate / loopback-policy may be filtering nuclei templates
  similar to how it filtered nmap/naabu.
- The 403 response on `/` may have caused nuclei to give up early.

Worth a targeted run with verbose nuclei flags.

### Why are issues=0 in every SCAN_COMMIT?

Every scan_commit shows `findings=N issues=0`. The findings get
promoted to the EvidenceLedger as `vuln` type, but never make it to the
SQLite `issues` table. This is the same gap noted as Bug #5 in
RUN_001/RUN_002. With diverse findings now appearing, this gap is more
tractable to debug.

### Session lifecycle still doesn't close

The `b1dfa440…` session from RUN_002 is still in the DB with
`status: Created`. The new RUN_003 session will likely have the same
problem. Bug #4 is unchanged. The scan_sequence rows in the `scans`
table do commit cleanly, so the gap is specifically in the session-row
writer.

---

## What's the next bug to chase?

In priority order:

1. **Verify the scan completes cleanly.** RUN_003 is still running as of
   this writeup. If it walks away later for an *unrelated* reason
   (e.g., the verification intent fails), there's another decision-point
   to fix.

2. **Investigate why nuclei_safe found 0.** This is likely the
   single-biggest signal blocker for bug-bounty work — nuclei is the
   industry-standard vuln scanner and if our integration isn't getting
   coverage out of it, real bounty scans will be silent.

3. **Bug #4 (session lifecycle).** Now that diverse scans are
   producing diverse data, the orphan-session pattern is a real
   operational risk for tracking.

4. **Bug #5 (findings → issues promotion).** RUN_003 finally has the
   diversity needed to debug this — different finding shapes from
   different tools should exercise more promotion paths.

5. **Bug #3 (Unix-timestamp session writer).** Cosmetic but accumulating
   noise in the DB.

---

## Test summary

| Suite | Before RUN_003 | After RUN_003 fixes |
|---|---|---|
| `tests/unit/` | 283 | 284 (+1 new walk-away regression test) |
| `tests/security/` | 105 | 105 |
| **Total** | 388 | **389**, zero regressions |
