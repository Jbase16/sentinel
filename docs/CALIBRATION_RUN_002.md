# Calibration Run #2 — 2026-05-14

Second end-to-end Phase 1 calibration. Goal: verify Bug #1 (PATH shadowing)
and Bug #2 (token-rotation race) fixes hold under load, then continue
diagnosing the "only one tool runs" symptom.

**Verdict:** Bug #1 fix landed. Bug #2 fix landed and held throughout the
scan. The "only one tool runs" symptom turned out to be a **third bug**,
not a consequence of the first two — a Strategos walk-away decision
triggered by the loopback-target safety policy.

---

## Setup (delta from RUN_001)

| Component | RUN_001 | RUN_002 |
|---|---|---|
| `require_auth` default | True (Phase 0) | True |
| AI model | `qwen3:8b` override | `sentinel-9b-god-tier` (default) |
| PATH normalization | none — venv shadowed Homebrew | **prepended at startup** |
| Token source | regen-per-config | env → **file** → generate |
| `get_config()` lock | none | **threading.Lock** |
| `_write_token_file()` | always writes | **idempotent** |
| cas.py / ledger.py | direct `from_env()` | uses `get_config()` |

Session ID: `b1dfa440-99e1-426d-bad0-eb29e7377f10`

---

## Bug #1 — PATH shadowing — FIXED

Backend startup logged the fix taking effect:

```
[Startup] PATH normalised; prepended:
  ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin',
   '/usr/sbin', '/sbin', '/Users/jason/go/bin']
```

Result: when the engine subprocesses call `shutil.which("httpx")`, they
now get `/opt/homebrew/bin/httpx` (the ProjectDiscovery binary), not the
Python HTTP library from a neighbouring venv.

Tests pinning the invariant: `tests/unit/test_config_singleton.py::TestPathNormalization`
(4 tests, all passing).

## Bug #2 — token-rotation race — FIXED

The smoking gun in RUN_001 was a `[Config] API token written` log line
**4 minutes after startup**, indicating a second `SentinelConfig` was
materializing mid-scan and clobbering the token file.

Root cause was not a true race — it was **`core/epistemic/cas.py:30`** and
**`core/epistemic/ledger.py:145`** calling `SentinelConfig.from_env()`
directly instead of `get_config()`. Every CAS / EvidenceLedger
instantiation during scan execution created a fresh config (with a fresh
random token), wrote it to disk, and broke auth.

RUN_002 backend log around scan time:

```
16:40:24,544 [INFO] core.epistemic.ledger: [EvidenceLedger] Recorded Observation ...
16:40:47,602 [INFO] core.epistemic.ledger: [EvidenceLedger] Promoted Finding ...
```

EvidenceLedger was active during the scan — **but no `API token written`
line followed.** The token file was untouched, auth never desynchronised,
and `curl -H "Authorization: Bearer $(cat ~/.sentinelforge/api_token)"`
returned HTTP 200 after the scan completed. Fix held.

Tests pinning the invariants:
`tests/unit/test_config_singleton.py::TestSingletonStability` (6 tests,
including a concurrent-threads stress test).

The full fix has four parts:
1. `from_env()` reads existing token from `~/.sentinelforge/api_token`
   (env → file → generate)
2. `get_config()` holds a `threading.Lock` around materialisation
3. `_write_token_file()` is idempotent (no-op if file matches in-memory)
4. `cas.py` / `ledger.py` switched from `from_env()` to `get_config()`

---

## NEW Bug #7 — Strategos walks away when surface-enum is policy-skipped

This is the real reason only `httpx` runs against Juice Shop.

### Reproduction

Calibration scan against `http://127.0.0.1:3000` (Juice Shop) with
`bug_bounty` mode. The backend log captures the full chain:

```
[Strategos] Dispatching: httpx (1/3)
[ScannerEngine] SCAN_BEGIN scan_id=... session_id=... target=http://127.0.0.1:3000
[EvidenceLedger] Recorded Observation ... httpx -> ...
... (httpx runs successfully against Juice Shop, finds 6 missing-header issues) ...
[ScanCommit] findings=6 issues=0 evidence=1
[Strategos] ✓ httpx complete. Findings: 6
[Strategos] Progress: phase=2 active_tools=1/3 ...

[Strategos] Decision: Executing intent_surface_enum
[Strategos] Policy: Blocked host-wide port scanners ['nmap', 'naabu']
            — target is loopback                        ← (1)
[Narrator] DEFENSE: Blocked 2 tools [nmap, naabu] by Policy:
           Host-wide port scanning is irrelevant for loopback targets.
[Strategos] No tools available for intent_surface_enum. Skipping.  ← (2)
[Strategos] Walk Away: No new surface discovered.
            Aborting deep scan.                         ← (3)
[Narrator] MISSION: Terminating scan. No new attack surface
           discovered in surface enumeration phase
```

### Diagnosis

(1) is correct. Host-wide port-scanning loopback is genuinely useless.
The policy is doing its job.

(2) is *also* correct. Once nmap/naabu are blocked, the surface_enum
intent has no runnable tools, so the engine skips that intent. Fine.

(3) is the bug. The walk-away heuristic interprets "this phase ran zero
tools" as "no new surface discovered, abort the scan." But the phase
didn't run zero tools because *no surface existed* — it ran zero tools
because *every selected tool was policy-blocked*. Those are completely
different situations:

- "No surface found" → walk away is correct (nothing more to investigate)
- "All tools policy-blocked for this phase" → continue to the next phase
  with whatever surface was already established (httpx found URLs!)

The engine conflates them. As a result, every scan against a loopback
target stops after `httpx`, even though `nuclei`, `nikto`, and the
mutation engines could have run against the surface httpx discovered.

### Likely fix location

`core/scheduler/strategos.py` — search for "Walk Away" and the
`early_termination` decision emitter. The heuristic needs to distinguish:
- `surface_growth == 0 AND tools_run > 0` → real walk-away signal
- `surface_growth == 0 AND tools_run == 0 AND tools_blocked > 0` → skip
   the intent, continue to next intent without aborting

### Why this matters for bug-bounty work

Real bounty targets are not on loopback — they're on the public internet,
which means the loopback policy won't fire. So Bug #7 doesn't affect
real bounty scans directly. But it **does** break our calibration loop
against the lab. We have two options:

1. **Fix Bug #7** — the engine becomes more robust regardless. The fix
   is small (one heuristic in Strategos) and improves any future
   scenarios where a policy legitimately blocks a phase's tools.

2. **Bypass the loopback policy for the lab** — give Juice Shop a
   non-loopback hostname (Docker networking trick) so the policy
   doesn't fire. Doesn't fix the bug, but unblocks calibration.

Path 1 is the right call. Path 2 papers over real engine behaviour the
user would want to know about.

---

## Other Phase 1 findings from this run

### Win: AI-engine integration is live

Log line at 16:40:24,539 then 16:40:47,601:
```
httpx: HTTP Request: POST http://localhost:11434/api/generate "HTTP/1.1 200 OK"
```

Ollama was called during scan processing — the AI engine is correctly
classifying httpx output and proposing next steps. This is the first
empirical confirmation that the Ollama integration works end-to-end with
the locally-loaded `sentinel-9b-god-tier` model. Accounts for the bulk
of the 23s wall time.

### Win: dedup store is real and active

```
[FindingsStore] Duplicate finding detected: 03be8f5517c3
                (first seen 2026-02-24T05:04:46, seen 126x)
[FindingsStore] Duplicate finding detected: 851c84504dc2
                (first seen 2026-05-15T05:02:04, seen 22x)
```

The dedup store recognised findings from previous test runs going back
to February — meaning the engine has been remembering findings across
restarts via the SQLite store. Real persistence; this is the
foundation for "don't keep submitting the same bug" behaviour.

### Carry-over from RUN_001 (still open)

- **Bug #3 — Session table writes timestamp as Unix float string instead
  of ISO datetime.** Confirmed again in RUN_002: session `b1dfa440…`
  has `start_time: 1778888424.50003`. Inspector handles both formats now
  (read-side band-aid); the writer still needs the real fix.

- **Bug #4 — Session lifecycle never closes.** Session row stuck at
  `status: Created` even though `scans` row went `committed`.

- **Bug #5 — Findings not promoted to issues.** 6 findings, 0 issues
  again. Hold for re-evaluation after Bug #7 is fixed and more diverse
  tools produce findings.

---

## Suggested next move

Fix **Bug #7** (Strategos walk-away). One-function change in
`core/scheduler/strategos.py`. Add a test that asserts: when a phase has
no runnable tools because all candidates were policy-blocked, the engine
proceeds to the next intent instead of terminating.

After Bug #7 is fixed, re-run the calibration. Expected outcome:
- `nuclei` and `nikto` run against Juice Shop's discovered URLs.
- Findings table grows beyond 6 generic header findings.
- Some Juice Shop Scoreboard items get found.

If RUN_003 produces more diverse findings, we've cleared the first
calibration milestone and can start grading against the Scoreboard
specifically.

---

## Test summary

| Suite | Before RUN_002 | After RUN_002 fixes |
|---|---|---|
| `tests/unit/` | 273 | 283 (+10 new singleton/PATH tests) |
| `tests/security/` | 105 | 105 (unchanged) |
| Total | 378 | **388**, zero regressions |
