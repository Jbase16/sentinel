# Calibration Run #1 — 2026-05-14

First end-to-end Phase 1 calibration scan against Juice Shop.

**Summary:** The pipeline works — auth, scope, scheduler, DB writes, event
streaming, lifecycle, CAL policies — all functioned end-to-end. Only one
tool actually executed (`httpx`), but the scheduler progressed through all
5 phases and made 50 decisions. The scan completed cleanly in 4.25s with
6 findings.

**Verdict:** The rig is alive. Now we know what to fix.

---

## Setup

| Component | State |
|---|---|
| Backend | `127.0.0.1:8765`, `require_auth=true`, started clean |
| Lab | Juice Shop v17.2.0 on `127.0.0.1:3000` |
| Model | `sentinel-9b-god-tier` loaded into Ollama (17 GB gguf symlinked into `./models/`) |
| Scope | 7 rules from `scripts/lab/juice-shop-scope.txt`, `--scope-strict` |
| Mode | `bug_bounty` |

Session ID: `fb1f374c-4f28-4fdc-b95a-24880b5fcc18`

---

## What worked

1. **Phase 0 auth-flip is real.** Sensitive endpoints (`/v1/scans/start`,
   `/v1/forge/compile`) return HTTP 401 without a token, HTTP 401 with a
   wrong token, and accept the right token. Public liveness endpoints
   (`/v1/ping`, `/v1/health`, `/v1/status`) are open by design.

2. **Scheduler progresses through all 5 phases.** The decisions table shows:
   - `intent_passive_recon` → `intent_active_live` → `intent_surface_enum`
     → `intent_vuln_scan` → `intent_heavy_artillery`
   - `phase_transition` to PHASE_1, 2, 3, 4, 5 all recorded
   - Tool selection is sensible per intent (e.g. nuclei/nikto for vuln_scan)

3. **Scope enforcement engaged.** Every URL was checked against the bounty
   scope; the scan stayed pinned to `127.0.0.1`.

4. **Event stream is live.** SSE events flowed in real time:
   `scan_started`, `tool_started`, `tool_completed`, `scan_completed`.

5. **DB writes succeeded.** 1 session row, 1 scan row (`status=committed`),
   6 findings, 1 evidence, 50 decisions all persisted.

6. **The boot interlock did its job at startup.** Backend bound `127.0.0.1`
   with `require_auth=true`; no `CriticalSecurityBreach`.

---

## What didn't work (the real bugs)

### Bug #1 — PATH shadowing: wrong `httpx` is being invoked  [BLOCKER]

The scheduler selected several tools per phase (nuclei, nikto, subfinder,
dnsx, gobuster) but **only one tool actually ran** — and it ran the wrong
binary:

```
$ which httpx
/Users/jason/venvs/chatgpt-cli/bin/httpx        # ← Python HTTP library
$ /opt/homebrew/bin/httpx --version
   __    __  __       _  __                     # ← ProjectDiscovery Go tool
  / /_  / /_/ /_____ | |/ /
```

The `httpx` resolved by `shutil.which()` is the Python HTTP library from a
neighbouring venv, not the ProjectDiscovery binary the engine expects.
This explains:
- Why all 6 findings are generic "Missing Security Header" (the Python
  httpx returned response headers; nothing security-specific parsed them).
- Why no `nuclei` / `nikto` findings exist — the Go-binary-shaped output
  parsers got fed Python-httpx-library output and silently produced nothing.

**Hypothesis:** the engine subprocess inherits a PATH where
`/Users/jason/venvs/chatgpt-cli/bin/` shadows `/opt/homebrew/bin/`. The
Swift app's `BackendManager.swift:354-364` explicitly prepends Homebrew
paths — but the backend was started via plain `python3 -m uvicorn` here,
not via the Swift launcher, so the PATH order was your shell's default.

**Fix paths:**
- Engine should resolve tools by *expected behaviour* (run `--version`,
  match against a known prefix) before accepting `shutil.which` results.
- OR engine should prepend `/opt/homebrew/bin` to PATH at startup, matching
  what the Swift launcher does.
- OR engine should accept an explicit `tools.httpx.path` config override.

### Bug #2 — Token-rotation race: a second config is being materialized mid-scan  [HIGH]

Backend log shows:
```
2026-05-14 21:58:15 — backend startup, first config materialized
2026-05-14 22:02:00 — [Config] API token written to ~/.sentinelforge/api_token
```

A new `SentinelConfig` instance was created **4 minutes after startup**, at
the moment the first scan kicked off. This regenerates the API token and
rewrites the token file. The token in `~/.sentinelforge/api_token` is now
the *new* token, but the auth handler still holds a reference to the *old*
singleton's token — so every request after 22:02 returns
`AUTH_001: Invalid authentication token`.

Reproduction confirmed: `/v1/tools` and `/v1/ai/status` (both
`verify_token`) and `/v1/scans/start` (`verify_sensitive_token`) all
reject the file's token after 22:02.

**Hypothesis:** `get_config()` singleton is not thread-safe. Two coroutines
race on the `_config is None` check; both create a `SentinelConfig` (each
generating its own random `api_token`); the file gets two writes; the
auth handler reads whichever singleton landed first.

**Fix paths:**
- Add a lock around the `_config is None` materialization in
  `core/base/config.py:get_config()`.
- OR materialize the singleton at module-import time (eager singleton).
- OR have `_write_token_file()` skip the rewrite if the file already
  contains a token of the right length.

### Bug #3 — Session table writes inconsistent timestamp formats  [MEDIUM]

Old sessions store `start_time` as ISO datetime strings
(`2026-01-31T12:29:27.254791`). The new scan stored it as a Unix
timestamp string (`1778821320.67109`). Same column, two formats.

SQLite then does **lexicographic** comparison on `ORDER BY start_time DESC`,
which made the inspector pick old `verification-scan-*` sessions instead
of the actual latest one (the inspector now does dual-format normalisation
as a band-aid; the writer still needs the real fix).

**Fix path:** locate the writer that produces numeric timestamps (probably
`core/data/db.py` `save_session` or similar) and normalise to ISO.

### Bug #4 — Session lifecycle never closes  [MEDIUM]

Every session in the DB has `status: active` or `Created` and
`end_time: NULL`, *even after the scan completes*. The `scans` table got
`status: committed` correctly, but the parent `sessions` row was never
finalised. This is the same root cause as the four orphan
`verification-scan-*` rows I called out during Phase 0 review.

**Fix path:** the scan-completion event handler needs to also UPDATE the
sessions row to set `status='completed'` and `end_time=now()`.

### Bug #5 — Findings not promoted to issues  [LOW]

6 `Missing Security Header` findings exist in `findings` table; 0 rows in
`issues` table. Either the rule-based promotion didn't fire, or the
finding-shape doesn't match what the rule engine expects. Worth re-checking
once Bug #1 is fixed (real tools producing real findings might promote
correctly).

### Bug #6 — Inspector cosmetic issues (already fixed in this run)

- Severity case sensitivity (DB stores `MEDIUM`, inspector matched
  `medium`). Fixed.
- ORDER BY on mixed-format timestamps. Fixed (read-side band-aid; writer
  still needs Bug #3 fix).

---

## What we still don't know

Because only one (wrong) tool ran, this calibration scan **did not exercise**:

- Whether nuclei would find any of Juice Shop's published vulnerabilities
- Whether persona-diff IDOR testing fires against authenticated routes
- Whether the SQLi/SSRF mutators do anything useful against Juice Shop
- Whether Wraith's chain-mode exploitation flow works
- Whether forge's adversarial-debate exploit generation works
- Whether the replay capsule machinery gets invoked (we confirmed earlier
  it isn't, but didn't verify in the run)

All of those are Phase 1 work *after* Bug #1 is fixed. Until then, the
calibration loop is structurally compromised.

---

## Priority order

1. **Bug #1 (PATH shadowing)** — blocks everything else. Until the right
   tools run, calibration tells us nothing about Sentinel's actual
   detection capability. Fix this first.

2. **Bug #2 (token race)** — blocks repeated scanning. Once auth rotates
   mid-scan, every subsequent request fails. You'd have to restart the
   backend between every scan. Fix second.

3. **Bug #4 (session lifecycle)** — every scan leaves an orphan row in the
   DB. Doesn't block functionality but makes diagnostics confusing.

4. **Bug #3 (timestamp format)** — feeds into #4's diagnostic noise.

5. **Bug #5 (finding→issue promotion)** — investigate after #1 produces
   real findings.

---

## Concrete next actions

After Bug #1 is fixed, repeat this run with the same target/scope/mode.
Compare:
- Number of tools that ran (should be more than 1).
- Tool-specific findings (nuclei should produce template-based findings,
  nikto should produce header/path findings).
- Compare findings against Juice Shop's Score Board for the first real
  coverage measurement.

If after fixing Bug #1 the scan still produces only `httpx` execution,
the second-level diagnosis is the tool-installation check inside the
scheduler — it may believe nuclei/nikto are missing even though they're
on PATH.

---

## Artefacts from this run

- Session UUID: `fb1f374c-4f28-4fdc-b95a-24880b5fcc18`
- Inspect: `python3 scripts/inspect_scan.py show --session fb1f374c-4f28-4fdc-b95a-24880b5fcc18`
- Raw scan log: `/private/tmp/claude-501/.../b3bx90t2s.output`
- Backend log: `/private/tmp/claude-501/.../bzcxlis8i.output`
  (preserves the `[Config] API token written` line at 22:02:00 — the
  smoking gun for Bug #2)
