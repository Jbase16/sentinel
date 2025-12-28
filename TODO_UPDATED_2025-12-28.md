# SentinelForge — Updated TODO (Repo Audit)
Audit date: 2025-12-28

This file is a refreshed TODO list based on a repo-wide scan + targeted deep review of critical paths (server/API, scanner engine, eventing, DB persistence, UI client, CI, Ghost, Nexus/Cronus/Mimic/Omega scaffolds).

Scope notes:
- I treated `TODO.md` as the previous "source of truth" and verified claims against current code.
- Many higher-level modules (CRONUS/MIMIC/NEXUS/OMEGA) exist as **wrapper-only scaffolds** (explicit `NotImplementedError`) and are not yet wired into the active scan path.

---

## A) Status vs existing `TODO.md`

Legend:
- ✅ = implemented and verified in code/tests
- ⚠️ = partially implemented / drifted / missing critical edge cases
- ⛔️ = implemented but unsafe / insecure defaults / high-risk bug
- ⬜️ = not implemented

### P0 — Immediate fixes

#### 1) Fix Shell Injection Vulnerabilities
Status: ✅ (core execution paths)

Verified:
- No `shell=True` in `core/` (CI gates this; tests also grep it).
- Tool execution uses tokenized argv lists (`asyncio.create_subprocess_exec` / `subprocess.Popen(..., shell=False)`).
- API boundary tool allowlist validation exists: `core/server/api.py:80-90` (`ScanRequest.validate_modules`).
- Removed `bash -lc` tool definitions; registry tool definitions are argv lists: `core/toolkit/registry.py`.
- Installer uses `CommandChain` (Python-level `&&/||`) + `create_subprocess_exec`: `core/toolkit/installer.py`.

Caveat / follow-up:
- `core/toolkit/shims/*.py` still builds **string commands** (legacy) and runs via `ExecutionEngine` + `shlex.split` (`core/engine/executor.py`). This is not `shell=True`, but it is still **argument-injection prone** if user input can include spaces/flags. Either quarantine these shims harder, or migrate them to argv-list execution.

#### 2) Fix CORS Configuration
Status: ⚠️ (HTTP is good; WS coverage + wildcard matching drift)

Implemented:
- Dynamic CORS middleware that returns exact origin (credential-safe): `core/server/api.py:515-595`.

Gaps:
- WebSocket origin checks are inconsistent and do **not** use wildcard-aware matcher:
  - `core/server/api.py:597-614` uses `origin not in allowed_origins` (breaks `http://localhost:*` patterns).
  - `core/server/api.py:1081-1096` (`/ws/terminal`) has **no origin check at all**.
  - `core/server/api.py:1304-1347` (`/ws/pty`) has **no origin check**.

Action: see section **B.1 (Terminal/WebSocket hardening)**.

#### 3) Fix Missing Config Exports
Status: ✅ (as claimed)

#### 4) Fix Event Emission Bug
Status: ✅ (scan failure emits `scan_failed`)

Verified:
- `_begin_scan()` emits `GraphEventType.SCAN_FAILED` on exception: `core/server/api.py:399-412`.

#### 5) Fix Tool Import Paths
Status: ✅

Verified:
- `core/toolkit/tools.py` re-exports `install_tools` / `uninstall_tools`.
- API uses the re-export for `/tools/install` and `/tools/uninstall`: `core/server/api.py:972-1034`.

#### 6) Fix Wordlist Path
Status: ✅ (with a reliability caveat)

Verified:
- Wordlist base resolved from repo root: `core/toolkit/registry.py:10-46`.
- Commands filter `None` wordlist parts: `core/toolkit/registry.py:237-246`.

Caveat:
- If `assets/wordlists/common.txt` is missing, `COMMON_WORDLIST` becomes `None` and several tools will still run but likely degrade. Tests currently assume `COMMON_WORDLIST` exists.

#### 7) Fix Database Initialization Race Condition
Status: ✅

Verified:
- `Database._init_lock` is `threading.Lock()` and used with `with` in async init: `core/data/db.py:64-83`.

---

### P1 — Hardening

#### 8) Add Session Cleanup
Status: ✅

Verified:
- Session cleanup task exists and is started/stopped on API lifecycle: `core/server/api.py:168-220` + `:472-506`.

#### 9) Add Global Event Sequence Counter
Status: ⚠️ (partial + critical drift)

Implemented:
- `GraphEvent.event_sequence` is a global monotonic counter: `core/cortex/events.py:23-79`.

Not yet unified:
- `EventStore` uses its own `_sequence` and does **not** use `GraphEvent.event_sequence`: `core/cortex/event_store.py:67-93`.
- `DecisionLedger` uses its own `_sequence`: `core/scheduler/decisions.py:265-292`.

Critical consequence:
- SSE `GraphEvent.id` is derived from `StoredEvent.sequence` (`uuid5(..., f"sentinel-event-{sequence}")`), so IDs and sequences restart from 1 on backend restart.
- Swift client persists `lastSequence` and deduplicates by `event.id` → after restart this can cause silent drops / permanent desync.

Action: see **B.2 (Event stream correctness: sequence + restart epoch)**.

#### 10) Add Circuit Breaker for AI Health
Status: ✅ (for the covered call path)

Caveat:
- Some AI call sites bypass the breaker (example: `core/ai/strategy.py` calls `AIEngine.client.generate(...)` directly). Decide whether that is acceptable.

#### 11) Add Resource Guards
Status: ✅

Verified:
- `ResourceGuard` exists and is actively enforced for evidence size + findings count: `core/engine/scanner_engine.py:43-108` and usage at `:1011-1042`.

#### 12) Add Scan Transactionality
Status: ⚠️ (scaffold exists; not wired into hot path)

Implemented:
- `ScanTransaction` exists with explicit DB transaction semantics: `core/engine/scanner_engine.py:169-331`.

Not wired:
- The scan pipeline currently persists findings/issues/evidence via per-store fire-and-forget writes (`FindingsStore.add_finding`, `EvidenceStore.add_evidence`, etc.).
- `ScanTransaction` is not used by `ScannerEngine.scan()` or by the API tool dispatch loop.

Action: define *one* commit boundary for a scan session (or per-tool) and route writes through the transaction.

#### 13) Add Terminal Origin Check
Status: ⛔️ (not correct; terminal WS is also functionally broken)

See **B.1**.

#### 14) Add Log Queue Overflow Warning
Status: ⚠️

Implemented:
- Global `_log_queue` warns on overflow in `_log_sink_sync`: `core/server/api.py:629-633`.

Not addressed:
- Session logs (`ScanSession.logs`) grow unbounded; no cap/backpressure: `core/base/session.py:78-154`.

#### 15) Add API Versioning
Status: ⚠️ (core scaffolding exists; migration incomplete)

Implemented:
- `v1_router` exists and some endpoints are versioned + legacy routes delegate: `core/server/api.py:106-114` + `:719-855`.

Gaps:
- Many endpoints remain only on the legacy router (or mix v1 + legacy), and clients/tests are not consistently v1-first.
- Deprecation is documented in docstrings but not surfaced as `deprecated=True` in decorators.

---

### P2 — Long-term bets

#### 16) Deterministic Replay Capsules
Status: ⬜️ (not implemented)

Related existing foundations:
- EventStore ring buffer exists.
- `ScanTransaction` exists but isn’t wired.

#### 17) Causal Attack-Pressure Graph
Status: ⬜️ (not implemented as described)

Note:
- `core/cortex/pathfinder.py` exists (different concept). No `core/cortex/causal_graph.py` present.

#### 18) Continuous Autonomous Monitoring
Status: ⬜️

#### 19) Time-Travel Debugging
Status: ⬜️ (but CRONUS scaffolding exists; see section C)

#### 20) Schema Migrations
Status: ⬜️

#### 21) Per-Target Rate Limiting
Status: ⬜️

Current:
- Rate limiting is per-client-IP only: `core/server/api.py:129-150`.

---

## B) New / Unlisted high-impact TODOs (discovered in audit)

### B.1) TERMINAL + WEBSOCKET SECURITY & FUNCTIONALITY (P0)

Problems:
- Duplicate WebSocket route definitions for the same path:
  - `@app.websocket("/ws/pty")` appears twice (`core/server/api.py:597` and `:1304`).
  - One handler is a stub (accepts then does nothing), the other is the real PTY bridge.
  - Starlette routing ambiguity here is a correctness hazard.
- `/ws/terminal` does not read inbound messages at all (client sends keystrokes; server ignores): `core/server/api.py:1081-1096`.
- No enforcement of `SecurityConfig.terminal_require_auth`: config exists (`core/base/config.py:66-68`) but is not used in WS handlers.
- Origin checks are inconsistent and currently **do not** support wildcard-port patterns.

Minimum fix set:
- Pick a single terminal endpoint (`/ws/pty` recommended) and remove/rename the other.
- Enforce:
  - `terminal_enabled`
  - origin allowlist using `is_origin_allowed(origin, allowed_patterns)`
  - auth when `require_auth` is true, and also when `terminal_require_auth` is true
- Ensure the handler consumes inbound messages and supports resize commands.
- Update Swift UI to connect to the correct endpoint:
  - `ui/Sources/Models/HelixAppState.swift:113-119` connects to `/ws/terminal` today.
  - `ui/Sources/Views/Navigation/TerminalView.swift:55` hardcodes `/ws/terminal`.

### B.2) EVENT STREAM CORRECTNESS: GLOBAL SEQUENCE + RESTART EPOCH (P0/P1)

Problems:
- Server restart breaks client sequence tracking and dedup (see A.9).
- Two event taxonomies exist and drift:
  - `core/cortex/events.py:GraphEventType`
  - `core/contracts/events.py:EventType` (contract system is not integrated)

Fix direction:
- Establish an explicit "event stream epoch" (random UUID at process start) and include it in SSE payload.
- Make client treat epoch changes as a reset (clear dedup set; reset lastSequence).
- Unify sequence sources:
  - Either make `EventStore.sequence` == `GraphEvent.event_sequence`, or eliminate one.
- Decide which event contract is authoritative and wire validation into emission (or delete contract module if not used).

### B.3) GHOST / LAZARUS INTEGRATION BUG (P0)

Bug:
- `GhostAddon.response()` calls `self.lazarus.process(flow)` but `LazarusEngine` has no `process` method.
  - Call site: `core/ghost/proxy.py:111-115`
  - Lazarus implementation: `core/ghost/lazarus.py` (`response()` / `_process_async()` only)

Impact:
- Ghost proxy will crash/throw on eligible JS responses, degrading proxy usefulness and potentially breaking sessions.

### B.4) AI CALL-SITE HARDENING (P1)

Observations:
- `core/ai/strategy.py` uses `print()` heavily and calls AI client directly (bypassing breaker/timeout conventions).
- `core/forge/compiler.py` generates exploit code from AI and writes it to disk; no validation before execution.

Action:
- Decide where AI calls are allowed to bypass circuit breaker (if anywhere).
- Add validation / sandbox policy gating before executing any generated code.

### B.5) DB WRITE RELIABILITY / FAILURE VISIBILITY (P1)

Observations:
- Stores persist via fire-and-forget tasks (`create_safe_task`, BlackBox actor).
- Failures can be silent relative to the scan lifecycle (scan may "complete" with missing persisted artifacts).

Action:
- Decide what must be durable (sessions, findings, evidence) and make those writes part of an explicit commit boundary.
- Add surfaced error signals when persistence fails.

---

## C) Planned upgrade modules (presence vs implementation)

These map to the upgrade pillars you described.

### CRONUS
Status: ⚠️ scaffold present, core logic not implemented
- Present: `core/cronus/*` (TimeMachine/Differ/Hunter)
- Many methods intentionally raise `NotImplementedError`.

### MIMIC
Status: ⚠️ scaffold present, core logic not implemented
- Present: `core/mimic/*` (Downloader/ASTParser/RouteMiner)
- Many methods intentionally raise `NotImplementedError`.

### NEXUS
Status: ⚠️ scaffold present, core logic not implemented
- Present: `core/nexus/*` (Primitive inventory + solver + executor)
- Collector/solver/executor are wrapper-only.

### OMEGA
Status: ⚠️ scaffold present, core logic not implemented
- Present: `core/omega/*`
- `OmegaManager.run()` is wrapper-only; phases deferred.

### THANATOS
Status: ⬜️ no `core/thanatos/` module detected
- Closest existing adjacent subsystem is `core/forge/*` (exploit generation/execution).

---

## D) Overall review — Good / Bad / Ugly / HOLY FUCK impressive

### Good
- Scanner execution path is largely hardened (argv lists, `shell=False`, no `create_subprocess_shell`).
- `ScannerEngine` has real operational safety controls (timeouts, global watchdog, resource guard): `core/engine/scanner_engine.py`.
- Decision emission architecture is strong: `Strategos` + `DecisionContext` + `EventBus` is coherent and test-backed (`tests/unit/test_strategos_*`, `tests/integration/test_decision_emission.py`).
- CI is unusually robust for a security tool: dedicated security-gate + bandit/semgrep/safety workflows.

### Bad
- Terminal WebSocket is both insecure and not reliably functional due to duplicated routes and missing inbound message handling.
- Event stream restart semantics are currently broken for any client that persists sequence/dedups.
- Multiple “authoritative” schemas/contracts exist (events, scan state) without being wired, creating drift.

### Ugly
- Ghost proxy integration likely throws at runtime due to Lazarus call mismatch.
- Auth story is incomplete for a production posture:
  - UI uses placeholder token (`Bearer dev-token`) while backend token is random-by-default.
  - WebSockets don’t respect `terminal_require_auth`.
- Persistent storage can silently fail (fire-and-forget), undermining reproducibility.

### HOLY FUCK impressive
- The “Layered” architecture direction is real in code (not just docs):
  - EventStore replay + SSE (`/events/stream`) is a serious foundation for reactive UI.
  - Strategos decision audit trail + Narrator pipeline is the right shape for explainable autonomy.
  - Resource-aware scanner watchdog + cancellation semantics are production-shaped.

---

## E) Suggested next execution order (if you want a practical sequence)

1) P0: Fix terminal WS duplication + security + update UI endpoints.
2) P0/P1: Fix event stream restart semantics (epoch + sequence unification) and update Swift persistence logic.
3) P0: Fix Ghost/Lazarus integration bug.
4) P1: Decide and implement DB durability boundaries (transactionality).
5) P2: Implement CRONUS/MIMIC/NEXUS/OMEGA internals or explicitly keep them as scaffolds with clear gating.
