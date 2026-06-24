# SentinelForge — Production Readiness Master TODO

**Status:** 🔴 NOT production-ready
**Owner:** _unassigned_
**Created:** 2026-06-10
**Source:** End-to-end production-readiness audit (Python engine + FastAPI server + CLI + SwiftUI app + integration seams)

---

## How we officially claim "production ready"

This is a **gate**, not a wishlist. We may stamp SentinelForge production-ready **only when both** of the following hold:

1. **Every `P0` and `P1` task below is checked `[x]`** and its *Acceptance criterion* is objectively met.
2. **The CI gate (T03) is green on `main`** — meaning the tests, lint, security-gate, and Swift build that prove the above actually run on every push.

`P2` items are **hardening**: strongly recommended, tracked, and burned down post-launch, but they do **not** block the v1.0 readiness stamp. Each `P2` left open at launch must be explicitly accepted in the sign-off block at the bottom.

**Execution order** is risk-reduction-per-unit-effort (cheap, high-impact first), so the gate goes green fast and the multi-day work happens against a protected baseline.

---

## Execution order (burn-down sequence)

| # | ID | Task | Priority | Est. | Done |
|---|------|------|----------|------|------|
| 1 | T02 | Fix Release entitlements + hardened runtime | P0 | hrs | [ ] |
| 2 | T04 | Declare missing runtime deps in `pyproject` | P1 | hrs | [ ] |
| 3 | T03 | Commit the CI gate (tests/lint/bandit/forbidden-pattern/swift) | P0 | ½ day | [ ] |
| 4 | T07 | Unconditionally token-gate `/ws/pty` | P1 | hrs | [ ] |
| 5 | T06 | Delete/quarantine the fake `SandboxRunner` | P1 | hrs | [ ] |
| 6 | T09 | `hmac.compare_digest` + stop trusting `X-Forwarded-For` | P2 | hrs | [ ] |
| 7 | T10 | Reject `-`-leading targets + re-assert tool allowlist | P2 | hrs | [ ] |
| 8 | T08 | Fail-closed on safety-policy load + ban bare `except:` | P1 | ½ day | [ ] |
| 9 | T01 | Bundle the engine; make the app launch off any machine | P0 | days | [ ] |
| 10 | T05 | Notarization + signing pipeline | P0 | 1–2 days | [ ] |
| 11 | T11 | Move sequence persistence off the hot path + `schema_version` | P2 | ½ day | [ ] |
| 12 | T12 | Structured logging + central redaction | P2 | 1 day | [ ] |
| 13 | T13 | Repo hygiene + accurate docs/runbook | P2 | 1 day | [ ] |
| 14 | T14 | Single source of truth for version | P2 | hrs | [ ] |

---

## P0 — Release blockers (all required for the stamp)

### [ ] T01 — Make the app launch its backend off any machine
- **Why:** `BackendManager.resolveBackendRoot` returns `~/Developer/sentinelforge` and `resolvePythonExecutable` expects a repo `.venv`; a distributed `.app` finds neither and never starts the engine.
- **Files:** `ui/Sources/Services/BackendManager.swift` (`resolveBackendRoot` ~L581, `resolvePythonExecutable` ~L621, `launchIntegratedServer` ~L272)
- **Do:**
  - [ ] Build a self-contained engine (PyInstaller/`py2app` one-file or embedded signed binary) into `SentinelForge.app/Contents/Resources/`.
  - [ ] Make `resolveBackendRoot` prefer `Bundle.main.resourceURL`; dev-checkout paths become a *fallback only when present*.
  - [ ] Make `resolvePythonExecutable` prefer the bundled runtime (the `bundledPython` branch ~L627); fall back to repo `.venv` only in dev.
  - [ ] Surface a clear "engine missing / failed to start" error to the user instead of a silent status hang.
- **Acceptance:** On a clean macOS user account (no source checkout, no Homebrew Python, no repo `.venv`), launching the signed `.app` starts the backend and `/v1/health` returns `ready` within the readiness timeout.

### [ ] T02 — Stop shipping debug entitlements in Release
- **Why:** Both build configs point at `SentinelForge.entitlements` which sets `get-task-allow=true` + `cs.debugger=true` → notarization rejects it, and any same-user process can read app memory (incl. the API bearer token).
- **Files:** `ui/SentinelForge.xcodeproj/project.pbxproj` (L457, L478), `ui/SentinelForge.entitlements`, `ui/SentinelForge.Release.entitlements`
- **Do:**
  - [ ] Release config → `CODE_SIGN_ENTITLEMENTS = SentinelForge.Release.entitlements`.
  - [ ] Keep `get-task-allow`/`cs.debugger` in the Debug entitlements only.
  - [ ] Set `ENABLE_HARDENED_RUNTIME = YES` for Release.
- **Acceptance:** `codesign -d --entitlements - <Release.app>` shows **no** `get-task-allow`; `xcrun notarytool submit` accepts the build.

### [ ] T03 — Commit the CI gate the docs already promise
- **Why:** `.github/workflows/` contains only `.DS_Store`; the documented 6-workflow "security-first CI" does not run. Nothing gates regressions (e.g., re-introducing `shell=True` or wiring the fake sandbox).
- **Files:** new `.github/workflows/ci.yml` (+ `security-scan.yml`, `sentinel-health.yml` per `.github/SECURITY_CI_OVERVIEW.md`)
- **Do:**
  - [ ] `ci.yml` on `push`/`pull_request`: install (`pip install -e '.[dev]'` + the deps from T04), `ruff check core/`, `bandit -c .bandit -r core/ -ll`, `pytest -q`, and a forbidden-pattern grep (`! grep -rn "shell=True" core/ --include=*.py`; same for `os.system(`, `eval(`).
  - [ ] Add a Swift build job (`xcodebuild build` or `swift build`).
  - [ ] Make these checks **required** for merge to `main`.
- **Acceptance:** A PR that adds `shell=True` to a `core/` file fails CI; the green check is required before merge.

### [ ] T05 — Signing + notarization release pipeline
- **Why:** No `DEVELOPMENT_TEAM`, no hardened runtime, no notarization step; `CODE_SIGN_STYLE = Automatic` only. The app is unsandboxed by necessity (spawns `nmap`/`zsh`), so Developer-ID + notarization is the *only* viable distribution path and it isn't configured.
- **Files:** `ui/SentinelForge.xcodeproj/project.pbxproj`, release scripts (note `dmgbuild` already in deps)
- **Do:**
  - [ ] Configure Developer ID Application signing + `DEVELOPMENT_TEAM`.
  - [ ] Add an archive → `notarytool submit --wait` → `stapler staple` step.
  - [ ] Produce a signed, stapled `.dmg` (use the already-present `dmgbuild`).
- **Acceptance:** `spctl -a -vvv <App>` reports `accepted, source=Notarized Developer ID`; the `.dmg` installs and runs on a machine that has never seen the source.

---

## P1 — Must-fix before calling it production

### [ ] T04 — Declare the runtime deps `core/` actually imports
- **Why:** `pip install sentinelforge` (the declared package) ImportErrors at boot — `pyproject.toml` omits `pyyaml` (`config.py:557`), `sse-starlette` (`realtime.py:12`), `aiohttp` (2 files). Only the frozen `requirements.txt` works, and it pins an editable git self-install.
- **Files:** `pyproject.toml`, `requirements.txt`
- **Do:**
  - [ ] Add `pyyaml`, `sse-starlette`, `aiohttp`, explicit `pydantic`, `pyjwt` to `[project.dependencies]`.
  - [ ] Remove the `-e git+https://github.com/Jbase16/sentinel.git@…#egg=sentinelforge` self-install from `requirements.txt`.
  - [ ] Move heavyweight/optional deps (`torch`, `transformers`, `semgrep`) into extras (`[project.optional-dependencies]`).
- **Acceptance:** In a fresh venv, `pip install .` then `python -c "import core.server.api"` succeeds with no `ModuleNotFoundError`; the server boots.

### [ ] T06 — Delete or quarantine the fake "sandbox"
- **Why:** `forge/sandbox.py:SandboxRunner` is named/documented as a safety sandbox but only runs `sys.executable script_path` + timeout (no isolation). Currently dead code, but exported and `/forge/execute` is pre-listed in `get_sensitive_endpoints()` — wiring it is a latent RCE.
- **Files:** `core/forge/sandbox.py`, `core/forge/__init__.py`, `core/base/config.py` (`get_sensitive_endpoints`)
- **Do (pick one):**
  - [ ] **Option A (preferred for v1):** delete `sandbox.py`, drop it from `__init__.py`, and remove `/forge/execute` from `get_sensitive_endpoints()` so the inventory matches reality.
  - [ ] **Option B:** rename to `UnsafeLocalRunner`, gate behind an explicit `SENTINEL_ALLOW_EXPLOIT_EXEC` opt-in, and run inside a container / `sandbox-exec` profile with `rlimit` (CPU/mem/fsize) and `--network none`.
- **Acceptance:** No code path can execute AI-generated code without explicit, isolated, opt-in execution; `get_sensitive_endpoints()` lists only endpoints that exist.

### [ ] T07 — Unconditionally token-gate the PTY shell
- **Why:** `/ws/pty` spawns `/bin/zsh`; `terminal_require_auth` defaults `False`, so `SENTINEL_REQUIRE_AUTH=false` on loopback (interlock-permitted) yields an unauthenticated root-equivalent shell, and a missing `Origin` header skips the origin check.
- **Files:** `core/server/routers/realtime.py` (`validate_websocket_connection` ~L55-66)
- **Do:**
  - [ ] Force `require_auth = True` for `endpoint_name == "/ws/pty"` regardless of global auth (match `/forge/*`).
  - [ ] Treat a missing `Origin` on `/ws/pty` as **deny**.
- **Acceptance:** A token-less WebSocket connect to `/ws/pty` is rejected (`4403`) even when `SENTINEL_REQUIRE_AUTH=false`; a connect with no `Origin` header is rejected. Add a regression test.

### [ ] T08 — Fail-closed on safety-policy load + kill bare excepts
- **Why:** `api.py:140` swallows CAL policy-load failures and boots to `state="ready"` with the safety constitution possibly absent (fail-*open*). Plus 6 bare `except:`, 89 `except: pass`, 421 broad `except Exception` hide failures and make debugging impossible.
- **Files:** `core/server/api.py` (lifespan, ~L135-177), `core/cortex/causal_graph.py` (L1226/1238/1288), `core/ai/debate.py` (L271/321), `core/executor/oracle.py` (L100), + `.bandit`/ruff config
- **Do:**
  - [ ] If policies are expected but loaded count is 0 / load raised, set `boot_status="degraded"` and **refuse to accept scans** (don't report `ready`).
  - [ ] Replace all bare `except:` with `except Exception:` (preserve `KeyboardInterrupt`/`SystemExit`).
  - [ ] Enable ruff `E722` (bare-except) as a CI error; triage the `except: pass` sites — log-with-context or re-raise where the caller can't proceed.
- **Acceptance:** Boot with an unreadable policy DB reports `degraded` and rejects `/v1/mission/start`; ruff `E722` passes clean in CI.

---

## P2 — Hardening (tracked; explicitly accept any left open at launch)

### [ ] T09 — Constant-time token compare + don't trust `X-Forwarded-For`
- **Files:** `core/server/routers/auth.py` (L112, L143, `get_client_ip` L85-89), `core/server/routers/realtime.py` (L82)
- **Do:** use `hmac.compare_digest` for all three token comparisons (as `chain.py:654` already does); only honor `X-Forwarded-For` behind a configured trusted-proxy allowlist, else use `request.client.host`.
- **Acceptance:** token compares route through `compare_digest`; rate-limit key cannot be spoofed via a client-supplied header. Tests added.

### [ ] T10 — Close flag-injection + add defense-in-depth allowlist on the args path
- **Files:** `core/toolkit/normalizer.py` (`normalize_target`), `core/engine/scanner_engine.py` (`_execute_tool` ~L1748; `queue_task` variants L1062 & L1162)
- **Do:** reject normalized targets matching `^-`; add `if tool not in TOOLS: raise` at the top of `_execute_tool`; unify the two divergent `queue_task` arg checks into one shared validator (prefer a per-tool arg allowlist over the metachar denylist).
- **Acceptance:** a target of `-oN/tmp/x` is rejected before exec; a `_pending_tasks` entry with an unknown tool raises rather than executing. Tests added.

### [ ] T11 — Sequence persistence off the hot path + ordered migrations
- **Files:** `core/base/sequence.py` (`next_id`/`_persist_sequence` L182-225), `core/data/db.py`
- **Do:** persist on interval/shutdown (the `persist_to_db` hook exists) instead of every `next_id()`; document `_last_issued` as diagnostics-only; add a `schema_version` table so migrations are ordered/inspectable.
- **Acceptance:** a 10k-event scan issues no per-event sequence writes; `schema_version` reflects applied migrations.

### [ ] T12 — Structured logging + central redaction
- **Files:** `core/base/config.py` (`setup_logging`), logging call sites
- **Do:** add request/scan correlation IDs; route findings/tokens/headers through one redaction filter (extend `_redact_headers` thinking) so secrets can't leak via `logger.error(...)`; confirm MIMIC secret redaction is actually applied on all sinks.
- **Acceptance:** logs carry a correlation id; a known secret injected into a finding never appears in `system.log`. Test added.

### [ ] T13 — Repo hygiene + truthful docs/runbook
- **Files:** repo root, `.github/SECURITY_CI_OVERVIEW.md`, `CLAUDE.md`, `README.md`
- **Do:** move scratch dumps (`output.txt`, `sentinel-*.prompt`, 15+ root `verify_*.py`, `TRIAD.md`, `MoreTODO.md`) under an ignored `scratch/`; strip the auto-generated `[Automatically generated — review and enhance]` docstrings; write a real SentinelForge `CLAUDE.md`/`README`; reconcile the CI docs with the workflows that now exist (T03); add an **install / upgrade / rollback / ops** runbook.
- **Acceptance:** `git status` is clean of multi-hundred-KB dumps; CI docs describe only workflows that exist; a new operator can install/upgrade/roll back from the runbook alone.

### [ ] T14 — One source of truth for version
- **Files:** `pyproject.toml` (`0.1.0`), `core/server/api.py` (FastAPI `version="1.0.0"`), app build
- **Do:** derive the FastAPI and app versions from the package version (or a single `__version__`); pick the real v1 number.
- **Acceptance:** all three report the same version string.

---

## Production readiness sign-off

Flip each category to ✅ with the listed evidence. **All categories ✅ + every P0/P1 checked + CI green ⇒ stamp v1.0.**

| Category | Gate (evidence required) | Status |
|---|---|---|
| Build & dependency hygiene | `pip install .` boots in a clean venv (T04); deps pinned, no git self-install | 🔴 |
| Configuration & secrets | secure defaults verified; no secrets in logs (T12); keychain argv reviewed | 🟡 |
| Error handling & crash safety | no bare `except:`; fail-closed safety boot (T08) | 🔴 |
| Logging / telemetry | structured + correlation ids + central redaction (T12) | 🟡 |
| Security (exec/input/boundaries) | sandbox resolved (T06); PTY gated (T07); flag-injection closed (T10); const-time compare (T09) | 🟡 |
| Concurrency / async correctness | sequence race documented/fixed (T11); rate-limit key un-spoofable (T09) | 🟡 |
| Performance & resource risks | no per-event DB writes (T11); scan resource bounds verified | 🟡 |
| Data integrity | `schema_version` + ordered migrations (T11); corruption path documented | 🟢* |
| Test coverage & CI reliability | CI gate green and required on `main` (T03) | 🔴 |
| Packaging / release | bundled engine (T01); notarized signed `.dmg` (T05); Release entitlements (T02) | 🔴 |
| Docs / runbooks | truthful CI docs + install/upgrade/rollback runbook (T13) | 🟡 |

`*` Data integrity is already strong (WAL, busy_timeout, foreign_keys, MigrationRunner); T11 closes the remaining gaps.

---

### Final stamp

```
[ ] All P0 tasks complete (T01, T02, T03, T05)
[ ] All P1 tasks complete (T04, T06, T07, T08)
[ ] CI gate green and required on main (T03)
[ ] All readiness categories ✅ (or P2 exceptions explicitly accepted below)

P2 exceptions accepted for v1.0 (list IDs + rationale):
  - ____________________________________________

Signed-off by: ______________________    Date: __________
SentinelForge v______ — PRODUCTION READY
```
