# SentinelForge TODO — Stabilization and Hardening

Use this as the single source of truth for the immediate stabilization work. Items are concrete, file-scoped, and ordered by priority. Check off as you land patches.

## Critical Breakages (Blocking)
- [ ] core/base/config.py — restore imports and missing types
  - [ ] Add: `from dataclasses import dataclass, field`; `from typing import List, Optional`; `from pathlib import Path`; `import os, logging, secrets`
  - [ ] Define `AIConfig` with fields: `provider: str`, `ollama_url: str`, `model: str`, `fallback_enabled: bool`, `request_timeout: float`, `max_concurrent_requests: int`
  - [ ] Verify `SentinelConfig.from_env()` uses `AIConfig` and all referenced names exist
  - [ ] Ensure legacy exports at bottom resolve: `AI_PROVIDER`, `OLLAMA_URL`, `AI_MODEL`
- [ ] add_all_comments.py — quarantine/remove
  - [ ] File is syntactically broken (unmatched quotes, undefined `BASE_DIR`/`HEADERS`). Mark as deprecated or delete to avoid accidental execution

## Missing Functions / Modules
- [ ] core/toolkit/tools.py — re‑export registry API and implement discovery
  - [ ] Re-export: `from .registry import TOOLS, get_tool_command`
  - [ ] Implement `get_installed_tools() -> dict[str, dict]` using `shutil.which()` over `TOOLS`
  - [ ] Re-export installers: `from .installer import install_tools, uninstall_tools`
- [ ] core/engine/scanner_engine.py — replace absent ScannerBridge
  - [ ] Change import to `from core.toolkit.raw_classifier import classify`
  - [ ] Replace `ScannerBridge.classify(...)` call with `classify(tool, target, output_text)`
- [ ] KnowledgeGraph stub or replacement
  - [ ] Implement minimal `core/cortex/memory.py` with `KnowledgeGraph.instance().export_json()` and `NodeType` enum, or
  - [ ] Temporarily make `/cortex/graph` and `/ws/graph` return a stub `{"nodes": [], "edges": []}` to avoid 500s

## API ↔ EventBus Mismatches
- [ ] core/server/api.py — imports and emits
  - [ ] Add missing import: `from core.cortex.events import GraphEvent`
  - [ ] Replace non-existent methods with explicit emits or implement helpers:
    - [ ] Replace `event_bus.emit_scan_started(...)` with `event_bus.emit(GraphEvent(type=GraphEventType.SCAN_STARTED, payload={...}))`
    - [ ] Replace `emit_tool_invoked`, `emit_tool_completed`, `emit_scan_completed` similarly
  - [ ] Replace `event_bus._store.append(...)` (lines ~326–331) with `get_event_store().append(GraphEvent(type=GraphEventType.SCAN_FAILED, payload={...}))`
  - [ ] Ensure `_get_latest_results_sync/_get_latest_results` return the same `killchain` shape `{ "edges": [...] }`

## Security Posture (Defaults and Enforcement)
- [ ] core/base/config.py — safer defaults
  - [ ] Set `require_auth=True` by default
  - [ ] Set `terminal_enabled=False`, `terminal_require_auth=True`
  - [ ] Keep `allowed_origins` to localhost schemes by default
- [ ] core/server/api.py — respect configured origins
  - [ ] Replace CORS `allow_origins=["*"]` (lines ~426–433) with `list(get_config().security.allowed_origins)`
- [ ] core/server/api.py — terminal auth enforcement
  - [ ] In `/ws/pty`, if `terminal_require_auth=True`, validate token even when `require_auth=False`
- [ ] core/server/api.py — client IP / rate limit
  - [ ] Clarify trust of `X-Forwarded-For`; prefer `request.client.host` unless behind known proxy

## Installer Hardening
- [ ] core/toolkit/installer.py — remove `shell=True` and inline shell ops
  - [ ] Replace `create_subprocess_shell(..., shell=True)` with `create_subprocess_exec` and arg lists (lines ~202–209, ~318–324)
  - [ ] Split strategies that contain `"||"` into sequential attempts (lines ~18, 24, 30, 40, 105)
  - [ ] Enforce allowlist of tool names at API boundary (validate names in `TOOLS`)
  - [ ] Improve prerequisite detection and messaging for brew/go/pip

## Toolkit Registry / Paths
- [ ] core/toolkit/registry.py — fix wordlist directory
  - [ ] Set `REPO_ROOT = Path(__file__).resolve().parents[2]`; `WORDLIST_DIR = REPO_ROOT / "assets" / "wordlists"`
  - [ ] Ensure `COMMON_WORDLIST` exists; warn and degrade gracefully if missing

## ScannerEngine Robustness
- [ ] core/engine/scanner_engine.py — lifecycle
  - [ ] Remove or implement `engine.shutdown(reason=...)` calls used in API dispatch (no-op if not present)
  - [ ] Ensure log emission doesn’t double‑publish via both TaskRouter and EventBus bridges
  - [ ] Add tests for idle/wall‑clock/global timeout and cancellation

## Scripts / Operational Hygiene
- [ ] scripts/start_servers.sh — configurability
  - [ ] Make `MLX_PYTHON` overridable via env; fallback to venv python if not set/present
  - [ ] Replace `nc` dependency with a Python TCP dial loop or document requirement

## Tests to Add / Fix
- [ ] Fix imports so API starts; then run integration tests
  - [ ] tests/integration/test_api_basic.py should pass (`/ping`, `/status`)
- [ ] Add `/events/stream` replay tests (since=N and truncation warning)
- [ ] ScannerEngine async unit tests
  - [ ] Idle timeout terminates and logs
  - [ ] Wall‑clock timeout terminates and logs
  - [ ] Global timeout cancels, terminates/kills processes
  - [ ] Mid‑run cancellation cleans up subprocesses
- [ ] Installer tests (mocked)
  - [ ] Strategies fallback without `shell=True`
  - [ ] Tool name validation rejects unknowns
- [ ] Security tests
  - [ ] CORS honors `allowed_origins`
  - [ ] `/ws/pty` enforces `terminal_enabled` and `terminal_require_auth`

## Validation Checklist
- [ ] Start API (`uvicorn core.server.api:app`) and verify endpoints: `/ping`, `/status`, `/events/stats`, `/cortex/graph`
- [ ] POST `/scan` on a benign target; observe `/events/stream` sequence: `scan_started` → tool lifecycle → `scan_completed`
- [ ] Run `pytest tests/integration -v -s` and address any regressions

## Deferred (Track as separate tickets)
- [ ] Implement full `KnowledgeGraph` engine or align UI to existing killchain/events stores
- [ ] Align `/results` schema contract with UI and document in `docs/architecture.md`

## Game‑Changer Upgrades (Design Tickets)
- [ ] Deterministic replay capsules (re-run scans exactly; full forensic reproducibility)
- [ ] Evidence lineage with hash‑chained attestations and optional signing
- [ ] Adaptive covert scanning profiles with traffic‑shaping personas
- [ ] Causal “attack‑pressure” graph to prioritize exploitation paths
- [ ] CAL‑backed live policy contracts to gate operations by scope/authorization
- [ ] Self‑consistency arbitration using local specialized checkers feeding Narrator/Arbitration
