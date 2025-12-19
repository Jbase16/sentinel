# SentinelForge TODO — Stabilization and Hardening

Use this as the single source of truth for the immediate stabilization work. Items are concrete, file-scoped, and ordered by priority. Check off as you land patches.

## Critical Breakages (Blocking) — UPDATED FROM CODE REVIEW

### Environment & Dependencies
- [ ] **pip install requirements.txt** — Current environment missing httpx, aiosqlite, fastapi
  - Root cause: Virtual environment not activated or packages not installed
  - Test: `python3 -c "from core.base.config import get_config; print('OK')"` should not error
  - Status: BLOCKS ALL IMPORTS

### core/base/config.py — MOSTLY COMPLETE, ONE FIX NEEDED
- [x] Add imports (dataclass, field, typing, pathlib, os, logging, secrets) — ALREADY DONE
- [x] Define `AIConfig` dataclass — ALREADY DONE
- [x] Verify `SentinelConfig.from_env()` — ALREADY DONE
- [ ] **Add legacy exports** (lines 359+) — CRITICAL
  - Missing: `AI_PROVIDER`, `OLLAMA_URL`, `AI_MODEL`, `AI_FALLBACK_ENABLED`, `setup_logging()`, `get_config()`
  - These are imported by `core/ai/ai_engine.py:38` but never defined in config.py
  - Solution: Add at end of config.py with lambdas or direct references

### core/server/api.py — EVENT EMISSION BUG
- [ ] **Fix line 330-334: wrong _store.append() call**
  - Current (WRONG): `event_bus._store.append(GraphEventType.SCAN_ERROR, {...})`
  - Fix (CORRECT): `event_bus.emit(GraphEvent(type=GraphEventType.SCAN_FAILED, payload={...}))`
  - Also change event type from SCAN_ERROR to SCAN_FAILED (enum doesn't have SCAN_ERROR)
  
- [ ] **Verify all emit_* methods exist** in EventBus
  - emit_scan_started() — EXISTS
  - emit_tool_invoked() — EXISTS
  - emit_tool_completed() — EXISTS
  - emit_scan_completed() — EXISTS
  - Status: All methods exist and are correct (PASS)

### tools/dev/add_all_comments.py — BROKEN, MARKED FOR DELETION
- [ ] Delete or completely rewrite file
  - File is syntactically broken (unmatched quotes, missing imports)
  - Status: QUARANTINE (don't execute)

## Missing Functions / Modules — UPDATED FROM CODE REVIEW

### core/cortex/scanner_bridge.py — DEAD CODE, NEEDS DECISION
- [ ] **DECISION NEEDED**: Scanner imports ScannerBridge but never uses it
  - Class exists in `core/cortex/scanner_bridge.py:5`
  - Method `ScannerBridge.classify()` wraps `classify()` function
  - **Option A**: Remove import from scanner_engine.py (SIMPLER)
  - **Option B**: Actually use ScannerBridge in scan classification pipeline (BETTER DESIGN)
  - **Current Status**: Imported but unused — indicates incomplete refactoring
  - Impact: No functional issues, just code smell

### core/toolkit/tools.py — ACTUALLY OK
- [x] Re-export: `from .registry import TOOLS, get_tool_command` — ALREADY DONE
- [x] Implement `get_installed_tools()` — ALREADY DONE (uses shutil.which)
- [x] Re-export installers — ALREADY DONE
- **Status**: PASS (no changes needed)

### KnowledgeGraph stub or replacement
- [ ] Implement minimal `core/cortex/memory.py` with `KnowledgeGraph.instance().export_json()` and `NodeType` enum, or
- [ ] Temporarily make `/cortex/graph` and `/ws/graph` return a stub `{"nodes": [], "edges": []}` to avoid 500s

## API ↔ EventBus Mismatches — UPDATED FROM CODE REVIEW

### All emit_* methods EXIST and are CORRECT
- [x] `event_bus.emit_scan_started()` — EXISTS (events.py:101)
- [x] `event_bus.emit_tool_invoked()` — EXISTS (events.py:123)
- [x] `event_bus.emit_tool_completed()` — EXISTS (events.py:134)
- [x] `event_bus.emit_scan_completed()` — EXISTS (events.py:112)
- [x] GraphEvent import already present — ALREADY DONE
- **Status**: All emit_* methods work correctly (PASS)

### ONLY ONE BUG: Line 330-334
- [ ] **Replace direct _store.append() call with event_bus.emit()**
  - Location: api.py lines 330-334 (in exception handler)
  - Current (WRONG): `event_bus._store.append(GraphEventType.SCAN_ERROR, {...})`
  - Correct (RIGHT): `event_bus.emit(GraphEvent(type=GraphEventType.SCAN_FAILED, payload={...}))`
  - Impact: Will cause AttributeError when scan fails

### Results schema
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

## Installer Hardening — HIGH PRIORITY SECURITY FIX

### core/toolkit/installer.py — SHELL INJECTION VULNERABILITY
- [ ] **Remove `shell=True` — HIGH SECURITY PRIORITY**
  - [ ] Replace `create_subprocess_shell(..., shell=True)` with `create_subprocess_exec` and arg lists (lines ~202–209, ~318–324)
  - Issue: `shell=True` allows command injection if tool names are user-controlled
  - [ ] **Handle `"||"` operators in strategies** — These are shell-only syntax
    - Current: `["brew", "tap", "projectdiscovery/tap/subfinder", "||", "brew", "install", "subfinder"]`
    - Problem: `||` is not a command, it's a shell operator (OR operator)
    - Solution: Split into sequential try-except attempts
    - Example fix:
      ```python
      async def try_strategy(strategy):
        try:
          return await execute_command(strategy["cmd"][:3])  # Just the tap
        except:
          return await execute_command(strategy["cmd"][4:])  # Fall back to install
      ```
  - [ ] Enforce allowlist of tool names at API boundary (validate names in `TOOLS`)
  - [ ] Improve prerequisite detection and messaging for brew/go/pip
  - Status: CRITICAL — blocks secure tool installation

## Toolkit Registry / Paths — CRITICAL PATH BUG

### core/toolkit/registry.py — WORDLIST PATH BROKEN
- [ ] **Fix wordlist directory path** — CRITICAL
  - Current (WRONG): 
    ```python
    BASE_DIR = Path(__file__).resolve().parents[1]  # Goes to core/
    WORDLIST_DIR = BASE_DIR / "assets" / "wordlists"  # Resolves to core/assets/wordlists (WRONG)
    ```
  - File location: `core/toolkit/registry.py`
  - parents[1] goes to: `core/` (one level up)
  - Actual wordlists: `REPO_ROOT/assets/wordlists` (two levels up)
  
  - Fix (CORRECT):
    ```python
    REPO_ROOT = Path(__file__).resolve().parents[2]  # Goes to repo root
    WORDLIST_DIR = REPO_ROOT / "assets" / "wordlists"
    ```
  - [ ] Verify COMMON_WORDLIST exists after fix
  - [ ] Warn and degrade gracefully if wordlists missing (fallback to empty set)
  - Status: BLOCKS dirsearch, gobuster, feroxbuster, wfuzz tools

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

## Additional High-Priority Fixes (From Code Review)

### Database & Session Management
- [ ] core/data/db.py — Fix initialization race condition
  - [ ] Change from `asyncio.Lock()` to `threading.Lock()` (init called from sync context)
  - [ ] Implement double-checked locking pattern
  - Status: Could cause concurrent initialization if multiple threads call Database.instance() simultaneously

- [ ] core/server/api.py — Persist sessions to DB immediately
  - [ ] Currently sessions only in memory (`_session_manager` dict)
  - [ ] When API restarts, all session data lost
  - [ ] Fix: Save to DB on creation, load on API startup
  - Status: Data loss risk

### CORS & Security Configuration
- [ ] core/server/api.py — CORS should respect config
  - [ ] Current: Hardcoded `allow_origins=["*"]`
  - [ ] Fix: Use `list(get_config().security.allowed_origins)`
  - [ ] Current defaults too permissive: `terminal_enabled=True`, `terminal_require_auth=False`
  - [ ] For production: `terminal_enabled=False`, `terminal_require_auth=True`, `require_auth=True`

### Code Quality & Architecture
- [ ] Unify tool metadata storage
  - [ ] Currently: TOOLS (registry.py) + INSTALLERS (installer.py) + get_installed_tools() = 3 sources of truth
  - [ ] Proposal: Single ToolRegistry class with all methods
  - [ ] Priority: MEDIUM (functional but duplicated)

- [ ] Eliminate TaskRouter or clarify its role
  - [ ] Currently unclear how TaskRouter differs from EventBus
  - [ ] Both emit UI events
  - [ ] Either use only EventBus or clarify separation of concerns
  - [ ] Priority: MEDIUM (architectural cleanliness)

- [ ] Clear async/sync boundaries
  - [ ] SessionManager is async but accessed from sync code
  - [ ] EventStore.append() is sync but called from async
  - [ ] Use asyncio.to_thread() for sync operations in async context
  - [ ] Priority: MEDIUM (robustness)

## Novel Upgrades — HIGH IMPACT (Design Tickets)

### Tier 1: Game-Changers (Differentiate Sentinel)
- [ ] **Deterministic Replay Capsules** — Save complete scan state (tool outputs, decisions, system state)
  - Enables: Perfect debugging, forensic analysis, reproducible scans, training data
  - Est. effort: 2-3 days (modify EventStore + Database)
  - Impact: VERY HIGH (forensic gold)

- [ ] **Evidence Lineage with Hash-Chained Attestations** — Prove evidence hasn't been tampered
  - Enables: Admissible in court/compliance, chain of custody, immutable records
  - Est. effort: 1-2 days (add to evidence_store.py)
  - Impact: HIGH (compliance + trust)

- [ ] **Causal "Attack-Pressure" Graph** — Dependency graph of findings
  - Enables: Exploitation sequencing, impact analysis, visual killchain
  - Est. effort: 2-3 days (new module + graph algorithms)
  - Impact: HIGH (workflow improvement)

### Tier 2: Evasion & Sophistication
- [ ] **Adaptive Covert Scanning Profiles** — Persona-based traffic shaping
  - Enables: Stealth scanning, WAF evasion, mimicry
  - Est. effort: 2-3 days (new module + Strategos integration)
  - Impact: MEDIUM (advanced use cases)

- [ ] **CAL-Backed Live Policy Contracts** — Executable, human-readable policies
  - Enables: Non-engineers can set policy, live updates, compliance audits
  - Est. effort: 3-5 days (CAL parser integration)
  - Impact: HIGH (policy management)

- [ ] **Self-Consistency Arbitration** — Local validators for findings
  - Enables: Reduce false positives, attest findings, multi-stage validation
  - Est. effort: 2-3 days (local checker framework)
  - Impact: MEDIUM (quality improvement)

### Tier 3: Observability
- [ ] **Event Persistence to Disk** — Survive API restarts
  - Enables: Complete audit trail, offline analysis, forensics
  - Est. effort: 1 day (add jsonl sink to EventStore)
  - Impact: MEDIUM (observability)

- [ ] **Structured Logging (JSON to file)** — Machine-readable logs
  - Enables: Analysis tools, alerting, integration
  - Est. effort: 1 day (JSON handler)
  - Impact: LOW (nice-to-have)

- [ ] **OpenTelemetry/Prometheus Metrics** — Distributed tracing support
  - Enables: Integration with observability platforms, performance monitoring
  - Est. effort: 2-3 days (instrumentation)
  - Impact: LOW (nice-to-have)

## Deferred (Track as separate tickets)
- [ ] Implement full `KnowledgeGraph` engine or align UI to existing killchain/events stores
- [ ] Align `/results` schema contract with UI and document in `docs/architecture.md`
