# SentinelForge TODO — Pass 3 Stabilization & Hardening

**Source**: GLM Review (Passes 1 & 2) — Comprehensive system analysis and prioritized action plan

This is the single source of truth for Pass 3 work. Items are concrete, file-scoped, and ordered by priority. Check off as you land patches.

---

## P0 — IMMEDIATE FIXES (Week 1, ~8 Hours)

**Priority: Correctness, Safety, Unblock Deployment**

### 1. Fix Shell Injection Vulnerabilities (2 hours)

**Location**: `core/toolkit/installer.py`, `core/engine/executor.py`

**Problem**: `shell=True` allows command injection if tool names are user-controlled

**Fixes Required**:
- [ ] Replace `create_subprocess_shell` with `create_subprocess_exec` everywhere (installer.py:203-209, 318-324; executor.py)
- [ ] Add `CommandValidator` with allowlist checks:
  ```python
  class CommandValidator:
      ALLOWED_TOOLS = set(TOOLS.keys())
      
      @staticmethod
      def validate_tool(name: str) -> bool:
          return name in CommandValidator.ALLOWED_TOOLS
      
      @staticmethod
      def validate_args(args: List[str]) -> List[str]:
          validated = []
          for arg in args:
              if any(op in arg for op in ['|', '&', ';', '$', '`', '(']):
                  raise ValueError(f"Shell operator in argument: {arg}")
              validated.append(arg)
          return validated
  ```
- [ ] Remove bash -lc from tool definitions; handle fallback strategies in Python
  - Current: `["bash", "-lc", "printf '%s\\n' $(cat wordlist) | tool {target}"]`
  - Problem: {target} interpolation creates injection points
  - Solution: Split into sequential Python logic, avoid shell entirely
- [ ] Enforce allowlist of tool names at API boundary (validate names in `TOOLS`)

**Validation**:
- [ ] Unit tests for command execution validation
- [ ] Verify no shell=True remains in codebase (grep search)
- [ ] Test with malicious input attempts

**Status**: CRITICAL — blocks secure tool installation, highest security risk

---

### 2. Fix CORS Configuration (COMPLETED ✅)

**Location**: `core/server/api.py:438-518`

**Problem**: Wildcard CORS with credentials enabled is local-privilege escalation

**Solution Implemented**:
- [x] Created `is_origin_allowed()` function for dynamic origin validation
- [x] Implemented `DynamicCORSMiddleware` that returns exact origin (CORS spec compliant)
- [x] Supports wildcard port patterns (`http://localhost:*`) while returning exact origin
- [x] WebSocket origin check already in place at `api.py:520-524`

**Code**: Custom middleware validates patterns like `http://localhost:*` and returns
the EXACT origin in `Access-Control-Allow-Origin` header (required when credentials enabled).

**Validation**:
- [x] 8 CORS security tests added in `tests/unit/test_command_validation.py`
- [x] Tests verify wildcard ports work, external origins rejected, scheme validation
- [x] All 25 tests pass

**Status**: ✅ FIXED — No wildcard origin returned, spec-compliant CORS

---

### 3. Fix Missing Config Exports (ALREADY WORKING ✅)

**Location**: `core/base/config.py:356-397`, `core/ai/ai_engine.py:38`

**Problem**: Legacy aliases executed AFTER imports, causing NameError on startup

**Status**: ✅ VERIFIED WORKING - No changes needed

**Verification**:
- [x] All imports work correctly: `from core.base.config import AI_PROVIDER, OLLAMA_URL, AI_MODEL, AI_FALLBACK_ENABLED`
- [x] `ai_engine.py` imports successfully
- [x] Config values load properly from environment

**Current Structure (Correct)**:
1. Classes defined first (lines 28-350)
2. `_config` variable and `get_config()` function (lines 356-387)
3. Legacy aliases at end (lines 391-397) - work because `get_config()` initializes on first call

The current implementation is correct - `get_config()` creates the config on-demand when first called by the legacy aliases.

---

### 4. Fix Event Emission Bug (COMPLETED ✅)

**Location**: `core/server/api.py:336-350`

**Problem**: Wrong API call crashes with AttributeError, breaks UI state

**Solution Implemented**:
- [x] Replaced `event_bus._store.append()` with `event_bus.emit(GraphEvent(...))`
- [x] Changed from non-existent `SCAN_ERROR` to `SCAN_FAILED` event type
- [x] Uses proper `GraphEvent(type=..., payload=...)` constructor

**Code Fix** (`api.py:342-350`):
```python
# Emit SCAN_FAILED event to notify UI and DecisionLedger
try:
    event_bus.emit(GraphEvent(
        type=GraphEventType.SCAN_FAILED,
        payload={"error": str(e), "target": req.target}
    ))
except Exception:
    pass
```

**Validation**:
- [x] Unit tests added: `TestScanEventEmission` (3 tests)
- [x] Verified SCAN_FAILED event type exists
- [x] Verified GraphEvent creation works
- [x] Verified EventBus.emit() method exists

**Test Results**: 28 passed (including 3 new event tests)

**Status**: ✅ FIXED — Proper event emission, UI/DecisionLedger will receive SCAN_FAILED

---

### 5. Fix Tool Import Paths (30 minutes)

**Location**: `core/toolkit/tools.py`

**Problem**: `/tools/install` and `/tools/uninstall` endpoints reference functions not exported

**Fix Required**: Re-export in `core/toolkit/tools.py`:
```python
from core.toolkit.installer import install_tools, uninstall_tools

__all__ = [
    "install_tools",
    "uninstall_tools",
    "get_installed_tools",
    "TOOLS",
    "get_tool_command"
]
```

**Validation**:
- [ ] Verify endpoints work with curl: `curl -X POST http://localhost:8765/tools/install -d '{"tools": ["nmap"]}'`
- [ ] Check imports resolve correctly

**Status**: HIGH — blocks tool installation API

---

### 6. Fix Wordlist Path (30 minutes)

**Location**: `core/toolkit/registry.py:7-8`

**Problem**: Path resolves to `core/assets/wordlists` (doesn't exist), should be repo root

**Current (WRONG)**:
```python
BASE_DIR = Path(__file__).resolve().parents[1]  # core/
WORDLIST_DIR = BASE_DIR / "assets" / "wordlists"  # core/assets/wordlists (WRONG)
```

**Fix Required**:
```python
REPO_ROOT = Path(__file__).resolve().parents[2]  # repo root
WORDLIST_DIR = REPO_ROOT / "assets" / "wordlists"

# Fallback to inline wordlists if directory missing
if not WORDLIST_DIR.exists():
    logger.warning(f"Wordlist directory not found: {WORDLIST_DIR}, using inline wordlists")
    WORDLIST_DIR = None
```

**Validation**:
- [ ] Verify COMMON_WORDLIST exists after fix
- [ ] Test affected tools: dirsearch, gobuster, feroxbuster, wfuzz
- [ ] Test graceful degradation when wordlists missing

**Status**: MEDIUM — blocks directory fuzzing tools, nmap/port scanners still work

---

### 7. Fix Database Initialization Race Condition (1 hour)

**Location**: `core/data/db.py:63`

**Problem**: `asyncio.Lock()` requires running event loop, but `__init__` runs in sync context

**Current (WRONG)**:
```python
def __init__(self):
    self._init_lock = asyncio.Lock()  # ❌ Can't use in __init__
```

**Fix Required**: Use `threading.Lock()` instead:
```python
import threading

def __init__(self):
    self._init_lock = threading.Lock()
```

**Validation**:
- [ ] Unit test: verify Database can be instantiated in sync context
- [ ] Test concurrent initialization from multiple threads

**Status**: HIGH — blocks any sync code path that instantiates Database

---

## P1 — HARDENING (Weeks 2-3, ~16 Hours)

**Priority: Stability, Performance, Maintainability**

### 8. Add Session Cleanup (2 hours)

**Location**: `core/server/api.py`

**Problem**: `_session_manager` dict grows indefinitely, memory leak in long-running processes

**Fix Required**:
```python
from datetime import datetime, timedelta

async def cleanup_old_sessions(max_age: timedelta = timedelta(days=1)):
    now = datetime.now()
    to_remove = []
    
    async with _session_manager_lock:
        for session_id, session in _session_manager.items():
            if now - session.start_time > max_age:
                to_remove.append(session_id)
        
        for session_id in to_remove:
            del _session_manager[session_id]

# Schedule cleanup task (every 24 hours)
async def start_session_cleanup():
    while True:
        await asyncio.sleep(86400)  # 24 hours
        await cleanup_old_sessions()
```

**Validation**:
- [ ] Monitor session count over time
- [ ] Test cleanup removes old sessions correctly
- [ ] Verify no active sessions accidentally removed

**Status**: HIGH — memory leak in production

---

### 9. Add Global Event Sequence Counter (2 hours)

**Location**: `core/cortex/events.py`, `core/scheduler/decisions.py`

**Problem**: EventStore and DecisionLedger have separate sequences, no correlation possible

**Fix Required**:
```python
import threading

_global_sequence = 0
_global_sequence_lock = threading.Lock()

def next_sequence() -> int:
    global _global_sequence
    with _global_sequence_lock:
        _global_sequence += 1
        return _global_sequence

# Use in EventStore
class EventStore:
    def append(self, event: GraphEvent) -> StoredEvent:
        with self._lock:
            sequence = next_sequence()  # Global, not local
            stored = StoredEvent(sequence=sequence, event=event)
            # ...

# Use in DecisionLedger
class DecisionLedger:
    def commit(self, decision: DecisionPoint) -> DecisionPoint:
        with self._lock:
            sequence = next_sequence()  # Global, not local
            sequenced_decision = decision.with_sequence(sequence)
            # ...
```

**Validation**:
- [ ] Verify cross-subsystem ordering works
- [ ] Test that sequence numbers are globally monotonic

**Status**: MEDIUM — missing correlation between decisions and events

---

### 10. Add Circuit Breaker for AI Health (3 hours)

**Location**: `core/ai/ai_engine.py`

**Problem**: If Ollama crashes/hangs, AI request hangs for 300s, cascades through system

**Fix Required**:
```python
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.open_until = time.time()
    
    def call(self, func: Callable, *args, **kwargs):
        if self.is_open():
            raise CircuitBreakerOpenError()
        
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise
    
    def is_open(self) -> bool:
        return self.failure_count >= self.failure_threshold and time.time() < self.open_until
    
    def on_success(self):
        self.failure_count = 0
    
    def on_failure(self):
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.open_until = time.time() + 60.0  # Open for 60s

# Use in AIEngine
class AIEngine:
    def __init__(self):
        self.client = OllamaClient(...)
        self.circuit_breaker = CircuitBreaker()
    
    def stream_chat(self, question: str):
        try:
            yield from self.circuit_breaker.call(
                self.client.stream_generate,
                user_prompt,
                system_prompt
            )
        except CircuitBreakerOpenError:
            yield "AI Chat unavailable (circuit breaker open)."
```

**Validation**:
- [ ] Test circuit breaker opens after N failures
- [ ] Verify circuit breaker resets after timeout
- [ ] Add health check endpoint for AI status

**Status**: HIGH — prevents cascading failures from AI unavailability

---

### 11. Add Resource Guards (3 hours)

**Location**: `core/engine/scanner_engine.py`

**Problem**: Unlimited subprocesses, findings, disk usage (exhaustion vectors)

**Fix Required**:
```python
class ResourceGuard:
    def __init__(self, max_findings: int = 10000, max_disk_mb: int = 1000):
        self.findings_count = 0
        self.max_findings = max_findings
        self.disk_usage = 0
        self.max_disk_mb = max_disk_mb
    
    def check_findings(self, count: int) -> bool:
        if self.findings_count + count > self.max_findings:
            raise ResourceExhaustedError(f"Too many findings: {self.findings_count + count}")
        self.findings_count += count
        return True
    
    def check_disk(self, size_bytes: int) -> bool:
        if self.disk_usage + size_bytes > self.max_disk_mb * 1024 * 1024:
            raise ResourceExhaustedError(f"Too much disk usage")
        self.disk_usage += size_bytes
        return True

# Use in ScannerEngine
class ScannerEngine:
    def __init__(self, session=None):
        self.resource_guard = ResourceGuard()
    
    async def _run_tool_task(self, tool: str, ...):
        # ... after getting output ...
        output_size = len(output_text.encode('utf-8'))
        self.resource_guard.check_disk(output_size)
        
        findings_count = len(findings)
        self.resource_guard.check_findings(findings_count)
```

**Validation**:
- [ ] Test resource limits enforced correctly
- [ ] Verify graceful error messages when limits exceeded
- [ ] Monitor resource usage during scans

**Status**: MEDIUM — prevents resource exhaustion attacks

---

### 12. Add Scan Transactionality (3 hours)

**Location**: `core/engine/scanner_engine.py`, `core/data/db.py`

**Problem**: Mid-scan crash creates inconsistent state (SCAN_STARTED but no SCAN_COMPLETED)

**Fix Required**:
```python
class ScanTransaction:
    def __init__(self, session_id: str, db: Database, event_bus: EventBus):
        self.session_id = session_id
        self.db = db
        self.event_bus = event_bus
        self.committed = False
        self.pending_events: List[GraphEvent] = []
        self.pending_writes: List[Callable] = []
    
    def emit_event(self, event: GraphEvent):
        self.pending_events.append(event)
    
    def save_finding(self, finding: Dict):
        self.pending_writes.append(lambda: self.db.save_finding(finding, self.session_id))
    
    async def commit(self):
        # 1. Write all pending DB records
        for write in self.pending_writes:
            await write()
        
        # 2. Emit all pending events
        for event in self.pending_events:
            self.event_bus.emit(event)
        
        # 3. Mark as committed
        self.committed = True
    
    async def rollback(self):
        # Delete any partial writes
        # Don't emit events
        pass

# Use in Strategos
async def run_mission(self, ...):
    tx = ScanTransaction(session_id, db, event_bus)
    try:
        tx.emit_event(GraphEvent(type=SCAN_STARTED, ...))
        # ... run scan ...
        tx.save_finding(finding)
        await tx.commit()
    except Exception:
        await tx.rollback()
        raise
```

**Validation**:
- [ ] Test commit writes all pending data
- [ ] Test rollback cleans up partial state
- [ ] Verify no inconsistent state after mid-scan crash

**Status**: HIGH — prevents inconsistent state from crashes

---

### 13. Add Terminal Origin Check (1 hour)

**Location**: `core/server/api.py`

**Problem**: `/ws/pty` accepts connections from any origin

**Fix Required** (already included in CORS fix above):
```python
@app.websocket("/ws/pty")
async def websocket_pty(websocket: WebSocket):
    if config.terminal_enabled:
        origin = websocket.headers.get("origin")
        if origin not in config.security.allowed_origins:
            await websocket.close(code=403, reason="Origin not allowed")
            return
```

**Validation**:
- [ ] Test connection from allowed origin succeeds
- [ ] Test connection from disallowed origin rejected
- [ ] Verify auth check still works after origin check

**Status**: MEDIUM — additional security layer

---

### 14. Add Log Queue Overflow Warning (30 minutes)

**Location**: `core/base/session.py`

**Problem**: Silent log drops when queue overflow

**Fix Required**:
```python
# In log emission code
if queue.full():
    logger.warning(f"Log queue overflow, dropping entry. Queue size: {queue.maxsize}")
```

**Validation**:
- [ ] Generate logs rapidly to trigger overflow
- [ ] Verify warning appears in logs
- [ ] Consider circular buffer instead of silent drop

**Status**: LOW — operational observability

---

### 15. Add API Versioning (2 hours)

**Location**: `core/server/api.py`

**Problem**: No `/v1/` prefix, breaking changes will hurt consumers

**Fix Required**:
```python
from fastapi import APIRouter

# Versioned router
v1_router = APIRouter(prefix="/v1")

@v1_router.post("/scan")
async def start_scan(req: ScanRequest):
    pass

@v1_router.get("/status")
async def get_status():
    pass

# Mount in app
app.include_router(v1_router)

# Add deprecation warnings for old endpoints
@app.post("/scan", deprecated=True)
async def start_scan_legacy(req: ScanRequest):
    return await start_scan(req)
```

**Validation**:
- [ ] Verify `/v1/scan` works
- [ ] Test deprecation warning on old endpoints
- [ ] Document versioning strategy

**Status**: MEDIUM — long-term maintenance

---

## P2 — LONG-TERM BETS (Months 2-3, ~40 Hours)

**Priority: Platformization, Automation, Extensibility**

### 16. Deterministic Replay Capsules (8 hours)

**Location**: `core/cortex/event_store.py`, `core/data/db.py`

**Goal**: Save complete scan state (tool outputs, decisions, system state)

**Design**:
```python
@dataclass
class ScanCapsule:
    target: str
    decisions: List[DecisionPoint]
    tool_outputs: Dict[str, str]
    findings: List[Finding]
    environment: Dict
    checksum: str  # Hash of all content
    
    def verify(self) -> bool:
        """Verify capsule integrity (hash chain)."""
        pass
    
    def sanitize(self) -> "ScanCapsule":
        """Remove sensitive data for sharing."""
        pass
    
    @classmethod
    def from_session(cls, session: ScanSession) -> "ScanCapsule":
        """Create capsule from completed scan session."""
        pass
    
    def replay(self) -> ScanSession:
        """Replay scan from capsule, return identical results."""
        pass
```

**Enables**: Perfect debugging, forensic analysis, reproducible scans, training data

**Status**: VERY HIGH (game-changer feature)

---

### 17. Causal Attack-Pressure Graph (6 hours)

**Location**: New module `core/cortex/causal_graph.py`

**Goal**: Dependency graph of findings, identify "pressure points"

**Design**:
```python
class CausalGraphBuilder:
    def build(self, findings: List[Finding]) -> DiGraph:
        # 1. Extract causal relationships from findings
        # 2. Build directed graph (A → B means A enables B)
        # 3. Identify "pressure points" (nodes with high out-degree)
        # 4. Calculate "fix impact" (removing node X disables Y paths)
        pass
    
    def identify_pressure_points(self) -> List[str]:
        """Return findings that, if fixed, disable most attack paths."""
        pass
    
    def calculate_fix_impact(self, finding_id: str) -> int:
        """Return number of attack paths disabled by fixing this finding."""
        pass
```

**Enables**: "Fix these 2 bugs and you're 80% safer", automated remediation prioritization

**Status**: HIGH (workflow improvement)

---

### 18. Continuous Autonomous Monitoring (6 hours)

**Location**: New module `core/monitoring/continuous.py`

**Goal**: Baseline + incremental scans with change detection

**Design**:
```python
class ContinuousMonitor:
    def __init__(self, alert_threshold: float = 0.8):
        self.baseline: ScanState = None
        self.alert_threshold = alert_threshold
    
    async def check_for_changes(self):
        current = await self.incremental_scan()
        delta = self.diff(self.baseline, current)
        
        if delta.severity >= self.alert_threshold:
            await self.alert_team(delta)
    
    def diff(self, baseline: ScanState, current: ScanState) -> Delta:
        # Calculate difference, assign severity score
        pass
    
    async def incremental_scan(self) -> ScanState:
        # Only scan changed assets, skip known-good findings
        pass
```

**Enables**: Production security monitoring, avoid scan fatigue

**Status**: HIGH (production readiness)

---

### 19. Time-Travel Debugging (6 hours)

**Location**: New module `core/debugging/time_travel.py`

**Goal**: Scrub through scan timeline, inspect state at any decision

**Design**:
```python
class TimeTravelDebugger:
    def __init__(self):
        self.snapshots: Dict[int, ScanState] = {}
    
    def snapshot(self, decision_id: int, state: ScanState):
        self.snapshots[decision_id] = state.copy()
    
    def get_state_at(self, sequence: int) -> ScanState:
        # Find nearest snapshot, replay events up to target
        pass
    
    def get_timeline(self) -> List[Tuple[int, DecisionType, str]]:
        # Return list of (sequence, decision_type, description)
        pass
```

**Enables**: Perfect debugging of failed scans, forensic analysis

**Status**: HIGH (debugging superpower)

---

### 20. Schema Migrations (4 hours)

**Location**: New directory `core/data/migrations/`

**Goal**: Versioned database schemas with upgrade/downgrade

**Design**:
```
core/data/migrations/
  __init__.py
  001_initial_schema.sql
  002_add_confidence_column.sql
  003_add_foreign_keys.sql
  004_add_evidence_hashes.sql
```

```python
class MigrationRunner:
    def __init__(self, db: Database):
        self.db = db
    
    async def run_migrations(self):
        version = await self.get_current_version()
        while True:
            next_migration = self.get_next_migration(version)
            if not next_migration:
                break
            await self.apply_migration(next_migration)
            version += 1
    
    async def apply_migration(self, migration: str):
        sql = self.load_migration_sql(migration)
        await self.db.execute(sql)
    
    async def rollback_to(self, target_version: int):
        # Downgrade logic
        pass
```

**Enables**: Safe schema evolution, backward compatibility

**Status**: MEDIUM (production requirement)

---

### 21. Per-Target Rate Limiting (2 hours)

**Location**: `core/server/api.py`

**Goal**: Prevent aggressive scanning of single target

**Design**:
```python
from collections import defaultdict

class PerTargetRateLimiter:
    def __init__(self, requests_per_minute: int = 10):
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def is_allowed(self, target: str) -> bool:
        with self._lock:
            now = time.time()
            window = 60.0
            self.requests[target] = [t for t in self.requests[target] if now - t < window]
            if len(self.requests[target]) >= self.requests_per_minute:
                return False
            self.requests[target].append(now)
            return True

# Use in API
@app.post("/scan")
async def start_scan(req: ScanRequest):
    target_limiter = PerTargetRateLimiter(requests_per_minute=5)
    if not target_limiter.is_allowed(req.target):
        raise RateLimitExceeded("Too many scans for this target")
```

**Enables**: Prevent WAF blocks, respect target resources

**Status**: MEDIUM (operational safety)

---

### 22. Database Health Monitoring (2 hours)

**Location**: `core/data/db.py`

**Goal**: Monitor connection pool, query latency, automatic recycling

**Design**:
```python
class Database:
    def __init__(self):
        self.metrics = {
            "connection_pool_size": 0,
            "active_connections": 0,
            "slow_queries": [],
            "last_query_latency": 0.0
        }
    
    async def execute(self, query: str, params: Dict):
        start = time.time()
        try:
            result = await self._execute_impl(query, params)
            latency = time.time() - start
            self.metrics["last_query_latency"] = latency
            
            if latency > 1.0:  # Slow query
                self.metrics["slow_queries"].append((query, latency))
            
            return result
        finally:
            self.update_connection_metrics()
    
    def get_health(self) -> Dict:
        return self.metrics
    
    async def recycle_connections(self):
        # Close idle connections, reopen fresh
        pass
```

**Enables**: Proactive issue detection, automatic recovery

**Status**: LOW (operational observability)

---

### 23. Event Persistence to Disk (4 hours)

**Location**: `core/cortex/event_store.py`

**Goal**: Survive API restarts, complete audit trail

**Design**:
```python
class EventStore:
    def __init__(self, persist_to_disk: bool = True, retention_days: int = 30):
        self._persist_to_disk = persist_to_disk
        self._retention_days = retention_days
        self._disk_path = Path("data/events.jsonl")
    
    def append(self, event: GraphEvent) -> StoredEvent:
        # ... existing in-memory append ...
        
        if self._persist_to_disk:
            self._persist_to_disk(stored)
    
    def _persist_to_disk(self, stored: StoredEvent):
        with open(self._disk_path, "a") as f:
            f.append(json.dumps({
                "sequence": stored.sequence,
                "timestamp": stored.timestamp,
                "event": stored.event.dict()
            }) + "\n")
    
    async def load_from_disk(self):
        # Load events from JSONL on startup
        pass
    
    async def cleanup_old_events(self):
        # Delete events older than retention_days
        pass
```

**Enables**: Complete audit trail, offline analysis, forensics

**Status**: MEDIUM (observability)

---

### 24. Evidence Content-Addressing (3 hours)

**Location**: `core/data/evidence_store.py`

**Goal**: Hash evidence blobs, deduplicate identical outputs

**Design**:
```python
class EvidenceStore:
    def add_evidence(self, raw_output: str) -> Evidence:
        # Hash the output
        content_hash = hashlib.sha256(raw_output.encode()).hexdigest()
        
        # Check if already exists
        existing = self._by_hash.get(content_hash)
        if existing:
            return existing
        
        # Create new evidence
        evidence = Evidence(
            hash=content_hash,
            content=raw_output,
            size=len(raw_output),
            timestamp=datetime.now()
        )
        
        self._by_hash[content_hash] = evidence
        return evidence
    
    def get_by_hash(self, hash: str) -> Optional[Evidence]:
        return self._by_hash.get(hash)
```

**Enables**: Disk space savings, deduplication, signature capability

**Status**: LOW (efficiency improvement)

---

### 25. CAL Policy Interpreter (6 hours)

**Location**: New module `core/cortex/cal_interpreter.py`

**Goal**: Compile CAL policies to Python, integrate with ArbitrationEngine

**Design**:
```python
# Step 1: Python policies (baseline)
class ScopePolicy(Policy):
    def evaluate(self, decision, context) -> Verdict:
        target = context.get("target")
        if target not in self.authorized_domains:
            return Verdict.VETO
        return Verdict.ALLOW

# Step 2: Compile CAL to Python
class CALCompiler:
    def compile_policy(self, cal_source: str) -> Policy:
        # Parse CAL syntax
        # Generate Python class
        # Return executable Policy instance
        pass

# cal_policy = parse_cal("""
#     POLICY scope_enforcement:
#         REQUIRE target IN authorized_domains
#         IF severity == 'HIGH' THEN REQUIRE explicit_approval
# """)
# python_policy = cal_to_python(cal_policy)

# Step 3: Integrate with ArbitrationEngine
class ArbitrationEngine:
    def __init__(self):
        self.policies = []
    
    def load_cal_policy(self, cal_source: str):
        policy = CALCompiler().compile_policy(cal_source)
        self.policies.append(policy)
```

**Enables**: Non-engineers can set policy, live updates, compliance audits

**Status**: HIGH (policy management)

---

## Validation Checklist (After P0 Fixes)

### Basic Functionality
- [ ] Start API: `uvicorn core.server.api:app`
- [ ] Verify endpoints respond: `/ping`, `/status`, `/events/stats`, `/cortex/graph`
- [ ] POST `/scan` on benign target
- [ ] Observe `/events/stream` sequence: `scan_started` → tool lifecycle → `scan_completed`

### Integration Tests
- [ ] Run `pytest tests/integration -v -s`
- [ ] Fix any regressions from P0 changes
- [ ] Verify all critical paths pass

### Security Validation
- [ ] Test shell injection attempts (all paths fail)
- [ ] Test CORS from disallowed origin (rejected)
- [ ] Test `/ws/pty` from disallowed origin (rejected)
- [ ] Test API auth enforcement (if enabled)

---

## Deferred (Track as Separate Tickets)

### Architectural Decisions Needed
- [ ] Implement full `KnowledgeGraph` engine or align UI to existing killchain/events stores
- [ ] Eliminate TaskRouter or clarify its role (both emit UI events, separation unclear)
- [ ] Unify tool metadata storage (currently 3 sources of truth: TOOLS, INSTALLERS, get_installed_tools)

### Code Quality & Maintainability
- [ ] Clear async/sync boundaries (SessionManager async accessed from sync code, EventStore.append sync called from async)
- [ ] Replace placeholder documentation headers with actual summaries
- [ ] Document IPC contract and API schemas in `docs/architecture.md`

---

## References

**Source Document**: `docs/GLM Review - 2 Passes.md`

**Previous Work**:
- Pass 1: 7-Phase Hardening (Layer 3/4 logic hardening — completed Dec 16)
- Pass 2: Repository Cleanup (file organization — completed Dec 21)

**Next Phase**: Pass 4 (to be defined after P0-P2 completion)

---

## Notes

- **P0 items must be completed before production deployment**
- **P1 items should be completed for production readiness**
- **P2 items are strategic bets for platform differentiation**
- **Estimated total effort**: ~64 hours (3-4 weeks for P0+P1, 2-3 months for P2)
- **All time estimates are for experienced engineers familiar with codebase**