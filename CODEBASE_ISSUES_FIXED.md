# SentinelForge Codebase Issues - Fixed

## Critical Issues Identified & Resolved

### 1. **core/toolkit/tools.py** ✅ FIXED
**Issue**: Duplicate dictionary key in TOOLS definition
- Line 263: `"eyewitness"` tool had `"target_type": "url"` specified twice
- **Impact**: Second value overrides first (Python silently allows this)
- **Fix**: Removed duplicate key, added detailed inline comments

**Additional Improvements**:
- Added comprehensive documentation for junior developers
- Explained PATH manipulation and why it's necessary
- Documented target normalization logic with examples
- Clarified async installation rationale
- Added error handling context for subprocess failures

---

### 2. **core/base/task_router.py** ⚠️ NEEDS REVIEW
**Issue**: Missing comprehensive error handling
- AIEngine.process_tool_output() can raise exceptions that aren't caught
- No logging for failed event emissions
- Circular import risk with ai_engine

**Recommendations**:
1. Wrap AIEngine calls in try/except
2. Add logging for all error paths
3. Make emit_ui_event more resilient to subscriber failures

---

### 3. **core/server/api.py** ⚠️ NEEDS ATTENTION
**Multiple Issues**:

a) **Session Manager Race Condition**
- Lines 145-160: Session registration/unregistration uses asyncio.Lock correctly
- BUT: `_scan_state` dictionary is modified without lock protection
- **Risk**: Concurrent requests could see inconsistent state
- **Fix**: Use same lock for `_scan_state` modifications

b) **Event Buffer Memory Leak**
- Line 138: EventBuffer max_size=200, but no cleanup on scan completion
- Old events accumulate across multiple scans
- **Fix**: Clear buffer on scan completion or implement TTL

c) **Missing Sequence Number Tracking**
- `/events/stream` endpoint (line 721) accepts `since` parameter
- BUT: Client has no way to get current sequence number on connect
- **Fix**: Send current sequence in initial connection event

d) **Database Init Race**
- Line 198: `await db.init()` in startup_event
- Line 236: `_get_latest_results_sync()` doesn't check if DB is initialized
- **Risk**: Sync functions called before async init completes
- **Fix**: Add initialization check or make all DB access async

e) **Log Queue Overflow**
- Line 99: `_log_queue` maxsize=10000
- Line 217: `put_nowait` silently fails if queue is full
- **Impact**: Lost log messages during heavy scanning
- **Fix**: Use `await queue.put()` with timeout instead of put_nowait

---

### 4. **ui/Sources/Services/SentinelAPIClient.swift** ⚠️ MINOR ISSUES

a) **Missing Error Context**
- All API methods throw generic `APIError.badStatus`
- No distinction between 404, 500, network timeout, etc.
- **Fix**: Create specific error types with HTTP status codes

b) **Timeout Configuration**
- Line 16: `timeoutIntervalForRequest = 120.0` (2 minutes)
- Some scans take 10+ minutes, will timeout mid-scan
- **Fix**: Make timeout configurable per-endpoint

c) **Missing Retry Logic**
- Network failures cause immediate error
- No exponential backoff for transient failures
- **Fix**: Add URLSession retry policy for 5xx errors

---

### 5. **core/cortex/events.py** ℹ️ ARCHITECTURAL CONCERN

**Issue**: Event store is in-memory only
- Line 161: `deque(maxlen=10000)` stores events
- Events are lost on server restart
- **Impact**: No scan history across restarts

**Already Noted in Architecture**:
- Line 130: Comment mentions "can be swapped to SQLite for persistence"
- This is Phase 1 of the upgrade plan (persist to SQLite)

**Temporary Fix**:
- Increase maxlen to 50000 for longer history
- Add periodic disk checkpointing

---

### 6. **Circular Import Chain** ⚠️ FRAGILE

Current import order:
```
api.py → task_router.py → ai_engine.py → findings_store.py
         ↓
      tools.py (bottom import)
```

**Risk**: If any module tries to import TaskRouter at the top, cycle breaks
**Evidence**: tools.py lines 443-446 use try/except to handle missing TaskRouter

**Solutions**:
1. Move TaskRouter import to function scope (current workaround)
2. Create a thin event broker layer (dependency inversion)
3. Use Python's `TYPE_CHECKING` for type hints only

---

## Summary of Fixes Applied

| File | Issue | Status |
|------|-------|--------|
| tools.py | Duplicate dict key | ✅ Fixed + Documented |
| tools.py | Missing comments | ✅ Added comprehensive docs |
| task_router.py | Missing error handling | ⚠️ Needs implementation |
| api.py | Session race condition | ⚠️ Needs lock refactor |
| api.py | Event buffer leak | ⚠️ Needs cleanup logic |
| api.py | DB init race | ⚠️ Needs async consistency |
| SentinelAPIClient.swift | Generic errors | ⚠️ Needs error types |
| events.py | In-memory only | ℹ️ Planned for Phase 1 |

---

## Next Steps for Production Readiness

### Immediate (Before Next Run)
1. ✅ Fix duplicate key in tools.py
2. ⏳ Add try/except in TaskRouter.handle_tool_output()
3. ⏳ Add lock protection for _scan_state modifications
4. ⏳ Clear event buffer on scan completion

### Short Term (This Week)
1. Implement proper error types in Swift client
2. Add database initialization checks
3. Implement log queue overflow handling
4. Add retry logic for API calls

### Medium Term (Phase 1)
1. Persist events to SQLite (per architecture plan)
2. Implement proper dependency injection for TaskRouter
3. Add comprehensive logging throughout
4. Write integration tests for concurrent scans

---

## Running the System Now

**What should work:**
- Single scan execution (no concurrency)
- Tool discovery and installation
- UI updates via SSE events
- Chat with graph context

**What might fail:**
- Concurrent scans (race conditions)
- Very long scans (log queue overflow)
- Network errors (no retry)
- Server restart (lost event history)

**Recommended Testing Order:**
1. Start backend: `python -m uvicorn core.server.api:app --host 127.0.0.1 --port 8765`
2. Test health: `curl http://127.0.0.1:8765/ping`
3. Test tools: `curl http://127.0.0.1:8765/tools/status`
4. Run single scan via UI
5. Check logs for errors

