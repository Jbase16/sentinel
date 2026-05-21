# Calibration Runs #8–#9 — 2026-05-14

Two more calibration runs. Goal: get `wraith_persona_diff` to actually
attempt differential auth replay against MegaShop.

| Run | Change | Result |
|---|---|---|
| **008** | **Bug #10 fix**: wire `AuthSessionManager` from `knowledge.personas` in persona_diff | persona_diff progresses past AuthSessionManager check; crashes on `'ExecutionPolicy' has no attribute 'execute_http'` (Bug #11) |
| **009** | **Bug #11 fix**: pass `policy_runtime=None` (type mismatch in auth_diff_scanner.py) | Scan hung at feroxbuster commit before reaching verification (Bug #12 discovered) |

---

## Bug #10 — AuthSessionManager not wired from personas — FIXED

### Reproduction (RUN_007)

```
[Strategos] Dispatching: wraith_persona_diff (1/3)
[AuthDiffScanner] No AuthSessionManager found. Cannot run differential analysis.
[Strategos] ✓ wraith_persona_diff complete. Findings: 0
```

`AuthDiffScanner.initialize()` at `core/wraith/auth_diff_scanner.py:48` looks
for `session.knowledge["session_bridge"]` to be an `AuthSessionManager`
instance. Nothing in the pipeline was constructing one from
`knowledge["personas"]`, even though the factory
`AuthSessionManager.from_knowledge()` already exists and does exactly
the right thing.

### Fix

In `core/toolkit/internal_tools/persona_diff.py:execute()`, call the
factory before constructing AuthDiffScanner:

```python
from core.wraith.session_manager import AuthSessionManager

session = await get_state().get_session(context.session_id)  # (Bug #9 fix)
...

bridge = await AuthSessionManager.from_knowledge(
    session.knowledge,
    base_url=target,
)
if bridge is None:
    await self.log(queue, "persona_diff: no personas configured; skipping.")
    return []

scanner = AuthDiffScanner(session)
```

`from_knowledge()` is idempotent: it caches the bridge in
`knowledge["session_bridge"]` and returns existing instance if already
present. So this call is safe even if some future code path runs it
twice.

### RUN_008 confirmation

```
[Strategos] Dispatching: wraith_persona_diff (1/3)
[ERROR] Login failed for 'user': HTTP 404 (response body redacted)
[ERROR] Failed to authenticate persona 'user'
[ERROR] Login failed for 'admin': HTTP 404 (response body redacted)
[ERROR] Failed to authenticate persona 'admin'
[ERROR] Login flow failed for 'user': 'ExecutionPolicy' object has no attribute 'execute_http'
[ERROR] Login flow failed for 'admin': 'ExecutionPolicy' object has no attribute 'execute_http'
[AuthDiffScanner] Failed to initialize PersonaManager sessions.
[Strategos] ✓ wraith_persona_diff complete. Findings: 0
```

The HTTP 404 errors are *expected* — the placeholder personas in
`megashop-personas.json` point at `/api/login` which doesn't exist on
MegaShop. That's user-correctable. But the `'ExecutionPolicy' object
has no attribute 'execute_http'` errors are real engine bugs — Bug #11.

---

## Bug #11 — ExecutionPolicy vs ExecutionPolicyRuntime type confusion — FIXED

### Root cause

In `core/wraith/auth_diff_scanner.py:61`:

```python
self.manager = PersonaManager(
    personas=auth_bridge.personas,
    policy_runtime=self.session.scope_context.policy if hasattr(self.session, "scope_context") else None,
)
```

`session.scope_context.policy` is an `ExecutionPolicy` (the config
dataclass at `core/wraith/execution_policy.py:73`). But PersonaManager
declares `policy_runtime: Optional[ExecutionPolicyRuntime]` — the
*runtime* class at line 113. When PersonaManager later calls
`self.policy_runtime.execute_http(...)` in `personas.py:213`, it gets
an AttributeError because ExecutionPolicy has no such method.

This is a classic mis-type at a construction site: the type annotation
on PersonaManager was correct, the wraith code passed in the wrong
type, and Python doesn't enforce annotations at runtime.

### Fix

Pass `None` for `policy_runtime`. The login flow degrades to direct
`httpx` requests (without rate limiting / retry policy), which is fine
for our calibration loop and any single-target scan. The longer-term
fix would be to construct a real runtime via
`core.wraith.execution_policy.build_policy_runtime(context=...)`, but
that requires plumbing InternalToolContext into AuthDiffScanner.

Fix applied at `core/wraith/auth_diff_scanner.py:61` with an explanatory
comment referencing this doc.

### Why empirical verification is incomplete

RUN_009 was meant to confirm Bug #11 fix by showing
persona_diff completes its login attempts cleanly (HTTP 404s only, no
AttributeError). **The scan hung at feroxbuster commit before reaching
the verification phase** — Bug #12 below. So we have:

- ✅ Logical verification: 389 tests still pass; the type-correct fix
  passes None where the wrong-typed object was previously injected.
- ❌ Empirical verification: blocked by Bug #12.

Next session, either fix Bug #12 first, or write a unit test that
invokes `WraithPersonaDiffTool.execute` directly with a mocked session
+ knowledge, to confirm the login flow completes without the
AttributeError.

---

## Bug #12 — DISCOVERED — feroxbuster scan commit hang

### Symptom (RUN_009)

```
20:27:49 [INFO] Strategos: Dispatching: feroxbuster (1/3)
20:27:49 [INFO] Strategos: Dispatching: gobuster (2/3)
20:27:51 [INFO] EvidenceLedger: Recorded Observation obs-f269468fb6e9: feroxbuster
...
20:28:29 [INFO] Strategos: ✓ gobuster complete. Findings: 6
... (3+ minutes of silence, backend log never updated) ...
```

gobuster committed in 40 seconds. feroxbuster's `Recorded Observation`
happened *before* gobuster's (20:27:51 vs 20:28:29), suggesting it
finished its work fast. But the `SCAN_COMMIT` for feroxbuster's
`scan_id=9ac49798-19c2-4e54-8712-b5fcb5928960` never appeared.

`pgrep` showed no feroxbuster process running. Ollama was idle
(`expires_at` in the model registry didn't refresh — confirming no
in-flight inference). The backend process was idle (0.2% CPU). Yet the
strategos was waiting on feroxbuster to complete its intent before
advancing.

### Hypothesis

Looks like a scanner_engine async-task hang. feroxbuster's tool task
completed, its observation was recorded, but the commit pipeline never
fired — likely an awaited future that never resolved. The
`tool_timeout_seconds` of 300s should eventually fire, but during a
3+ minute observation window nothing logged.

### Recovery

Killed pysentinel and the backend manually. The DB remained consistent
(scan_sequence=1320 was the last commit), but the session row stayed in
`status: Created` (Bug #4 pattern — sessions never close on abort).

### Next steps

Worth a focused investigation into `core/engine/scanner_engine.py` —
specifically the commit path for tool-completion events when multiple
tools dispatch in parallel within an intent. Possible regression
triggers:
- The `scan_sequence` allocation might collide on parallel commits.
- The `_wait_for_intent_completion` might wait on a tool that never
  posts a completion event.
- BlackBox's single-writer queue might deadlock under specific timing.

This is now the top blocker for further wraith calibration — without
reliable scan completion, we can't verify the Bug #11 fix end-to-end.

---

## Layer-by-layer progression

| Layer | RUN_007 | RUN_008 | RUN_009 |
|---|---|---|---|
| 1. Verification phase reached | ✅ | ✅ | hung before reaching |
| 2. wraith_persona_diff dispatches | ✅ | ✅ | (would have) |
| 3. AuthSessionManager constructed | ❌ (Bug #10) | ✅ | (would have) |
| 4. PersonaManager initializes | ❌ ("No AuthSessionManager") | ❌ (Bug #11) | (would have) |
| 5. Login flow executes | ❌ | ❌ (AttributeError) | (unknown) |
| 6. Differential analysis runs | ❌ | ❌ | (unknown) |

Each run goes one layer deeper. RUN_010 (after Bug #12 fix) should
either reach layer 5 (login flow execution with HTTP 404s only, no
crash) or expose another latent layer.

---

## Aggregate change summary, this session

| File | Change |
|---|---|
| `core/toolkit/internal_tools/persona_diff.py` | Wire AuthSessionManager via `from_knowledge()` (Bug #10) |
| `core/wraith/auth_diff_scanner.py` | Pass `policy_runtime=None` instead of mis-typed ExecutionPolicy (Bug #11) |

**Tests: 389 passing, 0 regressions.**

---

## Open backlog

1. **Bug #12** — feroxbuster commit hang. Top blocker for further scans.
2. **Bug #11 empirical verification** — need a working scan that reaches
   verification phase to confirm no AttributeError.
3. **MegaShop credentials** — placeholder personas can't actually log
   in (HTTP 404). For real IDOR testing, get MegaShop's actual
   `/login` path and credentials.
4. **Carryover bugs**: #4 (session lifecycle), #5 (issues promotion shape
   dependence), #3 (timestamp format), `nuclei_mutating` capability gate,
   `api_discoverer` intent assignment.
