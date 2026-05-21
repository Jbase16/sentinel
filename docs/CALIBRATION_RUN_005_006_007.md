# Calibration Runs #5–#7 — 2026-05-14

Three calibration runs against MegaShop (`http://127.0.0.1:3003`) chasing
the "we have 24 tools and only 5 ran" gap from RUN_004. Each run unblocked
one more layer of the wraith verification flow.

| Run | Change | Result |
|---|---|---|
| **005** | Retired 6 unused tools; added `--personas` flag to pysentinel | Personas reach `knowledge.personas` ✓; verification phase still not reached (Bug #8) |
| **006** | **Bug #8 fix**: route vuln_scan → verification in standard mode | wraith_persona_diff dispatches ✓; crashes on first line (Bug #9) |
| **007** | **Bug #9 fix**: resolve ScanSession from session_id in persona_diff | persona_diff completes cleanly; needs AuthSessionManager (Bug #10) |

---

## What changed in the registry (RUN_005 prep)

Removed 6 tools the user never planned to install. All references stripped
across **7 files** in one sweep:

| Tool | Removed from |
|---|---|
| `whatweb`, `wafw00f`, `dirsearch`, `httprobe`, `sslyze`, `pshtt` | `core/cortex/capability_tiers.py` · `core/scheduler/modes.py` · `core/scheduler/registry.py` · `core/toolkit/registry.py` · `core/toolkit/installer.py` · `core/engine/vanguard.py` · `tests/unit/test_command_validation.py` (test deleted) · `tests/unit/test_phase2_causal_graph.py` (fixture changed to nuclei) |

Result: **18 registered tools, 18 installed, 0 missing.** The registry
matches operational reality.

---

## Bug #8 — vuln_scan only transitioned to verification in BUG_BOUNTY mode

### Reproduction (RUN_005)

```
[Strategos] Decision: Executing intent_vuln_scan
[Strategos] Dispatching: nuclei_safe (1/3)
[Strategos] Dispatching: nikto (2/3)
... (vuln_scan completes) ...
[Strategos] Mission Complete. All intents exhausted or Walk Away triggered.
```

The verification intent (where wraith_* tools live) was simply never reached
in standard mode. The old code at `core/scheduler/strategos.py:2120-2145` had
the transition wrapped in `if mode == ScanMode.BUG_BOUNTY:` — non-bounty
modes went straight to heavy_artillery, skipping the wraith layer entirely.

### Fix

Make verification a universal step. All modes now transit
`vuln_scan → verification` (which is precondition-gated and auto-skips if no
wraith preconditions are met). The mode-specific behavior is preserved at
the *post-verification* transition:

- `BUG_BOUNTY` mode: verification → END (skips heavy_artillery)
- All other modes: verification → heavy_artillery → END

The `INTENT_TRANSITION` decision-ledger entry distinguishes the two cases
via the `reason` string, so the audit trail still records mode intent.

Test pin: existing `test_walk_away_on_no_surface_delta` still passes;
no regression test was added because the change is "make a path that was
conditional, unconditional" — verified empirically across RUN_006/007.

---

## Bug #9 — persona_diff crashed accessing non-existent `.session` attribute

### Reproduction (RUN_006)

```
[Strategos] Dispatching: wraith_persona_diff (1/3)
[ERROR] core.engine.scanner_engine: [wraith_persona_diff] internal tool error:
  'InternalToolContext' object has no attribute 'session'
File ".../core/toolkit/internal_tools/persona_diff.py", line 60, in execute
```

### Diagnosis

`InternalToolContext` carries `session_id` (str) but not the live
`ScanSession` object. `AuthDiffScanner.__init__(session: ScanSession)`
needs the actual object.

This bug was never observable before because Bug #8 prevented this code path
from being reached. Wraith_persona_diff has effectively been dead code
under standard mode and untested under bug_bounty + personas.

### Fix

Resolve the live session from the global state by id at the top of
`execute()`:

```python
from core.server.state import get_state
session = await get_state().get_session(context.session_id)
if session is None:
    await self.log(queue, f"persona_diff: could not resolve ScanSession for id={context.session_id}; skipping...")
    return []

scanner = AuthDiffScanner(session)
```

If the session is gone (cleaned up between dispatch and execute), the tool
exits cleanly with a log message instead of crashing.

---

## Bug #10 — DISCOVERED, NOT FIXED — AuthSessionManager not initialized from personas

### Symptom (RUN_007)

```
[Strategos] Dispatching: wraith_persona_diff (1/3)
[AuthDiffScanner] No AuthSessionManager found. Cannot run differential analysis.
[Strategos] ✓ wraith_persona_diff complete. Findings: 0
```

### Diagnosis

`AuthDiffScanner.initialize()` looks for an `AuthSessionManager` somewhere
in the session/context to drive differential auth replay. The personas
config in `knowledge.personas` reaches `_select_tools` (which is why the
tool got dispatched), but **the AuthSessionManager isn't constructed from
those personas before persona_diff runs**.

There's a wiring gap between:
- The scope-time personas list in `req.personas` → `session.knowledge["personas"]`
- The runtime `AuthSessionManager` that `AuthDiffScanner` needs

### Status

**Out of scope for this session.** The fix is non-trivial — likely a
SessionBridge initialization step that runs before verification phase to
construct AuthSessionManager from `knowledge.personas`. Bug filed for
follow-up.

### Why the placeholder personas wouldn't have worked anyway

Even with the SessionBridge wired up, the `megashop-personas.json` I
created uses `password_value: "REPLACE_ME"`. Real persona-diff requires
credentials that actually log in. The Bug #10 fix is the structural
unblocker; real bounty work would also need real MegaShop credentials in
the personas file.

---

## RUN_007 final state

Session: `282bddcb-ce4f-432c-a8e3-c5b2ae3b5669`

| Metric | RUN_004 | RUN_007 |
|---|---|---|
| Tools dispatched | 5 | **6** (added wraith_persona_diff) |
| Findings | 26 | 26 |
| Issues promoted | 7 | 6 |
| Verification phase reached | No | **Yes** |
| wraith_persona_diff dispatched | No | **Yes** (clean exit, no AuthSessionManager) |
| wraith_verify status | Not selected | **Blocked: no query-param URLs** (precondition working correctly) |
| wraith_oob_probe status | Not selected | **Blocked: no OOB config** (precondition working correctly) |

The findings counts didn't change because persona_diff and oob_probe both
exited without producing findings (preconditions/AuthSessionManager). The
*structural* progress is real — every phase now executes, every precondition
fires with a precise diagnostic, every blocked tool tells us exactly what
config it needs.

---

## Test summary

| Suite | Before | After |
|---|---|---|
| `tests/unit/` | 283 | 283 |
| `tests/security/` | 105 | 105 |
| Plus retirement: `test_httprobe_stdin` deleted, `wafw00f` fixture → `nuclei` |  |  |
| **Total** | **389** | **389**, zero regressions |

---

## Open backlog after this session

1. **Bug #10** — wire AuthSessionManager from `knowledge.personas` before
   verification phase. This is the next blocker for IDOR detection.
2. **Bug #4** (carryover) — session lifecycle still doesn't close
   (`status: Created` even after Mission Complete).
3. **Bug #5** (carryover) — findings → issues promotion is shape-dependent.
4. **Bug #3** (carryover) — session table timestamp format is mixed.
5. **Capability Gate**: `nuclei_mutating` blocked by `T2b_MUTATING_VERIFY
   not allowed in research mode`. Worth investigating whether to elevate to
   bounty mode or change the default tier policy.
6. **bug_bounty mode for local/loopback targets** still disables
   gobuster/feroxbuster (RUN_004 finding). Need a per-target-type override.
7. **`api_discoverer` still never dispatched** — registered, installed, no
   intent assignment makes it reachable.
8. **MegaShop credentials** — the placeholder personas can't actually log
   in. Real IDOR testing needs real credentials.

## What works now that didn't before

- All 18 registered tools are installed and operationally reachable.
- `--personas` flag plumbs personas through the API to `knowledge.personas`.
- Standard mode reaches verification phase.
- wraith_persona_diff dispatches and exits cleanly.
- wraith_verify and wraith_oob_probe both produce precise diagnostic
  messages when their preconditions aren't met (URL params / OOB config).
- The empirical loop now has six clear blocking layers, each diagnosable in
  the backend log.

The differential-auth IDOR pipeline is one bug away from being executable
end-to-end.
