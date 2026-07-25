# Calibration Run #23 — AI Assistant audit

The final unevaluated UI surface. Same discipline as Report Composer
(#22–26) and Attack Graph (#27): trace UI → API → backend, look for the
recurring contract-drift bug class, fix the actual code, back with tests.

**Verdict:** ✅ The AI Assistant is the *strongest* feature audited this
cycle — session-scoped, graph-truth-guarded, with real safety-gated scan
orchestration. It is NOT a generic chatbot. Three contract-drift defects
fixed: a self-contradicting system prompt that claimed capabilities the
code can't back, a Swift stream that collapsed all newlines, and a dead +
broken non-streaming call. 9 new contract tests, zero regressions.

---

## The trace

```
ChatView (SwiftUI)
  → LLMService.stream(...)            ui/Sources/Services/LLMService.swift
  → SentinelAPIClient.streamChat(prompt, sessionID)
  → POST /v1/ai/chat   {"prompt","session_id"}   (text/plain token stream)
  → core/server/routers/ai.py  chat_with_ai
  → AIEngine.stream_chat(question, session_id)    core/ai/ai_engine.py
  → Ollama (sentinel-9b-god-tier)
```

## What's already excellent (and was left untouched)

This feature is close to "Holy Fuck" tier as-is — worth recording what it
does RIGHT so we don't regress it:

- **Session-scoped context** (`_resolve_chat_context`): explicit
  `session_id` → active scan session → in-memory session → persisted DB
  snapshot → latest. It pulls `db.get_findings(session_id)` — i.e. it does
  NOT have the global-store bug the Report Generator had in #25.
- **Correct finding vocabulary**: reads `severity` / `type` / `message`,
  not the stale `risk` / `title` that broke other consumers this session.
- **Deterministic graph-truth guard**: attack-path questions
  (`is_attack_path_question`) bypass the LLM entirely and render straight
  from the causal-graph contract; any attack-chain claim the model *does*
  emit is sanitized against the real graph
  (`_apply_attack_path_claim_guard`). An offensive-security AI that cannot
  invent attack paths is a genuine differentiator.
- **Real, safety-gated scan orchestration**: the model can emit
  `>>> EXEC: {"tool":"nmap","args":[...]}`; `_try_dispatch_exec` validates
  the tool against `config.scan.safe_tools | restricted_tools`, routes it
  through the `ActionDispatcher` approval gate, and only runs against an
  active scan. Not a stub.
- **Scan-coverage awareness**: failed/timed-out tool runs are surfaced to
  the model as explicit "BLIND SPOTS where vulnerabilities may exist
  undetected." Smart — it makes the AI honest about what the scan missed.

## The defects (all the same class: producer/consumer contract drift)

### 1. The system prompt lied to the model (backend)

`AIEngine.stream_chat`'s inline "manifesto" claimed two capabilities the
chat path cannot back:

- *"SYSTEM ACCESS: You can read the user's clipboard if asked"* — there is
  **no clipboard-read code anywhere** the chat AI can reach. The only
  `NSPasteboard` usage in the app is copy-*to*-clipboard in the report
  views; `_try_dispatch_exec` only dispatches scan tools. The
  `clipboard_enabled` config flag governs the *terminal*, not the AI.
- *"you can suggest installing tools via 'brew' or 'pip'"* — directly
  contradicted by the same prompt's COMMAND PROTOCOL: *"NEVER suggest
  installation commands."*

Telling an LLM it has powers it lacks is a textbook confabulation trigger:
ask it to "read my clipboard" and it will *pretend* it did and invent
contents. For a security assistant whose entire value is trustworthy
analysis, that's corrosive — one fabrication poisons trust in every
correct answer.

**Fix:** extracted the manifesto to a module constant
(`SENTINEL_IDENTITY_MANIFESTO`) and rewrote it to (a) describe only
code-backed capabilities (read-only analysis + EXEC scan orchestration via
the Action Dispatcher + reporting) and (b) **name its limits explicitly**
— *"You CANNOT read the clipboard, access the filesystem, run arbitrary
shell commands, or install software … say so plainly instead of pretending
to do it."* Stating the boundary is itself an anti-confabulation guardrail
(constraint inversion: a false-capability bug turned into an instruction
that suppresses the failure mode). Extracting to a constant makes the
contract unit-testable.

### 2. The Swift stream collapsed every newline (frontend)

`SentinelAPIClient.streamChat` read the response with `bytes.lines` (which
strips the trailing `\n`), trimmed each line, dropped empty lines, and the
consumer concatenated chunks verbatim (`streamedResponse += token`). Net
effect: a finding list / attack chain / multi-line EXEC status rendered as
one run-on blob. **Fix:** yield each line *with* its newline (including
blank lines), so structured output keeps its shape.

### 3. Dead + broken non-streaming call (frontend)

`chatQuery` had zero callers and was doubly wrong: it sent the question as
a `?question=` query param (backend expects JSON body `prompt` → 422) and
JSON-decoded a `text/plain` stream. **Fix:** removed it; `streamChat` is
the real path. (Removing dead-broken code is not a capability reduction.)

## Tests

`tests/unit/test_ai_manifesto_contract.py` (9 tests) pins the prompt
contract so it can't silently drift again:

- clipboard / filesystem / shell / "arbitrary" may appear ONLY inside a
  negated (limit) clause, never as a claim;
- no `brew` / `pip` install advertising;
- the prompt explicitly states its limits and tells the model to decline
  rather than fake actions;
- the genuine capabilities (EXEC + Action Dispatcher, findings analysis,
  attack graph, Report Composer) are NOT gutted;
- `stream_chat` references the shared constant and hasn't re-inlined a
  second manifesto (guards against the copy creeping back).

## Test deltas

| Suite | Before | After |
|---|---|---|
| AI engine prompt contract | 0 (no coverage) | **9** |
| exec-injection + trinity hardening | pass | pass (unchanged) |

Zero regressions from the change.

## Pre-existing breakage noted (NOT caused here, NOT in scope)

`tests/unit/test_command_validation.py` has 40 failures that pre-date this
run (confirmed by stashing the change — identical failures). Root cause:
stale imports like `from core.server.api import ping_v1` for functions a
prior refactor renamed/removed. Worth a separate cleanup pass; flagged, not
fixed here.

## Frontend rebuild required

Defects 2 and 3 are Swift (`ui/Sources/Services/SentinelAPIClient.swift`).
Rebuild the macOS app to pick them up. The backend manifesto fix is live on
the next server start.

## The meta-pattern, one last time

Every defect this cycle — across Report Composer, Attack Graph, and now the
AI Assistant — was the same shape: **a contract between two components that
was correct in structure but never tested end-to-end against real data, so
it drifted.** Here the "producer" was the system prompt and the "consumer"
was the model's actual toolset. Same fix pattern: read the real contract,
make it a named/testable primitive, assert the invariant.
