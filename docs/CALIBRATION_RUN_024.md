# Calibration Run #24 — AI Assistant: expert on the entire scan

Goal: make the AI Assistant act as a genuine expert on the WHOLE scan after
it runs, not a chatbot that sees a truncated slice. This run delivers the
first two of three planned intelligence layers.

**Verdict:** ✅ The assistant now holds a complete, exact picture of every
scan (Layer 1) and remembers the conversation (Layer 2). Live-verified on a
real **157-finding** gitlab.com scan — where the old code was blind to 127
of them. 29 new tests, 145 in the AI/security/graph/reporting sweep, zero
regressions.

---

## The constraint that shapes everything

`sentinel-9b-god-tier` (gemma2-9B) has an **8192-token** context ceiling —
the architectural max for this model. The entire system prompt + scan
context + question + answer must fit in ~6000 words. A large scan cannot be
injected verbatim, so the answer is *architecture*, not brute force: hold an
accurate executive summary, look up details on demand — exactly how a human
expert works.

## State before this run (audited)

| Capability | Before |
|---|---|
| Findings the AI sees | First **30** only (`findings[:30]`); blind beyond |
| Quantitative accuracy | Counted from the 30-sample → **wrong** on big scans |
| Conversation memory | **None** — every turn stateless (`ChatRequest` = prompt+session_id) |
| Scan overview | None computed |

On the 157-finding gitlab scan, asking "how many open ports?" would answer
from 30 findings and be wrong. It found **99**.

## Layer 1 — Scan Intelligence Briefing (`core/ai/scan_briefing.py`)

A **deterministic, computed-once digest of the ENTIRE scan**, injected at the
TOP of the chat context (above the per-finding detail). Properties:

- **Complete** — every count is over ALL findings/issues, never a sample.
- **Accurate** — computed from data, not LLM-generated, so it cannot
  hallucinate a number.
- **Compact** — bounded (~400–700 tokens) regardless of scan size via capped
  enumerations with explicit "+N more" markers (so the model knows when a
  list was clipped).
- **Deterministic** — stable ordering (severity rank, then count-desc).

Contents: totals, severity histogram, finding-type breakdown, host
breakdown, complete open-port list, issues-by-confidence + top issues,
attack-graph summary (chains/pressure points), and coverage gaps
(failed/timed-out tools = blind spots).

Wired into `AIEngine.stream_chat`: the briefing leads the context; the
per-finding detail is now sorted **most-severe-first** (so a capped view
shows the worst findings, not an arbitrary slice) and labeled "showing N of
M — use the briefing totals for counts."

### Live verification (real DB, session `c794116a`)

```
SCAN INTELLIGENCE BRIEFING — complete, exact digest of the ENTIRE scan.
Target: https://gitlab.com
KEY TOTALS (exact — quote these directly, do not recount):
- Findings (total): 157
- Open ports (distinct): 99
- Severity counts: MEDIUM 3 · INFO 154
Finding types (7): Open Port ×99 · Discovered Subdomain ×50 · ...
Open ports (99 distinct): 7, 9, 13, 21, 22, 23, 25, ... 49157
```

### The live test caught a REAL bug (the payoff)

Feeding the briefing to the real `sentinel-9b-god-tier` model and asking
"how many open ports?":

| | Model answer |
|---|---|
| First version (list only, no explicit count) | **"79 open ports"** ❌ (miscounted the 99-item list) |
| After KEY TOTALS fix | **"99 distinct open ports"** ✅ |

Ground truth confirmed against the DB: 99 Open Port findings AND 99 distinct
ports — the answer is unambiguously 99. The data was always in the briefing;
the 9B model was *recounting the long port list* and getting it wrong.

**Fix:** lead the briefing with a `KEY TOTALS` block of explicit, labeled,
copy-able numbers ("Open ports (distinct): 99"), placed BEFORE the long
enumerations, plus an instruction: *"quote these directly, do not recount …
you will miscount."* The model now copies the number instead of computing it.

This is the lesson in one line: **handing an LLM the data is not the same as
handing it the answer.** Pinned by `TestKeyTotalsAreQuotable` (4 tests).

## Layer 2 — Conversation memory (multi-turn)

The chat endpoint stays stateless per request; the client replays the
thread. `format_conversation_history()` renders recent turns into the prompt
within a budget:

- keeps the **most recent** turns, drops the oldest (a follow-up refers to
  the latest exchange), bounded by turn-count and char budget;
- **always keeps at least the latest turn**;
- **sanitizes replayed USER turns** through `sanitize_user_question` — a
  planted `>>> EXEC:` in history cannot reach the dispatch path by being
  echoed back.

Wired end-to-end:
- Backend: `ChatRequest.history` (bounded list) → `stream_chat(history=…)` →
  `format_conversation_history` block before the question.
- Swift: `HelixAppState.send` captures prior `thread.messages` (before adding
  the new turn) → `LLMService.generate(history:)` →
  `SentinelAPIClient.streamChat(history:)` → `body["history"]`.

Now follow-ups resolve: "show me the third one", "what about that port?"

## Also fixed (carried from the #23 audit, frontend)

`SentinelAPIClient.streamChat` previously collapsed all newlines (split on
`bytes.lines`, dropped them); structured answers rendered as one blob. Now
each line is yielded with its `\n`. (Shipped in the same Swift files.)

## Tests

| File | Tests | Pins |
|---|---|---|
| `tests/unit/test_scan_briefing.py` | 10 | completeness past the 30-cap, bounded size, determinism, graph/issue/coverage rendering |
| `tests/unit/test_chat_memory.py` | 10 | chronological render, budget/turn trimming, role filtering, EXEC sanitization |
| `tests/unit/test_ai_manifesto_contract.py` | 9 | (Run #23) prompt-contract honesty |

Broad sweep (AI + exec-injection + trinity + causal graph + reporting +
cross-view integration): **145 passed, zero regressions.**

## Deployment

- **Layer 1 (briefing): backend-only — live on next server restart, no app
  rebuild.** This is the biggest single win and needs nothing from the UI.
- **Layer 2 (memory): needs an app rebuild** (Swift sends the thread). The
  backend already accepts `history`.

## Remaining: Layer 3 — on-demand drill-down (not built yet)

An agentic loop: the model emits `>>> QUERY: {"kind":"finding","id":…}` (or
evidence search), the backend resolves it read-only against the session and
feeds the result back so the model continues. Lets the AI be expert on
specific details (raw evidence for one finding) without holding everything in
the 8192 budget. This is a larger architectural addition (a tool-use loop)
and is gated on explicit go-ahead. Tracked as task #32.

## The meta-pattern

Same shape as the rest of the cycle: a producer/consumer contract
(model ↔ scan data) that was lossy and untested against real data. Fix:
compute the truth, make it a named/testable primitive, verify live.
