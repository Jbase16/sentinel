# Phase 7 — The Persona Foundry

> The part everyone else gives up on.

## The wall everyone hits

Every authenticated-vulnerability finder — Sentinel included, until now —
hits the same wall: **the test needs real accounts on the target, and
account creation can't be fully automated.** Sign-up flows have anti-bot
controls (CAPTCHA, email verification, SMS codes, payment 3-D Secure)
precisely to stop automation. So every tool in this space ends its
workflow at the same handoff:

> "Here's where you need to go sign up two accounts manually."

That handoff is where the funnel leaks. The researcher's attention —
the scarce resource — gets spent on thirty minutes of typing,
navigating, and inbox-checking per account, per program. A researcher
who could test ten programs a week tests two.

## Why nobody solves it (and why that's the wrong reason)

The obvious way to "solve" the wall is to **bypass** it: CAPTCHA-solving
services, account farms, synthetic-identity generators. Those cross the
ethical and Terms-of-Service line. So the industry treats the wall as
immovable and stops there.

That's a false dichotomy. The wall isn't one thing — it's a thin layer
of *rare-but-hard* steps embedded in a thick layer of *boring* steps:

| Step | Frequency | Needs a human? |
|------|-----------|----------------|
| Navigate to /signup | every signup | no |
| Type email / name / password | every signup | no |
| Click "create account" | every signup | no |
| Read a verification email | most signups | the *click* does, the *reading* doesn't |
| Solve a CAPTCHA | some signups | **yes** |
| Enter an SMS code | some signups | the *receiving* does |
| Complete payment 3-D Secure | rare | **yes** |

The boring 95% is exactly what services *don't care* if you automate.
The rare 5% is what they put there to require a human — so **give it to
a human.** Not as a "go do all of this manually" dump, but as a
**frictionless handoff**: a notification with a one-second click.

That reframe — *automate the boring, hand off the rare, keep the human
the agent of every consequential action* — is the Persona Foundry.

## The principle that keeps it legitimate

The researcher remains the agent of every action that matters:

- **They intend the signup.** It runs from a recipe they recorded or
  approved, against a target they're authorized to test.
- **They solve every anti-bot challenge.** The CAPTCHA, the 3-D Secure,
  the "are you human" — all handed to the human. The system never
  attempts to defeat an anti-bot control.
- **They own the email and phone** used for verification. The Foundry
  only ever uses mailboxes/numbers the researcher granted access to —
  never stolen, never spoofed.
- **Every account is a real, owned, accountable identity** — a research
  persona with a real name, a dedicated email, optionally a dedicated
  phone and payment method. Not a fabricated identity.

And it's all **auditable + rate-limited by construction:**

- Every account the Foundry creates is logged — persona, service,
  recipe, timestamp, outcome. The researcher can answer "what did this
  tool create, where, when" at any moment.
- A per-(persona, service) cap refuses to create more than N accounts
  on the same service in a rolling window. The system *cannot* become
  an account farm; the guardrail is in the code path, not the docs.

## Architecture

Seven components, each shipped + tested (1285 unit tests green):

```
                 ┌─────────────────────────────────────────────┐
                 │  PF5  Account Topology Planner               │
                 │  "what accounts does THIS test need?"        │
                 │  vuln class → account structure              │
                 └──────────────────┬──────────────────────────┘
                                    │ AccountPlan
                                    ▼
   ┌────────────────────┐   ┌───────────────────────────────────┐
   │ PF2 Persona Vault  │◄──┤  PF1 SignupRecipe                 │
   │ identities + audit │   │  parameterized signup-flow         │
   │ + rate limit       │   │  (persona: bindings)               │
   └─────────┬──────────┘   └──────────────┬────────────────────┘
             │ persona                      │ recipe
             └──────────────┬───────────────┘
                            ▼
              ┌─────────────────────────────┐    ┌──────────────────┐
              │  PF3 Recipe Replayer        │───▶│ PF7 Playwright    │
              │  execute recipe + persona   │    │ Driver (browser)  │
              │  pause at every wall        │    └──────────────────┘
              └──────────────┬──────────────┘
                             │ Challenge
                             ▼
              ┌─────────────────────────────┐
              │  PF4 Challenge Handoff Bus  │  ◄── THE NOVEL CORE
              │  route wall → human         │
              │  await 1-click resolution   │
              └──────────────┬──────────────┘
                             │ ChallengeResolution
                             ▼
              ┌─────────────────────────────┐
              │  PF6 HTTP surface           │
              │  /plan /personas /recipes   │
              │  /challenges  /resolve      │  ← the human's 1-click
              └─────────────────────────────┘
```

### PF1 — SignupRecipe (`core/foundry/recipe.py`)

A declarative, serializable, **parameterizable** signup flow. The key
word is parameterizable: form fields bind to *persona fields*
(`persona:email`, `generated:password`), not literals. One recorded
recipe + N personas = N accounts. Step kinds: NAVIGATE, FILL, CLICK,
WAIT_FOR, EXTRACT, CHALLENGE. Driver-agnostic — describes *what*, not
*how*.

### PF2 — Persona Vault (`core/foundry/vault.py`)

The ethical backbone. Stores research identities (0600 files, password
redacted in repr). Append-only audit log of every account creation.
Per-(persona, service) rate limiting that refuses farm-like behavior
before any network action. A persona is real, owned, accountable — the
Foundry's legitimacy rests on this.

### PF3 — Recipe Replayer (`core/foundry/replay.py`)

Executes a recipe with a persona's values bound in, driving a concrete
Driver. State machine: PENDING → RUNNING → (AWAITING_CHALLENGE →
RUNNING)* → COMPLETED/FAILED/ABORTED. At every anti-bot wall it packages
a Challenge (with screenshot + URL) and **awaits the human** — never
attempts a solve. Scope-gated (no off-origin navigation), fail-fast
(missing persona field / rate-limit), audited.

### PF4 — Challenge Handoff Bus (`core/foundry/challenges.py`) — THE CORE

The categorical innovation. The replay engine calls `bus.submit(challenge)`
and awaits. The bus fires a notifier (desktop / mobile push / UI badge)
and awaits a resolution future. The human sees the notification, solves
the rare-but-hard thing, and their response calls `bus.resolve(id, ...)`
— completing the future, resuming the automation. Bounded wait (a walked-
away human times out, never hangs the engine). Process-singleton so the
engine-awaits / human-resolves loop works across async contexts.

### PF5 — Account Topology Planner (`core/foundry/planner.py`) — THE FRAMING

The front of the funnel. Maps **what vuln class you're testing → what
account topology you need.** Cross-principal IDOR → 2 accounts in
*different* tenants, each with a fingerprinted private resource.
Privilege escalation → 2 accounts in the *same* tenant with *different*
roles. Horizontal IDOR → 1 account. It merges topologies across classes
to create the *minimum* accounts that cover all the tests. Nobody else
maps vuln→topology — every other tool just makes accounts.

### PF6 — HTTP surface (`core/server/routers/foundry.py`)

Makes the Foundry operable + completes the handoff loop over HTTP.
`GET /v1/foundry/challenges` (human polls) + `POST .../resolve` (1-click)
are the cross-context handoff. Plus `/plan`, persona CRUD (passwords
never returned), recipe store CRUD.

### PF7 — Playwright Driver (`core/foundry/driver_playwright.py`)

The real browser. Maps the Driver protocol onto Playwright's async API.
Headful by default (natural CAPTCHA handoff + dodges headless bot
detection). Import-guarded so the Foundry loads without the dependency;
the operator runs `pip install playwright && playwright install chromium`
to activate.

## The worked example — Airtable

The calibration-#60 runbook hand-waved "sign up two accounts." The
Foundry replaces that with a precise plan. Asking the planner for
Airtable's two best-fit vuln classes:

```python
plan_accounts("airtable", ["idor_cross_principal", "privilege_escalation"])
```

produces **4 accounts across 3 tenants**, each with exact setup and a
planted fingerprint:

1. **victim** (owner, tenant_a) — create a private base, plant
   `OWNED_BY_VICTIM_d65274`, note its URL (the attacker's target).
2. **attacker** (peer, tenant_b) — a *different* tenant; reads the
   victim's URL. If it returns the victim's fingerprint → IDOR.
3. **admin** (same_tenant_admin, tenant_shared) — establishes a
   privileged surface.
4. **member** (same_tenant_member, tenant_shared) — low-privilege in
   the *same* tenant; tries to reach the admin surface.

With explicit relationship constraints (victim/attacker MUST be
different tenants — same-tenant access might be legitimate sharing;
admin/member MUST be same tenant different roles).

From there: the vault holds the four personas; a recorded Airtable
signup recipe replays four times (each boring step automated); each
anti-bot wall hands off to the human in one click; the resulting
accounts feed straight into `run_verify_phase(personas=[...])` — and
Sentinel's strongest detection (Phase 3 multi-principal IDOR + Phase 4
cross-flow diff) fires.

## Why this disrupts

Every other account-automation tool optimizes "find more bugs per
program." The Foundry changes a different number: **programs tested per
week.** Remove the per-account signup friction and a researcher's
throughput multiplies. That's the disruption — not a better scanner, a
better *funnel*.

And it's shareable. A recipe carries no secrets (bindings, not values),
so one researcher records Airtable's signup once and every researcher
can replay it with their own identity. The community's tooling improves
with use — a moat nothing else in this space has.

## What's done vs what's left

**Done (backend, 1285 tests green):** PF1–PF7 — the full plan → vault →
recipe → replay → real browser → handoff arc.

**Left (polish, operator-facing):**
- The **recorder** — auto-capture a real signup into a recipe (vs
  hand-authoring). Ghost Protocol's flow-capture (Phase 4-G2) is the
  substrate; this is a focused adapter.
- A **SwiftUI handoff panel** — the "Sentinel needs you" notification +
  one-click resolve, so the human never leaves the app.
- A **/signup orchestration endpoint** — kicks off a replay in the
  background; trivial now that the Driver + handoff loop exist.

The hard, novel part is shipped. The rest is wiring.
