# Phase 2 Design — Bug Bounty Program Scope Ingestion

**Goal:** Sentinel takes a bug bounty program identifier (HackerOne handle,
Bugcrowd handle, or arbitrary policy URL) and autonomously produces a
working scope file + personas file + restrictions config — collapsing the
manual "read the program page, copy creds, edit configs, run scan"
workflow into "tell Sentinel the program."

**Why this matters:** Phase 1 closed all 12 calibration bugs and Sentinel
now produces clean signal end-to-end against any pre-configured target.
But every real bounty scan still requires 15+ minutes of operator setup
per program. For someone working multiple programs, this dominates the
work. Phase 2 removes it.

**Status:** Design — not yet implemented. Implementation begins on
sign-off.

---

## 1. Architecture

Three logical layers, each independently testable:

```
┌─────────────────────────────────────────────────────────────────┐
│  CLI / orchestration                                             │
│    sentinel ingest --program <handle|url>                        │
│    sentinel scan --program <handle|url>  (ingest + scan)         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2: Resolver + Extractor                                   │
│    ProgramResolver   — handle → policy URL                       │
│    Extractor (ABC)   — policy text → ProgramScope                │
│      ├─ GenericUrlExtractor       (LLM-only, fallback)           │
│      ├─ HackerOneExtractor        (API + page parsing)           │
│      └─ BugcrowdExtractor         (API + page parsing)           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: Verifier + Compilers                                   │
│    CredentialVerifier — attempt login, mark verified/failed      │
│    AccountRegistrar   — auto-signup when policy authorizes       │
│    ScopeCompiler      — ProgramScope.scope → CAL DSL             │
│    PersonaCompiler    — ProgramScope.personas → personas.json    │
│    PolicyGate         — restriction rules → CAL DSL guards       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Outputs (existing Sentinel inputs)                              │
│    <program>-scope.txt        (consumed by core/scheduler)       │
│    <program>-personas.json    (consumed by wraith)               │
│    <program>-restrictions.json (consumed by Strategos guards)    │
└─────────────────────────────────────────────────────────────────┘
```

**Key property: each layer's output is the next layer's input,
serialized as JSON.** That means every stage is independently
inspectable, replayable, and testable. If extraction goes wrong on a
specific program, you can re-run just the verification step with the
extracted JSON as input.

## 2. Data model

The core type is `ProgramScope`. All extractors produce one. All
compilers consume it. Stored as JSON on disk for replay/audit.

```python
# core/intel/program_scope.py

@dataclass
class Persona:
    name: str                        # "user", "admin", "anonymous"
    persona_type: str                # "user" | "admin" | "anonymous" | "merchant" | ...
    base_url: str                    # Where they log in
    login_flow: Optional[LoginFlow]  # None for anonymous
    username: Optional[str]
    password: Optional[str]
    role_hint: Optional[str]         # Free-text role descriptor
    source: CredentialSource         # Where this credential came from
    verified: VerificationStatus     # VERIFIED | FAILED | UNVERIFIED
    confidence: float                # 0.0-1.0

@dataclass
class LoginFlow:
    endpoint: str                    # "/api/login"
    method: str                      # "POST"
    username_param: str              # "email" or "username"
    password_param: str              # "password"
    content_type: str                # "application/json" | "application/x-www-form-urlencoded"
    token_extract_path: Optional[str]    # JSONPath: "data.token"
    cookie_extract_name: Optional[str]   # Cookie name: "session_id"
    additional_fields: Dict[str, str]    # CSRF tokens, etc.

@dataclass
class ScopeRule:
    pattern: str                     # "*.gitlab.com", "192.168.0.0/16"
    rule_type: ScopeRuleType         # DOMAIN | IP_CIDR | URL_PATH
    in_scope: bool                   # True = include, False = exclude
    notes: Optional[str]

@dataclass
class Restriction:
    kind: RestrictionKind            # NO_DOS | NO_AUTOMATED_SCAN | RATE_LIMIT |
                                     # NO_SOCIAL_ENG | NO_DATA_DESTRUCTION | ...
    severity: str                    # "hard" (block scan) | "soft" (warn)
    description: str
    raw_quote: str                   # Verbatim quote from policy

@dataclass
class ProgramScope:
    # Identity
    handle: Optional[str]            # "gitlab", "hackerone"
    platform: Platform               # HACKERONE | BUGCROWD | INTIGRITI |
                                     # YESWEHACK | DIRECT_URL
    name: str                        # "GitLab"
    source_url: str                  # The page we extracted from
    fetched_at: datetime

    # Scope
    scope_rules: List[ScopeRule]

    # Credentials
    personas: List[Persona]
    signup_endpoint: Optional[str]   # If auto-registration is an option

    # Constraints
    restrictions: List[Restriction]
    rate_limit_rps: Optional[float]
    payout_max_usd: Optional[int]

    # Provenance — for audit / debugging
    raw_content_hash: str            # sha256 of the page we extracted from
    extractor_version: str           # Which extractor + version produced this
    extraction_confidence: float     # Overall confidence
```

`★ Why this shape?` Two design choices worth flagging:

1. **`raw_content_hash` + `extractor_version`** — When extraction
   goes wrong six months from now, you need to know whether the program
   page changed or our extractor regressed. Hashing the raw content and
   stamping the extractor version lets you diff.

2. **`Persona.verified` is its own enum, not a boolean.** Three states
   matter: VERIFIED (login succeeded), FAILED (login attempted, didn't
   work), UNVERIFIED (no login attempted yet — e.g., scope didn't
   include creds, we just generated them from signup). FAILED means
   "we know these don't work" — that's a finding for the operator, not
   silent dropout.

## 3. File structure

```
core/intel/                                  # NEW package
├── __init__.py
├── program_scope.py                          # Data model + JSON serialization
├── resolver.py                               # Handle → policy URL
├── extractors/
│   ├── __init__.py
│   ├── base.py                               # Extractor ABC + helpers
│   ├── generic_url.py                        # LLM-only fallback
│   ├── hackerone.py                          # H1 API + page
│   ├── bugcrowd.py                           # Bugcrowd API + page
│   └── intigriti.py                          # (Phase 2H)
├── verifier.py                               # CredentialVerifier
├── registrar.py                              # AccountRegistrar (auto-signup)
├── compilers/
│   ├── __init__.py
│   ├── scope_compiler.py                     # ProgramScope.scope → CAL DSL
│   ├── persona_compiler.py                   # ProgramScope.personas → personas.json
│   └── policy_gate.py                        # Restrictions → CAL guards
├── token_store.py                            # Keychain-first secure storage
└── llm_extraction.py                         # LLM prompt + structured output

core/server/routers/                          # Existing — add endpoint
└── intel.py                                  # NEW: POST /api/v1/intel/ingest

scripts/
└── sentinel_ingest.py                        # NEW CLI entry: sentinel ingest

tests/unit/intel/
├── __init__.py
├── test_program_scope.py                     # Serialization round-trip
├── test_resolver.py
├── test_extractor_generic.py                 # With mocked LLM
├── test_extractor_hackerone.py               # With recorded API fixtures
├── test_extractor_bugcrowd.py
├── test_verifier.py                          # With mock target server
├── test_registrar.py
├── test_scope_compiler.py
├── test_persona_compiler.py
├── test_policy_gate.py
└── test_token_store.py

tests/integration/intel/
├── test_ingest_hackerone_public.py           # Against recorded fixtures
├── test_ingest_juice_shop_endtoend.py        # Local lab — full flow
└── fixtures/
    ├── hackerone_gitlab_program.html         # Recorded H1 program page
    ├── bugcrowd_tesla_program.html
    └── generic_program_md.txt
```

**Convention: extractors are zero-dependency on each other.** They share
only the data model and the LLM helper. This isolation means adding a
new platform doesn't risk regressing existing ones, and a flaky platform
adapter degrades gracefully (we just fall back to GenericUrlExtractor).

## 4. Sequencing — what gets built in what order

Each phase is shippable on its own. After each phase, you can use the
new capability against real programs and observe behavior before
moving on.

### Phase 2A — Foundation (data model + generic extractor + verifier)

**Deliverable:** `sentinel ingest --url <any URL>` works. Operator pastes
the policy URL, scanner produces a `ProgramScope` JSON file with
extracted scope rules, personas (creds if listed), and restrictions.
Login verification confirms which creds actually work.

**Why this first:** Generic URL extraction is the fallback used by every
platform-specific extractor. Building it first means everything else
gets to compose on top of a working foundation. Also: any URL works,
so we can test against real program pages immediately without
implementing platform-specific resolution.

Files: `program_scope.py`, `extractors/base.py`, `extractors/generic_url.py`,
`verifier.py`, `llm_extraction.py`, the unit tests for each.

### Phase 2B — Platform adapters (HackerOne, Bugcrowd)

**Deliverable:** `sentinel ingest --program gitlab` works. Resolver maps
the handle to the right platform, fetches the program page (public for
now), runs platform-specific extraction (which understands the page
DOM structure, not just LLM extraction). Extraction quality goes from
~70% to ~95% on these platforms because of structural parsing.

Files: `resolver.py`, `extractors/hackerone.py`, `extractors/bugcrowd.py`,
plus their tests with recorded fixtures.

### Phase 2C — Compilers (scope DSL + personas)

**Deliverable:** Ingested `ProgramScope` JSON → existing Sentinel
config files (CAL scope file + personas.json + restrictions config).
After this, `sentinel scan --program gitlab` works end-to-end.

Files: `compilers/scope_compiler.py`, `compilers/persona_compiler.py`,
`compilers/policy_gate.py`, plus tests.

### Phase 2D — Auto-registration

**Deliverable:** When the policy authorizes self-service signup but
doesn't provide creds, the registrar creates test accounts via the
target's signup endpoint, then verifies them. Operator passes
`--allow-auto-register`; default is off (it's the only step that mutates
target state).

Files: `registrar.py`, integration test against Juice Shop signup flow.

### Phase 2E — Policy gates

**Deliverable:** Extracted restrictions feed back into Strategos
scheduling. "No DoS testing" → disable nuclei DoS templates. "No
automated scanning" → block scan or downgrade to passive-only.
"Rate-limit 5 rps" → enforce in the scanner engine.

Files: `compilers/policy_gate.py` (probably split out of Phase 2C),
Strategos integration.

### Phase 2F — CLI integration

**Deliverable:** Single command operator-facing UX. Outputs a summary
report ("found 3 scope domains, 2 verified personas, 1 hard
restriction; scan would proceed").

Files: `scripts/sentinel_ingest.py`, `core/server/routers/intel.py`.

### Phase 2G — Secure token storage

**Deliverable:** macOS Keychain integration for HackerOne / Bugcrowd
API tokens, with encrypted file fallback for non-macOS. Token rotation
+ refresh. This unlocks **private programs** which is most of the
high-payout bounty work.

Files: `token_store.py`, integration with existing
`core/base/config.py`.

## 5. Key design decisions

### LLM extraction model: local Ollama (Sentinel-9b), not Claude API

**Decision:** Use the local Ollama-served model already integrated in
`core/ai/ai_engine.py`. Don't add an Anthropic SDK dependency.

**Rationale:**
- **Private programs are confidential by contract.** Sending a private
  H1 program's scope text to a third-party API would violate most
  bounty platform ToS. Local-only is the safe default.
- **Sentinel already has the LLM infrastructure.** The `ai_engine.py`
  module is wired and tested. Adding an external API would be a
  net-new dependency and credential.
- **Structured extraction is one of the easier LLM tasks.** Even small
  local models do well at "extract JSON matching this schema from this
  page" when the prompt is good and we verify the output.

**Tradeoff acknowledged:** Extraction quality will be lower than what
GPT-4 / Claude could do. We mitigate this with: (a) regex pre-pass for
obvious patterns before LLM kicks in, (b) login verification catches
extraction errors quickly, (c) operator can always override.

**Future option:** Add an `--llm=claude` flag for *public* programs
when extraction quality matters more than privacy. Not Phase 2 scope.

### Auto-registration: opt-in via `--allow-auto-register`

**Decision:** Default off. Operator must explicitly authorize. When
enabled, only fires if policy text contains explicit authorization
language (keyword-matched + LLM-verified).

**Rationale:** This is the only Phase 2 capability that mutates target
state. The cost of getting it wrong (creating accounts on a program
that doesn't authorize it) is severe — potentially a ToS violation.
Opt-in default makes the operator the gating check.

### Token storage: macOS Keychain primary, encrypted file fallback

**Decision:** Use macOS Keychain via `security` CLI on macOS. On other
platforms, fall back to AES-encrypted file in `~/.sentinelforge/`.

**Rationale:** Keychain is the platform standard for credential storage
on macOS, and SentinelForge is primarily macOS (the UI is SwiftUI).
The fallback covers headless / Linux deployments without forcing a
new dependency for the common case.

### LLM extraction output: Pydantic schema with strict validation

**Decision:** LLM emits JSON conforming to a Pydantic schema. Anything
that fails schema validation is dropped (logged, not raised). Failed
schema attempts trigger one retry with `validation_error` appended to
the prompt as a self-correction hint.

**Rationale:** Free-form text is unparseable. JSON is parseable but
unvalidated JSON is dangerous (hallucinated fields, wrong types).
Schema validation gives us a clean contract between LLM and the rest
of the pipeline.

### Verification mode: best-effort + visible

**Decision:** Login verification attempts every extracted credential
but **does not block** ingestion if some fail. Failed creds are
recorded with `verified=FAILED` and surfaced in the report.

**Rationale:** Some programs list creds that are stale, behind
additional auth (MFA, captcha), or test-environment-only that we
can't reach. Hard-failing the whole ingest on one bad credential
would be brittle. Surfacing the failure as a finding lets the operator
decide what to do.

## 6. Outstanding open questions

The design above resolves most decisions. Three remain genuinely open
and would benefit from operator input before implementation:

### Q1: Should HackerOne API token be required for handle resolution?

**Context:** HackerOne has a public API that requires an API token for
most endpoints. Without a token, we'd have to screen-scrape the public
program pages (which work but break when the site redesigns).

**Option A:** Token-required. Operator must set up an API token before
`--program <handle>` works.
**Option B:** Token-optional. Without a token, screen-scrape; with a
token, use the API. Token unlocks private programs only.
**Recommendation:** B. Better UX for new users.

### Q2: What does Sentinel do when policy is silent about automated scanning?

**Context:** Most program policies don't explicitly say "automated
scanning is allowed." Some say it's disallowed. Most say nothing.

**Option A:** Silence = allowed (current behavior of every other scanner).
**Option B:** Silence = warn but proceed.
**Option C:** Silence = require operator confirmation.
**Recommendation:** B. Industry norm is A, but B adds one line of
output and keeps operator informed.

### Q3: How long do we cache extracted `ProgramScope` files?

**Context:** Program pages change. Old extractions go stale. Re-running
extraction every scan is wasteful.

**Option A:** Cache forever, manual `--refresh` to re-extract.
**Option B:** Cache 7 days, auto-refresh after.
**Option C:** Cache by content-hash — if the source page hasn't
changed, reuse; if it has, re-extract.
**Recommendation:** C. Most accurate, no operator burden, but slightly
more complex to implement (HEAD-then-GET pattern).

## 7. What this is NOT

To keep scope honest:

- **Not a bounty payout optimizer.** Sentinel still scans every in-scope
  target; we don't weight by payout. (Future.)
- **Not a duplicate-finding deduplicator across programs.** Each scan
  is independent. (Future.)
- **Not a submission-template generator.** Finding-to-submission is a
  separate concern. (Future Phase.)
- **Not a CAPTCHA solver.** If a target's signup or login requires a
  CAPTCHA, auto-registration fails gracefully and reports it. Operator
  intervenes.

## 8. Risk register

| Risk | Likelihood | Severity | Mitigation |
|---|---|---|---|
| LLM hallucinates credentials | Med | Low | Login verification catches it |
| Platform page redesign breaks extractor | Med | Med | Fall back to GenericUrlExtractor |
| Auto-registration violates ToS | Low | High | Opt-in default + policy verification |
| Local LLM is too weak for hard pages | Med | Low | Operator overrides; future Claude fallback |
| API rate limits during high-volume use | Low | Med | Caching by content hash (Q3 above) |
| Stale cached scope misses new in-scope assets | Low | Med | Cache invalidation on page change |

## 9. Approval gates

Before each phase ships:

- **2A:** Generic extractor works against 5 real program pages
  (manually selected) with ≥70% credential extraction accuracy
- **2B:** HackerOne and Bugcrowd adapters work against 10 real programs
  each with ≥90% accuracy on scope + creds
- **2C:** End-to-end ingest → scope file → scan against Juice Shop lab
  produces clean scan with no manual editing
- **2D:** Auto-registration creates valid Juice Shop account, persona
  verification passes
- **2E:** Restriction "no DoS" disables nuclei DoS templates verifiably
- **2F:** Single `sentinel scan --program <handle>` command works for
  Juice Shop lab end-to-end
- **2G:** Private program API auth works against at least one private
  HackerOne program

---

## Next step on approval

Open questions Q1, Q2, Q3 are the only design choices I can't make
without operator input. Once those are answered (or my recommendations
accepted), implementation begins with Phase 2A: data model + generic
extractor + verifier.

Estimated Phase 2A delivery: ~6–8 hours of focused work. Includes:
data model (program_scope.py), generic extractor with LLM prompt,
credential verifier with mock target tests, full unit coverage. Live
test against one real program page.
