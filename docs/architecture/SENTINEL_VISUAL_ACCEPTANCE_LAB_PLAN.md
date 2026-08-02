# Sentinel Visual Acceptance Lab Plan

Status: S01 native recording integration implemented; native acceptance proof pending

## Decision summary

Build a deterministic, entirely local website lab that Sentinel can see and use
through the same native browser, Foundry, scan, policy, receipt, and evidence paths
used for a real URL.

The lab requires:

- no registered domain;
- no public hosting;
- no paid email, SMS, database, certificate, or cloud service;
- no traffic to third-party targets;
- no dependency on CI infrastructure;
- no lab-only shortcut inside Sentinel's production execution path.

The primary target URL will be:

```text
http://127.0.0.1:3100
```

When hostname behavior is important, optional local-only names can be mapped to
`127.0.0.1`:

```text
app.sentinel-lab.test
mail.sentinel-lab.test
control.sentinel-lab.test
```

The `.test` top-level domain is permanently reserved for private testing by
[RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606). It does not need to be
registered or purchased. The loopback IP remains the default so the first version
does not require modifying `/etc/hosts`.

## Purpose

Passing unit tests proves that individual contracts behave as expected. It does not
prove that the macOS app, native Ghost browser, recipe recorder, recipe replay,
challenge handoff, authenticated persona windows, behavioral engine, target
transport, receipts, and findings all work together.

This lab closes that gap. It provides a known website whose visible workflows,
server-side state, vulnerabilities, secure controls, and request history are all
observable. Sentinel must use it exactly as it would use an authorized external
website.

The lab is not intended to make a local toy scanner look successful. Its job is to
make failures obvious before those failures reach a real bounty target.

## What success means

The lab is successful when one repeatable acceptance run can demonstrate all of the
following:

1. A person can visually record a signup recipe in Sentinel's native Ghost browser.
2. Sentinel converts the recording into semantic persona bindings without placing
   account secrets in ordinary logs or artifacts.
3. Sentinel replays the recipe for a second persona.
4. Sentinel pauses at a fake email-verification challenge and visibly requests the
   required human handoff.
5. The challenge is completed through the local inbox and the signup resumes.
6. Sentinel opens isolated authenticated windows for Alice and Bob.
7. An ordinary one-click URL scan reaches the behavioral engine using explicit
   signed authority.
8. The vulnerable version of a scenario produces the expected independently
   confirmed finding.
9. The visually identical secure version does not produce that finding.
10. The lab's private request ledger agrees with Sentinel's receipts about which
    requests occurred, which persona sent them, and in what order.
11. A retry or restart cannot silently renew a consumed proof budget.
12. The entire result can be reconstructed from a versioned, redacted run bundle.

## Non-goals

Version one will not:

- imitate every possible website framework or visual layout;
- solve a real CAPTCHA;
- contact a real email or SMS provider;
- simulate Cloudflare, a production CDN, a WAF, or public internet latency exactly;
- use real customer accounts or objects;
- prove that Sentinel will find every vulnerability on every website;
- authorize report submission;
- replace later validation against explicitly authorized public programs;
- modify the validated Gemma model or its prompts.

## Technical and non-technical scope

### Technical explanation

The slice adds a local Docker Compose acceptance environment with a standalone
reference SaaS target, a separate lab control plane, a local SMTP sink, deterministic
scenario state, and an out-of-band request ledger. Later implementation phases connect
the existing native Foundry and behavioral workflows to that target without bypassing
`ExecutionPolicy`, scope checks, signed envelopes, proof budgets, receipts, or
independent confirmation.

The initial infrastructure phase does not add a new production proof oracle, does not
change model behavior, and does not grant Sentinel any additional execution class.
Native acceptance phases will generate traffic only to an explicitly selected
loopback lab origin.

### Non-technical explanation

Sentinel gets its own private practice website. The website looks and behaves like a
real account-based service: Alice can sign up, receive an email code, create a
document, and Bob can attempt to access it. We control both a deliberately broken
version and a correctly secured version, so Sentinel has to find the real difference
instead of merely producing a convincing story.

This does not give Sentinel permission to do more on real websites. It gives us a
free, visible, repeatable place to prove that the permission and safety system works
before using an authorized live target.

## Recommended stack

| Layer | Selection | Reason |
| --- | --- | --- |
| Orchestration | Docker Compose | Matches the existing lab approach, provides isolated services, health checks, resource limits, and one-command lifecycle management. |
| Target backend | Python 3.12, FastAPI, and Uvicorn | Already familiar to the repository, easy to instrument, supports server-rendered pages and JSON APIs, and avoids a second backend ecosystem. |
| Target frontend | Jinja2-rendered HTML with vanilla JavaScript and CSS | Produces real visual workflows and DOM variation without a Node build chain or large frontend dependency surface. |
| State | SQLite | Free, local, disposable, easy to seed, and sufficient for deterministic multi-user lab scenarios. |
| Fake email | [Mailpit](https://mailpit.axllent.org/docs/) | Provides a local SMTP server, visual web inbox, and API-accessible messages without delivering external mail. |
| Request truth | Append-only JSON Lines ledger on a mounted volume | Creates an independent account of target traffic without importing Sentinel code into the target. |
| Optional routing/TLS | Caddy with a [local internal CA](https://caddyserver.com/docs/caddyfile/directives/tls) | Reserved for a later HTTPS and cookie-policy phase; it does not require a public domain or paid certificate. |
| Test driver | Existing Python test tooling plus native macOS acceptance harness | Keeps contract and wire tests fast while preserving a separate gate for the actual Swift/WKWebView path. |
| Broad scanner target | Existing pinned OWASP Juice Shop lab | Retained as a complementary calibration target for general scanner behavior, not as the Foundry reference application. |

### Deliberately excluded

The initial lab should not add React, Vite, PostgreSQL, Redis, Kubernetes, Terraform,
a cloud database, public DNS, or a hosted CI service. None is required to prove the
workflow, and each would add cost, nondeterminism, or maintenance without improving
the acceptance signal.

The reference website must remain a standalone target. It must not import Sentinel
internals or accept a hidden “test passed” signal from Sentinel. Its only shared
contracts are ordinary browser behavior, HTTP, SMTP, and documented artifact formats.

## Free, no-domain network design

### Default mode

All published ports bind explicitly to `127.0.0.1`, not all host interfaces:

| Service | Host URL | Purpose |
| --- | --- | --- |
| Reference SaaS | `http://127.0.0.1:3100` | The URL Sentinel is allowed to target. |
| Lab Control Center | `http://127.0.0.1:3101` | Scenario selection, reset, expected state, and independent request evidence. |
| Mailpit inbox | `http://127.0.0.1:3102` | Visual fake inbox for verification challenges. |
| Mailpit SMTP | Compose network only | Receives messages from the reference SaaS; not published unless debugging requires it. |

Compose port declarations must include the host IP. Docker documents that omitting it
can bind a published port to all interfaces:
[Compose service ports](https://docs.docker.com/reference/compose-file/services/#ports).

### Optional hostname mode

Some behaviors depend on hostname boundaries, cookie domains, or multiple origins.
Those scenarios can use a documented, reversible `/etc/hosts` mapping:

```text
127.0.0.1 app.sentinel-lab.test
127.0.0.1 control.sentinel-lab.test
127.0.0.1 mail.sentinel-lab.test
```

This costs nothing and does not publish the lab. The acceptance runner must still
resolve each permitted hostname to loopback before starting.

### Optional HTTPS mode

HTTP is the correct default for the first implementation because it removes
certificate trust from Foundry debugging. A later phase may add local HTTPS to test
secure cookies, mixed-content behavior, and certificate handling. That phase should
use a local CA and document the macOS trust action explicitly. It must never request
a public certificate for the lab.

## Service architecture

```text
Sentinel macOS app
  |
  | ordinary native browser and scan traffic
  v
Reference SaaS target :3100
  |-- visible HTML and JavaScript workflows
  |-- JSON endpoints
  |-- SQLite scenario state
  |-- SMTP messages ----------------------> Mailpit
  `-- append-only request events ----------> private ledger volume

Lab Control Center :3101
  |-- reset and seed scenarios
  |-- select secure or vulnerable twin
  |-- show Alice and Bob state
  |-- show expected versus observed result
  `-- read the private request ledger

Acceptance orchestrator
  |-- starts and health-checks Compose
  |-- launches Sentinel with isolated state
  |-- drives or observes the native workflow
  |-- collects Sentinel and lab evidence
  `-- decides pass or fail from explicit assertions
```

The control center and ledger are measurement equipment, not target surface. The
signed envelope used for acceptance must authorize only the reference SaaS origin.
Sentinel must never be given the control or Mailpit origins as scan targets.

## Reference SaaS product model

The website should look like a small document-collaboration service rather than a
page full of vulnerability buttons.

### User-facing areas

- landing and pricing pages;
- login, logout, password reset, and session expiry;
- account creation;
- email verification;
- organization or workspace onboarding;
- profile and settings;
- documents and projects;
- invitations and team membership;
- role assignment;
- sharing and export;
- API-token management;
- object archival and deletion;
- useful empty, loading, error, and permission-denied states.

### Account creation shapes

The same logical signup should be renderable in several visual forms:

- classic single-page form;
- multi-step wizard;
- modal dialog;
- identity-first flow that asks for email before other fields;
- dynamically revealed fields;
- mobile-width responsive form;
- reordered and ambiguously labeled fields.

The field vocabulary should include:

- email;
- display name;
- username;
- phone;
- password and confirmation;
- date of birth;
- select and checkbox controls;
- terms acceptance;
- optional organization name;
- email verification code or link.

These variations are not decorative. They test whether recipe recording captures
semantic intent and stable bindings rather than memorizing one pixel layout.

### Personas

Initial seeded personas:

- Alice — ordinary researcher-owned user;
- Bob — distinct ordinary researcher-owned user;
- Carol — optional organization administrator for role-differentiated scenarios;
- Anonymous — no authenticated state.

The lab stores only fake generated identities. Acceptance artifacts must never contain
Persona Vault secrets in clear text.

## Lab Control Center

The control center should make the invisible state of the target visible to the
operator without leaking it through the target website.

Required controls:

- choose a scenario;
- choose the vulnerable or secure twin;
- reset to a named deterministic seed;
- display service health;
- display Alice, Bob, and Carol account state;
- open the local fake inbox;
- enable a documented fault injection;
- show expected behavior;
- show observed target requests;
- show request actor, method, route, status, and correlation ID;
- download the lab side of the run bundle.

Required fault injections:

- delayed response;
- one transient 500 response;
- connection loss after request receipt;
- expired verification code;
- invalid verification code;
- session expiry;
- duplicate submission;
- target restart between proof steps;
- malformed but safe response;
- cleanup failure.

Faults must be selected before a run and recorded in its manifest. They must never be
randomly introduced without a seed.

## Scenario design

Every security scenario must be implemented as a matched pair:

- the vulnerable twin contains one precisely documented broken enforcement rule;
- the secure twin has the same routes, visuals, objects, identifiers, and ordinary
  behavior but enforces the rule correctly.

This makes the secure twin a required negative control. A scanner that reports both
twins has not proven it can distinguish a vulnerability from normal application
behavior.

### Initial scenario catalog

#### S01 — Visual signup recording

Record Alice's account creation manually in the native Ghost browser. Assert that the
saved recipe contains semantic persona bindings, expected challenge boundaries, and
no literal secret values.

#### S02 — Recipe replay for a second persona

Replay the recorded recipe for Bob using a distinct generated identity. Assert that
Bob receives a separate account and isolated authenticated session.

#### S03 — Email-verification challenge

Exercise successful code entry, operator decline, timeout, wrong code, and expired
code. Assert that Sentinel pauses visibly and does not fabricate challenge
completion.

#### S04 — Authority denial before traffic

Attempt recording or replay with a missing, expired, wrong-origin, or insufficient
envelope. Assert zero target requests and an explicit denial state.

#### S05 — Cross-user document access, vulnerable

Alice creates a document. Bob reaches the same document identifier through an
authorized safe-read experiment. The target incorrectly returns Alice's document.
Sentinel must independently confirm the cross-principal authorization failure.

#### S06 — Cross-user document access, secure

The route and UI are identical to S05, but the target rejects Bob. Sentinel must not
produce the S05 finding.

#### S07 — Already-visible difference

The initial captures already expose a difference. Assert that Sentinel does not
mislabel passive visibility as a newly confirmed adaptive proof.

#### S08 — Receipt persistence

Repeat and restart a completed proof. Assert zero renewed target traffic when the
durable receipt already covers the same execution.

#### S09 — Lifecycle and omission

Use researcher-owned objects to test one exact state-machine prerequisite. The
vulnerable twin accepts the forbidden transition; the secure twin rejects it. Cleanup
must be proven before mutation is authorized.

#### S10 — General scanner calibration

Keep a non-persona vulnerability scenario and the existing Juice Shop target in the
test matrix so improvements to the behavioral path do not hide regressions in ordinary
URL scanning.

## Golden native acceptance journey

The first full visual acceptance test should follow one observable story:

1. Start the local lab from a clean seed.
2. Launch Sentinel with an isolated acceptance state directory.
3. Create or load an explicitly loopback-scoped signed envelope.
4. Create Alice and Bob in Persona Vault.
5. Open the reference SaaS in Sentinel's native Ghost browser.
6. Record Alice's signup visually.
7. Save and inspect the resulting recipe.
8. Replay the recipe for Bob.
9. Stop at the email-verification challenge.
10. Read the code from the local Mailpit inbox.
11. Resume and complete Bob's signup.
12. Open authenticated native windows for Alice and Bob.
13. Have Alice create a fresh researcher-owned document.
14. Start an ordinary one-click URL scan with the explicit behavioral profile.
15. Confirm the vulnerable twin.
16. Reset and repeat against the secure twin.
17. Restart the relevant Sentinel process and retry the completed execution.
18. Collect and compare Sentinel receipts with the lab request ledger.
19. Produce a single pass/fail run bundle.

The journey must use the native Swift/WKWebView route for the final gate. A Python
mock, direct API call, or synthetic recorder event is useful at lower layers but
cannot satisfy this acceptance test.

## Current S01 native recording procedure

This is the first operator-run slice. It validates recording and recipe inspection;
it does not yet mark the entire golden journey as native-proven.

1. In the lab repository, prepare one clean run:

   ```bash
   make acceptance-prepare SCENARIO=s01 VARIANT=classic
   ```

   Do not reset the lab or run its test layers after this command. Record the run id
   printed by the command.

2. Open `ui/SentinelForge.xcodeproj` in Xcode, select the
   `SentinelForge-Acceptance` scheme, and run it. This scheme sets
   `SENTINEL_DATA_DIR=/tmp/sentinelforge-acceptance-state`, keeping tokens,
   personas, envelopes, recipes, captures, and logs separate from normal operator
   state. It also binds the isolated backend and every Swift client to port `8766`,
   so an ordinary Sentinel backend on port `8765` cannot be mistaken for the
   acceptance backend.

3. Open **Persona Foundry**. Create a fresh synthetic recording persona whose email,
   password, first name, and last name match the values that will be typed into the
   website. Do not use a real identity or reuse the lab's already-created seeded
   Alice account.

4. Create and select an authorization envelope with these load-bearing values:

   ```text
   Target/program: sentinel-lab
   Authorized origin: https://app.sentinel-lab.test
   Allowed workflow: sentinel-lab
   Authorization basis: local s01 acceptance run <run-id>
   Disclosure attestation: enabled
   ```

   Only the app origin is authorized. The control-center and mail origins must not be
   added.

5. Choose **Record Recipe** and enter:

   ```text
   Service handle: sentinel-lab
   Recipe name: s01 classic signup
   Origin URL: https://app.sentinel-lab.test/signup
   Recording persona: the fresh persona from step 3
   Visual variant: classic
   ```

6. Complete the visible signup in the Sentinel Native Driver window. Type the same
   persona email, name, and password stored in the vault. A username may be chosen
   for this recording; the resulting recipe binds usernames to a replay-time
   generator. Check the terms box and submit.

7. When the website reaches `/verify`, read the six-digit code from the already-open
   `https://mail.sentinel-lab.test` page, return to the native window, submit the
   code, and continue until the native window reaches `/app`. Then close the native
   window.

8. Back in Persona Foundry, select **Inspect** on `s01 classic signup`. Confirm that:

   - the visual variant is `classic`;
   - the secret audit is `pass`;
   - email, password, confirmation, name, and terms have semantic identities;
   - the email verification challenge appears before the verification-code fill;
   - provenance contains the envelope id, recording persona id, and lab correlation
     identifiers;
   - no typed password, session token, verification token, or six-digit code appears
     in the persisted recipe.

If the recipe is absent or inspection shows a failed secret audit, stop at the
`record` or `recipe` stage. Do not continue to replay and conceal the upstream
failure.

## Acceptance layers

### Layer 1 — Contract tests

Fast tests for recipe parsing, binding resolution, event schemas, scenario seeding,
ledger events, expected outcomes, and artifact validation.

### Layer 2 — Real wire tests

Start the actual Compose services and send real HTTP requests through the normal
transport and policy boundaries. No monkeypatch may replace the target or Foundry
router being evaluated.

### Layer 3 — Native macOS acceptance

Exercise the real Swift client, Ghost window, WKWebView event capture, visual
challenge strip, Foundry API, and ordinary Scan screen. This is the authoritative
gate for UI-facing workflows.

### Layer 4 — Broad local calibration

Run the existing pinned Juice Shop suite and selected reference SaaS scenarios to
detect regressions outside the new behavioral path.

### Layer 5 — Authorized live canary

Only after the local gates are stable, run a minimal explicitly authorized live
canary under the program's rules. A live canary is a separate approval and is not
part of this free local lab.

## What “proven” means

Results should use precise validation labels:

| Label | Meaning |
| --- | --- |
| Contract-validated | A component passed isolated schema and behavior tests. |
| Wire-proven | Real local HTTP traffic crossed the production policy and transport path. |
| Native-proven | The actual macOS UI and WKWebView completed the visual journey and produced matching evidence. |
| Live-observed | The same bounded behavior was observed on an explicitly authorized external target. |

A scenario becomes **native-proven** only when:

- the vulnerable twin is detected;
- the secure twin is not reported as vulnerable;
- the target ledger matches the expected request, actor, method, and ordering;
- no request reaches an unauthorized origin;
- required receipts reconstruct the execution;
- retry and restart do not renew consumed traffic;
- artifacts contain no clear-text secrets;
- cleanup reaches a terminal known state;
- three consecutive clean-seed runs pass;
- every run records the Sentinel commit, dirty state, app build, configuration,
  Compose image identity, scenario version, and seed.

A screenshot alone is not proof. A receipt alone is not proof. Passing only the
vulnerable twin is not proof.

## Evidence and run bundle

Each acceptance run should write to a new content-addressed directory outside normal
Sentinel user state:

```text
acceptance-artifacts/<run-id>/
  manifest.json
  result.json
  stage-events.jsonl
  lab-request-ledger.jsonl
  sentinel-logs.redacted.txt
  receipts.json
  recipe.redacted.json
  signup-audit.json
  screenshots/
  findings/
  cleanup.json
```

The manifest must identify:

- run ID and timestamps;
- Sentinel Git commit and dirty-worktree flag;
- macOS app build identity;
- Python version and dependency lock identity;
- Compose file identity and container image digests;
- selected scenario, twin, seed, and fault set;
- authorized origins, personas, workflows, action classes, and budgets;
- all service health states;
- artifact hashes.

The final result must name the first failing stage:

```text
lab health
-> Foundry plan
-> persona
-> envelope
-> record
-> recipe
-> replay
-> challenge
-> account
-> authenticated window
-> capture
-> passive shadow
-> adaptive execution
-> independent proof
-> receipt
-> feedback
-> scan finding
-> cleanup
```

This prevents a downstream “no finding” result from concealing an upstream browser,
account, or authority failure.

## Safety requirements

1. Publish all host ports only on `127.0.0.1`.
2. Put target services on an internal Compose network where practical so they have no
   default route to the public internet. See Docker's
   [Compose networking documentation](https://docs.docker.com/compose/how-tos/networking/).
3. Reject an acceptance target unless its resolved addresses are loopback and its
   hostname is either loopback or an explicitly permitted `.sentinel-lab.test` name.
4. Authorize only the reference SaaS origin; never authorize the control center,
   Mailpit UI, Docker API, host filesystem, or container metadata endpoints.
5. Use a separate temporary Sentinel home, database, capture store, receipt store,
   log directory, and artifact directory for every clean run.
6. Never reuse real Persona Vault identities or tokens.
7. Keep SMTP delivery inside the Compose network. The application must not fall back
   to external email.
8. Seed only synthetic data marked as lab-owned.
9. Make scenario reset loopback-only, authenticated, and inaccessible from the target
   origin.
10. Keep the private ledger out of the reference website's static files and APIs.
11. Pin container and Python dependency versions. Prefer image digests for permanent
    release gates.
12. Configure health checks, memory limits, CPU limits, log limits, and bounded
    artifact retention.
13. Preserve all existing production policy, scope, approval, proof-budget, receipt,
    and cleanup rules.
14. Treat any unexpected external connection as an immediate acceptance failure.

## Determinism rules

- Each scenario has a schema version and named seed.
- Seeded IDs are stable where stability is part of the assertion.
- One scenario may request unpredictable IDs when testing discovery; its random seed
  must still be recorded.
- Clock-dependent scenarios use a controllable lab clock, not sleeps as correctness
  logic.
- Faults are selected, named, and recorded.
- Database state is recreated from migrations and seed data for a clean run.
- Request correlation IDs propagate through the target and lab ledger.
- UI animations are disabled or made deterministic during screenshot capture.
- Tests wait on observable readiness signals rather than arbitrary long delays.

## Visual verification

Every supported signup shape should have:

- a reference screenshot at required window sizes;
- semantic DOM assertions;
- visible and enabled state assertions;
- keyboard navigation checks;
- stable accessibility labels for meaningful controls;
- recorder-event assertions;
- recipe-binding assertions;
- replay results for Alice and Bob.

Pixel comparison is a regression aid, not the only oracle. A visually similar page
can have a broken control, and a harmless font change should not invalidate semantic
behavior.

The initial viewport matrix should cover one normal desktop size and one narrow size.
Additional browsers are outside version-one scope because the production native path
is WKWebView.

## Operator commands

The finished developer workflow should expose small stable commands:

```text
make lab-up
make lab-health
make lab-reset SCENARIO=s05 TWIN=vulnerable SEED=default
make acceptance-foundry
make acceptance-behavioral
make acceptance-native
make acceptance-lab
make lab-artifacts
make lab-down
```

`make acceptance-lab` should run all non-interactive gates and then clearly state
whether native operator interaction is required. It must not claim the native journey
passed when it was skipped.

## Implementation phases

### Phase 0 — Freeze contracts and measurements

#### Technical work

- Define the scenario manifest, request-ledger event, expected-outcome, stage-event,
  and run-result schemas.
- Define stable correlation identifiers between lab traffic and Sentinel receipts.
- Define redaction rules and the native-proven gate.
- Inventory the current Foundry UI-to-backend request contracts.
- Confirm how acceptance-only state directories are injected without changing
  production defaults.

#### Non-technical result

Before building the practice website, define the scorecard and the replayable evidence
that decides whether Sentinel succeeded.

#### Target traffic and authority

No target traffic and no authority change.

#### Exit gate

Schemas have tests, malformed evidence is rejected, and the definition of a pass does
not depend on a human reading logs.

### Phase 1 — Local infrastructure and reference website shell

#### Technical work

- Add a dedicated Compose project separate from the current Juice Shop file.
- Add the FastAPI/Jinja2 target, SQLite state, Mailpit, control center, internal
  network, loopback-only published ports, health checks, and resource limits.
- Implement deterministic reset and seed.
- Implement the out-of-band request ledger.
- Add runtime checks that refuse non-loopback resolution.

#### Non-technical result

One free command starts a private website, its control panel, and a fake inbox on the
Mac. Nothing is published to the internet.

#### Target traffic and authority

Only manual or test traffic to loopback services. Sentinel execution authority is
unchanged.

#### Exit gate

Fresh start, health check, reset, seed, request logging, and shutdown pass three times
without stale state.

### Phase 2 — Visual account and scenario system

#### Technical work

- Implement signup, login, verification, onboarding, document, membership, and
  session workflows.
- Implement visual variants from shared semantic workflow definitions.
- Implement vulnerable and secure twins.
- Add control-center state views and deterministic fault injection.
- Add semantic and screenshot regression checks.

#### Non-technical result

The practice site becomes realistic enough to visually record account creation and
compare a genuinely broken security rule with a correctly protected one.

#### Target traffic and authority

Local browser traffic only. No new Sentinel authority.

#### Exit gate

All visual variants complete manually, each twin matches its documented enforcement
rule, and the secure and vulnerable versions remain visually equivalent.

### Phase 3 — Foundry native recording and replay

#### Technical work

- Run recipe recording through the real native Ghost window.
- Verify semantic bindings and redaction.
- Replay for a distinct persona through the production Foundry path.
- Complete local email challenge handoff through the visible challenge UI.
- Resolve the current UI/backend authority mismatch so signup cannot silently rely on
  an absent envelope.
- Add real recognition and acceptance coverage for email-code and email-link
  transitions.

#### Non-technical result

Sentinel can watch Alice create an account, learn the reusable steps, create Bob
without copying Alice's secrets, and ask for help when the website requires a code.

#### Target traffic and authority

Adds no new execution class. It exercises existing browser navigation and form
submission authority against the explicitly approved loopback target.

#### Exit gate

The full signup journey is native-proven for two personas, and invalid authority
produces zero target traffic.

### Phase 4 — Authenticated behavioral one-click acceptance

#### Technical work

- Open and verify isolated authenticated persona windows.
- Route the ordinary Scan UI through the explicit behavioral profile.
- Execute the vulnerable and secure BOLA twins.
- Reconcile target ledger entries with captures, proof receipts, findings, and
  feedback.
- Assert duplicate and restart suppression.

#### Non-technical result

The normal Scan button can use Alice and Bob on the practice site, prove the broken
lock in the vulnerable version, and correctly leave the repaired lock alone.

#### Target traffic and authority

This phase produces bounded local target traffic under the existing signed envelope
and proof budget. It does not broaden real-target authority.

#### Exit gate

Both twins and receipt persistence are native-proven for three consecutive clean
runs.

### Phase 5 — Failure, recovery, and cleanup hardening

#### Technical work

- Exercise every named fault.
- Kill and restart target and Sentinel components at defined stages.
- Prove terminal cleanup state for owned mutations.
- Verify that uncertainty is surfaced rather than converted into a finding or
  success.
- Add bounded retention and artifact validation.

#### Non-technical result

The practice site starts misbehaving on purpose so we can prove Sentinel fails safely,
resumes honestly, and does not spend the same permission twice.

#### Target traffic and authority

No new authority. Local retries remain bounded by durable production receipts.

#### Exit gate

Every fault produces its documented terminal state and no fault can renew authority
or conceal cleanup uncertainty.

### Phase 6 — Permanent regression and release gate

#### Technical work

- Add the contract and wire layers to the normal local verification workflow.
- Keep native acceptance as an explicit macOS release gate.
- Run the existing Juice Shop calibration alongside the reference SaaS.
- Store only redacted, bounded artifacts.
- Document version updates and scenario change review.

#### Non-technical result

Future Sentinel changes cannot quietly break account creation, persona separation,
one-click behavioral scanning, or evidence production without the lab naming the
exact broken stage.

#### Target traffic and authority

Local acceptance traffic only. No authority change.

#### Exit gate

The full matrix is reproducible from a clean checkout using documented prerequisites,
and a skipped native gate can never be displayed as a pass.

## Proposed repository layout

The implementation should use a dedicated top-level lab area rather than mix target
code into Sentinel's production packages:

```text
labs/
  visual_acceptance/
    README.md
    compose.yml
    .env.example
    target/
      Dockerfile
      requirements.lock
      app/
      migrations/
      templates/
      static/
    control/
      Dockerfile
      app/
    scenarios/
      schema.json
      s01_signup_recording/
      s05_bola_vulnerable/
      s06_bola_secure/
    scripts/
      health
      reset
      collect-artifacts
    tests/
      contract/
      wire/
      visual/
```

The final path may be adjusted to existing repository conventions during
implementation, but production code and intentionally vulnerable lab code must remain
unmistakably separated.

## Cost model

| Item | Required cost |
| --- | --- |
| Public domain | $0 — none is used. |
| Web hosting | $0 — services run on the local Mac. |
| TLS certificate | $0 — HTTP by default; optional local CA later. |
| Email delivery | $0 — Mailpit receives mail locally. |
| SMS delivery | $0 — simulated challenge only. |
| Database | $0 — SQLite. |
| Frontend hosting/build service | $0 — assets are bundled in the target container. |
| Cloud CI | $0 — not required for the acceptance gate. |
| Container runtime | $0 incremental cost, assuming the existing local runtime used by Sentinel's current lab. |

The real costs are local disk space, CPU time, and maintenance. The plan deliberately
avoids converting any of those into a recurring subscription.

## Risks and controls

| Risk | Control |
| --- | --- |
| Sentinel overfits one lab layout | Render multiple visual shapes from the same semantic workflow and retain Juice Shop calibration. |
| Lab code accidentally teaches Sentinel the answer | Keep target standalone; compare only through HTTP behavior and independent artifacts. |
| Vulnerable target becomes reachable on the LAN | Bind to loopback, use an internal network, and fail health checks on unsafe publication. |
| Control plane is scanned as a target | Separate origin and signed scope; assert zero control-plane requests from Sentinel. |
| Mocks create false confidence | Reserve “native-proven” for the real Swift/WKWebView path. |
| Secure twin drifts from vulnerable twin | Generate both from one scenario definition with an explicit enforcement switch. |
| Flaky timing hides bugs | Use observable readiness, controlled lab time, deterministic seeds, and bounded waits. |
| Secrets leak into evidence | Synthetic identities, central redaction, artifact schema validation, and secret-pattern tests. |
| A restart renews an experiment | Verify durable receipt identity against the independent target ledger. |
| Local success is mistaken for universal coverage | Use precise validation labels and retain an authorized live-canary stage. |

## Recommended stopping point before resuming feature expansion

Implement through Phase 4 before treating the ordinary one-click behavioral path as
integration-proven. Phase 5 should follow before broadening state-changing proof
authority. Phase 6 should be complete before calling the lab a permanent release gate.

This does not pause all Sentinel development. It establishes the point at which new
behavioral slices can be measured against a real visual workflow instead of relying
only on mocked or router-level tests.

## First implementation pass

The first code pass should be Phase 0 plus the smallest Phase 1 vertical slice:

1. schemas for scenario, ledger event, and run result;
2. Compose with one target service and one control service;
3. one loopback URL;
4. one health page;
5. one resettable SQLite seed;
6. one request-ledger event;
7. loopback publication and resolution guards;
8. focused contract and real-wire tests.

It should not yet contain a fake vulnerability. The first pass proves that the
measuring instrument itself is deterministic and isolated before it is trusted to
grade Sentinel.
