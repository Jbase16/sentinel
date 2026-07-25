# Phase 1 Playbook — Find Out If Sentinel Works

**Goal of Phase 1:** Run Sentinel end-to-end against real-shaped targets and
generate honest empirical signal about what it finds, what it misses, and
where the engine breaks. No new subsystems. No speculative features. Just
running it, observing, debugging.

Phase 1 has two stages:

1. **Calibration** — scan a known-vulnerable lab target you control. Verify
   the rig actually finds what's findable.
2. **First real scan** — scan a bug-bounty program with a clear scope. Treat
   the result as empirical data, not as success or failure.

You do not move to stage 2 until stage 1 produces credible results.

---

## Prerequisites (one-time)

1. **Ollama installed and the Sentinel model loaded.**
   ```bash
   # if Ollama isn't running:
   brew services start ollama   # or: ollama serve

   # if the Sentinel model isn't loaded:
   #   1) put sentinel-9b-god-tier-Q4_K_M.gguf in ./models/
   #   2) ollama create sentinel-9b-god-tier -f Modelfile
   ```

2. **Docker installed** (for the Juice Shop lab).

3. **Python deps installed.**
   ```bash
   python3 -m pip install -r requirements.txt
   ```

---

## The empirical loop

For every scan, the loop is:

```
preflight → start lab (or real target) → run scan → inspect → triage gaps
   ↑                                                                  │
   └──────────────────  fix what broke and repeat  ←──────────────────┘
```

Most loops will fail the first time. That's the point — each failure is a
specific, debuggable signal about where the engine has a blind spot.

---

## Stage 1: Calibration scan against Juice Shop

### Step 1 — Pre-flight

```bash
python3 scripts/preflight.py --all
```

Expected output:

```
[OK] python version                   — 3.11+
[OK] core python deps                 — all importable
[OK] modelfile                        — FROM ./models/sentinel-...gguf
[OK] ollama reachable                 — http://localhost:11434
[OK] sentinel model loaded            — sentinel-9b-god-tier
[OK] api token file                   — 43 bytes, mode 0o600
[OK] sentinel backend                 — ready @ 127.0.0.1:8765
[OK] calibration lab                  — http://127.0.0.1:3000 up
[OK] scope file                       — scripts/lab/juice-shop-scope.txt: 7 rules

all checks passed — you're ready to scan.
```

Any `[!!]` failure prints a specific remediation hint. Fix and re-run until
everything is `[OK]`. **Do not skip this step.** Half of Phase 1 friction
comes from skipping pre-flight and then debugging a scan that was never going
to work.

### Step 2 — Start the calibration lab

```bash
cd scripts/lab
docker compose up -d
# wait ~30s for Juice Shop to come up
docker compose ps           # should show 'healthy'
curl -fsS http://127.0.0.1:3000/ -o /dev/null && echo "Juice Shop up"
cd ../..
```

The lab binds **only to 127.0.0.1**. It is not reachable from other machines
on your network. This is deliberate — Juice Shop is intentionally vulnerable
and must never face an untrusted network.

### Step 3 — Start the Sentinel backend

In a separate terminal:

```bash
bash scripts/start_backend.sh
```

This script activates the venv, ensures deps, and launches uvicorn on
`127.0.0.1:8765`. Watch for the line:

```
[Startup] state=ready
```

If you see `CriticalSecurityBreach` instead, the SecurityInterlock blocked
boot — something in your env wants the API on `0.0.0.0` without auth.
**Do not work around this.** Fix the env.

### Step 4 — Run the calibration scan

```bash
python3 pysentinel.py \
    --target http://127.0.0.1:3000 \
    --mode bug_bounty \
    --scope scripts/lab/juice-shop-scope.txt \
    --scope-strict
```

`--scope-strict` means "deny anything that doesn't match an allow rule." For
calibration, this is the right setting — if Sentinel ever asks to scan
something outside `127.0.0.1`, you want it blocked at the request layer
before the engine even starts.

Watch the event stream. You should see:

```
🟢 SCAN STARTED: http://127.0.0.1:3000 (session: ...)
🔧 [TOOL] Running httpx...
✅ [TOOL] httpx finished (1 findings, exit: 0)
📍 Phase Transition: ...
... findings ...
🏁 SCAN COMPLETED in 87.4s
   Total Findings: N
```

If the stream stalls for more than 60 seconds with no events, the engine is
likely waiting on a tool that's hung. Cancel with `Ctrl-C` and check what
the last tool was.

### Step 5 — Inspect what happened

```bash
python3 scripts/inspect_scan.py show --latest
```

You'll get a one-screen summary:

```
=== Session <uuid> ===
  target  : http://127.0.0.1:3000
  status  : completed
  duration: 87.4s

Counts
  findings    : 12
  issues      : 4
  evidence    : 7
  graph edges : 23

Tool execution
  [ok] httpx                runs=1  exit=0×1
  [ok] subfinder            runs=1  exit=0×1
  [!!] nuclei               runs=1  exit=1×1  (timed_out: 0)

Findings by severity
  high       2
  medium     5
  low        3
  info       2

Decisions by type
  tool_selection            12
  intent_transition         8
  phase_transition          4
```

**What to look for:**

- `[!!]` next to any tool — that tool failed. The scan still ran, but with
  blind spots. Look at the evidence for that tool to see why.
- Findings with `severity: high` — these are your candidates for credible
  bugs. Eyeball each one before celebrating.
- `Decisions by type` — gives you a sense of how much the scheduler was
  actively making choices vs. just running tools.

### Step 6 — Grade against the Juice Shop Scoreboard

Visit the running lab in a browser:
```
http://127.0.0.1:3000/#/score-board
```

This is Juice Shop's documented list of intentional vulnerabilities. Compare
to what Sentinel found:

- **Sentinel found a Scoreboard vuln** → that mutator works against this
  shape. Note the tool and finding type.
- **Sentinel missed a Scoreboard vuln** → coverage gap. Possible causes:
  - The relevant endpoint wasn't discovered (crawler gap).
  - The mutator ran but didn't recognise the evidence (parser gap).
  - The scheduler didn't reach the phase that runs that mutator (planner gap).
  Use `inspect_scan.py show --latest --json | jq .findings` to see the raw
  finding records.
- **Sentinel found something the Scoreboard doesn't list** → manually verify.
  Could be a real find. Could be a false positive.

Write down every gap. The gap list is the Phase 1 backlog.

### Step 7 — Diagnose a gap

For a missing vuln, start with these three questions:

1. **Did the relevant endpoint get crawled?**
   ```bash
   python3 scripts/inspect_scan.py show --latest --json | \
       jq '.findings[] | {tool, target}' | sort -u
   ```
   If the endpoint that hosts the missing vuln isn't in any finding's
   `target`, the crawler didn't reach it. Crawler gap.

2. **Did the relevant tool run against that endpoint?**
   ```sql
   sqlite3 ~/.sentinelforge/sentinel.db \
     "SELECT tool, target FROM evidence WHERE session_id = '<uuid>'"
   ```
   If the tool ran but produced no finding, the mutator's signal detection
   missed it. Parser gap.

3. **Did the scheduler ever get to the phase that runs that mutator?**
   Look at `Decisions by type` in the inspector output. If you see lots of
   `phase_transition` but never the phase you expected, the scheduler
   dropped out before getting there. Planner gap.

Write the diagnosis next to each gap in your backlog. By the time you've
diagnosed 5–10 gaps, patterns will emerge: most gaps tend to be one or two
root causes manifesting many places.

### Step 8 — Iterate

For each diagnosed gap:
- If the root cause is in code you can confidently change, fix it and re-run
  the calibration scan.
- If the root cause requires a bigger redesign, note it in `docs/roadmap.md`
  (now is a good time to make that file real) and continue.

You're calibrated when Sentinel finds at least **3 documented Scoreboard
vulnerabilities** without false positives that would result in noise reports
to a bounty program. That's the bar. Lower than that, the rig isn't ready.

### Step 9 — Tear down

```bash
cd scripts/lab && docker compose down
```

---

## Stage 2: First real bounty target

You should only be reading this section after Stage 1 produced credible
results.

### Choosing the program

The first program is a calibration target too, not your big swing. Constraints:

- **Clear written scope.** You can write the scope file from the program
  page in under five minutes. Anything vaguer is a future scope-violation
  bug for you.
- **Tolerant of automated scanning.** Most programs spell this out
  explicitly in the rules. If you don't see explicit permission, assume no.
- **Active triage team.** Look at the median response time published on the
  program page. Anything over 30 days will not give you the feedback loop
  you need.
- **Web app target.** Sentinel's strongest mutators (SQLi/SSRF/IDOR/
  reflection/persona-diff) all assume HTTP. Save mobile/native for later.
- **Small enough surface that you can manually verify.** If the scope is
  *.example.com and example.com has 200 subdomains, you cannot eyeball
  what Sentinel missed. Start with a program whose attack surface fits in
  one browser tab.

### Per-target scope file

Make a new file. Do not edit `scripts/lab/juice-shop-scope.txt`.

```bash
mkdir -p scope-files
cat > scope-files/program-X.txt <<'EOF'
# scope rules for HackerOne program <X> as documented at <url>
# pulled <date>

*.example-target.com
api.example-target.com
example-target.com

!staging.example-target.com
!*.internal.example-target.com
EOF
```

Pre-flight against this file:

```bash
python3 scripts/preflight.py --scope scope-files/program-X.txt
```

Spot-check by hand with the scope test pattern:

```python
# scratch.py — sanity check before running
from core.base.scope import ScopeRegistry, ScopeRule, AssetType, ScopeDecision

reg = ScopeRegistry(bounty_mode=True)
# ... add your rules ...
for url in [
    "https://example-target.com/login",        # expect ALLOW
    "https://api.example-target.com/v1",       # expect ALLOW
    "https://staging.example-target.com",      # expect DENY
    "https://other-company.com",               # expect DENY
]:
    d = reg.resolve(url)
    print(f"{d.verdict.value:8} {url}")
```

If a single one of those prints the wrong verdict, **do not run a scan.**
Fix the scope first.

### Running the first scan

```bash
python3 scripts/preflight.py --all   # confirm rig is healthy
python3 pysentinel.py \
    --target https://<chosen-program-host> \
    --mode bug_bounty
```

Watch the event stream. Cancel immediately if:

- A finding mentions a domain not in your scope file.
- The scan starts probing internal IPs (`10.*`, `192.168.*`, `127.*`).
- Tool exit codes show pattern of failures suggesting the target is rate-limiting.

When the scan completes:

```bash
python3 scripts/inspect_scan.py show --latest
```

### Triage workflow

For each finding the inspector lists:

1. **Verify by hand.** Open the target in a browser, attempt the
   reproduction manually. If you can't reproduce, it's a false positive.
2. **Check scope.** Confirm the finding's `target` is unambiguously in
   scope according to the program rules. When in doubt, exclude.
3. **Assess severity honestly.** Most "high" findings from a scanner are
   actually medium when triaged. Don't inflate.
4. **Decide: report, drop, or shelve.**
   - Report: the finding is reproducible, in scope, and not a known issue
     in the program's exclusion list. Write the report by hand for the
     first 1–3 — you're learning what triagers want before automating.
   - Drop: false positive or out of scope. Note it for future Sentinel
     tuning.
   - Shelve: real signal but needs more investigation. Save the session
     ID, keep the lab running, dig deeper.

### Writing the first report (manual)

Recommended structure for HackerOne / Bugcrowd / etc. is roughly:

```
# <Vulnerability Class>: <one-line summary>

## Summary
<2–3 sentences. What's vulnerable, what's the impact.>

## Steps to reproduce
1. <browser-pasteable steps>
2. ...

## Proof of concept
<curl command or screenshot. If Sentinel generated a Forge exploit,
 paste the relevant snippet. Always strip out anything Sentinel-internal.>

## Impact
<what an attacker can do with this>

## Suggested remediation
<one paragraph; nothing fancy>

## Discovery context
Discovered during an automated scan; verified manually.
Sentinel session: <uuid>  (kept locally for replay)
```

Do **not** mention "AI-generated" anywhere in the report. Triagers read
that as low-effort. The session ID stays local — it's for *your* records,
in case the triager has questions.

### What to learn from the first 3 reports

Independent of whether they're accepted, the first three reports teach you:

- What evidence triagers ask for that Sentinel didn't capture.
- What false-positive shapes you keep submitting (don't).
- How long the triage cycle takes for this program.
- Which finding classes are worth Sentinel's time on this target.

After three real reports — accepted, rejected, or duplicate — you have
empirical signal for Phase 2.

---

## When does Phase 1 end?

Phase 1 ends when you can answer all three of these honestly:

1. **Does Sentinel find real vulnerabilities?** At least one accepted (paid
   or unpaid) bounty report from a Sentinel-driven scan.
2. **Does Sentinel stay in scope?** Zero out-of-scope findings submitted.
   Zero scope-violation flags from any program.
3. **Do you trust the engine to run unattended for an hour?** No
   intervention required, no surprises in the inspector output.

If all three are yes, Phase 1 has answered the central question and you
have the data to design Phase 2. If any is no, keep iterating.

If after 4 weeks of trying you can't get to three yeses, the answer to
"does Sentinel work for bounties?" may be "not yet" — and the right move
is to either pick a different target class or pause Phase 1 and rebuild
the weakest subsystem before trying again.

---

## What does NOT belong in Phase 1

To keep the loop tight, defer these things:

- **Multi-target scanning.** One target at a time.
- **Persistent capsule writing.** The `CapsuleRecorder` exists but isn't
  wired to scan execution yet. Phase 2.
- **Report automation.** You write reports by hand for the first 1–3.
- **UI polish.** The Swift app and pysentinel.py are both fine; don't
  iterate on the UI when you're iterating on the engine.
- **New subsystems.** No new Thanatos modules, no new mutators. Only fix
  what the calibration gaps surface.
- **Adding more bug bounty programs.** One at a time. Three rounds of
  feedback from one program is worth a hundred shallow scans across ten.

When Phase 1 is done, the Phase 2 roadmap writes itself from your
calibration backlog and your first-report friction. Until then, do less.
